"""Batch analysis jobs: import + analyze + save many binaries in parallel.

``submit()`` returns immediately with a job id (MCP tool calls must stay well
under the client timeout). Analysis itself runs on a thread pool; each program
gets its own AutoAnalysisManager so different binaries analyze concurrently.
Ghidra is not thread-happy about project bookkeeping, so import/save are
serialized under ``runtime.lock`` while only the (long) analysis phase runs
outside it.
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ..util import sha256_file
from .runtime import FleetError, runtime

log = logging.getLogger("ghidra_fleet.analyzer")


class Analyzer:
    # hard cap so accidentally passing a whole system directory doesn't
    # create a job with thousands of items
    MAX_JOB_FILES = 1000

    def __init__(self) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._job_seq = 0
        # sha256 -> Event for imports in flight; dedupes identical content
        # submitted in the same batch (worker races otherwise double-import)
        self._inflight: dict[str, threading.Event] = {}

    # ------------------------------------------------------------------ submit

    def submit(
        self, paths: str | list[str], recursive: bool = False
    ) -> dict[str, Any]:
        files = self._expand(paths, recursive)
        if not files:
            raise FleetError("没有找到任何要分析的文件")
        if len(files) > self.MAX_JOB_FILES:
            raise FleetError(
                f"一次作业最多 {self.MAX_JOB_FILES} 个文件，收到 {len(files)} 个。"
                f"请分批提交或只传目标文件/子目录"
            )

        with self._lock:
            self._job_seq += 1
            job_id = f"job{self._job_seq}_{uuid.uuid4().hex[:6]}"
            job: dict[str, Any] = {
                "job_id": job_id,
                "submitted": time.time(),
                "items": [
                    {"path": p, "status": "queued", "error": None, "program_name": None}
                    for p in files
                ],
            }
            self._jobs[job_id] = job
            # keep the registry bounded
            if len(self._jobs) > 50:
                for old in list(self._jobs)[:-50]:
                    self._jobs.pop(old, None)

        pool = ThreadPoolExecutor(
            max_workers=runtime.cfg.max_workers, thread_name_prefix="fleet-analyze"
        )
        for item in job["items"]:
            pool.submit(self._run_item, job, item)
        pool.shutdown(wait=False)

        return {
            "job_id": job_id,
            "submitted": len(files),
            "max_workers": runtime.cfg.max_workers,
            "hint": "调用 analysis_status(job_id) 轮询进度；分析完成的二进制可立即查询",
        }

    @staticmethod
    def _normalize_paths(paths: str | list[str]) -> list[str]:
        """Coerce sloppy client input into a flat list of path strings.

        LLM clients sometimes stringify the whole array instead of sending a
        real list ('[\"a.exe\", \"b.exe\"]' as one string) - unpack that.
        """
        if isinstance(paths, str):
            paths = [paths]
        out: list[str] = []
        for p in paths:
            if isinstance(p, str) and p.lstrip().startswith("["):
                with contextlib.suppress(Exception):
                    parsed = json.loads(p)
                    if isinstance(parsed, list):
                        out.extend(str(x) for x in parsed)
                        continue
            out.append(str(p))
        return out

    def _expand(self, paths: str | list[str], recursive: bool) -> list[str]:
        paths = self._normalize_paths(paths)
        project_root = runtime.cfg.project_dir.resolve()
        out: list[str] = []
        seen = set()
        for raw in paths:
            p = Path(raw).expanduser()
            if p.is_dir():
                it = p.rglob("*") if recursive else p.iterdir()
                for f in it:
                    if not f.is_file():
                        continue
                    if project_root in f.resolve().parents or f.resolve() == project_root:
                        continue  # never re-import our own project storage
                    key = str(f.resolve())
                    if key not in seen:
                        seen.add(key)
                        out.append(key)
            elif p.is_file():
                key = str(p.resolve())
                if key not in seen:
                    seen.add(key)
                    out.append(key)
            else:
                raise FleetError(
                    f"路径不存在: '{raw}'。请确认盘符/路径正确；"
                    f"paths 参数请传数组（如 [\"C:/a.exe\"]），不要传 JSON 字符串"
                )
        return out

    # ------------------------------------------------------------------ worker

    @staticmethod
    def _progress_monitor(on_progress):
        """Build a Ghidra TaskMonitor whose callback feeds on_progress(pct, msg).

        PyGhidraTaskMonitor(timeout, TriConsumer) calls the consumer with
        (progress, maximum, message); the timeout would auto-cancel analysis,
        so it is set to a practically-infinite value.
        """
        import jpype  # type: ignore @UnresolvedImport
        from ghidra.pyghidra import PyGhidraTaskMonitor  # type: ignore @UnresolvedImport
        from jpype.types import JInt  # type: ignore @UnresolvedImport

        @jpype.JImplements("org.apache.commons.lang3.function.TriConsumer")
        class _Cb:
            @jpype.JOverride
            def accept(self, progress, maximum, message):
                # progress reporting must never be able to break the analysis
                with contextlib.suppress(Exception):
                    maximum = int(maximum or 0)
                    pct = int(int(progress or 0) * 100 // maximum) if maximum > 0 else None
                    on_progress(pct, str(message) if message else "")

        return PyGhidraTaskMonitor(JInt(24 * 3600), _Cb())

    def _run_item(self, job: dict[str, Any], item: dict[str, Any]) -> None:
        item["status"] = "analyzing"
        item["started"] = time.time()
        path = item["path"]
        sha: str | None = None
        leader: threading.Event | None = None

        def on_progress(pct, msg):
            if pct is not None:
                item["progress_pct"] = pct
            if msg:
                item["phase"] = msg[:80]

        try:
            runtime.ensure_started()
            sha = sha256_file(path)

            # Cached already? Or identical content currently being imported by
            # a sibling worker -> wait for it instead of double-importing.
            while True:
                with runtime.lock:
                    existing = runtime.find_by_sha(sha)
                    if existing and runtime._domain_file_exists(existing):
                        item["status"] = "done"
                        item["cached"] = True
                        item["program_name"] = existing
                        item["elapsed"] = round(time.time() - item["started"], 1)
                        return
                    ev = self._inflight.get(sha)
                    if ev is None:
                        leader = threading.Event()
                        self._inflight[sha] = leader
                        break
                ev.wait(timeout=300)

            program_name = self._import_and_analyze(path, sha, on_progress)
            item["status"] = "done"
            item["program_name"] = program_name
            item["elapsed"] = round(time.time() - item["started"], 1)
        except Exception as e:
            log.exception("analysis failed for %s", path)
            item["status"] = "failed"
            item["error"] = f"{type(e).__name__}: {e}"[:400]
            item["elapsed"] = round(time.time() - item["started"], 1)
        finally:
            if leader is not None:
                with runtime.lock:
                    self._inflight.pop(sha, None)
                leader.set()

    def _import_and_analyze(self, path: str, sha: str, on_progress=None) -> str:
        import pyghidra
        from ghidra.program.util import GhidraProgramUtilities  # type: ignore @UnresolvedImport
        from java.io import File  # type: ignore @UnresolvedImport

        base = f"{sha[:8]}__{Path(path).name}"
        with runtime.lock:
            if runtime._domain_file_exists(base):
                # same hash prefix collision with different content: make unique
                base = f"{sha[:12]}__{Path(path).name}"

            program = runtime._project.importProgram(File(path))
            if program is None:
                raise FleetError(
                    f"Ghidra 无法导入 '{path}'（没有匹配的 loader，文件格式不受支持?）"
                )
            runtime._project.saveAs(program, "/", base, True)

        # Long phase: run WITHOUT the runtime lock so other binaries analyze in parallel.
        try:
            if GhidraProgramUtilities.shouldAskToAnalyze(program):
                if on_progress is not None:
                    pyghidra.analyze(program, monitor=self._progress_monitor(on_progress))
                else:
                    pyghidra.analyze(program)
        except Exception:
            with runtime.lock:
                runtime._release_program(program)
            raise

        with runtime.lock:
            runtime._project.save(program)
            meta = runtime.program_meta(program)
            meta.update(
                {
                    "sha256": sha,
                    "original_path": str(Path(path).resolve()),
                    "file_size": Path(path).stat().st_size,
                    "imported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                }
            )
            runtime.add_manifest_entry(base, meta)
            runtime._register(base, program)
        return base

    # ------------------------------------------------------------------ status

    def status(self, job_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            if job_id:
                job = self._jobs.get(job_id)
                if job is None:
                    raise FleetError(f"job 不存在: {job_id}（旧的 job 可能已被清理）")
                jobs = [job]
            else:
                jobs = list(self._jobs.values())
            out = []
            for job in jobs[-20:]:
                items = [
                    {
                        "path": Path(i["path"]).name,
                        "status": i["status"],
                        "progress_pct": i.get("progress_pct"),
                        "phase": i.get("phase"),
                        "program_name": i.get("program_name"),
                        "cached": i.get("cached", False),
                        "elapsed": i.get("elapsed"),
                        "error": i.get("error"),
                    }
                    for i in job["items"]
                ]
                done = sum(1 for i in job["items"] if i["status"] in ("done", "failed"))
                out.append(
                    {
                        "job_id": job["job_id"],
                        "progress": f"{done}/{len(job['items'])}",
                        "finished": done == len(job["items"]),
                        "items": items,
                    }
                )
        return {"jobs": out}

    def active_paths(self) -> set:
        """Paths currently being analyzed (for list_binaries markers)."""
        with self._lock:
            active = set()
            for job in self._jobs.values():
                for item in job["items"]:
                    if item["status"] in ("queued", "analyzing"):
                        active.add(item["path"])
            return active

    def binaries_summary(self) -> list[dict[str, Any]]:
        """Manifest + live status rows behind the list_binaries tool."""
        runtime.ensure_started()
        active = self.active_paths()
        with runtime.lock:
            rows = []
            for name, meta in runtime.all_programs().items():
                orig = str(meta.get("original_path", ""))
                if orig in active:
                    status = "analyzing"
                elif not runtime._domain_file_exists(name):
                    status = "missing"  # ghost entry: project file deleted manually
                elif name in runtime._programs:
                    status = "open"
                else:
                    status = "ready"
                rows.append(
                    {
                        "program_name": name,
                        "file": Path(orig).name if orig else name,
                        "sha256": str(meta.get("sha256", ""))[:12] + "...",
                        "language": meta.get("language", ""),
                        "file_size": meta.get("file_size"),
                        "imported_at": meta.get("imported_at"),
                        "status": status,
                    }
                )
        return rows


analyzer = Analyzer()
