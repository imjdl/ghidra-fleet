"""FleetRuntime: JVM lifecycle, shared Ghidra project, manifest, program handle LRU.

Locking model (deadlock-free by ordering: never take ``self.lock`` -> plock):

- ``self.lock`` (global, short): protects the Ghidra project handle, the LRU
  dict, the manifest and resolve/open/evict bookkeeping.
- per-program RLock: held for the whole query/mutation on one program, so
  different binaries can be queried in parallel while the same binary is
  serialized against itself.
- pin counters: programs with in-flight work are never evicted from the LRU.
- Batch analysis is the exception: it runs ``pyghidra.analyze`` on background
  worker threads (one AutoAnalysisManager per program, parallel across programs).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

log = logging.getLogger("ghidra_fleet.runtime")


class FleetError(RuntimeError):
    """User-facing error (bad binary name, missing file, ...)."""


class Config:
    def __init__(self) -> None:
        self.ghidra_install_dir: Path | None = self._env_path("GHIDRA_INSTALL_DIR")
        # stable regardless of install method (src checkout vs wheel) and cwd
        default_projects = Path.home() / ".ghidra_fleet" / "projects"
        self.project_dir: Path = self._env_path("GHIDRA_FLEET_PROJECT_DIR", default_projects)
        self.project_name: str = os.environ.get("GHIDRA_FLEET_PROJECT_NAME", "fleet")
        workers = int(os.environ.get("GHIDRA_FLEET_MAX_WORKERS", "0") or 0)
        self.max_workers: int = workers if workers > 0 else min(4, os.cpu_count() or 2)
        self.max_open: int = int(os.environ.get("GHIDRA_FLEET_MAX_OPEN", "6") or 6)
        # empty string disables the explicit heap override (falls back to Ghidra defaults)
        self.xmx: str | None = os.environ.get("GHIDRA_FLEET_XMX", "4G") or None

    @staticmethod
    def _env_path(name: str, default: Path | None = None) -> Path | None:
        value = os.environ.get(name, "").strip()
        return Path(value) if value else default


class FleetRuntime:
    def __init__(self) -> None:
        self.cfg = Config()
        self.lock = threading.RLock()
        self._started = False
        self._project = None  # ghidra.base.project.GhidraProject handle
        self._programs: OrderedDict[str, Any] = OrderedDict()  # program_name -> Program (open)
        self._decomp: dict[str, Any] = {}  # program_name -> DecompInterface
        self._plocks: dict[str, threading.RLock] = {}  # program_name -> per-program lock
        self._pins: dict[str, int] = {}  # program_name -> in-flight use count
        self._manifest: dict[str, Any] = {"version": 1, "programs": {}}

    # ------------------------------------------------------------------ startup

    @property
    def manifest_path(self) -> Path:
        return self.cfg.project_dir / "manifest.json"

    def ensure_started(self) -> None:
        if self._started:
            return
        with self.lock:
            if self._started:
                return
            if not self.cfg.ghidra_install_dir:
                raise FleetError(
                    "环境变量 GHIDRA_INSTALL_DIR 未设置。"
                    "请在 MCP 配置的 env 中指向 Ghidra 安装目录"
                    "（即包含 ghidraRun 与 Ghidra/ 子目录的那个文件夹）"
                )
            install = self.cfg.ghidra_install_dir
            if not (install / "Ghidra" / "application.properties").exists():
                raise FleetError(f"GHIDRA_INSTALL_DIR 不是有效的 Ghidra 安装目录: {install}")

            log.info("starting JVM (ghidra=%s, xmx=%s)...", install, self.cfg.xmx)
            from pyghidra.launcher import HeadlessPyGhidraLauncher

            launcher = HeadlessPyGhidraLauncher(install_dir=str(install))
            if self.cfg.xmx:
                launcher.add_vmargs(f"-Xmx{self.cfg.xmx}")
            launcher.start()

            from ghidra.base.project import GhidraProject
            from ghidra.framework.model import ProjectLocator

            self.cfg.project_dir.mkdir(parents=True, exist_ok=True)
            locator = ProjectLocator(str(self.cfg.project_dir), self.cfg.project_name)
            try:
                if locator.exists():
                    self._project = GhidraProject.openProject(
                        str(self.cfg.project_dir), self.cfg.project_name, True
                    )
                else:
                    self._project = GhidraProject.createProject(
                        str(self.cfg.project_dir), self.cfg.project_name, False
                    )
            except Exception as e:
                if "LockException" in type(e).__name__ or "Unable to lock" in str(e):
                    lock_file = self.cfg.project_dir / (self.cfg.project_name + ".lock")
                    raise FleetError(
                        f"Ghidra 项目被另一个 ghidra-fleet 实例占用"
                        f"（{self.cfg.project_dir / self.cfg.project_name}）。"
                        f"同一时间只允许一个实例使用同一个项目目录：请关闭其他会话里的 "
                        f"ghidra-fleet，或给不同会话配置不同的 GHIDRA_FLEET_PROJECT_DIR。"
                        f"若确认没有其他实例，删除 {lock_file} 后重试。"
                    ) from e
                raise
            self._load_manifest()
            self._started = True
            log.info(
                "ghidra-fleet ready: project=%s/%s, programs_in_manifest=%d",
                self.cfg.project_dir,
                self.cfg.project_name,
                len(self._manifest["programs"]),
            )

    # ------------------------------------------------------------------ manifest

    def _load_manifest(self) -> None:
        if self.manifest_path.exists():
            try:
                data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
                if isinstance(data.get("programs"), dict):
                    self._manifest = data
            except Exception:  # corrupted manifest: start fresh rather than die
                log.exception("manifest.json unreadable, starting empty manifest")

    def _save_manifest(self) -> None:
        tmp = self.manifest_path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(self._manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        tmp.replace(self.manifest_path)

    def add_manifest_entry(self, program_name: str, meta: dict[str, Any]) -> None:
        with self.lock:
            self._manifest["programs"][program_name] = meta
            self._save_manifest()

    def find_by_sha(self, sha256: str) -> str | None:
        for name, meta in self._manifest["programs"].items():
            if meta.get("sha256") == sha256:
                return name
        return None

    def all_programs(self) -> dict[str, dict[str, Any]]:
        return dict(self._manifest["programs"])

    # ------------------------------------------------------------------ resolve

    def resolve_name(self, binary: str) -> str:
        """Resolve a user-supplied binary reference to the canonical program_name.

        Accepts: exact program_name, original path, unique file name,
        sha256 (full or 8-hex prefix).
        """
        progs = self._manifest["programs"]
        if binary in progs:
            return binary
        target = binary.replace("\\", "/").strip("/").lower()

        for name, meta in progs.items():
            p = str(meta.get("original_path", "")).replace("\\", "/").lower()
            if p and (p == target or p.endswith("/" + target)):
                return name

        base = target.rsplit("/", 1)[-1]
        by_base = [
            n
            for n, m in progs.items()
            if n.lower().rsplit("__", 1)[-1] == base
            or str(m.get("original_path", "")).replace("\\", "/").lower().rsplit("/", 1)[-1] == base
        ]
        if len(by_base) == 1:
            return by_base[0]
        if len(by_base) > 1:
            raise FleetError(
                f"'{binary}' 匹配到 {len(by_base)} 个二进制（同名不同内容）: "
                f"{by_base[:6]}，请改用完整 program_name 或 sha256 前 8 位"
            )

        for name, meta in progs.items():
            if name.split("__", 1)[0].lower() == target or meta.get("sha256", "").lower() == target:
                return name

        raise FleetError(
            f"未找到二进制 '{binary}'。请先调用 analyze_binaries 导入分析，"
            f"或用 list_binaries 查看已有的二进制列表"
        )

    # ------------------------------------------------------------------ programs

    def _domain_file_exists(self, program_name: str) -> bool:
        return self._project.getRootFolder().getFile(program_name) is not None

    def get_program(self, binary: str):
        """Resolve + open a program, tracking it in the LRU cache."""
        with self.lock:
            self.ensure_started()
            name = self.resolve_name(binary)
            prog = self._programs.get(name)
            if prog is not None:
                self._programs.move_to_end(name)
                return prog
            if not self._domain_file_exists(name):
                raise FleetError(
                    f"'{name}' 在 manifest 里但项目文件缺失（项目可能被移动/删除）。"
                    f"可删除 projects 目录后重新 analyze_binaries。"
                )
            prog = self._project.openProgram("/", name, False)
            self._register(name, prog)
            return prog

    def _register(self, name: str, prog) -> None:
        self._programs[name] = prog
        while len(self._programs) > self.cfg.max_open:
            # pinned programs are in active use: let the cache overshoot for now
            oldest = next((n for n in self._programs if self._pins.get(n, 0) == 0), None)
            if oldest is None or oldest == name:
                break
            self._evict(oldest)

    def _evict(self, name: str) -> None:
        prog = self._programs.pop(name, None)
        ifc = self._decomp.pop(name, None)
        if ifc is not None:
            with contextlib.suppress(Exception):
                ifc.dispose()
        if prog is None:
            return
        try:
            if prog.isChanged():
                self._project.save(prog)
        except Exception:
            log.exception("save before evict failed for %s", name)
        self._release_program(prog)

    def _pin(self, name: str) -> threading.RLock:
        self._pins[name] = self._pins.get(name, 0) + 1
        return self._plocks.setdefault(name, threading.RLock())

    def _unpin(self, name: str) -> None:
        left = self._pins.get(name, 1) - 1
        if left > 0:
            self._pins[name] = left
        else:
            self._pins.pop(name, None)

    @contextlib.contextmanager
    def acquire_program(self, binary: str):
        """Resolve + open + pin a program and hold its per-program lock.

        Use this from tool implementations: queries on different binaries run
        in parallel; queries on the same binary are serialized.
        """
        with self.lock:
            self.ensure_started()
            name = self.resolve_name(binary)
            prog = self.get_program(name)  # RLock re-entrant; LRU touched
            plock = self._pin(name)
        try:
            with plock:
                yield prog
        finally:
            with self.lock:
                self._unpin(name)

    @contextlib.contextmanager
    def temp_program(self, binary: str):
        """Open a program for a short read-only scan without LRU churn.

        Reuses an already-open handle when available, otherwise opens and
        releases a temporary one - avoids evict/save cycles when scanning a
        large fleet with a small max_open cache.
        """
        with self.lock:
            self.ensure_started()
            name = self.resolve_name(binary)
            plock = self._pin(name)
            existing = self._programs.get(name)
            if existing is not None:
                self._programs.move_to_end(name)
                prog, owned = existing, False
            else:
                prog, owned = self._project.openProgram("/", name, False), True
        try:
            with plock:
                yield prog
        finally:
            with self.lock:
                self._unpin(name)
                if owned:
                    self._release_program(prog)

    def delete_program(self, binary: str) -> str:
        """Delete a binary's project file and manifest entry."""
        with self.lock:
            self.ensure_started()
            name = self.resolve_name(binary)
            if self._pins.get(name, 0) > 0:
                raise FleetError(f"'{name}' 正在被查询/分析使用，请稍后再删除")
            df = self._project.getRootFolder().getFile(name)
            if name in self._programs:
                self._evict(name)
            if df is None:
                # ghost manifest entry: project file already gone
                self._manifest["programs"].pop(name, None)
                self._save_manifest()
                return f"'{name}' 的项目文件已不存在，已清理 manifest 记录"
            try:
                df.delete()  # void + IOException in Ghidra 12 (no boolean return)
            except Exception as e:
                raise FleetError(
                    f"删除 '{name}' 的项目文件失败（文件可能仍被占用）: {e}"
                ) from e
            self._manifest["programs"].pop(name, None)
            self._save_manifest()
            return f"已删除 '{name}'（项目文件 + manifest 记录）"

    def _release_program(self, prog) -> None:
        # GhidraProject owns the consumer handle for programs it opened/imported.
        try:
            self._project.close(prog)
        except Exception:
            try:
                prog.release(self._project)
            except Exception:
                log.exception("could not release evicted program %s", prog.getName())

    def save_program(self, prog) -> None:
        with self.lock:
            self._project.save(prog)

    def get_decompiler(self, prog):
        # Cache by the canonical program_name (not prog.getName()): the
        # internal name is just the original file name, so two same-named
        # binaries with different content would otherwise share one
        # DecompInterface, and eviction (keyed by canonical name) would never
        # dispose the right one -> "File is closed" on reopen.
        key = None
        for name, p in self._programs.items():
            if p is prog:
                key = name
                break
        if key is None:
            key = prog.getName()  # temp handle outside the LRU: best effort
        ifc = self._decomp.get(key)
        if ifc is not None:
            return ifc
        from ghidra.app.decompiler import DecompileOptions, DecompInterface

        ifc = DecompInterface()
        ifc.setOptions(DecompileOptions())
        ifc.openProgram(prog)
        self._decomp[key] = ifc
        return ifc

    def program_meta(self, prog) -> dict[str, Any]:
        meta = {
            "name": str(prog.getName()),
            "language": str(prog.getLanguageID()),
            "compiler": str(prog.getCompilerSpec().getCompilerSpecID()),
            "size": int(prog.getMemory().getSize()),
            "image_base": str(prog.getImageBase()),
        }
        return meta


runtime = FleetRuntime()
