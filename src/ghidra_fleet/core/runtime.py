"""FleetRuntime: JVM lifecycle, shared Ghidra project, manifest, program handle LRU.

All Ghidra Java API access from tool threads must happen while holding
``runtime.lock`` so the single embedded JVM is driven serially. Batch analysis
is the exception: it runs ``pyghidra.analyze`` on background worker threads
(one AutoAnalysisManager per program, parallel across programs).
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger("ghidra_fleet.runtime")


class FleetError(RuntimeError):
    """User-facing error (bad binary name, missing file, ...)."""


class Config:
    def __init__(self) -> None:
        self.ghidra_install_dir: Optional[Path] = self._env_path("GHIDRA_INSTALL_DIR")
        # stable regardless of install method (src checkout vs wheel) and cwd
        default_projects = Path.home() / ".ghidra_fleet" / "projects"
        self.project_dir: Path = self._env_path("GHIDRA_FLEET_PROJECT_DIR", default_projects)
        self.project_name: str = os.environ.get("GHIDRA_FLEET_PROJECT_NAME", "fleet")
        workers = int(os.environ.get("GHIDRA_FLEET_MAX_WORKERS", "0") or 0)
        self.max_workers: int = workers if workers > 0 else min(4, os.cpu_count() or 2)
        self.max_open: int = int(os.environ.get("GHIDRA_FLEET_MAX_OPEN", "6") or 6)
        # empty string disables the explicit heap override (falls back to Ghidra defaults)
        self.xmx: Optional[str] = os.environ.get("GHIDRA_FLEET_XMX", "4G") or None

    @staticmethod
    def _env_path(name: str, default: Optional[Path] = None) -> Optional[Path]:
        value = os.environ.get(name, "").strip()
        return Path(value) if value else default


class FleetRuntime:
    def __init__(self) -> None:
        self.cfg = Config()
        self.lock = threading.RLock()
        self._started = False
        self._project = None  # ghidra.base.project.GhidraProject handle
        self._programs: "OrderedDict[str, Any]" = OrderedDict()  # program_name -> Program (open)
        self._decomp: Dict[str, Any] = {}  # program_name -> DecompInterface
        self._manifest: Dict[str, Any] = {"version": 1, "programs": {}}

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
                    raise FleetError(
                        f"Ghidra 项目被另一个 ghidra-fleet 实例占用"
                        f"（{self.cfg.project_dir / self.cfg.project_name}）。"
                        f"同一时间只允许一个实例使用同一个项目目录：请关闭其他 ZCode 会话里的 "
                        f"ghidra-fleet，或给不同会话配置不同的 GHIDRA_FLEET_PROJECT_DIR。"
                        f"若确认没有其他实例，删除项目目录下的 {self.cfg.project_name}.lock 后重试。"
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

    def add_manifest_entry(self, program_name: str, meta: Dict[str, Any]) -> None:
        with self.lock:
            self._manifest["programs"][program_name] = meta
            self._save_manifest()

    def find_by_sha(self, sha256: str) -> Optional[str]:
        for name, meta in self._manifest["programs"].items():
            if meta.get("sha256") == sha256:
                return name
        return None

    def all_programs(self) -> Dict[str, Dict[str, Any]]:
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
            oldest = next(iter(self._programs))
            if oldest == name:
                break
            self._evict(oldest)

    def _evict(self, name: str) -> None:
        prog = self._programs.pop(name, None)
        ifc = self._decomp.pop(name, None)
        if ifc is not None:
            try:
                ifc.dispose()
            except Exception:
                log.exception("decompiler dispose failed for %s", name)
        if prog is None:
            return
        try:
            self._project.save(prog)
        except Exception:
            log.exception("save before evict failed for %s", name)
        self._release_program(prog)

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
        key = prog.getName()
        ifc = self._decomp.get(key)
        if ifc is not None:
            return ifc
        from ghidra.app.decompiler import DecompInterface, DecompileOptions

        ifc = DecompInterface()
        ifc.setOptions(DecompileOptions())
        ifc.openProgram(prog)
        self._decomp[key] = ifc
        return ifc

    def program_meta(self, prog) -> Dict[str, Any]:
        meta = {
            "name": str(prog.getName()),
            "language": str(prog.getLanguageID()),
            "compiler": str(prog.getCompilerSpec().getCompilerSpecID()),
            "size": int(prog.getMemory().getSize()),
            "image_base": str(prog.getImageBase()),
        }
        return meta


runtime = FleetRuntime()
