"""End-to-end smoke test driving the core directly (no MCP layer).

Usage:
    .venv/Scripts/python tests/smoke_test.py <binary1> <binary2> ...

Picks small system binaries if no paths are given. Verifies:
batch parallel analysis, caching (second submit skips), queries,
renames persisted after handle eviction + reopen.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

if not os.environ.get("GHIDRA_INSTALL_DIR"):
    print("ERROR: 请先设置 GHIDRA_INSTALL_DIR=<你的 Ghidra 安装目录> 再运行测试")
    raise SystemExit(1)
os.environ.setdefault("GHIDRA_FLEET_PROJECT_DIR", str(Path(__file__).resolve().parents[1] / "projects"))
os.environ.setdefault("GHIDRA_FLEET_MAX_OPEN", "3")

from ghidra_fleet.core import queries  # noqa: E402
from ghidra_fleet.core.analyzer import analyzer  # noqa: E402
from ghidra_fleet.core.runtime import runtime  # noqa: E402

PASS = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f"  -- {detail}" if detail else ""))
    if cond:
        PASS += 1
    else:
        raise SystemExit(f"smoke test failed at: {name} {detail}")


def _which_any(names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def main() -> None:
    targets = sys.argv[1:]
    if not targets:
        if os.name == "nt":
            names = ["where.exe", "robocopy.exe", "hostname.exe"]
        else:
            names = ["ls", "true", "uname"]
        targets = [p for p in (shutil.which(n) for n in names) if p][:2]
    if len(targets) < 2:
        raise SystemExit("需要至少两个测试样本：传参指定，或确保 PATH 上有系统小工具")
    print(f"targets: {targets}")

    t0 = time.time()
    runtime.ensure_started()
    print(f"JVM + project startup: {time.time() - t0:.1f}s")

    # 1) batch analyze
    job = analyzer.submit(targets)
    job_id = job["job_id"]
    print(f"submitted {job_id}, max_workers={job['max_workers']}")
    while True:
        st = analyzer.status(job_id)
        j = st["jobs"][0]
        print(f"  progress {j['progress']}")
        if j["finished"]:
            break
        time.sleep(3)
    for item in j["items"]:
        print(f"  {item['path']}: {item['status']} cached={item.get('cached')} "
              f"elapsed={item.get('elapsed')}s {item.get('program_name') or item.get('error')}")
        check(f"analyze {item['path']}", item["status"] == "done", item.get("error") or "")

    # 2) cache: resubmit must be instant and cached
    t0 = time.time()
    job2 = analyzer.submit(targets)
    while not analyzer.status(job2["job_id"])["jobs"][0]["finished"]:
        time.sleep(0.5)
    cached_all = all(i.get("cached") for i in analyzer.status(job2["job_id"])["jobs"][0]["items"])
    check("re-submit cached & fast", cached_all and time.time() - t0 < 30,
          f"{time.time() - t0:.1f}s")

    # 3) list_binaries content
    names = [r["program_name"].lower() for r in analyzer.binaries_summary()]
    check("list_binaries has both", all(
        any(t.split("\\")[-1].lower() in n for n in names) for t in targets), str(names))

    # 4) queries on first binary
    prog = runtime.get_program(targets[0])
    funcs = queries.list_functions(prog, limit=1000)
    check("list_functions non-empty", len(funcs) > 0, f"{len(funcs)} functions")
    print(f"  sample: {funcs[:3]}")

    segs = queries.list_segments(prog)
    check("list_segments", len(segs) > 0, segs[0] if segs else "")

    strs = queries.list_strings(prog, limit=10)
    print(f"  strings sample: {strs[:2]}")

    imports = queries.list_imports(prog, limit=10)
    print(f"  imports sample: {imports[:3]}")
    exports = queries.list_exports(prog, limit=10)
    print(f"  exports sample: {exports[:3]}")

    # 5) decompile a real (non-thunk) function
    fm = prog.getFunctionManager()
    target_fn = None
    for f in fm.getFunctions(True):
        if not f.isThunk() and f.getBody().getNumAddresses() > 16:
            target_fn = f
            break
    check("found non-thunk function", target_fn is not None)
    fname = target_fn.getName(True)
    code = queries.decompile(prog, fname, 4000)
    check("decompile produced C", "{" in code and len(code) > 100, code[:120].replace("\n", " "))

    callers = queries.function_xrefs(prog, fname)
    print(f"  xrefs sample: {callers[:2]}")

    # 6) mutation + eviction + reopen persistence
    new_name = "fleet_test_renamed_" + str(int(time.time()))
    print(queries.rename_function(prog, fname, new_name))
    entry = str(target_fn.getEntryPoint())
    print(queries.set_comment(prog, entry, "smoke test comment", "plate"))

    runtime._evict(runtime.resolve_name(targets[0]))  # force close
    prog2 = runtime.get_program(targets[0])
    check("rename persisted after reopen",
          any(new_name in r for r in queries.list_functions(prog2, limit=1000)))

    # 7) cross-binary search
    hits = queries.find_in_all_binaries("string", "Windows", 3)
    print(f"  find_in_all_binaries sample: {hits[:4]}")
    check("cross-binary search ran", isinstance(hits, list) and len(hits) > 0)

    # 8) prototype / variable-type writes (ApplyFunctionSignatureCmd + DataTypeParser)
    with_params = None
    host = None
    for t in targets:
        p = runtime.get_program(t)
        for f in p.getFunctionManager().getFunctions(True):
            if not f.isThunk() and len(f.getParameters()) > 0:
                with_params, host = f, p
                break
        if with_params is not None:
            break
    if with_params is None:
        print("[SKIP] 没有带参数的函数，跳过 prototype/变量类型检查")
    else:
        entry_p = str(with_params.getEntryPoint())
        print(queries.set_function_prototype(
            host, with_params.getName(True),
            "int __stdcall fleet_proto(int count, char *data)"))
        info = queries.function_info(host, entry_p)
        check("prototype applied", "fleet_proto" in info["name"] + info["signature"],
              info["signature"])
        # str(Parameter) looks like "[int count@ECX:4]": strip decoration
        p0 = (
            info["params"][0].strip("[]").split("@")[0].strip().split()[-1].lstrip("*")
            if info["params"]
            else None
        )
        if p0:
            print(queries.rename_variable(host, entry_p, p0, "fleet_var"))
            print(queries.set_local_variable_type(host, entry_p, "fleet_var", "unsigned int"))
            info2 = queries.function_info(host, entry_p)
            check("variable renamed & typed",
                  any("fleet_var" in p for p in info2["params"]), str(info2["params"]))

    # 9) duplicate-content race: two copies of a NEW binary in one job
    import tempfile

    src = _which_any(["hostname", "cacls", "id", "whoami"])
    if src is None:
        print("[SKIP] duplicate-race check: no candidate binary")
    else:
        before = len(runtime.all_programs())
        with tempfile.TemporaryDirectory() as td:
            c1 = str(Path(td) / "dup_a.exe")
            c2 = str(Path(td) / "dup_b.exe")
            shutil.copyfile(src, c1)
            shutil.copyfile(src, c2)
            job3 = analyzer.submit([c1, c2])
            while not analyzer.status(job3["job_id"])["jobs"][0]["finished"]:
                time.sleep(2)
            items3 = analyzer.status(job3["job_id"])["jobs"][0]["items"]
            for i in items3:
                print(f"  dup {i['path']}: {i['status']} cached={i.get('cached')} {i.get('program_name')}")
            after = len(runtime.all_programs())
            check(
                "duplicate content -> single manifest entry",
                all(i["status"] == "done" for i in items3) and after == before + 1,
                f"before={before} after={after}",
            )

    print(f"\nALL {PASS} CHECKS PASSED")


if __name__ == "__main__":
    main()
