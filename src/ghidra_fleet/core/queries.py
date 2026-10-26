"""Query and mutation implementations against open Ghidra programs.

Every function here receives an already-open ``program`` (Java object obtained
via ``runtime.get_program``) and returns plain Python data. Java imports are
done inside the functions on purpose: they only resolve after the JVM started.
"""

from __future__ import annotations

from typing import Any, List, Optional

from ..util import MAX_SCAN, clamp_limit, clamp_offset, truncate
from .runtime import FleetError, runtime

# --------------------------------------------------------------------- helpers


def _try_addr(program, value: str):
    s = str(value).strip()
    if not s:
        return None
    af = program.getAddressFactory()
    try:
        return af.getAddress(s)
    except Exception:
        return None


def _require_addr(program, value: str):
    addr = _try_addr(program, value)
    if addr is None:
        raise FleetError(f"无法解析地址: '{value}'（示例: 0x140001000）")
    return addr


def resolve_function(program, name_or_address: str):
    """Find a function by entry address, exact name, or unique substring."""
    fm = program.getFunctionManager()
    raw = str(name_or_address).strip()

    if not raw.lower().startswith("0x"):
        # Ghidra 12 removed FunctionManager.getFunction(String): exact-name
        # lookup goes through the symbol table instead.
        st = program.getSymbolTable()
        for sym in st.getSymbols(raw):
            f = fm.getFunctionAt(sym.getAddress())
            if f is not None:
                return f

    addr = _try_addr(program, raw)
    if addr is not None:
        f = fm.getFunctionAt(addr) or fm.getFunctionContaining(addr)
        if f is not None:
            return f
        raise FleetError(f"地址 {raw} 处及其所在位置没有函数")

    needle = raw.lower()
    matches = []
    for f in fm.getFunctions(True):
        if needle in f.getName(True).lower():
            matches.append(f)
            if len(matches) >= 10:
                break
    if len(matches) == 1:
        return matches[0]
    if matches:
        raise FleetError(
            f"'{raw}' 非唯一，匹配到: {[m.getName(True) + ' @ ' + str(m.getEntryPoint()) for m in matches]}。"
            f"请用完整名称或入口地址"
        )
    raise FleetError(
        f"找不到函数 '{raw}'。用 list_functions 查看函数列表或 search_functions_by_name 搜索"
    )


def _string_value(data) -> Optional[str]:
    try:
        if not data.hasStringValue():
            return None
    except Exception:
        pass
    try:
        v = data.getValue()
        return v if isinstance(v, str) else None
    except Exception:
        return None


def _function_at(program, addr):
    return program.getFunctionManager().getFunctionContaining(addr)


def _fmt_ref(program, ref) -> str:
    frm = ref.getFromAddress()
    to = ref.getToAddress()
    rtype = str(ref.getReferenceType())
    who = _function_at(program, frm)
    who_s = who.getName(True) if who is not None else "-"
    return f"{frm}  {rtype:<12} -> {to if to is not None else '?'}  [{who_s}]"


# --------------------------------------------------------------------- queries


def list_functions(
    program, flt: Optional[str] = None, offset: int = 0, limit: int = 100
) -> List[str]:
    offset, limit = clamp_offset(offset), clamp_limit(limit)
    needle = (flt or "").lower()
    rows: List[str] = []
    skipped = 0
    for f in program.getFunctionManager().getFunctions(True):
        name = f.getName(True)
        if needle and needle not in name.lower():
            continue
        if skipped < offset:
            skipped += 1
            continue
        rows.append(f"{f.getEntryPoint()}  {name}")
        if len(rows) >= limit:
            break
    return rows


def search_functions_by_name(program, query: str, limit: int = 50) -> List[str]:
    needle = str(query).lower()
    limit = clamp_limit(limit)
    rows: List[str] = []
    for f in program.getFunctionManager().getFunctions(True):
        if needle in f.getName(True).lower():
            rows.append(f"{f.getEntryPoint()}  {f.getName(True)}")
            if len(rows) >= limit:
                break
    return rows


def function_info(program, name_or_address: str) -> dict:
    f = resolve_function(program, name_or_address)
    params = [str(p) for p in f.getParameters()]
    return {
        "name": f.getName(True),
        "entry": str(f.getEntryPoint()),
        "signature": str(f.getSignature()),
        "return_type": str(f.getReturnType().getName()),
        "params": params,
        "body_size": int(f.getBody().getNumAddresses()),
        "calling_convention": str(f.getCallingConventionName()),
    }


def decompile(program, name_or_address: str, max_chars: Optional[int] = None) -> str:
    f = resolve_function(program, name_or_address)
    ifc = runtime.get_decompiler(program)
    from ghidra.util.task import TaskMonitor  # type: ignore @UnresolvedImport

    result = ifc.decompileFunction(f, 90, TaskMonitor.DUMMY)
    if not result.decompileCompleted() or result.getDecompiledFunction() is None:
        raise FleetError(f"反编译失败: {result.getErrorMessage()}")
    code = result.getDecompiledFunction().getC()
    header = f"// {f.getName(True)} @ {f.getEntryPoint()}\n// {f.getSignature()}\n\n"
    return truncate(header + code, max_chars)


def disassemble(program, name_or_address: str, max_lines: int = 200) -> str:
    f = resolve_function(program, name_or_address)
    max_lines = max(1, min(int(max_lines), 2000))
    lines = [f"; {f.getName(True)} @ {f.getEntryPoint()}"]
    count = 0
    for ins in program.getListing().getInstructions(f.getBody(), True):
        lines.append(f"{ins.getAddress()}  {ins}")
        count += 1
        if count >= max_lines:
            lines.append("; ... [已达 max_lines 上限]")
            break
    return "\n".join(lines)


def xrefs_to(program, address: str) -> List[str]:
    addr = _require_addr(program, address)
    rm = program.getReferenceManager()
    rows = [_fmt_ref(program, r) for r in rm.getReferencesTo(addr)]
    if not rows:
        return [f"地址 {addr} 没有交叉引用"]
    return rows


def xrefs_from(program, address: str) -> List[str]:
    addr = _require_addr(program, address)
    rm = program.getReferenceManager()
    rows = []
    for r in rm.getReferencesFrom(addr):
        rows.append(f"{r.getFromAddress()}  {str(r.getReferenceType()):<12} -> {r.getToAddress()}")
    if not rows:
        return [f"地址 {addr} 没有向外的引用"]
    return rows


def function_xrefs(program, name_or_address: str) -> List[str]:
    f = resolve_function(program, name_or_address)
    rm = program.getReferenceManager()
    rows = [_fmt_ref(program, r) for r in rm.getReferencesTo(f.getEntryPoint())]
    if not rows:
        return [f"函数 {f.getName(True)} 没有被引用"]
    return rows


def list_imports(program, offset: int = 0, limit: int = 100) -> List[str]:
    offset, limit = clamp_offset(offset), clamp_limit(limit)
    rows: List[str] = []
    em = program.getExternalManager()
    for lib in em.getExternalLibraryNames():
        for loc in em.getExternalLocations(lib):
            addr = loc.getAddress()
            addr_s = str(addr) if addr is not None else "-"
            rows.append(f"{addr_s}  {lib}!{loc.getLabel()}")
    return rows[offset : offset + limit] if rows else ["(无导入符号)"]


def list_exports(program, offset: int = 0, limit: int = 100) -> List[str]:
    offset, limit = clamp_offset(offset), clamp_limit(limit)
    st = program.getSymbolTable()
    rows: List[str] = []
    it = st.getExternalEntryPointIterator()
    while it.hasNext():
        addr = it.next()
        sym = st.getPrimarySymbol(addr)
        name = sym.getName(True) if sym is not None else "?"
        rows.append(f"{addr}  {name}")
    return rows[offset : offset + limit] if rows else ["(无导出符号)"]


def list_segments(program) -> List[str]:
    rows = []
    for b in program.getMemory().getBlocks():
        perms = ("r" if b.isRead() else "-") + ("w" if b.isWrite() else "-") + ("x" if b.isExecute() else "-")
        rows.append(
            f"{b.getStart()}-{b.getEnd()}  {b.getName():<12} {perms}  {int(b.getSize())} bytes"
        )
    return rows


def list_strings(
    program, flt: Optional[str] = None, offset: int = 0, limit: int = 100
) -> List[str]:
    offset, limit = clamp_offset(offset), clamp_limit(limit)
    needle = (flt or "").lower()
    rows: List[str] = []
    scanned = 0
    skipped = 0
    it = program.getListing().getDefinedData(True)
    while it.hasNext() and scanned < MAX_SCAN:
        d = it.next()
        scanned += 1
        v = _string_value(d)
        if v is None:
            continue
        if needle and needle not in v.lower():
            continue
        if skipped < offset:
            skipped += 1
            continue
        shown = v if len(v) <= 200 else v[:200] + "..."
        rows.append(f"{d.getAddress()}  len={len(v)}  {shown!r}")
        if len(rows) >= limit:
            break
    if scanned >= MAX_SCAN and len(rows) < limit:
        rows.append(f"; [已扫描 {MAX_SCAN} 条数据后停止，结果可能不完整，请用 filter 缩小范围]")
    return rows


# --------------------------------------------------------------------- mutations


def _commit(program, description: str):
    """Save program changes to the shared project."""
    runtime.save_program(program)


def rename_function(program, old_name: str, new_name: str) -> str:
    from ghidra.program.model.symbol import SourceType  # type: ignore @UnresolvedImport
    from pyghidra import transaction  # type: ignore @UnresolvedImport

    f = resolve_function(program, old_name)
    with transaction(program, "ghidra-fleet rename_function"):
        f.setName(new_name, SourceType.USER_DEFINED)
    _commit(program, "rename_function")
    return f"已重命名 {f.getName(True)}: {old_name} -> {new_name} 并保存"


def rename_data(program, address: str, new_name: str) -> str:
    from ghidra.program.model.symbol import SourceType  # type: ignore @UnresolvedImport
    from pyghidra import transaction  # type: ignore @UnresolvedImport

    addr = _require_addr(program, address)
    st = program.getSymbolTable()
    with transaction(program, "ghidra-fleet rename_data"):
        sym = st.getPrimarySymbol(addr)
        if sym is not None:
            sym.setName(new_name, SourceType.USER_DEFINED)
        else:
            st.createLabel(addr, new_name, True)
    _commit(program, "rename_data")
    return f"已在 {addr} 设置标签 {new_name} 并保存"


def _iter_variables(func):
    try:
        return list(func.getAllVariables())
    except Exception:
        from ghidra.program.model.listing import Function as GFunction  # type: ignore @UnresolvedImport

        try:
            return list(func.getVariables(GFunction.FunctionUpdateType.CUSTOM))
        except Exception:
            return list(func.getParameters())


def rename_variable(program, function: str, old_name: str, new_name: str) -> str:
    from ghidra.program.model.symbol import SourceType  # type: ignore @UnresolvedImport
    from pyghidra import transaction  # type: ignore @UnresolvedImport

    f = resolve_function(program, function)
    target = None
    for v in _iter_variables(f):
        if v.getName() == old_name:
            target = v
            break
    if target is None:
        available = [v.getName() for v in _iter_variables(f)]
        raise FleetError(
            f"函数 {f.getName(True)} 中没有变量 '{old_name}'。可用变量: {available}"
        )
    with transaction(program, "ghidra-fleet rename_variable"):
        target.setName(new_name, SourceType.USER_DEFINED)
    _commit(program, "rename_variable")
    return f"已重命名变量 {old_name} -> {new_name}（{f.getName(True)}）并保存"


def set_function_prototype(program, function: str, prototype: str) -> str:
    import re

    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd  # type: ignore @UnresolvedImport
    from ghidra.app.util.parser import FunctionSignatureParser  # type: ignore @UnresolvedImport
    from ghidra.program.model.symbol import SourceType  # type: ignore @UnresolvedImport
    from ghidra.util.task import TaskMonitor  # type: ignore @UnresolvedImport
    from pyghidra import transaction  # type: ignore @UnresolvedImport

    f = resolve_function(program, function)
    text = prototype.strip()
    conv = None
    m = re.search(r"__(?:cdecl|stdcall|fastcall|thiscall|vectorcall|clrcall|syscall|unknown)", text)
    if m:
        conv = m.group(0)
        text = (text[: m.start()] + " " + text[m.end() :]).strip()

    parser = FunctionSignatureParser(program.getDataTypeManager(), None)
    try:
        fd = parser.parse(f.getSignature(), text)
    except Exception as e:
        raise FleetError(
            f"无法解析函数签名 '{prototype}'（示例: 'int func(char *buf, int len)'）: {e}"
        )
    if conv:
        try:
            fd.setCallingConvention(conv)
        except Exception:
            pass  # convention not valid for this language: keep the default

    with transaction(program, "ghidra-fleet set_function_prototype"):
        cmd = ApplyFunctionSignatureCmd(f.getEntryPoint(), fd, SourceType.USER_DEFINED)
        ok = cmd.applyTo(program, TaskMonitor.DUMMY)
    if not ok:
        raise FleetError(f"应用函数签名失败: {cmd.getStatusMsg()}")
    _commit(program, "set_function_prototype")
    g = program.getFunctionManager().getFunctionAt(f.getEntryPoint())
    return f"已应用签名: {g.getName(True)} @ {f.getEntryPoint()} = {g.getSignature()} 并保存"


def set_local_variable_type(program, function: str, variable_name: str, new_type: str) -> str:
    from ghidra.app.util.cparser.C import CParserUtils  # type: ignore @UnresolvedImport
    from ghidra.program.model.symbol import SourceType  # type: ignore @UnresolvedImport
    from pyghidra import transaction  # type: ignore @UnresolvedImport

    f = resolve_function(program, function)
    target = None
    for v in _iter_variables(f):
        if v.getName() == variable_name:
            target = v
            break
    if target is None:
        raise FleetError(f"函数 {f.getName(True)} 中没有变量 '{variable_name}'")

    # Ghidra 12 has no standalone string->DataType parser; run the real C
    # parser on a dummy signature and take its return type (supports
    # "struct X *", "unsigned char **", program typedefs, ...).
    text = f"{new_type.strip()} fleet_type_probe(void)"
    dt = None
    last_err = None
    for candidate in (text, text + ";"):
        try:
            fd = CParserUtils.parseSignature(None, program, candidate, True)
            if fd is not None:
                dt = fd.getReturnType()
                break
        except Exception as e:  # noqa: BLE001
            last_err = e
    if dt is None:
        raise FleetError(f"无法解析类型 '{new_type}': {last_err}")

    with transaction(program, "ghidra_fleet set_local_variable_type"):
        target.setDataType(dt, False, True, SourceType.USER_DEFINED)
    _commit(program, "set_local_variable_type")
    return f"已设置变量 {variable_name}: {new_type}（{f.getName(True)}）并保存"


_COMMENT_KINDS = ("plate", "pre", "eol", "post", "repeatable")


def set_comment(program, address: str, comment: str, kind: str = "eol") -> str:
    from ghidra.program.model.listing import CodeUnit  # type: ignore @UnresolvedImport
    from pyghidra import transaction  # type: ignore @UnresolvedImport

    kind = (kind or "eol").lower()
    if kind not in _COMMENT_KINDS:
        raise FleetError(f"kind 必须是 {'/'.join(_COMMENT_KINDS)} 之一，收到 '{kind}'")
    cu_kind = {
        "plate": CodeUnit.PLATE_COMMENT,
        "pre": CodeUnit.PRE_COMMENT,
        "eol": CodeUnit.EOL_COMMENT,
        "post": CodeUnit.POST_COMMENT,
        "repeatable": CodeUnit.REPEATABLE_COMMENT,
    }[kind]

    addr = _require_addr(program, address)
    listing = program.getListing()
    cu = listing.getCodeUnitAt(addr) or listing.getCodeUnitContaining(addr)
    if cu is None:
        raise FleetError(f"地址 {addr} 处没有代码单元")
    with transaction(program, "ghidra-fleet set_comment"):
        cu.setComment(cu_kind, comment)
    _commit(program, "set_comment")
    return f"已在 {addr} 设置 {kind} 注释并保存"


# --------------------------------------------------------------------- fleet-wide


def find_in_all_binaries(kind: str, query: str, limit_per_binary: int = 20) -> List[str]:
    kind = (kind or "").lower()
    if kind not in ("string", "function"):
        raise FleetError("kind 必须是 'string' 或 'function'")
    rows: List[str] = []
    programs = list(runtime.all_programs().items())[:200]  # bound output for big fleets
    for name, meta in programs:
        try:
            program = runtime.get_program(name)
        except Exception as e:
            rows.append(f"[{name}] 打开失败: {e}")
            continue
        hits: List[str] = []
        if kind == "function":
            hits = search_functions_by_name(program, query, limit_per_binary)
        else:
            hits = list_strings(program, flt=query, limit=limit_per_binary)
        if hits:
            rows.append(f"=== {name} ({len(hits)} hits) ===")
            rows.extend(hits)
    if not rows:
        return [f"所有 {len(programs)} 个二进制中都没有找到 {kind} 匹配 '{query}'"]
    return rows
