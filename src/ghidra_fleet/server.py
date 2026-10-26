"""MCP tool surface for ghidra-fleet.

Every tool targets a binary selected by the ``binary`` parameter, so one
server can serve an entire fleet of analyzed binaries at once. ``binary``
accepts: 完整 program_name（形如 ab12cd34__sample.exe）、原始路径、唯一文件名、
或 sha256 前 8 位 —— 用 list_binaries 查看全部。

Ghidra API calls are serialized under ``runtime.lock``; batch analysis runs
on background threads and never blocks a tool call for long.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional, Union

from fastmcp import FastMCP

from .core import queries
from .core.analyzer import analyzer
from .core.runtime import runtime

log = logging.getLogger("ghidra_fleet.server")

mcp = FastMCP("ghidra-fleet")


# --------------------------------------------------------------------- fleet ops


@mcp.tool()
def analyze_binaries(paths: Union[List[str], str], recursive: bool = False) -> dict:
    """批量导入并分析二进制文件（后台并行执行，立即返回 job_id）。

    paths: 单个路径或路径列表；目录会展开为其中的文件（recursive=true 时递归展开）。
    已分析过（相同 sha256）的文件会自动跳过并标记 cached。
    返回后用 analysis_status(job_id) 轮询进度；已完成的二进制可以立刻查询。
    """
    try:
        runtime.ensure_started()
        return analyzer.submit(paths, recursive=recursive)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@mcp.tool()
def analysis_status(job_id: Optional[str] = None) -> dict:
    """查询分析作业进度。不传 job_id 时返回最近的所有作业。"""
    try:
        return analyzer.status(job_id)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@mcp.tool()
def list_binaries() -> dict:
    """列出项目中所有已分析的二进制及其元数据（program_name、架构、大小、sha256、状态）。"""
    try:
        return {"binaries": analyzer.binaries_summary()}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@mcp.tool()
def find_in_all_binaries(kind: str, query: str, limit_per_binary: int = 20) -> list:
    """跨所有已分析的二进制搜索（旧的单文件 MCP 做不到的核心能力）。

    kind: "string" 或 "function"。query 为子串（不区分大小写）。
    典型用途：在一批样本中找共同的函数名/字符串特征。最多扫描最近分析的 200 个二进制。
    """
    try:
        with runtime.lock:
            return queries.find_in_all_binaries(kind, query, limit_per_binary)
    except Exception as e:
        return [f"ERROR: {type(e).__name__}: {e}"]


# --------------------------------------------------------------------- queries


@mcp.tool()
def list_functions(
    binary: str, filter: Optional[str] = None, offset: int = 0, limit: int = 100
) -> list:
    """列出二进制中的所有函数（分页）。filter 为函数名子串过滤（不区分大小写）。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.list_functions(program, filter, offset, limit)
    except Exception as e:
        return [f"ERROR: {type(e).__name__}: {e}"]


@mcp.tool()
def list_methods(
    binary: str, filter: Optional[str] = None, offset: int = 0, limit: int = 100
) -> list:
    """list_functions 的别名（兼容旧工具名习惯）。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.list_functions(program, filter, offset, limit)
    except Exception as e:
        return [f"ERROR: {type(e).__name__}: {e}"]


@mcp.tool()
def search_functions_by_name(binary: str, query: str, limit: int = 50) -> list:
    """按名称子串搜索函数（不区分大小写）。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.search_functions_by_name(program, query, limit)
    except Exception as e:
        return [f"ERROR: {type(e).__name__}: {e}"]


@mcp.tool()
def function_info(binary: str, function: str) -> dict:
    """查看函数详情：签名、入口地址、参数、返回类型、大小、调用约定。function 接受函数名或入口地址。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.function_info(program, function)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


@mcp.tool()
def decompile_function(binary: str, function: str, max_chars: int = 20000) -> str:
    """反编译函数为 C 伪代码。function 接受函数名（支持唯一子串）或入口地址。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.decompile(program, function, max_chars)
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


@mcp.tool()
def disassemble_function(binary: str, function: str, max_lines: int = 200) -> str:
    """反汇编函数（汇编指令列表）。function 接受函数名或入口地址。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.disassemble(program, function, max_lines)
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


@mcp.tool()
def get_xrefs_to(binary: str, address: str) -> list:
    """查看引用到指定地址的所有交叉引用（谁引用了它）。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.xrefs_to(program, address)
    except Exception as e:
        return [f"ERROR: {type(e).__name__}: {e}"]


@mcp.tool()
def get_xrefs_from(binary: str, address: str) -> list:
    """查看指定地址向外的所有引用（它引用了谁）。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.xrefs_from(program, address)
    except Exception as e:
        return [f"ERROR: {type(e).__name__}: {e}"]


@mcp.tool()
def get_function_xrefs(binary: str, function: str) -> list:
    """查看函数的调用者（谁调用了这个函数）。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.function_xrefs(program, function)
    except Exception as e:
        return [f"ERROR: {type(e).__name__}: {e}"]


@mcp.tool()
def list_imports(binary: str, offset: int = 0, limit: int = 100) -> list:
    """列出导入符号（库!名称）。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.list_imports(program, offset, limit)
    except Exception as e:
        return [f"ERROR: {type(e).__name__}: {e}"]


@mcp.tool()
def list_exports(binary: str, offset: int = 0, limit: int = 100) -> list:
    """列出导出符号。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.list_exports(program, offset, limit)
    except Exception as e:
        return [f"ERROR: {type(e).__name__}: {e}"]


@mcp.tool()
def list_segments(binary: str) -> list:
    """列出内存段（名称、范围、读写执行权限、大小）。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.list_segments(program)
    except Exception as e:
        return [f"ERROR: {type(e).__name__}: {e}"]


@mcp.tool()
def list_strings(
    binary: str, filter: Optional[str] = None, offset: int = 0, limit: int = 100
) -> list:
    """列出程序中的字符串（分页，filter 子串过滤）。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.list_strings(program, filter, offset, limit)
    except Exception as e:
        return [f"ERROR: {type(e).__name__}: {e}"]


# --------------------------------------------------------------------- mutations


@mcp.tool()
def rename_function(binary: str, old_name: str, new_name: str) -> str:
    """重命名函数（立即保存到项目，GUI 打开同一项目可见）。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.rename_function(program, old_name, new_name)
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


@mcp.tool()
def rename_data(binary: str, address: str, new_name: str) -> str:
    """在指定地址设置/重命名数据标签。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.rename_data(program, address, new_name)
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


@mcp.tool()
def rename_variable(binary: str, function: str, old_name: str, new_name: str) -> str:
    """重命名函数内的局部变量/参数。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.rename_variable(program, function, old_name, new_name)
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


@mcp.tool()
def set_function_prototype(binary: str, function: str, prototype: str) -> str:
    """设置函数原型/签名，例如 'int func(char *buf, int len)'。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.set_function_prototype(program, function, prototype)
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


@mcp.tool()
def set_local_variable_type(binary: str, function: str, variable_name: str, new_type: str) -> str:
    """设置函数局部变量/参数的类型，例如 'char *'、'unsigned int'、'struct MY_STRUCT *'。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.set_local_variable_type(program, function, variable_name, new_type)
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


@mcp.tool()
def set_comment(binary: str, address: str, comment: str, kind: str = "eol") -> str:
    """在指定地址设置注释。kind: plate/pre/eol/post/repeatable（默认 eol）。"""
    try:
        with runtime.lock:
            program = runtime.get_program(binary)
            return queries.set_comment(program, address, comment, kind)
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"
