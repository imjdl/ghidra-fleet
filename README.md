# ghidra-fleet

**一个 MCP 服务器，同时分析任意多个二进制文件，零端口占用。**

解决传统 GhidraMCP 的痛点："1 个二进制 = 1 个 GUI 实例 = 1 个端口 = 1 份 MCP 配置"。
ghidra-fleet 完全无 GUI 运行（headless），AI 配置一次即可批量导入、并行分析、
跨样本交叉查询，分析结果落在标准 Ghidra 项目里，随时可以打开 GUI 人工复核。

```
MCP 客户端 ──stdio── ghidra-fleet (fastmcp)
                       ├─ core/runtime.py   PyGhidra 内嵌 JVM + 共享 .gpr 项目
                       │                    + 程序句柄懒加载 / LRU 逐出（控内存）
                       ├─ core/analyzer.py  批量分析：线程池并行、sha256 去重复用、
                       │                    后台作业 + 轮询（不受 MCP 30s 超时影响）
                       └─ core/queries.py   反编译/交叉引用/列表/重命名/跨样本搜索
```

## 安装

前置：已安装 Ghidra + Python 3.10+。

> 实测环境：Windows 11 + Ghidra 12.1 + Python 3.14。Linux/macOS 提供了对应的
> 安装脚本与跨平台测试（测试样本自动按平台选取），但未在 CI 上持续验证。

```bat
:: Windows
scripts\setup_env.bat <你的 Ghidra 安装目录>
```

```bash
# Linux / macOS
GHIDRA_INSTALL_DIR=/path/to/ghidra scripts/setup_env.sh
```

脚本会创建 `.venv` 并安装：fastmcp（PyPI）+ pyghidra（**Ghidra 安装目录自带的
wheel，版本严格匹配**）。若自带 jpype1 wheel 不覆盖你的 Python 版本，会自动
改用 PyPI 的兼容版 jpype1。

## 配置到 MCP 客户端

以 ZCode 为例，`~/.zcode/cli/config.json` 的 `mcp.servers` 里加（用户级），
路径换成你自己的：

```json
"ghidra-fleet": {
  "type": "stdio",
  "command": "<repo>\\.venv\\Scripts\\python.exe",
  "args": ["-m", "ghidra_fleet"],
  "cwd": "<repo>",
  "env": {
    "GHIDRA_INSTALL_DIR": "<你的 Ghidra 安装目录>"
  },
  "timeoutMs": 120000
}
```

Linux/macOS 下 `command` 用 `<repo>/.venv/bin/python`。
`timeoutMs` 建议保留：首次调用要启动 JVM + Ghidra（约 10~30 秒），之后都是毫秒级。
旧的单文件 GUI 版 MCP 无需删除，两者共存。

## 工具一览（23 个）

所有查询/改名工具的第一个参数都是 `binary`，接受：
完整 program_name（`ab12cd34__sample.exe`）/ 原始路径 / 唯一文件名 / sha256 前 8 位。
用 `list_binaries` 随时查看全部。

| 类别 | 工具 | 说明 |
|---|---|---|
| 舰队 | `analyze_binaries` | 批量导入+并行分析（目录也可，单批上限 1000 个文件），立即返回 job_id |
| | `analysis_status` | 轮询作业进度（已完成的可立刻查询） |
| | `list_binaries` | 所有二进制 + 架构/大小/哈希/状态 |
| | `find_in_all_binaries` | **跨全部样本**搜同名函数/同字符串（找共享代码/家族特征，最多扫 200 个） |
| 查询 | `list_functions` / `list_methods` / `search_functions_by_name` | 函数列表/搜索 |
| | `decompile_function` / `disassemble_function` | 反编译 C / 反汇编 |
| | `function_info` | 签名、参数、调用约定等 |
| | `get_xrefs_to` / `get_xrefs_from` / `get_function_xrefs` | 交叉引用 |
| | `list_imports` / `list_exports` / `list_segments` / `list_strings` | 导入导出/内存段/字符串 |
| 修改 | `rename_function` / `rename_data` / `rename_variable` | 重命名（即时保存） |
| | `set_function_prototype` / `set_local_variable_type` | 签名/变量类型 |
| | `set_comment` | 注释（plate/pre/eol/post/repeatable） |

## 典型工作流

```
用户: 把 C:\samples\ 下的 20 个样本都分析了，找出它们的共同特征

AI:  1. analyze_binaries(["C:\\samples"], recursive=true)   → job_id
     2. analysis_status(job_id)                              → 轮询到完成（旧样本秒级跳过）
     3. list_binaries()                                      → 拿到全部 program_name
     4. find_in_all_binaries("string", "http://")            → 跨样本特征
        find_in_all_binaries("function", "encrypt")          → 共享函数
     5. decompile_function("ab12cd34__x.exe", "FUN_00401000")
        rename_function("ab12cd34__x.exe", "FUN_00401000", "c2_beacon_decode")
```

改名/注释/类型修改即时保存进项目；用 Ghidra GUI 打开
`<项目目录>/fleet.gpr`（File → Open Project）即可看到 AI 的全部标注。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `GHIDRA_INSTALL_DIR` | （必填） | Ghidra 安装目录 |
| `GHIDRA_FLEET_PROJECT_DIR` | `~/.ghidra_fleet/projects` | Ghidra 项目目录 |
| `GHIDRA_FLEET_PROJECT_NAME` | `fleet` | 项目名 |
| `GHIDRA_FLEET_MAX_WORKERS` | `min(4, CPU)` | 并行分析线程数；遇到分析器并发问题时设 `1` |
| `GHIDRA_FLEET_MAX_OPEN` | `6` | 同时保持打开的程序数（LRU 逐出） |
| `GHIDRA_FLEET_XMX` | `4G` | JVM 堆上限；设空串用 Ghidra 默认 |
| `GHIDRA_FLEET_LOG` | `INFO` | 日志级别 |

## 测试

```bash
GHIDRA_INSTALL_DIR=<Ghidra 安装目录> .venv/bin/python tests/smoke_test.py [样本1 样本2 ...]
GHIDRA_INSTALL_DIR=<Ghidra 安装目录> .venv/bin/python tests/stdio_test.py
```

不传样本时自动挑选 PATH 上的系统小工具（Windows 用 where/robocopy 等，
Linux/macOS 用 ls/true 等）。覆盖：并行分析、二次提交缓存跳过、重复内容去重、
各类查询、改名/签名/类型后逐出重开的持久性、跨样本搜索、stdio 协议层。

## 已知边界

- **同一项目目录同一时间只允许一个 server 实例**（Ghidra 项目锁）：开多个 MCP 会话时，
  第一个实例占用项目，其余实例会收到明确的锁冲突提示。多会话请错开使用，
  或给不同会话配置不同的 `GHIDRA_FLEET_PROJECT_DIR`。关闭占用方后即可恢复。
- 进程内并行分析在极少数格式上可能触发 Ghidra 分析器并发问题：把
  `GHIDRA_FLEET_MAX_WORKERS` 设为 `1` 即退化为顺序分析，接口不变。
- 进度是按文件粒度（queued/analyzing/done/failed），没有百分比。
- 删除二进制请直接删项目目录下对应文件并手工清 `manifest.json`（v1 未提供删除工具）。
