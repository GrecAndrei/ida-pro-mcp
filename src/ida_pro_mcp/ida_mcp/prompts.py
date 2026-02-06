"""
MCP Prompts for IDA Pro MCP.

Provides structured prompt templates that LLMs can use for common
reverse engineering workflows.
"""

try:
    from ida_mcp.rpc import prompt
except (ImportError, ValueError):
    try:
        from rpc import prompt
    except ImportError:
        from .rpc import prompt

from typing import Annotated, Optional


@prompt
def quickref() -> list[dict]:
    """Quick reference card for IDA Pro MCP tools - the most important tools and common workflows."""
    return [
        {
            "role": "user",
            "content": {
                "type": "text",
                "text": QUICKREF_TEXT,
            },
        }
    ]


@prompt
def workflow(
    task: Annotated[str, "The analysis task: triage|vuln_hunt|malware|diff|debug"] = "triage"
) -> list[dict]:
    """Get a step-by-step workflow guide for a specific analysis task."""
    workflows = {
        "triage": WORKFLOW_TRIAGE,
        "vuln_hunt": WORKFLOW_VULN,
        "malware": WORKFLOW_MALWARE,
        "diff": WORKFLOW_DIFF,
        "debug": WORKFLOW_DEBUG,
    }
    text = workflows.get(task, f"Unknown task '{task}'. Available: {', '.join(workflows.keys())}")
    return [
        {
            "role": "user",
            "content": {"type": "text", "text": text},
        }
    ]


QUICKREF_TEXT = """\
# IDA Pro MCP Quick Reference

## Getting Started
1. `idb(action="overview")` - Get binary metadata, summary, segments, and entrypoints in one call
2. `data(action="functions")` - List all functions
3. `data(action="strings")` - List all strings
4. `data(action="imports")` - List all imports

## Core Analysis
- `code(action="decompile", addr="0x401000")` - Decompile a function
- `code(action="disasm", addr="0x401000")` - Get assembly listing
- `code(action="xrefs_to", addr="0x401000")` - Who calls this?
- `code(action="xrefs_from", addr="0x401000")` - What does this call?
- `code(action="analyze", addr="main")` - Full analysis (decompile + callees + callers + strings)
- `code(action="diff_functions", addrs=["0x401000", "0x402000"])` - Compare two functions

## Search
- `search(action="find", pattern="malloc")` - Auto-detect search type (smart)
- `search(action="string", pattern="password")` - Search strings
- `search(action="bytes", pattern="48 8B 05")` - Search byte patterns
- `search(action="vulnerable")` - Find dangerous patterns (format strings, buffer overflows)
- `search(action="constants")` - Find crypto constants and magic numbers

## Modification
- `modify(action="rename", addr="0x401000", value="parse_config")` - Rename
- `modify(action="comment", addr="0x401000", value="Initialize config")` - Comment
- `modify(action="set_type", addr="0x401000", value="int __cdecl(int, char**)")` - Set type

## Batch Operations
- `batch(calls=[{tool:"code",action:"decompile",addr:"0x401000"},{tool:"data",action:"strings",count:10}])`
- `bulk(action="rename", items=[{addr:"0x401000",name:"func1"},{addr:"0x402000",name:"func2"}])`

## Graph Visualization
- `graph(action="callgraph", addr="main", format="mermaid")` - Call graph
- `graph(action="cfg", addr="0x401000", format="dot")` - Control flow graph
- `graph(action="xref_graph", addr="0x401000", direction="both")` - Cross-reference graph

## Advanced
- `agent(action="context_pack", addr="main")` - Gather all context for a function
- `calc(action="eval", expr="0x401000 + 0x100")` - Address math
- `types(action="list")` - List type library
- `structs(action="recover", addr="0x401000")` - Recover structure layout
- `entropy(action="scan")` - Detect packed/encrypted sections

## Tips
- Use `addr` with function names OR hex addresses: `addr="main"` or `addr="0x401000"`
- Use `batch()` to combine multiple read operations in one call
- Use `idb(action="overview")` as your first call to get oriented
- All list results support `offset` and `count` for pagination
"""

WORKFLOW_TRIAGE = """\
# Binary Triage Workflow

1. **Get Overview**: `idb(action="overview")` → metadata, summary, segments, entrypoints
2. **Check Strings**: `data(action="strings", count=50)` → interesting strings
3. **Check Imports**: `data(action="imports")` → API usage patterns
4. **Identify Main**: Look at entrypoints, find main() or WinMain()
5. **Decompile Entry**: `code(action="decompile", addr="main")` → understand program flow
6. **Follow Key Calls**: `code(action="analyze", addr="main")` → callees, callers, strings
7. **Search for Patterns**: `search(action="vulnerable")` → security issues
8. **Document Findings**: Use `modify(action="rename/comment")` to annotate
"""

WORKFLOW_VULN = """\
# Vulnerability Hunting Workflow

1. **Scan for Dangerous APIs**: `search(action="vulnerable")` → format strings, buffer overflows
2. **Find Crypto Constants**: `search(action="constants")` → hardcoded keys, magic numbers
3. **Check String Operations**: `search(action="api", pattern="strcpy|strcat|sprintf|gets")`
4. **Trace Data Flow**: `taint(action="forward", addr="<input_func>")` → where does input go?
5. **Check Bounds**: For each dangerous call, decompile the caller and check for size validation
6. **Find Command Injection**: `search(action="api", pattern="system|popen|exec")`
7. **Check Auth**: `search(action="string", pattern="password|auth|login|token")`
8. **Generate Report**: Document each finding with `modify(action="comment")`
"""

WORKFLOW_MALWARE = """\
# Malware Analysis Workflow

1. **Check Packing**: `entropy(action="scan")` → high entropy = possible packing
2. **Get Overview**: `idb(action="overview")` → file type, compiler, sections
3. **Check Imports**: `data(action="imports")` → suspicious API usage
4. **Find C2/Network**: `search(action="string", pattern="http|socket|connect|recv|send")`
5. **Find Crypto**: `search(action="constants")` → encryption algorithms
6. **Find Persistence**: `search(action="api", pattern="RegSetValue|CreateService|schtasks")`
7. **Find Anti-Debug**: `search(action="api", pattern="IsDebuggerPresent|NtQueryInformationProcess")`
8. **Decrypt Strings**: `emulate(action="decrypt_strings", addr="<decrypt_func>")`
9. **Map Functionality**: Use `graph(action="callgraph", addr="main")` to understand structure
"""

WORKFLOW_DIFF = """\
# Binary Diff Workflow

1. **Compare Functions**: `code(action="diff_functions", addrs=["0x401000", "0x402000"])`
2. **Use BinDiff**: `diff(action="compare", ...)` for full binary comparison
3. **Check Patched Functions**: Look at similarity scores < 1.0
4. **Analyze Changes**: Decompile both versions of changed functions
5. **Document**: Comment the differences found
"""

WORKFLOW_DEBUG = """\
# Debugging Workflow

1. **Start Debugger**: `debug(action="start")`
2. **Set Breakpoints**: `debug(action="bp_set", addr="main")`
3. **Run to Break**: `debug(action="continue")`
4. **Check Registers**: `debug(action="registers")`
5. **Step Through**: `debug(action="step_into")` or `debug(action="step_over")`
6. **Read Memory**: `memory(action="read", addr="0x401000", size=64)`
7. **Check Stack**: `debug(action="stack")`
8. **Trace Execution**: `trace(action="start")` → run → `trace(action="stop")` → `trace(action="get")`
"""
