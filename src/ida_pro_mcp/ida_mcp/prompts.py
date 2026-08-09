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

from typing import Annotated


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
    task: Annotated[str, "The analysis task: triage|vuln_hunt|malware|diff|debug|crypto|protocol|exploit|deobfuscate|firmware"] = "triage"
) -> list[dict]:
    """Get a step-by-step workflow guide for a specific analysis task."""
    workflows = {
        "triage": WORKFLOW_TRIAGE,
        "vuln_hunt": WORKFLOW_VULN,
        "malware": WORKFLOW_MALWARE,
        "diff": WORKFLOW_DIFF,
        "debug": WORKFLOW_DEBUG,
        "crypto": WORKFLOW_CRYPTO,
        "protocol": WORKFLOW_PROTOCOL,
        "exploit": WORKFLOW_EXPLOIT,
        "deobfuscate": WORKFLOW_DEOBFUSCATE,
        "firmware": WORKFLOW_FIRMWARE,
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
- `batch(template="analyze_function", template_vars={addr: "main"})` - Comprehensive analysis (decompile + strings + xrefs) in one call
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
- `modify(action="rename", addr="0x401000", value="func1")` - Rename multiple symbols via repeated calls

## Graph Visualization
- `graph(action="callgraph", addr="main", format="mermaid")` - Call graph
- `graph(action="cfg", addr="0x401000", format="dot")` - Control flow graph
- `graph(action="xref_graph", addr="0x401000", direction="both")` - Cross-reference graph

## Advanced
- `batch(template="deep_function_audit", template_vars={addr: "main"})` - Gather all context for a function (decompile + disasm + callers + callees)
- `calc(action="eval", expr="0x401000 + 0x100")` - Address math
- `types(action="list")` - List type library
- `types(action="infer", addr="0x401000")` - Infer structure layout
- `search(action="find", query="upx mpress vmprotect")` - Detect packed/encrypted sections

## Raw Binary / Firmware
- `idb(action="summary")` - Identify format, processor, entrypoints, and image bounds
- `segments(action="list")` - Inspect segments, permissions, and entropy
- `firmware_view(action="triage_snapshot")` - One-shot load/vector/MMIO orientation before deeper carving
- `firmware_view(action="scan_region")` - Profile unknown raw regions
- `firmware_view(action="region_profile")` - Measure pointer, string, and unknown-byte density
- `firmware_view(action="pointer_sweep")` - Find pointer-like cells and candidate tables
- `firmware_view(action="smart_carve", apply=false)` - Dry-run safe retyping suggestions
- `blackboard(action="list", category="firmware_view")` - Review prior conversion decisions

## Security Analysis
- `search(action="vulnerable")` - Scan for dangerous patterns and APIs
- `search(action="regex", pattern="strcpy|gets|sprintf|strcat")` - Buffer overflow hotspots
- `search(action="regex", pattern="printf\\(|fprintf\\(|sprintf\\(")` - Format string hotspots
- `search(action="regex", pattern="system\\(|popen\\(|_popen\\(|exec\\(")` - Command injection hotspots
- `gadgets(action="mitigations")` - Check ASLR/DEP/canary/CFI
- `gadgets(action="rop")` - Find ROP gadgets
- `search(action="find", query="GetProcAddress CreateThread socket")` - Detect C2/malware behavior
- `code(action="xrefs_to", addr="<sink>")` - Trace dangerous sinks to callers

## Deobfuscation & Crypto
- `search(action="find", query="xor decrypt rc4 base64")` - Find and decode XOR-encoded strings
- `code(action="smart_decompile", addr="0x401000")` - Pseudocode + behavior tags for stack-built strings
- `search(action="find", query="aes rc4 blowfish")` - Identify cryptographic algorithms

## Summarization & Classification
- `idb(action="overview")` - Binary overview for LLMs
- `code(action="smart_decompile", addr="main")` - Function summary
- `search(action="behavior", addr="0x401000")` - Classify function purpose
- `search(action="find", query="http:// https:// url ip")` - Extract URLs from strings
- `search(action="find", query="suspicious password admin token")` - Find suspicious strings

## Tips
- Use `addr` with function names OR hex addresses: `addr="main"` or `addr="0x401000"`
- Use `batch()` to combine multiple read operations in one call
- Use `idb(action="overview")` as your first call to get oriented
- All list results support `offset` and `count` for pagination
- Query/filter params auto-detect regex, glob, or plain substring
"""

WORKFLOW_TRIAGE = """\
# Binary Triage Workflow

1. **Get Overview**: `idb(action="overview")` → metadata, summary, segments, entrypoints
2. **Check Strings**: `data(action="strings", count=50)` → interesting strings
3. **Check Imports**: `data(action="imports")` → API usage patterns
4. **Identify Main**: Look at entrypoints, find main() or WinMain()
5. **Decompile Entry**: `code(action="decompile", addr="main")` → understand program flow
6. **Follow Key Calls**: `batch(template="analyze_function", template_vars={addr: "main"})` → decompile, strings, xrefs
7. **Search for Patterns**: `search(action="vulnerable")` → security issues
8. **Document Findings**: Use `modify(action="rename/comment")` to annotate
"""

WORKFLOW_VULN = """\
# Vulnerability Hunting Workflow

1. **Pattern Scan**: `search(action="vulnerable")` → dangerous APIs and patterns
2. **Buffer Overflows**: `search(action="regex", pattern="strcpy|gets|sprintf|strcat")`
3. **Format Strings**: `search(action="regex", pattern="printf\\(|fprintf\\(|sprintf\\(")`
4. **Command Injection**: `search(action="regex", pattern="system\\(|popen\\(|_popen\\(|exec\\(")`
5. **Hardcoded Creds**: `search(action="find", query="password secret token key")` → tokens, keys, secrets
6. **Check Mitigations**: `gadgets(action="mitigations")` → ASLR, DEP, stack cookies, CFI
7. **Trace Data Flow**: Use `code(action="xrefs_to", addr="<sink>")` to trace user input flow
8. **Stack Analysis**: `stack_analysis(action="buffers")` → find overflow targets
9. **Classify by CWE**: `annotation(action="mark_dangerous", addr="0x...")` to tag findings
10. **Document**: Use `annotation(action="mark_dangerous")` to annotate findings
"""

WORKFLOW_MALWARE = """\
# Malware Analysis Workflow

1. **Check Packing**: `search(action="find", query="upx mpress vmprotect")` → packer hints in sections/strings
2. **Get Overview**: `idb(action="overview")` → LLM-friendly binary summary
3. **Check Imports**: `data(action="imports")` → API usage by category
4. **Find C2/Network**: `search(action="find", query="http:// https:// url beacon")` → detect C2 behavior patterns
5. **Find Persistence**: `search(action="find", query="regsetvalue createprocess service")` → registry, services, scheduled tasks
6. **Find Evasion**: `search(action="find", query="isdebuggerpresent virtualprotect")` → anti-debug, anti-VM, anti-analysis
7. **Find Crypto**: `search(action="find", query="aes rc4 blowfish base64")` → encryption algorithms
8. **Decode Strings**: `code(action="smart_decompile", addr="0x401000")` → decompile for XOR-encoded strings
12. **Extract IOCs**: `search(action="find", query="http:// https:// url ip domain")` → URLs, IPs, domains, file paths
13. **Find URLs**: `search(action="find", query="http:// https://")` → extract URLs from strings
14. **Map Structure**: `graph(action="callgraph", addr="main")` → understand program flow
"""

WORKFLOW_DIFF = """\
# Binary Diff Workflow

1. **Compare Functions**: `code(action="diff_functions", addrs=["0x401000", "0x402000"])`
2. **Compare Memory Regions**: `memory(action="compare", addr="0x401000", end_addr="0x402000")`
3. **Check Patched Functions**: Look at similarity scores < 1.0
4. **Analyze Changes**: Decompile both versions of changed functions
5. **Document**: Comment the differences found
"""

WORKFLOW_DEBUG = """\
# Debugging Workflow

IDA MCP has no dedicated debugger/trace tool — drive the debugger through
`misc(action="python", code="<snippet>")` (authorization required) using the
idc/ida_dbg helpers, and read live memory with `memory(action="read", ...)`.

1. **Start Debugger**: `misc(action="python", code="idc.start_process(\"\", \"\", \"\")")`
2. **Set Breakpoints**: `misc(action="python", code="idc.add_bpt(0x401000)")`
3. **Run to Break**: `misc(action="python", code="idc.run_to(0x401000)")`
4. **Step Through**: `misc(action="python", code="idc.step_into()")` or `idc.step_over()`
5. **Read Registers**: `misc(action="python", code="idc.get_reg_value(\"rip\")")`
6. **Read Memory**: `memory(action="read", addr="0x401000", size=64)`
7. **Check Stack**: `memory(action="read", addr="<rsp>", size=256)`
8. **Continue Execution**: `misc(action="python", code="idc.continue_process()")`
"""

WORKFLOW_CRYPTO = """\
# Cryptographic Analysis Workflow

1. **Identify Algorithms**: `search(action="find", query="aes rc4 blowfish s-box")` → scan for known crypto constants
2. **Find Constants**: `search(action="find", query="crc32 md5 sha")` → AES S-box, SHA magic numbers, CRC tables
3. **Key Schedule**: `code(action="smart_decompile", addr="<crypto_func>")` → detect key expansion loops
4. **Encoding**: `search(action="find", query="base64 base32 hex")` → Base64, Base32, hex encoding tables
5. **Checksums**: `search(action="find", query="crc32 adler32")` → CRC32, Adler32, Fletcher
"""

WORKFLOW_PROTOCOL = """\
# Network Protocol Reverse Engineering Workflow

1. **Detect Protocols**: `search(action="find", query="recv send connect socket listen")` → identify HTTP, DNS, TLS, custom protocols
2. **Find Endpoints**: `search(action="find", query="http:// https:// ip port hostname")` → extract URLs, IPs, hostnames, ports
3. **Locate Parsers**: `code(action="callers", addr="<recv_func>")` → functions reading structured data from buffers
4. **Find Handlers**: `code(action="decompile", addr="<dispatch_func>")` → message/command dispatch tables
5. **Analyze Structure**: `code(action="smart_decompile", addr="<parse_func>")` → infer packet format from parsing code
6. **Document**: Use `annotation(action="auto_comment")` to annotate protocol functions
"""

WORKFLOW_EXPLOIT = """\
# Exploit Development Workflow

1. **Scan Vulnerabilities**: `search(action="vulnerable")` → find dangerous patterns
2. **Check Mitigations**: `gadgets(action="mitigations")` → ASLR, DEP, stack cookies, CFI
3. **Find ROP Gadgets**: `gadgets(action="rop", limit=100)` → ret-terminated sequences
4. **Stack Pivots**: `gadgets(action="stack_pivot")` → xchg rsp/mov sp gadgets
5. **Write Primitives**: `gadgets(action="write_what_where")` → arbitrary write gadgets
6. **Shellcode Space**: `gadgets(action="shellcode_space")` → W+X memory regions
7. **Build Chain**: `gadgets(action="pivot_chains")` → categorized building blocks
8. **Analyze Stack**: `stack_analysis(action="buffers")` → overflow targets
9. **Stack Canary**: `stack_analysis(action="canary")` → check for cookie protection
"""

WORKFLOW_DEOBFUSCATE = """\
# Deobfuscation Workflow

1. **Detect Encoding**: `code(action="smart_decompile", addr="0x401000")` → decompile to spot XOR/Base64/RC4 loops
2. **Stack Strings**: `code(action="smart_decompile", addr="<func>")` → character-by-character construction
3. **API Hashing**: `search(action="find", query="rol ror xor hash")` → hash-resolved API calls
4. **Opaque Predicates**: `code(action="disasm", addr="<func>")` → always-true/false branches
5. **CF Flattening**: `code(action="disasm", addr="<dispatcher>")` → dispatcher patterns
6. **Anti-Disasm**: `search(action="find", query="jmp align")` → jump-into-instruction tricks
"""

WORKFLOW_FIRMWARE = """\
# Raw Binary / Firmware Workflow

1. **Identify Format**: `idb(action="summary")` → format, processor, entrypoints, bounds
2. **Inspect Sections**: `segments(action="list")` → permissions, entropy, segment layout
4. **One-Shot Orientation**: `firmware_view(action="triage_snapshot")` → aggregate load-address, vector-table, and MMIO signals
5. **Profile Raw Regions**: `firmware_view(action="scan_region")` → estimate code/data/unknown mix
6. **Summarize Region**: `firmware_view(action="region_profile")` → pointer/string/unknown density
7. **Sweep Pointers**: `firmware_view(action="pointer_sweep")` → table and vtable candidates
8. **Dry-Run Carving**: `firmware_view(action="smart_carve", apply=false)` → safe retyping plan
9. **Review Prior Decisions**: `blackboard(action="list", category="firmware_view")` → reuse local analysis
10. **Continue Search**: `search(action="nl", pattern="entry init parser")` → map the now-sharpened binary
"""
