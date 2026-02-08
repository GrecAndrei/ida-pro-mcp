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
    task: Annotated[str, "The analysis task: triage|vuln_hunt|malware|diff|debug|crypto|protocol|exploit|deobfuscate"] = "triage"
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

WORKFLOW_CRYPTO = """\
# Cryptographic Analysis Workflow

1. **Identify Algorithms**: `crypto_id(action="identify")` → scan for known crypto constants
2. **Find Constants**: `crypto_id(action="constants")` → AES S-box, SHA magic numbers, CRC tables
3. **Key Schedule**: `crypto_id(action="key_schedule")` → detect key expansion loops
4. **Block Ciphers**: `crypto_id(action="block_cipher")` → substitution-permutation patterns
5. **Hash Functions**: `crypto_id(action="hash_detect")` → Merkle-Damgard, round functions
6. **Encoding**: `crypto_id(action="encoding")` → Base64, Base32, hex encoding tables
7. **Checksums**: `crypto_id(action="checksums")` → CRC32, Adler32, Fletcher
8. **Custom Crypto**: `crypto_id(action="custom_crypto")` → homebrew implementations
9. **Classify Functions**: `classify(action="function", addr="<crypto_func>")` → confirm category
"""

WORKFLOW_PROTOCOL = """\
# Network Protocol Reverse Engineering Workflow

1. **Detect Protocols**: `protocol(action="detect")` → identify HTTP, DNS, TLS, custom protocols
2. **Find Endpoints**: `protocol(action="endpoints")` → extract URLs, IPs, hostnames, ports
3. **Locate Parsers**: `protocol(action="parsers")` → functions reading structured data from buffers
4. **Find Handlers**: `protocol(action="handlers")` → message/command dispatch tables
5. **Analyze Structure**: `protocol(action="packet_struct")` → infer packet format from parsing code
6. **TLS Config**: `protocol(action="tls_config")` → cipher suites, certificate handling
7. **Socket Flow**: `protocol(action="socket_flow")` → trace socket lifecycle
8. **State Machine**: `protocol(action="state_machine")` → protocol state transitions
9. **Document**: Use `annotation(action="auto_comment")` to annotate protocol functions
"""

WORKFLOW_EXPLOIT = """\
# Exploit Development Workflow

1. **Scan Vulnerabilities**: `vuln_scan(action="scan_all")` → find all vulnerability classes
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

1. **Detect Encoding**: `deobfuscate(action="detect_encoding")` → XOR, Base64, RC4, custom
2. **XOR Scan**: `deobfuscate(action="xor_scan")` → find and auto-decode XOR-encoded strings
3. **Stack Strings**: `deobfuscate(action="stack_strings")` → character-by-character construction
4. **API Hashing**: `deobfuscate(action="api_hashing")` → hash-resolved API calls
5. **Opaque Predicates**: `deobfuscate(action="opaque_predicates")` → always-true/false branches
6. **CF Flattening**: `deobfuscate(action="control_flow_flatten")` → dispatcher patterns
7. **Dead Code**: `deobfuscate(action="dead_code")` → unreachable blocks
8. **Anti-Disasm**: `deobfuscate(action="anti_disasm")` → jump-into-instruction tricks
9. **Decode Data**: `deobfuscate(action="decode_attempt", addr="0x...", key="0xAB")` → manual decode
"""
