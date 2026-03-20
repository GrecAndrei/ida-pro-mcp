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
- `entropy(action="packed_detect")` - Detect packed/encrypted sections

## Security Analysis
- `vuln_scan(action="scan_all", scan_profile="balanced")` - Scan for all vulnerability classes (CWE-tagged) with risk scoring
- `vuln_scan(action="intelligence_report", scan_profile="deep", max_graph_depth=3, include_dataflow_graph=True, include_remediation_plan=True)` - Correlated exploit-path report with hotspots/recommendations/graph/plan
- `vuln_scan(action="osv_query", osv_coordinates=["PyPI:requests@2.19.0"])` - Query OSV for known vulnerable dependency versions
- `vuln_scan(action="buffer_overflow")` - Find buffer overflow patterns
- `gadgets(action="mitigations")` - Check ASLR/DEP/canary/CFI
- `gadgets(action="rop")` - Find ROP gadgets
- `c2_detect(action="indicators")` - Detect C2/malware behavior
- `taint(action="find_sinks")` - Find dangerous data sinks

## Deobfuscation & Crypto
- `deobfuscate(action="xor_scan")` - Find and decode XOR-encoded strings
- `deobfuscate(action="stack_strings")` - Find stack-built strings
- `deobfuscate(action="api_hashing")` - Detect API hash resolution
- `crypto_id(action="identify")` - Identify cryptographic algorithms

## Summarization & Classification
- `summarize(action="binary")` - Binary overview for LLMs
- `summarize(action="function", addr="main")` - Function summary
- `classify(action="function", addr="0x401000")` - Classify function purpose
- `string_ops(action="find_urls")` - Extract URLs from strings
- `string_ops(action="suspicious")` - Find suspicious strings

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
6. **Follow Key Calls**: `code(action="analyze", addr="main")` → callees, callers, strings
7. **Search for Patterns**: `search(action="vulnerable")` → security issues
8. **Document Findings**: Use `modify(action="rename/comment")` to annotate
"""

WORKFLOW_VULN = """\
# Vulnerability Hunting Workflow

1. **Full Scan**: `vuln_scan(action="scan_all", scan_profile="balanced")` → all vulnerability classes with CWE tags + risk ranking
2. **Buffer Overflows**: `vuln_scan(action="buffer_overflow")` → strcpy, gets, memcpy without bounds
3. **Format Strings**: `vuln_scan(action="format_string")` → printf family with non-const format
4. **Command Injection**: `vuln_scan(action="command_injection")` → system, popen, exec calls
5. **Hardcoded Creds**: `vuln_scan(action="hardcoded_creds")` → passwords, tokens, API keys in strings
6. **Check Mitigations**: `gadgets(action="mitigations")` → ASLR, DEP, stack cookies, CFI
7. **Trace Data Flow**: `taint(action="find_sinks")` → where does user input reach dangerous APIs?
8. **Stack Analysis**: `stack_analysis(action="buffers")` → find overflow targets
9. **Classify by CWE**: `vuln_scan(action="classify", addr="0x...")` → classify specific address
10. **OSV Dependency Check**: `vuln_scan(action="osv_query", osv_coordinates=["npm:lodash@4.17.20"])` → known package vulns from OSV
10. **Document**: Use `annotation(action="mark_dangerous")` to annotate findings
"""

WORKFLOW_MALWARE = """\
# Malware Analysis Workflow

1. **Check Packing**: `entropy(action="packed_detect")` → high entropy = possible packing
2. **Get Overview**: `summarize(action="binary")` → LLM-friendly binary summary
3. **Classify Functions**: `classify(action="binary")` → categorize all functions by purpose
4. **Check Imports**: `summarize(action="imports_by_category")` → API usage by category
5. **Find C2/Network**: `c2_detect(action="indicators")` → detect C2 behavior patterns
6. **Find Persistence**: `c2_detect(action="persistence")` → registry, services, scheduled tasks
7. **Find Evasion**: `c2_detect(action="evasion")` → anti-debug, anti-VM, anti-analysis
8. **Find Crypto**: `crypto_id(action="identify")` → encryption algorithms
9. **Decode Strings**: `deobfuscate(action="xor_scan")` → XOR-encoded strings
10. **Stack Strings**: `deobfuscate(action="stack_strings")` → char-by-char constructed strings
11. **API Hashing**: `deobfuscate(action="api_hashing")` → hash-resolved API calls
12. **Extract IOCs**: `c2_detect(action="ioc_extract")` → URLs, IPs, domains, file paths
13. **Find URLs**: `string_ops(action="find_urls")` → extract URLs from strings
14. **Map Structure**: `graph(action="callgraph", addr="main")` → understand program flow
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

1. **Scan Vulnerabilities**: `vuln_scan(action="scan_all", scan_profile="balanced")` → find all vulnerability classes
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
