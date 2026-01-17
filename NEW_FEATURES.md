# New Security & Analysis Features

## Summary

Added 5 powerful new actions focused on security analysis, function similarity, and library identification that make the MCP server more useful for reverse engineering tasks.

## New Actions

### 1. `search:vulnerable` - Vulnerability Pattern Detection

Find potentially dangerous code patterns automatically.

**Usage:**
```python
search(action="vulnerable", limit=100)
```

**Detects:**
- **Format string vulnerabilities**: `printf`, `sprintf`, `fprintf`, `snprintf`, `syslog`
- **Buffer overflow risks**: `strcpy`, `strcat`, `gets`, `scanf`, `memcpy`, `strncpy`
- **Integer overflow**: `atoi`, `atol`, `atoll`
- **Command injection**: `system`, `popen`, `exec*`, `ShellExecute`, `CreateProcess`, `WinExec`
- **Memory issues**: `malloc`, `calloc`, `realloc`, `free`, `HeapAlloc`, `VirtualAlloc`
- **Path traversal**: `fopen`, `open`, `CreateFile`
- **Weak crypto**: `rand`, `srand`, `MD5`, `SHA1`, `DES`, `RC4`

**Returns:**
```json
{
  "total_findings": 50,
  "by_type": {
    "format_string": 5,
    "buffer_overflow": 12,
    "command_injection": 3,
    "weak_crypto": 8
  },
  "findings": [
    {
      "addr": "0x401234",
      "dangerous_func": "strcpy",
      "vuln_type": "buffer_overflow",
      "func": "process_input",
      "func_addr": "0x401000",
      "disasm": "call strcpy"
    }
  ]
}
```

### 2. `search:constants` - Crypto & Magic Constant Detection

Find cryptographic constants and magic numbers in code.

**Usage:**
```python
search(action="constants", limit=50, include_context=True)
```

**Detects:**
- **MD5 constants**: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
- **SHA-1 constants**: 0xC3D2E1F0
- **SHA-256 constants**: 0x6A09E667, 0xBB67AE85, 0x3C6EF372, etc.
- **AES constants**: S-box values, round constants
- **CRC32 polynomials**: 0xEDB88320, 0x04C11DB7
- **Blowfish P-array**: 0x243F6A88, 0x85A308D3
- **TEA/XTEA delta**: 0x9E3779B9
- **Salsa20/ChaCha**: 0x61707865, 0x3320646E, etc.
- **RSA common exponents**: 0x10001 (65537), 0x3
- **Magic numbers**: DEADBEEF, CAFEBABE, FEEDFACE
- **File format magic**: MZ (PE), ELF, ZIP headers

**Returns:**
```json
{
  "total_found": 30,
  "crypto_constants": 28,
  "magic_numbers": 2,
  "findings": [
    {
      "addr": "0x402100",
      "value": "0x67452301",
      "constant": "MD5_A",
      "func": "hash_password",
      "disasm": "mov eax, 67452301h"
    }
  ]
}
```

### 3. `agent:similar` - Similar Function Finder

Find functions with similar structure, API usage, and behavior.

**Usage:**
```python
agent(action="similar", addr="0x401000", max_items=10)
```

**Scoring based on:**
- **Size similarity** (within 50%)
- **API overlap** (shared function calls)
- **String overlap** (shared string references)
- **Instruction count similarity**

**Returns:**
```json
{
  "target": "decrypt_string",
  "target_addr": "0x401000",
  "target_apis": ["malloc", "memcpy", "free"],
  "target_strings": ["ERROR", "key"],
  "similar_functions": [
    {
      "addr": "0x402000",
      "name": "encrypt_buffer",
      "score": 75,
      "reasons": ["api_overlap:80%", "similar_size"],
      "size": 245,
      "shared_apis": ["malloc", "memcpy", "free"]
    }
  ],
  "count": 10
}
```

**Use cases:**
- Found one crypto function? Find all related crypto functions
- Identified a string decoder? Find similar decoders
- Spotted a network handler? Find other handlers

### 4. `patterns:matched` - FLIRT Match Report

Show which functions were identified by FLIRT signatures.

**Usage:**
```python
patterns(action="matched", count=50)
```

**Returns:**
```json
{
  "matched_functions": [
    {
      "addr": "0x401000",
      "name": "_malloc",
      "size": 128,
      "is_lib": true,
      "is_thunk": false,
      "lib_hint": "stdlib"
    }
  ],
  "total_matched": 250,
  "total_unmatched": 150,
  "by_library": {
    "stdio": 45,
    "stdlib": 32,
    "string": 28,
    "crt": 67,
    "other": 78
  }
}
```

**Library hints:**
- `crt` - C runtime functions (prefixed with `_`)
- `stdio` - printf, scanf families
- `stdlib` - malloc, free, atoi
- `string` - str* functions
- `memory` - mem* functions
- `compiler_rt` - Compiler intrinsics (`__`)

### 5. `lumina:get_metadata` - Programmatic Lumina Access

Get Lumina metadata for functions (where available).

**Usage:**
```python
lumina(action="get_metadata", addr="0x401000")
```

**Returns:**
```json
{
  "ok": true,
  "addr": "0x401000",
  "current_name": "sub_401000",
  "lumina_available": true,
  "lumina_initialized": true,
  "has_lumina_name": true,
  "lumina_name": "create_ssl_context",
  "lumina_info": {
    "name": "create_ssl_context",
    "popularity": 125
  },
  "name_analysis": {
    "has_real_name": false,
    "is_library_func": false,
    "is_thunk": false,
    "name_source": "Lumina"
  }
}
```

**Notes:**
- Requires Lumina to be enabled in IDA (Tools > Lumina > Options)
- Availability depends on IDA version and licensing
- Falls back to name analysis if Lumina APIs unavailable

## Test Results

All 31 tests pass:
- 17 original improvement tests
- 9 new LLM-friendly action tests  
- 5 new security/analysis action tests

```
SUMMARY
  Passed: 31
  Failed: 0
  Total:  31
```

## Files Modified

1. `src/ida_pro_mcp/ida_mcp/tools/search.py` - Added `vulnerable` and `constants` actions
2. `src/ida_pro_mcp/ida_mcp/tools/agent.py` - Added `similar` action
3. `src/ida_pro_mcp/ida_mcp/tools/patterns.py` - Added `matched` action
4. `src/ida_pro_mcp/ida_mcp/tools/lumina.py` - Added `get_metadata` action
5. `ida_mcp_stdio.py` - Updated TOOL_ACTIONS registry
6. `tests/test_improvements.py` - Added 5 new tests

## LLM Benefits

These actions are specifically designed to be easier for LLMs to use than raw IDAPython:

1. **High-level queries** - No need to understand IDA API internals
2. **Structured output** - Easy to parse and reason about
3. **Grouped results** - Findings categorized by type/severity
4. **Common patterns** - Built-in knowledge of crypto constants and vulnerable functions
5. **Context included** - Disassembly and function names when needed

## Example LLM Workflow

### Session-Based Analysis (Simplified!)

**Before (Old Way - Tedious):**
```
LLM: idb(action="meta", idb="C:/samples/malware.exe")
LLM: data(action="functions", idb="C:/samples/malware.exe")
LLM: code(action="decompile", addr="0x401000", idb="C:/samples/malware.exe")
```

**After (New Way - Easy!):**
```
User: "Analyze this binary"

LLM: session(action="create", binary_path="C:/samples/malware.exe")
→ Creates session ABCD1234

LLM: idb(action="meta")
→ Automatically uses session ABCD1234

LLM: data(action="functions")
→ Still using ABCD1234

LLM: code(action="decompile", addr="0x401000")
→ No idb parameter needed!
```

### Multi-Binary Analysis

```
User: "Compare two binaries"

LLM: session(action="create", binary_path="C:/bin1.exe")
→ Session A: 12345678

LLM: data(action="functions")
→ Analyzes bin1.exe

LLM: session(action="create", binary_path="C:/bin2.exe")
→ Session B: 87654321

LLM: data(action="functions")
→ Analyzes bin2.exe

LLM: session(action="switch", session_id="12345678")
→ Back to bin1.exe

LLM: code(action="decompile", addr="0x401000")
→ Decompiles from bin1.exe
```

### Security Analysis Workflow

```
User: "Is this binary vulnerable?"

LLM: session(action="create", binary_path="C:/app.exe")

LLM: search(action="vulnerable")
→ Finds 15 strcpy calls, 3 sprintf calls

User: "Does it use crypto?"

LLM: search(action="constants")
→ Finds MD5 and AES constants

User: "Show me the MD5 function"

LLM: agent(action="quick", addr="0x402100")
→ Gets function name and pseudocode preview

User: "Are there similar functions?"

LLM: agent(action="similar", addr="0x402100")
→ Finds 3 other hash functions
```

Much easier than specifying the IDB path every time!
