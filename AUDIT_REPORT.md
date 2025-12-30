# IDA Pro MCP Audit Report

**Date:** 2024-06-12
**Scope:** Full Codebase (excluding plugin UI)
**Focus:** Transport, Frontend (LLM Contract), Core Logic, Security

## Executive Summary

The audit identified several critical issues affecting compatibility with older IDA versions (before 9.0) and reliability with specific MCP clients (Gemini CLI). While the core logic is generally sound, there are significant gaps in error handling for legacy environments and potential performance bottlenecks in large-scale analysis tools.

The `ida_mcp_stdio.py` protocol handling was recently patched to support `Content-Length` headers, fixing the primary connectivity issue. However, the `search` tool and `idb` tool contain bugs that could cause silent failures or crashes.

---

## 1. Critical Issues (Must Fix)

### 1.1 `search` Tool Silent Failures (IDA < 9.x)
- **File:** `src/ida_pro_mcp/ida_mcp/api_consolidated.py`
- **Issue:** The `search` tool (actions `bytes` and `immediate`) uses new IDA 9.x APIs (`ida_bytes.compiled_binpat_vec_t`, `ida_search.find_imm`) inside `if hasattr(...)` blocks. The `else` blocks are either empty (`pass`) or set a failure state without reporting it properly.
- **Impact:** On IDA 8.x, byte and immediate searches will silently return 0 results, misleading the LLM.
- **Remediation:** Implement the legacy `ida_search.find_binary` and `ida_search.find_immediate` calls in the `else` blocks.

### 1.2 `idb.meta` Memory Exhaustion Risk
- **File:** `src/ida_pro_mcp/ida_mcp/api_consolidated.py`
- **Issue:** The `meta` action calculates MD5/SHA256 hashes by reading the *entire* input file into memory: `data = f.read()`.
- **Impact:** For multi-gigabyte binaries (common in firmware or game dumps), this causes an Out-Of-Memory (OOM) crash, killing the IDA process and the MCP session.
- **Remediation:** Use chunked reading (e.g., 64KB blocks) to update the hash context.

### 1.3 `utils.get_stack_frame` Regression
- **File:** `src/ida_pro_mcp/ida_mcp/utils.py`
- **Issue:** `get_stack_frame_variables_internal` explicitly checks `if ida_major < 9: return []`.
- **Impact:** Stack variable analysis is completely disabled for IDA 8.x, despite the API being available (`ida_struct.get_frame`).
- **Remediation:** Implement the legacy `ida_struct` based logic for older versions.

---

## 2. High Priority Issues (Reliability & Performance)

### 2.1 `xrefs_to_field` Performance Bottleneck
- **File:** `src/ida_pro_mcp/ida_mcp/api_consolidated.py`
- **Issue:** The tool iterates through *every* ordinal in the Type Library (TIL) to find a matching struct field.
- **Impact:** On binaries with large type libraries (e.g., Windows kernel, large C++ projects), this operation can take tens of seconds or timeout.
- **Remediation:** Use `ida_typeinf.get_named_type_tid` to look up the struct directly if the field name is qualified (`Struct.field`).

### 2.2 `history.snapshot` Misleading Functionality
- **File:** `src/ida_pro_mcp/ida_mcp/api_consolidated.py`
- **Issue:** The `snapshot` action creates a JSON metadata file but *does not copy the IDB*. The return message says "actual IDB backup requires manual copy".
- **Impact:** Users/LLMs expect a snapshot to be a restore point. `restore` action only reads the metadata. No actual state restoration is possible.
- **Remediation:** Implement actual IDB file copying (using `shutil.copy2`) or rename the tool to `checkpoint` and clarify it's metadata-only.

### 2.3 `memory.read` String Encoding Assumption
- **File:** `src/ida_pro_mcp/ida_mcp/api_consolidated.py`
- **Issue:** `action="read", type="string"` forces `utf-8` decoding on the raw bytes fetched via `get_strlit_contents`.
- **Impact:** UTF-16 strings (common in Windows) may be mangled or cause decode errors if they contain bytes invalid in UTF-8.
- **Remediation:** Check `idc.get_str_type(ea)` and decode accordingly (ASCII, UTF-16LE, etc.).

---

## 3. Medium Priority Issues (UX & Frontend)

### 3.1 `session` Tool Logic Split
- **File:** `ida_mcp_stdio.py` vs `src/.../api_consolidated.py`
- **Issue:** The `session` tool logic exists *only* in `ida_mcp_stdio.py`. The `TOOLS` list in `api_consolidated.py` implies it handles 40 tools, but it doesn't implement `session`.
- **Impact:** If `ida_mcp_daemon.py` (HTTP mode) uses `api_consolidated.py` directly, it will lack session management capabilities.
- **Remediation:** Refactor session logic into a shared module or explicitly document that `session` is stdio-only.

### 3.2 `emulate.snippet` Misnomer
- **File:** `src/ida_pro_mcp/ida_mcp/api_consolidated.py`
- **Issue:** The `snippet` action claims to "emulate", but it actually performs a linear static disassembly trace. It does not execute instructions or update CPU state.
- **Impact:** Misleading for LLMs expecting register updates or side effects.
- **Remediation:** Update documentation to "static_trace" or implement actual emulation (e.g., via `ida_idd` or Unicorn).

### 3.3 Missing `search` Fallbacks
- **File:** `src/ida_pro_mcp/ida_mcp/api_consolidated.py`
- **Issue:** `search.immediate` sets `ea = (BADADDR, 0)` if `find_imm` is missing, effectively disabling the feature on older IDA.
- **Remediation:** Add legacy `find_immediate` support.

---

## 4. Security Considerations

### 4.1 Arbitrary Code Execution (ACE)
- **File:** `src/ida_pro_mcp/ida_mcp/api_consolidated.py` (`misc` tool)
- **Risk:** `misc(action="python")` allows executing arbitrary Python code.
- **Context:** This is a feature, not a bug, for an engineering tool. However, it means the LLM has full control over the host machine (as the user).
- **Recommendation:** Ensure this is clearly documented. No code change needed as it's intended.

### 4.2 File System Access
- **File:** `src/ida_pro_mcp/ida_mcp/api_consolidated.py` (`files` tool)
- **Risk:** `files.read` and `files.write` allow access to any file the user can access. `validate_path_safe` prevents `..` traversal but allows absolute paths.
- **Recommendation:** Consider restricting access to the binary's directory and the MCP cache directory unless a `--unsafe` flag is provided.

---

## 5. Transport & Infrastructure

### 5.1 JSON Parsing Error Handling
- **File:** `ida_mcp_stdio.py`
- **Issue:** In `_read_message`, if `json.loads(body)` fails after reading a `Content-Length` body, the function returns `None` (EOF), shutting down the server.
- **Remediation:** Log the error and return `{}` (skip) to keep the connection alive, as the framing is still valid.

### 5.2 Dead Code
- **Directory:** `src/ida_pro_mcp/ida_mcp/zeromcp/`
- **Issue:** This directory contains MCP protocol handling code (`jsonrpc.py`, `mcp.py`), but `ida_mcp_stdio.py` implements its own minimal version.
- **Remediation:** Delete `zeromcp` if it is unused to reduce maintenance burden.

---

## Recommendations Plan

1.  **Fix Critical Bugs**: Patch `api_consolidated.py` to fix `search` fallbacks, `idb.meta` chunking, and `utils.py` stack frame logic.
2.  **Fix Protocol Robustness**: Update `ida_mcp_stdio.py` to handle JSON errors gracefully.
3.  **Optimize**: Improve `xrefs_to_field` lookups.
4.  **Cleanup**: Remove unused `zeromcp` code.
