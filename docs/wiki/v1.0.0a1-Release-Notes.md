# IDA Pro MCP v1.0.0a1 — Genesis Alpha Release

Welcome to the first alpha release of **IDA Pro MCP** (`v1.0.0a1`)!

IDA Pro MCP is a production-grade Model Context Protocol (MCP) server that connects modern AI coding agents and LLMs directly to **Hex-Rays IDA Pro**. It provides a deterministic, action-specific analysis environment designed for reverse engineers, vulnerability researchers, and security analysts.

---

## What's in v1.0.0a1

### 1. 107 Deterministic Agent Operations (`ida_*`)
Rather than relying on vague, unconstrained prompts or fragile monolithic tools, IDA Pro MCP exposes 107 strict-schema operations organized into specialized capabilities:
* **Decompilation & Disassembly**: Full Hex-Rays pseudocode decompiler extraction (`ida_decompile`), disassembly windows (`ida_disassemble`), and architecture inspection.
* **Control Flow & Cross References**: Call graphs (`ida_callgraph`), direct callers (`ida_callers`), callees (`ida_callees`), and xref tracing (`ida_xrefs_to`).
* **Type System & Type Libraries**: Complete C type parsing (`ida_declare_type`), type application (`ida_apply_type`), struct/union field editing (`ida_struct_member_*`), enum management (`ida_enum_member_*`), and type library export/import (`ida_til_*`).
* **Firmware & Embedded Hardware Analysis**: Automated load base detection (`ida_fw_detect_load_base`), interrupt vector table recognition (`ida_fw_detect_vector_table`), MMIO peripheral mapping (`ida_fw_detect_mmio`), RTOS artifact scanning (`ida_fw_rtos_scan`), and binary carving (`ida_fw_carve`).
* **Memory & Byte Manipulation**: Safe byte reading (`ida_read_bytes`), verified patching (`ida_patch_bytes`), data item creation (`ida_create_data`, `ida_create_strlit`), segment attributes (`ida_set_segment_attrs`), and segment registers (`ida_sreg_*`).
* **Emulation & Arithmetic Evaluation**: In-database CPU instruction emulation (`ida_emulate`), register inspection (`ida_registers`), and bitwise calculation helpers (`ida_calc_*`).
* **Interactive Scripting**: In-process IDAPython execution (`ida_python`) with output capture and error reporting.

### 2. Dual-Engine Analysis Runtime
* **Crash-Isolated Multi-Process Engine (`idat`)**: Runs IDA headless processes per session with memory boundaries and automatic crash recovery. Corrupt binaries, hostile obfuscation, or decompiler panics cannot crash the host MCP server.
* **In-Process Kernel (`idalib`)**: High-throughput direct SDK bindings for IDA Pro 9.3+ for zero-overhead bulk queries and automation.
* **Rizin / r2 Secondary Hypothesis**: Integrated Rizin engine (`rz-bin`, `rz-diff`, `ida_r2_*`) for cross-validating symbols, architectures, and virtual cross-references.

### 3. Universal Coding Agent Support (22+ Environments)
The installer auto-detects and seamlessly configures all major AI developer environments:
* **Terminal & CLI Agents**: Claude Code, OpenClaw, Pi Coding Agent, Hermes Agent, Prime Agent, Codex, Gemini CLI, OpenCode, Copilot CLI, and Antigravity CLI.
* **Desktop IDEs & Extensions**: Cursor, VS Code (GitHub Copilot), Claude Desktop, Windsurf, Cline, Roo Code, ZCode, Kimi Code, MiniMax Code, and Antigravity IDE.
* **Format Agnostic**: Natively handles standard JSON (`mcpServers`), JSON with `servers`, JSON5 with nested paths (`mcp.servers`), TOML (`mcp_servers`), and YAML (`mcp_servers`).

### 4. Redesigned Universal Skill System (`agentskills.io`)
* Built according to the open **Agent Skills specification**.
* Implements **3-tier progressive disclosure**:
  1. Startup Discovery: Only lightweight metadata is injected into the model prompt (~30 tokens).
  2. Intent Activation: Detailed operational workflows load only when a reverse engineering intent is recognized.
  3. Execution References: Deep parameter schemas (`references/operations.md`) load on-demand.
* Automatically installed across universal and client-specific skill directories (`~/.agents/skills/`, `~/.claude/skills/`, `~/.codex/skills/`, `~/.openclaw/workspace/skills/`, and `~/.pi/agent/skills/`).

### 5. Durable Analysis Blackboard & Provenance
* Durable SQLite findings database preserving reverse engineering discoveries across turns and sessions.
* Full conflict detection, lifecycle state tracking (hypothesized, verified, refuted), anchor validation, and immutable audit logs.
* Search findings semantically or through query-lang expressions (`ida_search_findings`, `ida_search_query_lang`).

### 6. Robust Safety & IDB Protection Policy
* Every destructive operation (binary byte patches, segment deletion, renaming) requires explicit policy clearance or an interactive `risk_ack` token flow.
* Strict path boundary validation, symlink traversal rejection, and process tree isolation.

---

## Getting Started

### Quick Install
Download the source bundle from this release and run:

```bash
python install.py
```

Or for unattended, non-interactive installation across all detected agents:

```bash
python install.py --auto
```

### Verification
Once configured, test the connection from your AI agent:

```text
ida_help(query="ida_overview")
```

---

## Verifying Release Artifacts
All release assets include SHA-256 checksums and GitHub Actions build provenance attestations. To verify:

```bash
sha256sum -c SHA256SUMS
gh attestation verify ida-pro-mcp-1.0.0a1-py3-none-any.whl --repo GrecAndrei/ida-pro-mcp
```
