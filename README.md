# IDA Pro MCP

> **Work in Progress** — APIs, tools, configuration, and docs may change without notice. Breaking changes between commits are normal. Test coverage is strongest in host-side services and tool-surface layers; integration tests require IDA Pro and are run separately.

Reverse engineering for IDA Pro via the Model Context Protocol.

`ida-pro-mcp` exposes IDA analysis, decompilation, debugging, triage, and annotation as structured MCP tools so coding agents can operate on binaries with deterministic calls instead of fragile text scraping.

## What This Project Is

`ida-pro-mcp` is a session-oriented MCP server for IDA Pro 9.2+.

Two-layer architecture:
- **Host MCP server** (`ida_pro_mcp.host.server`) — MCP JSON-RPC over stdio. Manages sessions, response compaction, blackboard, intelligence layer, and the TCP bridge to IDA.
- **IDA runtime bridge** (`server_script.py`) — runs inside `idat`, exposes deterministic IDA SDK calls over a local TCP socket.

Tool implementations live in `src/ida_pro_mcp/ida_mcp/tools/`. Tool count and action lists are generated from schema metadata in `src/ida_pro_mcp/host/schemas_data.py`.

This project does **not** run any backend LLM service. Tool execution is deterministic IDA SDK logic plus optional local ML components. Any LLM behavior comes from the MCP client, not from an embedded server-side LLM.

## Requirements

- IDA Pro 9.2+
- Python 3.11+
- `uv` recommended (installer falls back without it)

## Install

```bash
python install.py
```

Interactive wizard on a real TTY. Use `--yes` for non-interactive automation.

What the installer does:
1. Creates a runtime venv in a stable install directory
2. Installs the MCP package from source or PyPI (`--runtime-source auto|local|pypi`)
3. Auto-detects IDA install path (`IDADIR` / `IDA_MCP_IDAT` fallback)
4. Configures supported MCP clients (Claude Code, OpenCode, Cursor, etc.) with backups
5. Installs Codex skills (`~/.codex/skills`) and Claude Code / OpenCode skills (`~/.claude/skills`, `~/.config/opencode/skills`)
6. Writes a structured install report to `<install-root>/install-report.json`

Default install directory:
- Linux/macOS: `~/.local/share/ida-pro-mcp`
- Windows: `%LOCALAPPDATA%/ida-pro-mcp`

### PyPI

```bash
pip install ida-pro-mcp
```

### Development

```bash
git clone https://github.com/GrecAndrei/ida-pro-mcp.git
cd ida-pro-mcp
pip install -e .
```

### Supported clients auto-configured by installer

Claude Code, OpenCode, Claude Desktop, Cursor, VS Code (Copilot), Windsurf, Cline, Roo Code, Codex, Copilot CLI, Gemini CLI, Antigravity

### Manual run

```bash
python -u -m ida_pro_mcp.host.server
```

### CLI

```bash
ida-pro-mcp-cli tool session '{"action":"status"}'
ida-pro-mcp-cli rpc tools/list '{}'
```

## Quick Start

### 1. Start server

Use installer-managed client config, or run manually (above).

### 2. Create a session

```json
{"name": "session", "arguments": {"action": "create", "binary_path": "/path/to/binary"}}
```

### 3. Get analysis state

```json
{"name": "session", "arguments": {"action": "state"}}
```

`session(action='state')` returns the full analysis snapshot: binary metadata, coverage, blackboard summary, engine status, and suggested next actions. Call it at the start of every turn.

> **Note on MCP resources**: `ida://state` and other `ida://` resources are defined in the protocol but MCP resources are application-driven — the LLM cannot read them autonomously. Use `session(action='state')` instead.

### 4. Analyze

```json
{"name": "code", "arguments": {"action": "smart_decompile", "addrs": "0x401000"}}
```

```json
{"name": "blackboard", "arguments": {"action": "frontier", "limit": 10}}
```

### 5. Batch multiple calls

```json
{
  "name": "batch",
  "arguments": {
    "calls": [
      "idb:meta",
      {"name": "data", "action": "imports"},
      {"tool": "search", "action": "strings", "pattern": "http"}
    ]
  }
}
```

## How LLMs Should Use It

Recommended pattern:

1. `session(action='create', binary_path='...')` — open session
2. `session(action='state')` — read full state (binary, coverage, blackboard, next actions)
3. `blackboard(action='frontier', limit=10)` — ranked unvisited functions
4. `code(action='smart_decompile', addrs='...')` — decompile prioritized targets (results carry `_cache_hit` / `_cache_age_seconds`; inspect these to decide whether to trust a hot cache)
5. `code(action='disasm', addrs='0x...', window=20)` — centered ±20-line slice around the focus address; response carries `"window": 20` for cache consumers
6. `data(action='functions', min_xrefs=2)` / `funcs.list(min_xrefs=2)` — drop the long tail of one-off thunks before paging
7. `blackboard(action='write', ...)` — persist findings
8. `predictor(action='recommend_bundle')` — next recommended actions if stuck

Practical rules:
- Prefer compact results, then zoom in with filters
- Use `batch` when the next calls are deterministic
- Paginate large result sets with tool-level `offset`/`count`
- Save milestones via bookmarks, blackboard entries, and session notes
- Write ops require `_risk_ack=true` to bypass the governance gate
- Match envelopes on `error.code` (uppercase), not `error.message` (free text)
- When a long tool call returns `IDA_TIMEOUT`, retry with a higher `IDA_MCP_RPC_HARD_WALLCLOCK_SEC` — not a crash

## Skills

The installer generates skills for Claude Code and OpenCode from `TOOL_DESCRIPTIONS`:

- `~/.claude/skills/ida-start/SKILL.md` — orientation, IDA key shortcuts, first-turn playbook
- `~/.claude/skills/ida-core/SKILL.md` — session, batch, bookmarks, truncation
- `~/.claude/skills/ida-analysis/SKILL.md` — decompile, search, data, funcs, types, modify
- `~/.claude/skills/ida-security/SKILL.md` — classify, gadgets, crypto, ABI, deobfuscate
- `~/.claude/skills/ida-advanced/SKILL.md` — ctree, microcode, graph, imports, export, history
- `~/.claude/skills/ida-debug/SKILL.md` — debugger, coverage, traces
- `~/.claude/skills/ida-workflow/SKILL.md` — blackboard, firmware, intelligence, taint, governance
- `~/.claude/skills/ida-project/SKILL.md` — save/load IDB, scripts, recent files

Same files are mirrored to `~/.config/opencode/skills/`.

Regenerate after tool metadata changes:
```bash
ida-pro-mcp-install --only skills
```

The same tool-doc skills for Codex agents live in `.agents/skills/` (auto-generated, checked in CI for drift).

## Tool Surface

67 tools, hundreds of actions. Default `tools/list` mode is `ultra` — short routing hints plus action enums, ~9.5k tokens total. Skills carry the reference docs; the tools carry live data.

`IDA_MCP_TOOLS_LIST_MODE` controls verbosity:
- `ultra` (default): action enums + short description (~9.5k tokens)
- `lean`: full action descriptions, stripped footnotes (~21k tokens)
- `full`: complete descriptions + full JSON Schema (~58k tokens)

Do **not** set `IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS=1` — it overrides `TOOLS_LIST_MODE` to `full` unconditionally.

### Tool categories

- Core/session: `session`, `batch`, `bookmarks`, `wiki`, `truncation`
- Data access: `idb`, `data`, `code`, `search`, `types`, `memory`, `query`
- Editing: `modify`, `funcs`, `segments`, `bulk`, `annotation`
- Analysis: `cfg_analysis`, `stack_analysis`, `abi`, `protocol`, `classify`, `compare`, `summarize`, `agent`
- Security RE: `threat_hunt`, `taint`, `gadgets`, `deobfuscate`, `crypto_id`, `yara_hunt`
- Debug/trace: `debug`, `trace_analysis`, `coverage`
- Structural: `ctree`, `microcode`, `graph`, `imports_deep`, `symbols`, `patterns`
- Utilities: `analysis`, `project`, `export`, `history`, `misc`, `calc`, `llm_helpers`, `binary_info`, `string_ops`
- Infrastructure: `blackboard`, `governance`, `filter`

### Tool aliases

- `plugins` → `misc`

### Global action wrappers

Available on all action-based tools:
- `action="grep"` — run source action then grep output
- `action="pick"` — run source action then keep specified fields
- `action="head"` / `action="tail"` — first/last N rows
- `action="stats"` — payload statistics
- `action="next"` — continue paginated output via `next_token`

## Local ML Components

All ML is local. No remote API calls.

### bge-code-v1 embeddings

Runs via `llama-server` with `bge-code-v1-q8_0.gguf`. Produces 1536-dim float vectors from pseudocode/function signatures.

Used by: `search(action='nl')`, `funcs(action='suggest_names')`, `funcs(action='find_similar')`, `FrontierEngine`, `blackboard(action='search')`.

### BehaviorClassifier

Zero-shot behavior detection via embedding similarity to labeled examples. Tags: `crypto_symmetric`, `network_http`, `process_injection`, `anti_analysis`, `persistence`, `credential_access`, etc.

Used by: `classify`, `search(action='behavior')`, `llm_helpers(action='behavioral_signature_search')`, `string_ops(action='score_c2')`, `smart_decompile` response tags.

### FrontierEngine

Embedding-driven analysis guidance. Answers "what should I analyze next?".

- Clusters all indexed function embeddings (k-means)
- Propagates LLM labels to cluster neighbors (cosine ≥ 0.82)
- Scores unvisited functions by proximity + xref count + entropy + cluster coverage

Runs every 180s. Access via `blackboard(action='frontier')`.

### UsageIntelligence

Passive observer that mines audit logs.

- **SequenceModel**: Markov chain over (tool, action) pairs
- **EffectivenessModel**: EMA scoring by productive outcome
- **DriftDetector**: LOOP, ANALYZE_WITHOUT_RECORD, REPEATED_ADDR, HIGH_ERROR_RATE signals

## Blackboard

SQLite-backed persistent working memory.

- Auto-extracted findings from every tool response
- Full CRUD: `write`, `read`, `list`, `update`, `delete`, `clear`, `prune`, `stats`
- `frontier`: ranked unvisited functions
- `coverage`: per-cluster coverage breakdown
- `propagate_labels`: spread labels to embedding-similar functions
- Auto-pruning by `max_entries`, `min_q_value`, `older_than_days`

## Session Management

- `create`/`switch`/`close`/`archive`/`unarchive` — lifecycle
- `state` — full analysis snapshot (replaces `ida://state` resource)
- `status` — session runtime state
- `snapshot`/`restore_snapshot` — point-in-time restore
- `notebook_append`/`notebook_read` — durable per-session notes
- `track_hypothesis`/`confirm_hypothesis`/`refute_hypothesis` — hypothesis tracking
- `get_phase`/`advance_phase` — analysis phase tracking
- `dashboard` — session overview
- `recent_workset` — resume from recent activity + bookmarks
- `macro_set`/`macro_run` — reusable call sequences
- `cleanup_stale` — remove sessions older than `max_age_days` (default 30); also prunes orphans whose binary + idb are both gone (`prune_orphans=true`)
- `idle_purge` — drop live runtimes whose `last_used` exceeds `idle_seconds` seconds. Companion to `cleanup_stale` (which owns db-only rows). Args: `idle_seconds` (int, required), `prune_orphans` (bool, default `true`). Returns `{closed_sids, orphan_sids, skipped_sids, count, ...}`.

## Hang Protection

Two layers make runaway calls impossible:

1. **Whitelist + cap** — full-program walks (`analysis.*`, `summarize.binary`, `intelligence.index_batch`, `search.semantic`, `firmware_view.smart_carve`, `funcs.metrics`, ...) get an extended socket recv timeout (≥120s + caller-requested `timeout`). The cap is `IDA_MCP_RPC_MAX_RECV_TIMEOUT` (default `600s`). No caller can pin the dispatcher open longer than this.
2. **Wall-clock watchdog** — `IDA_MCP_RPC_HARD_WALLCLOCK_SEC` (default `900s`) bounds the *entire* `call_tool` path including retries. Past the cap, the host terminates the IDA process and returns `IDA_TIMEOUT, recoverable=true`. The next call re-spawns IDA fresh.

Connection-layer failures (`ConnectionRefusedError`, `EOFError`, `ConnectionReset`, `ConnectionAborted`) are retried up to `IDA_MCP_RPC_MAX_RETRIES` (default 2) with linear backoff. `socket.timeout` / `TimeoutError` propagate so the dispatcher can still tell "IDA was busy" from "IDA went away".

## Guardrails

Write ops (`modify`, `funcs`, `data_ops`, etc.) require `_risk_ack=true`.

Additional governance:
- `governance(action='check')` — pre-flight validation for patches, renames, type changes
- Address lockstep validation — warns on mismatch between call args and response addresses
- Structured audit logging to `<cache_dir>/audit/YYYY-MM/audit_YYYY-MM-DD.jsonl`
- Token-bucket rate limiting per tool

Per-call overrides: `_guardrail_mode` (`assist`/`enforce`/`off`), `_guardrail_ack`.

## Response Controls

Per-call:
- `_response_mode`: `compact` (default) or `full`
- `_response_fields` / `_response_omit`: top-level field projection
- `_response_max_items`, `_response_max_string`, `_response_char_budget`
- `_response_table`: table compaction for repeated object rows
- `_qol_mode`: `tiny`/`balanced`/`debug` preset profile
- `_error_details`: `none`/`basic`/`full`

Environment defaults:
- `IDA_MCP_RESPONSE_MODE` (`compact`)
- `IDA_MCP_QOL_MODE` (`balanced`)
- `IDA_MCP_TOOLS_LIST_MODE` (`ultra`)
- `IDA_MCP_BATCH_COMPACT` (`1`)
- `IDA_MCP_COMPACT_MAX_ITEMS` (`48`)
- `IDA_MCP_COMPACT_MAX_STRING` (`1400`)
- `IDA_MCP_COMPACT_CHAR_BUDGET` (`30000`)
- `IDA_MCP_TRUNCATE_TOKENS` (`2000`)
- `IDA_MCP_RESPONSE_ENRICH` (`0`)

## Architecture

```
LLM Client (Claude Code / OpenCode / Cursor / etc.)
    │  JSON-RPC over stdio
    ▼
Host MCP Server  (ida_pro_mcp.host.server)
    │  session mgmt, response compaction, blackboard, intelligence
    │  TCP localhost
    ▼
IDA Runtime Bridge  (server_script.py inside idat)
    │
    ▼
Tool Modules  (ida_mcp.tools.*)  →  IDA SDK + Hex-Rays APIs
```

`tools/call` dispatch pipeline:
1. Canonicalize tool name (alias resolution)
2. Route session/IDB
3. Phase-gate preflight (skip when `_risk_ack=true`)
4. TCP RPC to IDA runtime
5. IDA tool execution
6. Host: compact/truncate response
7. Host: auto-blackboard extraction
8. Host: intelligence context injection (compact: top-3 recall hints)
9. Return MCP content

## Security Controls

- **Memory tool path validation**: enforces allowlist root (`IDA_MCP_MEMORY_ROOT`, default IDB dir)
- **RPC size caps**: 64 MB limits on both IDA-side and host-side
- **Atomic config writes**: tmp/fsync/replace prevents corruption on crash
- **`@idaread`/`@idawrite` safety net**: active by default, scoped bypass via `bypass_sync()` context

## Linux Support

IDA detection order: `IDADIR` → `IDA_MCP_IDAT` → common install globs → `PATH` lookup.

Client config locations handled for all supported clients using XDG-aware paths.

## Documentation Map

- `README.md` — this file
- `ARCHITECTURE.md` — module boundaries and ownership map
- `CONTRIBUTING.md` — contribution workflow and PR expectations
- `SAFETY_MODEL.md` — write safety, guardrails, risk acknowledgement
- `docs/OPENCODE_SETUP.md` — OpenCode-specific configuration
- `docs/POLICY.md` — governance policy reference
- `docs/TECHNICAL_REFERENCE.md` — implementation-level details
- `docs/TOOLS_REFERENCE.md` — generated tool/action/argument reference
- `docs/wiki/` — in-tool documentation consumed by the `wiki` MCP tool

## Troubleshooting

**"Tool not found"**: Run `tools/list` to confirm advertised surface. Check alias/canonical naming.

**"No active session"**: Call `session(action='create', binary_path='...')` first.

**Large context usage**: Verify `IDA_MCP_TOOLS_LIST_MODE=ultra` and `IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS` is unset (or `0`). Each `tools/list` call is ~9.5k tokens in ultra mode; `full` mode is ~58k tokens.

**MCP resources not working**: MCP resources (`ida://state` etc.) require user action in the client UI — the LLM cannot read them autonomously. Use `session(action='state')` instead.

**Changes not taking effect**: After `pip install --force-reinstall`, restart the MCP server (Claude Code: `/mcp`, OpenCode: restart the app or kill the server process).

## Development

```bash
python -m pytest tests/
python scripts/check_schema_integrity.py
```

## Contributing

See `CONTRIBUTING.md` and `ARCHITECTURE.md`.

## License

GNU General Public License v3.0 (GPL-3.0-only). See `LICENSE`.
