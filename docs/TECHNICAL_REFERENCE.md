# IDA Pro MCP Technical Reference

This document captures the current runtime architecture, behavioral contracts, and production
hardening for the IDA Pro MCP server.

**Last updated:** May 2026  
**Test count:** 679+ test functions across 41 test files  
**Tool modules:** 74 IDA-side tool modules, ~28 host-side tools advertised to the LLM

---

## 1. Architecture Overview

The server is split into three layers:

### 1.1 Host MCP Server (`ida_mcp_stdio.py` + `src/ida_pro_mcp/host/`)

`ida_mcp_stdio.py` is a thin ~78-line shim that re-exports the entire `host/` package. It performs
critical stream isolation (`_real_stdout`) before importing the server, then delegates to
`IDAMCPServer.run()`.

The `host/` package (`src/ida_pro_mcp/host/`) contains:

| File | Role |
|---|---|
| `server.py` | `IDAMCPServer` — JSON-RPC stdio server, tool dispatch, response shaping, blackboard pipeline, runtime leases |
| `session.py` | `Session`, `SessionManager`, `BookmarkManager` — session CRUD, snapshots, notebook, hypotheses, skill crystallization, activity log, dead-end detection |
| `schemas.py` | `TOOLS`, `TOOL_ACTIONS`, `TOOL_ARG_SCHEMAS`, `TOOL_ALIASES`, `ARG_ALIASES_BY_TOOL`, `ACTION_ALIASES_BY_TOOL`, `WRAPPER_ACTIONS`, schema builders (full/lean/ultra), alias resolution |
| `cartographer_mu.py` | Cartographer-μ semantic engine — S4REncoder, TurboQuantLite, BridgeRAGLite, MemRLUtility, SchemaBootRE, ContextComposer |
| `audit.py` | JSONL structured audit logging with daily rotation, size cap, args-hash tamper evidence |
| `rate_limit.py` | Token-bucket rate limiter with per-tool + global buckets |
| `config.py` | Runtime directory resolution, env var parsing, constants, limits, pointer note config |
| `context_density.py` | `ContextDensityOptimizer` — XML stripping, hex dump compression, code block compression, xref list truncation |
| `insight_index.py` | VOERA L1 — tag-based function routing index, in-memory with JSON persistence |
| `patterns.py` | `compile_smart_pattern`, `smart_match`, `GlobalFactsDatabase` (VOERA L2) |
| `errors.py` | `MCPError` enum, `make_error()` |
| `response_enrichment.py` | Address patching, decompile auto-digest, session resume, auto-blackboard write, ghost tool chains |
| `auto_nudge.py` | `AutoNudge` — hex address resolution, rip-relative detection, stuck detection, silent rerouting, smart tool suggestions |
| `resources.py` | MCP Resource provider — 65 `ida://` URIs (segments, functions, decompile, strings, imports, etc.) |

### 1.2 IDA Runtime Bridge (`src/ida_pro_mcp/server_script.py`)

Runs inside IDA Python (headless IDAT). Uses non-blocking TCP sockets. Listens on port 13337
(default). Implements lazy tool loading — modules under `src/ida_pro_mcp/ida_mcp/tools/` are
imported on first use.

Key behaviors:
- `load_tools()` scans `tools/` directory and imports all `.py` files
- `_try_load_single_tool()` lazy-loads individual tools
- `_tool_signature_info()` uses `inspect.signature` to validate actions
- `_apply_pre_analysis_options()` applies processor/bitness/endian BEFORE auto-analysis
- Heartbeat file at `TEMP/ida_mcp_heartbeat.txt` for health monitoring
- Pre-applies `IDA_MCP_PRE_ANALYSIS_OPTS` from env var JSON

### 1.3 Tool Modules (`src/ida_pro_mcp/ida_mcp/tools/`)

74 tool modules implementing analysis, edit, debug, and search operations. Each module exports a
function named after the module (e.g., `code.py` exports `def code(**kwargs)`).

Key categories:
- **Data access:** `code.py`, `data.py`, `search/`, `memory.py`, `idb.py`
- **Modification:** `modify.py`, `funcs.py`, `segments.py`, `bulk.py`, `annotation.py`
- **Analysis:** `ctree.py`, `graph.py`, `entropy.py`, `crypto_id.py`, `cfg_analysis.py`, `stack_analysis.py`, `deobfuscate.py`
- **Comparison:** `compare.py`, `lumina.py`
- **Threat hunting:** `threat_hunt.py`, `yara_hunt.py`, `gadgets.py`, `trace.py`, `trace_analysis.py`
- **Classification:** `classify.py`, `schemaboot.py`, `summarize.py`
- **LLM optimization:** `llm_helpers.py`, `memrl.py`, `turboquant.py`, `bridgerag.py`, `mbagcn.py`, `hybrid_search.py`
- **Governance:** `governance_engine.py`
- **Infrastructure:** `blackboard.py`, `filter.py`, `protocol.py`, `abi.py`, `project.py`, `query.py`, `query_lang.py`
- **Utilities:** `misc.py`, `calc.py`, `nav.py`, `wiki.py`, `batch.py`, `history.py`, `bookmarks` (via session)

### VOERA Memory Tiers

The architecture follows a 5-tier memory hierarchy (L0–L4):

| Tier | Module | Description |
|---|---|---|
| L0 Meta Rules | `schemas.py` — `TOOL_ACTIONS` | Canonical action definitions |
| L1 Insight Index | `insight_index.py` | Fast in-memory tag-based function routing |
| L2 Global Facts | `patterns.py` — `GlobalFactsDatabase` | Cross-session persistent facts (SQLite) |
| L3 Task Skills | `session.py` — `crystallize_skill()` | Reusable crystallized workflows with Q-values |
| L4 Session Archive | `blackboard.py` + `memrl.py` | Long-term blackboard persistence |

---

## 2. Server Lifecycle

### 2.1 JSON-RPC stdio

`IDAMCPServer.run()` reads JSON-RPC 2.0 requests from `stdin` and writes responses to
`_real_stdout` (captured before import redirect). Supports three methods:
- `tools/list` — schema generation (full/lean/ultra modes)
- `tools/call` — tool dispatch with full pipeline
- `resources/list` / `resources/read` — MCP resource URIs

Shutdown is handled via `atexit.register(self.shutdown)` plus `SIGINT`/`SIGTERM` signal
handlers. On shutdown: heartbeat thread stops, all runtimes are cleaned up, insight index is
persisted, global facts DB is closed.

### 2.2 Runtime Lease System

Each IDA runtime (spawned by `session(action="create")` with binary_path) has a disk-backed
lease file at `<cache_dir>/runtime_leases/SID_<id>.lease.json`.

- **TTL:** `IDA_MCP_RUNTIME_LEASE_TTL` (default 75s)
- **Heartbeat:** background thread writes lease every `TTL/3` seconds
- **Stale cleanup:** on server start and every heartbeat cycle; kills stale PIDs via SIGTERM →
  SIGKILL escalation
- **PID verification:** checks `/proc/<pid>/exe` against expected IDA binary names
- **Grace period:** verified against TTL before reaping to avoid killing active sessions

### 2.3 Process Spawning (`session(action="create")`)

When a session is created with a binary_path:
1. Reserved args (`-S`, `-L`, `-o`) are rejected
2. `-A` (auto-analysis) is automatically injected
3. `IDAT` binary is resolved via `IDADIR`/`IDA_DIR` env, `IDA_MCP_IDAT`, or PATH search
4. Subprocess is launched with stdin/stdout/stderr piped to log files
5. Lease record is written; IDA health is verified via TCP ping (`{"type": "ping"}`)

### 2.4 Session Management

`SessionManager` (backed by `<cache_dir>/sessions/`) provides:
- **CRUD:** create, get, update, delete, list (with query filtering)
- **Deduplication:** existing sessions matched by binary_path; `force_new=true` overrides
- **Persistence:** metadata as `SID_<id>_metadata.json`, orphaned IDB auto-recovery on load
- **Snapshots:** real persisted checkpoints (`SID_<id>_snapshots.json`), up to 50 per session
- **Analysis Notebook:** Markdown journal with auto-linking (`SID_<id>_notebook.md`)
- **Hypothesis Tracker:** structured confirm/refute with evidence binding
- **Skill Registry:** cross-session global SQLite DB (`global_skills.db`)
- **Activity Log:** last 500 entries, dead-end pattern detection
- **Merge/Link:** session merging and cross-binary linking
- **Cleanup:** stale sessions removed after 30 days

---

## 3. Tool Dispatch

### 3.1 Dispatch Pipeline (`_execute_tool_inner`)

Every `tools/call` passes through this sequence:

```
1. Alias resolution          (_resolve_tool_alias)
2. Arg normalization         (_normalize_tool_call_args)
3. Rate limiting check       (rate_limiter.check)
4. Silent rerouting          (get_reroute from auto_nudge)
5. Blocking stuck detection  (check_stuck_blocking from auto_nudge)
6. Action normalization      (clean_action_text, alias mapping)
7. Wrapper action dispatch   (grep/pick/head/tail/next/stats)
8. Guardrail check           (strict mode, pointer safety)
9. Host-side routing         (wiki/misc/project/session/query)
10. IDA bridge dispatch      (TCP to server_script.py)
11. Response shaping         (_prepare_response_payload)
12. MemRL observation        (_observe_memrl)
13. Next-cache write         (_cache_next_page)
14. Activity recording       (_record_activity)
15. Audit logging            (audit.log)
```

### 3.2 Host-Side vs IDA-Side

**Host-side tools** (no IDA process required):
- `session` — lifecycle management
- `wiki` — documentation system
- `batch` — multi-call orchestration
- `truncation` — continuation helper
- `bookmarks` — session-correlated bookmarking
- `misc` — `health`, `plugin_list`, `plugin_run`, `read_file`, `write_file`
- `project` — I/O operations (save, close, open, etc.)

**IDA-side tools** (require running IDA process):
- Dispatched via TCP to `server_script.py` on `127.0.0.1:13337`
- All 74 tool modules in `src/ida_pro_mcp/ida_mcp/tools/`

The host also provides **MCP Resources** (65 `ida://` URIs) as a virtual filesystem over the IDB,
accessible via `resources/read`.

### 3.3 Alias Resolution

Tool aliases are automatically built from snake_case, camelCase, and noisy variants. 200+ explicit
aliases defined in `_EXTRA_TOOL_ALIASES`:
- `"annotate"` → `"annotation"`
- `"decomp"` → `"code"`
- `"functions"` → `"funcs"`
- `"xfer_analysis"` → `"xref_analysis"`

Action aliases per tool also exist (e.g., `"rename"` → `"set_name"` for funcs).

### 3.4 Wrapper Actions

Six wrapper actions are injected at the schema level for all action-based tools:

| Wrapper | Purpose |
|---|---|
| `grep` | Filter results by pattern (substring or regex) |
| `pick` | Project specific top-level fields |
| `head` | First N items from results |
| `tail` | Last N items from results |
| `next` | Paginated continuation (cached server-side for 1800s) |
| `stats` | Aggregated statistics over result fields |

All wrappers require `source_action` (or alias `on`/`target_action`/`subaction`).

### 3.5 Arg Normalization

`_normalize_tool_call_args` handles LLM noise:
- Strips action wrappers like `action: "decompile"` → `"decompile"`
- Extracts positional args from action strings like `"read topic=foo"`
- Maps alias keys via `ARG_ALIASES_BY_TOOL`
- Normalizes field variants (bracketed `[0x401000]` → `0x401000`, comma-separated addrs → list)
- Handles nested dict actions, JSON payloads in action strings

### 3.6 Silent Tool Rerouting

`get_reroute` in `auto_nudge.py` fixes common LLM errors:
- Explicit map: `("search", "text")` → `("search", "name")`
- Heuristic: `memory.read` with small size → `code.disasm`
- Tracks reroutes for MemRL feedback

---

## 4. Cartographer-μ Semantic Engine

**File:** `src/ida_pro_mcp/host/cartographer_mu.py` (816 lines, pure Python + numpy)

A 32KB-parameter (effective) semantic engine replacing passive blackboard injection with
utility-driven, relevance-ranked context selection. Zero external ML libraries. Deterministic
(fixed seeds, no stochastic inference).

### 4.1 S4REncoder (Selective State Space Encoder)

128-dimensional state space model with RE-specific structured decay priors:
- **Address band** (0–16): decay 0.95
- **API band** (16–32): decay 0.80
- **String band** (32–48): decay 0.50
- **CF band** (48–64): decay 0.85
- **General band** (64–128): decay 0.30

Tokenizes payloads into feature tokens (tool name, addresses, APIs, keys), embeds via hash-based
projection, and updates hidden state via `h_t = A@h_t + B@x_t`.

### 4.2 TurboQuantLite (4-bit PolarQuant)

Compresses 128-dim vectors to ~64 bytes using:
1. **Hadamard rotation** (Walsh-Hadamard transform)
2. **4-bit Lloyd-Max quantization** (16 levels with learned centroids)
3. **QJL residual** (1-bit sign correction)

`similarity()` computes approximate inner product via bin-matching + QJL correction, enabling
fast nearest-neighbor search without decompression.

### 4.3 BridgeRAGLite (Cross-Reference Bridge Extraction)

Extracts bridge entities from payloads using three regex patterns:
- `addr`: `0x[0-9a-fA-F]{8,16}`
- `api`: 200+ known Windows/Linux APIs
- `func_name`: `sub_*` and symbol names

Scoring is domain-aware for reverse engineering:
- **Exact address match:** maximum relevance (0.85–1.0)
- **Bridge overlap:** Jaccard similarity weighted 0.7
- **Semantic similarity:** tiebreaker (0.2) when no bridges match
- **Temporal decay:** slower for bridged entries (`exp(-age/10)`), faster for orphans (`exp(-age/3)`)

### 4.4 MemRLUtility (Non-Parametric Q-Learning)

Per-entry Q-value table backed by SQLite. TD(0) update:
```
Q_new = Q_old + α * (reward - Q_old),  α=0.15
```

`observe_usage()` infers reward from LLM behavior:
- Injected entry + next call uses related bridges → +1.0
- Injected entry + no related bridges → -0.3
- Missed relevant entry → +0.5

`prune_low_q(threshold=0.2)` removes entries with persistently low utility.

### 4.5 SchemaBootRE (Deterministic Attribute Induction)

Extracts structured attributes from any tool payload:
- `tool`, `action`, `has_addr`, `has_api`, `has_crypto`, `has_network`
- `phase_hint`: triage → behavioral_analysis → threat_analysis
- Phase inference from crypto/network API patterns

`pre_filter()` filters blackboard entries by schema compatibility: phase match, address
compatibility, high-confidence pass-through, API compatibility.

### 4.6 ContextComposer (Pipeline Orchestrator)

Full pipeline per tool response:
```
1. SchemaBoot    → extract query attributes
2. Encode        → S4R state vector
3. Quantize      → TurboQuant 4-bit
4. Pre-filter    → SchemaBoot compatibility
5. BridgeRAG     → relevance scoring
6. MemRL         → utility = 0.8·relevance + 0.2·Q
7. Select top-k  → default k=3
8. Density opt   → 1-line compact summaries
```

Returns `working_memory` (compact entries), `memory_stats` (total/pre-filtered/injected/avg_utility),
`analysis_phase`, `bridges_detected`.

### 4.7 Cognitive Architecture and Bridge Query

The `agent.py` tool provides two additional actions:

- **`bridge_query`**: Bridge-Conditioned Multi-Hop Search. Chains through intermediate entities
  (bridge → string refs → candidates). Automatically extracts bridge entities and expands via
  dual-entity search.

- **`reflect`**: ReasoningBank Distillation. Analyzes attempted strategies, extracts insights
  and guardrails. Distills successes/failures into reusable strategy objects.

---

## 5. Production Hardening

### 5.1 Audit Logging (`audit.py`)

- **Format:** JSONL at `<cache_dir>/audit/YYYY-MM/audit_YYYY-MM-DD.jsonl`
- **Per record:** `ts`, `unix_ms`, `session_id`, `tool`, `action`, `args_hash` (SHA-256 first 16 hex),
  `args_keys`, `latency_ms`, `guardrail_mode`, `guardrail_blocked`, `error`, `result_type`, `result_size`
- **Args preview:** included for non-sensitive tools (excludes `raw_bytes`, `binary_path`, `idb_path`, `path`)
- **Rotation:** daily by date, auto-prunes oldest months when total exceeds 256 MB
- **Thread-safe:** uses `threading.Lock`

### 5.2 Rate Limiting (`rate_limit.py`)

Token-bucket algorithm with two scopes:
- **Per-tool:** default 10 calls/second (configurable via `IDA_MCP_RATE_LIMIT_PER_TOOL`)
- **Global:** default 30 calls/second (configurable via `IDA_MCP_RATE_LIMIT_GLOBAL`)
- **Burst:** default 20 tokens (configurable via `IDA_MCP_RATE_LIMIT_BURST`)
- **Disable:** `IDA_MCP_DISABLE_RATE_LIMIT=1` for testing

### 5.3 Blackboard Pruning

- **MemRL:** `prune_low_q(threshold=0.2)` removes entries below utility threshold
- **Session cleanup:** `cleanup_stale(max_age_days=30)` removes sessions untouched for >30 days
- **Activity log:** capped at 500 entries per session
- **Insight Index:** stale demotion via `get_stale_functions()`

### 5.4 Context Density Optimization (`context_density.py`)

`ContextDensityOptimizer` provides:
- XML/HTML tag stripping
- Code block compression (preview + count)
- Hex dump compression (preview + count)
- Xref list truncation with per-segment histogram
- Information density measurement
- Budget-aware response compaction (default 30K token budget)

### 5.5 Semantic Index

Configurable semantic ASM index:
- Versioned SQLite DB (`semantic_asm_index_v1.sqlite3`)
- Configurable workers (default 2) and wait time (default 3s)
- Scoring: substring match (48), pattern match (120), per-token (12)
- Source limit: default 3000 entries

### 5.6 MCP Resource Layer

65 read-only `ida://` URIs provide a virtual filesystem over the IDB:
- `ida://functions/{addr}/decompile` — decompilation on demand
- `ida://strings` — all strings
- `ida://imports`, `ida://exports` — import/export tables
- `ida://skills`, `ida://facts`, `ida://archive` — VOERA memory tiers
- `ida://bookmarks` — session bookmarks

Resources are resolved through a `ResourceResolver` that dispatches to the appropriate
IDA tool and caches results through the insight index.

---

## 6. Guardrails

### 6.1 Pointer Notes

The system detects when an LLM is about to compute addresses mentally and injects a safety note:
```
DO NOT CALCULATE POINTERS OR ADDRESSES MENTALLY;
ALWAYS USE THE CALC/MEMORY TOOL FOR ADDRESS MATH OR POINTER CHAINING.
```

**Detection signals:**
- **Strong signals:** tools `calc`, `memory` being called
- **Hint signals:** tools `data`, `code`, `nav`, `search`, `debug`, `batch`
- **Hex pattern:** `0x` followed by 3+ hex digits
- **Math pattern:** base+offset expressions like `0x1000 + 0x200`
- **Keywords:** addr, address, ea, offset, base, ptr, pointer, deref, index, stride, chain

Injected every `IDA_MCP_POINTER_NOTE_INTERVAL` (default 900s) when signal exceeds threshold
(`IDA_MCP_POINTER_NOTE_MIN_SIGNAL`, default 3).

### 6.2 Strict Mode (`IDA_MCP_GUARDRAIL_STRICT_WRITES`)

When enabled, blocks risky write operations (patch, rename, set_type, comment, delete, etc.)
unless `_guardrail_ack=true` is explicitly provided. Affects tools: `modify`, `bulk`,
`annotation`, `funcs`, `segments`, `memory`, `data_ops`.

### 6.3 Address Lockstep

All address arguments pass through hex normalization and validation. `_normalize_field_variants`
resolves bracket-wrapped addresses, strips quotes, and handles comma-separated lists.

### 6.4 Auto-Nudge Middleware

`AutoNudge` (injected into every response as `_nudge` field) solves 6 persistent LLM behavioral
patterns:
1. **Address arithmetic in head** → auto-resolve hex expressions
2. **Tool amnesia** → track call history per session
3. **Wrong tool selection** → suggest correct action on error
4. **No context awareness** → auto-resolve rip-relative addresses
5. **No progress awareness** → inject dashboard metrics
6. **Tool blindness** → suggest relevant tools based on content

**Stuck detection** (configurable via `IDA_MCP_DISABLE_STUCK_DETECTION`):
- Same function decompiled 4+ times → force redirect
- Same search query 5+ times → force redirect  
- Looping between 2 tools 3+ times → force redirect

**Smart tool suggestions** use Z-score normalized scoring with behavior-tag boosts and
MemRL Q-value integration.

### 6.5 Ghost Tool Chains

`response_enrichment.py` defines companion chains triggered by specific tool/action pairs:
- `code:decompile` → auto-runs `callers`, `callees`, `strings_in_func`
- `data:strings` → auto-runs `string_ops:find_urls`, `string_ops:find_ips`
- `data:imports` → auto-runs `imports_deep:summary`

Results are silently merged into the response before the LLM sees it. Certain tools
(`binary_info`, `idb`, `calc`, `wiki`, `memory`, `debug`, `misc`) are excluded from ghost chains.

---

## 7. Auto-Blackboard Pipeline

The full response enrichment pipeline (applied after tool execution):

```
1. Address Patching       → Resolve rip-relative expressions in pseudocode
2. Decompile Auto-Digest  → Extract APIs, patterns, security notes, complexity, density
3. Session Resume         → Inject previous analysis state on reconnect
4. Auto-Blackboard Write  → Silently write significant findings to blackboard
5. Security Detection     → Flag anti-debug, anti-VM, crypto, shellcode patterns
6. Ghost Tool Chains      → Pre-emptively execute companion tool calls
7. Auto-Nudge             → Compute _nudge field (hex resolution, suggestions, stuck alerts)
8. Cartographer-μ         → Encode → Quantize → BridgeRAG → MemRL → Context injection
9. Response Shaping       → _response_mode, field projection, truncation, table mode
```

### Auto-Blackboard Triggers

| Tool/Action | Condition | Category | Priority |
|---|---|---|---|
| `code:decompile` | Any function | decompile | 4–5 |
| `data:strings` | Suspicious patterns (http, .exe, password, etc.) | strings | 4 |
| `data:imports` | >20 APIs imported | imports | 3 |
| `crypto_id:detect` | Crypto constants found | crypto | 5 |
| `string_ops:find_urls/ips/c2` | Matches found | c2 | 5 |

---

## 8. Testing Strategy

### 8.1 Test Infrastructure

- **679 test functions** across 41 files under `tests/`
- Tests use a combined `conftest.py` and `MCPClient` helper class (subprocess stdio client)
- Host-side tests run without IDA (mock the runtime)
- Comprehensive tests include `test_mcp_comprehensive.py`, `test_host_wiki_and_hardening.py`,
  `test_improvements.py`, `test_revamp.py`, `test_session_features.py`, etc.

### 8.2 Benchmark Suite (`tests/benchmark_cartographer_mu.py`)

761-line comprehensive benchmark for Cartographer-μ measuring:
1. **Latency:** per-component and end-to-end pipeline
2. **Accuracy:** relevance ranking quality vs baselines
3. **Memory:** footprint and scalability across 10–5000 entries
4. **Determinism:** consistency guarantees across runs
5. **Learning:** MemRL convergence speed
6. **Scalability:** performance vs blackboard size

### 8.3 Key Test Files

| File | Focus |
|---|---|
| `test_cartographer_mu.py` | Cartographer-μ semantic engine |
| `test_memrl_bridgerag.py` | MemRL + BridgeRAGLite |
| `test_turboquant.py` | TurboQuantLite quantization |
| `test_governance_engine.py` | Governance rule engine |
| `test_host_wiki_and_hardening.py` | Wiki, audit, rate limiting |
| `test_mcp_client.py` | Full client-server round trips |
| `test_session_features.py` | Notebook, hypotheses, skills |
| `test_session_persistence.py` | Session save/load/snapshot |
| `test_hybrid_search.py` | Hybrid search engine |
| `test_llm_helpers_expansion_ast.py` | LLM helper tools |
| `test_decompilation_advanced_ast.py` | Advanced decompilation |
| `test_infrastructure.py` | Server infrastructure |
| `test_smart_match.py` | Pattern matching engine |
| `test_funcs_sync_routing.py` | Function sync/routing |
| `tool_sweep_probe.py` | Tool action sweep testing |

### 8.4 Optimization Profiles

Three QoL profiles control the trade-off between context efficiency and detail:

| Profile | Mode | Max Items | Max String | Char Budget | Error Details |
|---|---|---|---|---|---|
| `tiny` | compact | 24 | 800 | 12K | none |
| `balanced` | (env default) | 48 | 1400 | 30K | basic |
| `debug` | full | 10K | 500K | 0 | full |

---

## 9. Installer & Build System

### 9.1 Installer Architecture (`install.py`)

- Hardcoded MCP client config paths extracted into `client_configs.json`
- Dynamically loads and resolves paths from JSON data
- Writes MCP env defaults:
  - `IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS=1`
  - `IDA_MCP_TOOLS_LIST_MODE=full`
  - `IDA_MCP_RESPONSE_MODE=compact`
  - `IDA_MCP_QOL_MODE=balanced`
  - Additional compact/truncation budgets
- Supports env overrides, XDG fallback, OS-specific paths

### 9.2 Documentation Generation

- `docs/TOOLS_REFERENCE.md` generated from live schema metadata
- `docs/wiki/tools/*.md` generated from live tool metadata/schemas
- `docs/wiki/INDEX.md` generated from wiki tree content
- `.agents/tool-docs/*.md` generated by `scripts/generate_tool_skills.py`

### 9.3 Environment Variables (Key)

| Variable | Default | Purpose |
|---|---|---|
| `IDA_MCP_CACHE_DIR` | OS state dir | Runtime cache location |
| `IDA_MCP_IDAT` | auto-detect | Path to IDAT executable |
| `IDADIR` / `IDA_DIR` | auto-detect | IDA installation directory |
| `IDA_MCP_RESPONSE_MODE` | `compact` | Default response shaping |
| `IDA_MCP_QOL_MODE` | `balanced` | QoL profile |
| `IDA_MCP_TOOLS_LIST_MODE` | `full` | Schema verbosity |
| `IDA_MCP_CARTOGRAPHER_DIM` | `128` | S4R state dimension |
| `IDA_MCP_CARTOGRAPHER_TOPK` | `3` | Top-k context entries |
| `IDA_MCP_RATE_LIMIT_PER_TOOL` | `10` | Per-tool rate limit |
| `IDA_MCP_RATE_LIMIT_GLOBAL` | `30` | Global rate limit |
| `IDA_MCP_RUNTIME_LEASE_TTL` | `75` | Lease TTL (seconds) |
| `IDA_MCP_GUARDRAIL_STRICT_WRITES` | `false` | Strict guardrail mode |
| `IDA_MCP_POINTER_NOTE_INTERVAL` | `900` | Pointer note interval (s) |
| `IDA_MCP_VERTEX_COMPAT` | `false` | Vertex AI schema compat |
| `IDA_MCP_DISABLE_RATE_LIMIT` | — | Disable rate limiting |
| `IDA_MCP_DISABLE_STUCK_DETECTION` | — | Disable stuck detection |
| `IDA_MCP_BYPASS_SYNC` | `1` (internal) | Bypass IDA sync for server_script |

---

## 10. Tool Schema Contract

Source of truth is in `src/ida_pro_mcp/host/schemas.py`:
- `TOOLS` — ordered list of all 73 tool names
- `ADVERTISED_TOOLS` — 66 tools shown in `tools/list`
- `HIDDEN_TOOLS_IN_LIST` — 7 tools callable via alias/name but hidden from listings
- `TOOL_DESCRIPTIONS` — per-tool description text
- `TOOL_ACTIONS` — per-tool valid action list
- `TOOL_ARG_SCHEMAS` — JSON Schema for each tool's arguments
- `ARG_ALIASES_BY_TOOL` — per-tool argument name aliases
- `ACTION_ALIASES_BY_TOOL` — per-tool action name aliases

Schema builders (`build_input_schema`, `build_input_schema_lean`, `build_input_schema_ultra`)
handle three verbosity modes. `sanitize_schema_for_vertex` translates to Vertex AI / Gemini
compatible format when `IDA_MCP_VERTEX_COMPAT=1`.

Wrapper actions (`grep`, `pick`, `head`, `tail`, `next`, `stats`) are injected at schema
generation time for every action-based tool.
