# Agent Guidelines for IDA Pro MCP

## Recent Major Changes

### Repo Cleanup (May 2026)
- Removed 5 dead host modules superseded by `intelligence.py`: `cognitive_layer.py`, `attention_kernel.py`, `adaptive_heuristics.py`, `autogenic_semantics.py`, `cartographer_mu.py` (~170KB)
- Removed dead tool file `strings_xref.py` (aliased to `xref_analysis`, never loaded)
- Removed stale `self.attention_kernel` references from `server.py`
- Reorganized `tests/`: benchmarks → `tests/benchmarks/`, probes/manual scripts → `tests/probes/`, integration scripts → `tests/integration/`
- Moved design-vision docs to `docs/legacy/`: `ACTIVE_BLACKBOARD_KERNEL.md`, `EVIDENCE_PHYSICS_ENGINE.md`, `predictive_analysis_design.md`

### VOERA Architecture Integration (May 2026)
The following VOERA-inspired features have been integrated across the tool suite:

1. **Intelligence Engine** (`host/intelligence.py`)
   - Replaces the old `cartographer_mu`, `attention_kernel`, `cognitive_layer` pipeline
   - Handles auto-blackboard extraction, context injection, relevance ranking
   - `host/intelligence_helpers.py`: compact_policy_blob, derive_focus_candidates, prune_policy_store

2. **Context Density Optimization** (`llm_helpers.py`)
   - `compact` action: RE-specific content compaction (strips IDA tags, compresses hex dumps, truncates long xref lists)

3. **Neuro-Symbolic Governance** (`annotation.py`, `cybercane.py`)
   - `annotation(action="validate")`: Pre-flight validation for comments
   - `governance(action="check")`: Deterministic rule-based validation (re-exported from `cybercane.py`)

4. **Structured Semantic Retrieval** (`search/`, `classify.py`, `schemaboot.py`)
   - `search(action="structured", constraints={...})`: Pre-filters by induced schema
   - `classify(action="induce_schema")`: Induces attribute-value schema for functions
   - `schemaboot`: Structured semantic indexing with SQL+BM25 hybrid search

5. **Task Skill Crystallization** (`host/session.py`)
   - `SessionManager.crystallize_skill()`, `rate_skill()`, `suggest_strategy()`, `log_activity()`

6. **Bridge-Conditioned Multi-Hop Search** (`agent.py`, `bridgerag.py`)
   - `agent(action="bridge_query")`: Multi-hop entity expansion
   - `bridgerag`: Dedicated bridge query tool

7. **ML Tools** (`turboquant.py`, `memrl.py`, `mbagcn.py`)
   - `turboquant`: 4-bit quantization for fast embedding comparisons
   - `memrl`: Q-value learning and skill crystallization
   - `mbagcn`: Mamba-based GCN for CFG similarity encoding

8. **Firmware Analysis** (`firmware_view.py`, `firmware_heuristics.py`)
   - `firmware_view`: 19-action firmware triage and campaign orchestration tool
   - `firmware_heuristics.py`: Pure-logic helper library (no IDA deps) consumed by firmware_view

### Installer Refactoring
- Hardcoded MCP client config paths extracted from `install.py` into `client_configs.json`
- `install.py` now dynamically loads and resolves paths from JSON data

### Testing
- ~510+ tests runnable without IDA Pro installed
- Test layout: `tests/*.py` (unit tests), `tests/benchmarks/` (perf), `tests/probes/` (manual/integration), `tests/integration/` (IDA-required)

## When Working on This Project

### Code Style
- Follow existing patterns: `@tool` + `@idaread`/`@idawrite` decorators
- Use `make_error(MCPError.*, ...)` for consistent error handling
- Keep docstrings comprehensive with LLM-friendly examples
- Prefer compact text output (one match per line) to minimize context usage

### Architecture
- `ida_mcp_stdio.py` is a thin shim (~78 lines) re-exporting `host/` package
- All server logic lives in `src/ida_pro_mcp/host/`
- Tool files live in `src/ida_pro_mcp/ida_mcp/tools/`
- `_real_stdout` must be injected before `IDAMCPServer` import

### Key Files
- `host/config.py` — Cross-cutting constants, limits, regexes
- `host/patterns.py` — Canonical smart pattern matching (zero IDA deps)
- `host/session.py` — Session management + VOERA skill crystallization
- `host/server.py` — JSON-RPC stdio server
- `host/schemas.py` — TOOL_ACTIONS, descriptions, schema builders
- `host/intelligence.py` — Auto-blackboard, context injection, relevance ranking (replaces old cartographer_mu/attention_kernel/cognitive_layer)
- `host/auto_nudge.py` — Contextual suggestion middleware (stuck pattern detection, tool amnesia)
- `host/response_enrichment.py` — Post-processing: address patching, auto-digest, session resume injection

### Dead Code / Do Not Resurrect
These modules were removed — do not re-add them:
- `host/cognitive_layer.py` — superseded by `intelligence.py`
- `host/attention_kernel.py` — superseded by `intelligence.py`
- `host/adaptive_heuristics.py` — superseded by `intelligence.py`
- `host/autogenic_semantics.py` — superseded by `intelligence.py`
- `host/cartographer_mu.py` — superseded by `intelligence.py`
- `tools/strings_xref.py` — aliased to `xref_analysis`, never loaded
