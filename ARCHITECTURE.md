## Architecture Overview

Two primary runtime layers:

1. **Host MCP server** (`src/ida_pro_mcp/host/`) — manages sessions, schemas, blackboard, intelligence layer, and the JSON-RPC bridge to IDA.
2. **IDA-side tool runtime** (`src/ida_pro_mcp/ida_mcp/` + `src/ida_pro_mcp/server_script.py`) — deterministic IDA SDK tool implementations, runs inside `idat`.

Entry point for MCP clients: `python -u -m ida_pro_mcp.host.server` (stdio JSON-RPC).

## High-Level Data Flow

1. MCP client sends tool call over stdio JSON-RPC
2. Host server resolves session/runtime, validates args/schemas
3. Host forwards call to IDA runtime over local TCP bridge
4. IDA tool executes deterministic SDK logic, returns structured output
5. Host post-processes response (compact/truncation/blackboard/intelligence) and replies

## Module Boundaries

- `src/ida_pro_mcp/host/server/`
  - `server.py` — core server object, MCP protocol handling, `tools/list` and `tools/call`
  - `server_dispatch.py` — tool dispatch, routing, phase-gate preflight, policy audit
  - `server_session.py` — session CRUD and lifecycle (including `session(action='state')`)
  - `server_session_bootstrap.py` — bootstrap evidence control loop (calibration, tournament, drift)
  - `server_runtime.py` — runtime (idat process) lifecycle and process management
  - `server_runtime_leases.py` — runtime lease file tracking
  - `server_response.py` / `server_response_compact.py` — response processing, compaction
  - `server_batch.py` — batch macro execution
  - `server_blackboard.py` — blackboard tool integration
  - `server_semantic.py` — semantic search integration
  - `server_threat_hunt.py` — threat hunt integration
  - `server_workflow.py` / `server_workflow_batch.py` — workflow orchestration
  - `server_predictor.py` — predictive strategy suggestion
  - `server_wiki.py` — wiki tool integration
  - `resources.py` — `ida://` MCP resource definitions and `ResourceResolver`
  - `tool_registry.py` — canonical action lists and argument schemas
  - `session_skills.py` / `session_skills_bootstrap.py` — session-level skills and bootstrap mixin

- `src/ida_pro_mcp/host/analysis/`
  - `analysis_engine.py` — AnalysisEngine lifecycle and stage logic
  - `frontier.py` — FrontierEngine (embedding-driven analysis guidance)
  - `context_density.py` — ContextDensityOptimizer
  - `patterns.py` — pattern matching helpers

- `src/ida_pro_mcp/host/stores/`
  - `blackboard_store.py` — BlackboardStore SQLite-backed durable store
  - `knowledge_graph.py` — KnowledgeGraph relationship tracking
  - `insight_index.py` — insight indexing

- `src/ida_pro_mcp/host/schemas*.py`
  - Tool registry metadata: names, descriptions, actions, argument schemas, aliases
  - Source-of-truth for all exposed tool contracts

- `src/ida_pro_mcp/host/intelligence/`
  - BehaviorClassifier, BgeCodeEmbedder, ContextAssembler, UsageIntelligence

- `src/ida_pro_mcp/ida_mcp/tools/*.py`
  - IDA-side tool implementations
  - Keep tool output deterministic, structured, and stable

- `src/ida_pro_mcp/installer/`
  - `main.py` — installer entry point (`ida-pro-mcp-install` / `python install.py`)
  - `skills/__init__.py` — auto-generates Claude Code / OpenCode skills from TOOL_DESCRIPTIONS

## MCP Resources

`ida://` resources are defined in `resources.py` and served via `resources/read`. They are **application-driven** — the LLM cannot read them autonomously; the client UI must explicitly attach them.

The most important resource (`ida://state`) is also accessible as `session(action='state')` — a real tool call the LLM can use directly.

## Tool Call Dispatch Pipeline

1. Canonicalize tool name (alias resolution)
2. Strip and validate response options (`_response_mode`, `_qol_mode`, etc.)
3. Policy audit log
4. Phase-gate preflight — skipped when `_risk_ack=true`
5. Route to host-side handler (session/blackboard/workflow/etc.) or forward to IDA via TCP RPC
6. IDA tool execution (deterministic SDK logic)
7. Host: compact/truncate response
8. Host: auto-blackboard extraction from response payload
9. Host: intelligence context injection (top-3 blackboard recall hints in compact mode)
10. Return MCP content

## Complexity Hotspots

- `src/ida_pro_mcp/ida_mcp/tools/firmware_view.py` — largest tool, full firmware analysis campaign
- `src/ida_pro_mcp/ida_mcp/tools/llm_helpers.py` — analysis helpers
- `src/ida_pro_mcp/host/server/server_workflow.py` — workflow orchestration
- `src/ida_pro_mcp/ida_mcp/tools/code.py` — decompile, smart_decompile, ctree integration

## Design Rules

- **Deterministic first**: tool outputs must not depend on hidden mutable state
- **Stable schemas**: prefer additive changes over breaking shape changes
- **Backward compatibility**: preserve existing aliases and action compatibility
- **Defensive errors**: return structured errors (`{"error": true, "code": "...", "message": "..."}`) with actionable hints
- **No LLM runtime**: tool execution is pure IDA SDK + local ML; no server-side LLM calls

## Safe Areas For New Contributors

- New isolated tool actions with tests
- Documentation and wiki improvements
- Error-message quality improvements
- Response compaction/truncation tests

## Risky Areas (Review Carefully)

- Session/runtime lifecycle and process management
- Tool/action schema contract changes (regenerate skills and tool docs after)
- Bridge protocol between host and IDA runtime
- Workflow/planner behavior that alters action execution ordering
- Blackboard auto-extraction pipeline (affects every tool response)
