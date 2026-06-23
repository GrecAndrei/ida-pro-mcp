## Architecture Overview

This project has two primary runtime layers:

1. **Host MCP server** (`src/ida_pro_mcp/host/`) — manages sessions, schemas, blackboard, intelligence, and the JSON-RPC bridge to IDA.
2. **IDA-side tool runtime** (`src/ida_pro_mcp/ida_mcp/` and `src/ida_pro_mcp/server_script.py`) — deterministic IDA SDK tool implementations.

`ida_mcp_stdio.py` is the stdio entrypoint used by MCP clients.

## High-Level Data Flow

1. MCP client calls tool over stdio JSON-RPC.
2. Host server resolves session/runtime and validates args/schemas.
3. Host forwards tool call to IDA runtime over local TCP bridge.
4. IDA tool executes deterministic SDK logic and returns structured output.
5. Host post-processes response (compact/truncation/enrichment) and replies.

## Module Boundaries

- `src/ida_pro_mcp/services.py`
  - **Single import contract** for all subsystems.
  - Tools and test files import from here, not from `host/*` directly.
  - Internal `host/` structure can change freely — only this file needs updating.

- `src/ida_pro_mcp/host/server/`
  - Core host server object (`server.py`) and behavior mixins:
    - `server_runtime.py` — runtime lifecycle and process management
    - `server_runtime_leases.py` — runtime lease file tracking
    - `server_session.py` — session CRUD and lifecycle
    - `server_session_bootstrap.py` — bootstrap evidence control loop
    - `server_dispatch.py` — tool dispatch and routing
    - `server_response.py` / `server_response_compact.py` — response processing
    - `server_batch.py` — batch macro execution
    - `server_blackboard.py` — blackboard integration
    - `server_semantic.py` — semantic search integration
    - `server_threat_hunt.py` — threat hunt integration
    - `server_workflow.py` / `server_workflow_batch.py` — workflow orchestration
    - `server_predictor.py` — predictive prefetching
    - `server_wiki.py` — wiki tool integration

- `src/ida_pro_mcp/host/analysis/`
  - `analysis_engine.py` — AnalysisEngine lifecycle and stage logic
  - `analysis_engine_kg.py` — Knowledge Graph mixin for AnalysisEngine
  - `analysis_proposal_store.py` — ProposalStore CRUD
  - `frontier.py` — FrontierEngine (embedding-driven analysis guidance)
  - `gap_engine.py` — GapEngine for coverage gap detection
  - `narrative_engine.py` — NarrativeEngine for blackboard narrative
  - `context_density.py` — ContextDensityOptimizer
  - `patterns.py` — pattern matching helpers

- `src/ida_pro_mcp/host/stores/`
  - `blackboard_store.py` — BlackboardStore SQLite-backed durable store
  - `knowledge_graph.py` — KnowledgeGraph for relationship tracking
  - `chip_db.py` — Chip DB for architecture profiles
  - `symbol_db.py` — SymbolDB for symbol management
  - `insight_index.py` — insight indexing

- `src/ida_pro_mcp/host/schemas*.py`
  - Tool registry metadata (names, actions, argument schemas, aliases).
  - Source-of-truth for exposed tool contracts.

- `src/ida_pro_mcp/host/intelligence/`
  - ML components: BehaviorClassifier, BgeCodeEmbedder, ContextAssembler,
    FrontierEngine, VulnerabilityReasoner, UsageIntelligence, etc.

- `src/ida_pro_mcp/ida_mcp/tools/*.py`
  - IDA-side tool implementations.
  - Keep tool output deterministic, structured, and stable.

- `src/ida_pro_mcp/ida_mcp/tools/_common.py`
  - Shared imports/helpers for tool modules.

## Complexity Hotspots

The largest orchestration surfaces are currently:

- `src/ida_pro_mcp/ida_mcp/tools/firmware_view.py`
- `src/ida_pro_mcp/ida_mcp/tools/llm_helpers.py`
- `src/ida_pro_mcp/host/server/workflow.py`
- `src/ida_pro_mcp/ida_mcp/tools/code.py`

## Design Rules

- **Deterministic first**: tool outputs should not depend on hidden mutable state.
- **Stable schemas**: prefer additive changes over breaking shape changes.
- **Backward compatibility**: preserve existing aliases and action compatibility where possible.
- **Defensive errors**: return structured errors with actionable hints.

## Safe Areas For New Contributors

- New isolated tool actions with tests.
- Documentation and wiki improvements.
- Error-message quality improvements.
- Response compaction/truncation tests.

## Risky Areas (Review Carefully)

- Session/runtime lifecycle and process management.
- Tool/action schema contract changes.
- Bridge protocol behavior between host and IDA runtime.
- Large workflow/planner behavior that alters action execution ordering.
