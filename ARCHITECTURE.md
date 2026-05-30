## Architecture Overview

This project has two primary runtime layers:

1. Host MCP server (`src/ida_pro_mcp/host/`)
2. IDA-side tool runtime (`src/ida_pro_mcp/ida_mcp/` and `src/ida_pro_mcp/server_script.py`)

`ida_mcp_stdio.py` is the stdio entrypoint used by MCP clients.

## High-Level Data Flow

1. MCP client calls tool over stdio JSON-RPC.
2. Host server resolves session/runtime and validates args/schemas.
3. Host forwards tool call to IDA runtime over local TCP bridge.
4. IDA tool executes deterministic SDK logic and returns structured output.
5. Host post-processes response (compact/truncation/enrichment) and replies.

## Module Boundaries

- `src/ida_pro_mcp/host/server.py`
  - Core host server object and mixin composition.
  - Keep this file focused on assembly/wiring, not new feature logic.

- `src/ida_pro_mcp/host/server_*.py`
  - Host-side handlers by concern (session/workflow/dispatch/semantic/etc.).
  - Prefer adding behavior in a dedicated mixin file over enlarging one giant handler.

- `src/ida_pro_mcp/host/schemas*.py`
  - Tool registry metadata (names, actions, argument schemas, aliases).
  - Consider these files source-of-truth for exposed tool contracts.

- `src/ida_pro_mcp/ida_mcp/tools/*.py`
  - IDA-side tool implementations.
  - Keep tool output deterministic, structured, and stable.

- `src/ida_pro_mcp/ida_mcp/tools/_common.py`
  - Shared imports/helpers for tool modules.
  - New global helper behavior goes here only when reused broadly.

## Complexity Hotspots

The largest orchestration surfaces are currently:

- `src/ida_pro_mcp/ida_mcp/tools/firmware_view.py`
- `src/ida_pro_mcp/ida_mcp/tools/llm_helpers.py`
- `src/ida_pro_mcp/host/server_session.py`
- `src/ida_pro_mcp/host/server_workflow.py`
- `src/ida_pro_mcp/ida_mcp/tools/code.py`

When changing these files, prefer extraction-first refactors:

- move pure helper logic into private helper functions,
- isolate action routing tables,
- keep I/O and business logic separated.

## Design Rules

- Deterministic first: tool outputs should not depend on hidden mutable state.
- Stable schemas: prefer additive changes over breaking shape changes.
- Backward compatibility: preserve existing aliases and action compatibility where possible.
- Defensive errors: return structured errors with actionable hints.
- Batch-safe behavior: avoid side effects that break repeated/batched calls.

## Safe Areas For New Contributors

- New isolated tool actions with tests.
- Documentation and wiki improvements.
- Error-message quality improvements.
- Response compaction/truncation tests.
- Non-breaking schema alias additions.

## Risky Areas (Review Carefully)

- Session/runtime lifecycle and process management.
- Tool/action schema contract changes.
- Bridge protocol behavior between host and IDA runtime.
- Large workflow/planner behavior that alters action execution ordering.
