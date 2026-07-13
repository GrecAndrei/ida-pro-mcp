# AGENTS.md

## Project

IDA Pro MCP — JSON-RPC stdio server exposing IDA Pro RE capabilities to LLMs.

The default agent surface is action-specific `ida_*` MCP operations. The old
`tool(action=...)` API is a compatibility backend, not the public contract.

## Testing

Test behavior through stable interfaces, not implementation details.

**Rules:**
- Mock at the network/process boundary (`urllib.request.urlopen`, `subprocess.Popen`), not internals
- Assert on inputs/outputs — if someone changes the algorithm but the output stays correct, the test should still pass
- When behavior intentionally changes, the test SHOULD fail — update both together in the same commit
- No test registry ceremony. Tests don't need magic headers or hash tracking.

**Anti-patterns:**
- Asserting on private variable names, internal data structures, or file hashes → breaks on refactors
- Testing that "the function was called" instead of "the result is correct"
- Coarse bindings (hash of entire file) → false positives on unrelated changes

**What to test:**
- Host-side logic that doesn't require IDA (embeddings, server management, response parsing)
- Schema/dispatch integrity (no missing handlers, no duplicate tools)
- Docs sync (every tool documented, no removed tools in docs)

**What not to test:**
- IDA-side tools that need a live IDA session (these are validated via MCP integration)

## Adding an Agent Operation

1. Add an `AgentOperation` to `host/agent_operations.py` with a strict schema,
   valid example, concise description, and backend mapping.
2. Add a behavior-focused public-contract test.
3. Run `python scripts/generate_tool_skills.py`.

The operation registry generates `tools/list`, `ida_help`, installed skill
references, and `docs/TOOLS_REFERENCE.md`.

## Adding a Legacy Backend Tool

1. Create `ida_mcp/tools/<name>.py` with `@tool` function
2. Add to `_TOOL_ACTIONS` in `host/server/tool_registry.py`
3. Add to `TOOLS` in `host/schemas_data.py`
4. Add description to `TOOL_DESCRIPTIONS`
5. Add to `ida_mcp/tools/__init__.py::__all__`
6. If host-side only: add `tool_name == "<name>"` branch in `server_dispatch.py`
7. Add tests for any host-side logic (embeddings, config parsing, etc.)

## Removing a Tool

1. `grep -rn '"<name>"' src/ docs/ tests/ .agents/ --include="*.py" --include="*.md"`
2. Delete tool file, remove from all registry files, remove tests

## Key Files

| File | Purpose |
|------|---------|
| `host/agent_operations.py` | Public `ida_*` schemas, examples, mappings, help/docs source |
| `host/server/tool_registry.py` | Legacy backend `_TOOL_ACTIONS` dict |
| `host/schemas_data.py` | Legacy backend `TOOLS`, descriptions, RPC argument admission |
| `host/server/server_dispatch.py` | Tool routing and handlers |
| `ida_mcp/tools/__init__.py` | `__all__` list, `_TOOL_MODULE_MAP` |

## Invariants

- Every tool in `TOOLS` has entry in `_TOOL_ACTIONS`
- Every tool has description in `TOOL_DESCRIPTIONS`
- Every public operation has a strict schema and an example that validates
- Generated skill/docs match `agent_operations.py`

## Conventions

- No marketing jargon in descriptions
- Public operation descriptions: one clear sentence; do not expose action enums
- Legacy descriptions: one sentence + "Actions: a, b, c"
- `@tool` decorator on IDA-side functions, `@idaread` for read-only
- Wrapper actions (grep/pick/head/tail/next/stats) are dynamic — don't list in `_TOOL_ACTIONS`
