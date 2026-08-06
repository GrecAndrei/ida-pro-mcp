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

1. **`host/agent_operations.py`** — add an `AgentOperation` with strict schema,
   valid example, concise description, and backend mapping (`backend_tool`,
   `backend_action`, `argument_map`).

2. **`host/server/tool_registry.py`** — add the new `backend_action` to
   `_TOOL_ACTIONS[backend_tool]` so it is a recognized action for that tool.

3. **`host/schemas_data.py`** — add any new argument keys the action accepts to
   `TOOL_ARG_SCHEMAS[backend_tool]`. Unknown keys are rejected before dispatch.

4. **`host/policy.py`** — classify the new action:
   - Read-only → add `(tool, action)` to `READ_ONLY_ACTIONS`
   - IDB write → ensure `tool` is in `WRITE_IDB_TOOLS` or `action` is in `WRITE_ACTIONS`
   - Destructive → add `action` to `DESTRUCTIVE_ACTIONS` or pair to `DESTRUCTIVE_TOOL_ACTIONS`
   - Failing to classify lands in `UNKNOWN`, which blocks in `assist` mode.

5. **IDA-side tool** — implement the action in `ida_mcp/tools/<tool>.py`:
   - Add the action name to the `Literal[...]` type annotation on the `action` param
   - Add the `elif action == "<name>":` branch

6. **Tests** — add tests in `tests/`:
   - `test_agent_operations.py` — schema validity, routing, argument mapping
   - `test_agent_risk_ack.py` — mutating ops in the risk_ack list; read-only ops not there
   - `tests/host/test_policy.py` — correct risk tier for the new `(tool, action)` pair

7. **Generated docs** — run `python scripts/generate_tool_skills.py` to
   regenerate `docs/TOOLS_REFERENCE.md` and `.agents/skills/ida-pro-mcp/SKILL.md`.

8. **README.md** — update the operations table (add the new op to its group row)
   and the `N exact-schema operations` count in the intro paragraph.

9. **Wiki** — update the relevant page in `docs/wiki/tools/` (or create a new
   page). Update `docs/wiki/INDEX.md` if a new page was added.

The full test suite enforces steps 7–9: `test_docs_sync.py` will fail if
TOOLS_REFERENCE, SKILL.md, the README table, or the README count are stale.

## Adding a Legacy Backend Tool

1. Create `ida_mcp/tools/<name>.py` with `@tool` function
2. Add to `_TOOL_ACTIONS` in `host/server/tool_registry.py`
3. Add to `TOOLS` in `host/schemas_data.py`
4. Add description to `TOOL_DESCRIPTIONS`
5. Add to `ida_mcp/tools/__init__.py::__all__`
6. If host-side only: add `tool_name == "<name>"` branch in `server_dispatch.py`
7. Add tests for any host-side logic (embeddings, config parsing, etc.)

## Installer Touchpoints

The installer (`installer/main.py`) has an interactive wizard that configures
the server for users. When you add something that has a user-facing setup step,
check whether the wizard needs updating.

**Things that require installer changes:**

- **New env var that controls a feature** — add it to the wizard or at minimum
  emit an `ui.info()` line so users know it exists. Env vars silently ignored
  are invisible to users who ran the installer.

- **New model or backend** — both the embed model and the reranker must be
  surfaced in the interactive wizard. The wizard must prompt for each model;
  auto-detect it via a `find_*` helper in `installer/runtime.py`; offer a
  managed download; and write the path into `embedder.json` via
  `write_embedder_state`. Two models are needed for full semantic search:
  an embedding model and a reranker (cross-encoder). Don't add one without the
  other — a missing reranker silently degrades search quality.

- **New backend binary** (like `llama-server` or `libmcp_llama.so`) — add
  detection in `installer/runtime.py`, show the user whether it was found, and
  explain what to do if it wasn't (build command, download URL, etc.). The
  wizard is the user's only visibility into which backend will run.

- **New MCP client config env var** — add it to `build_stdio_config()` in
  `installer/clients.py` so it gets written to Claude Desktop, Cursor, VS Code,
  etc. Vars not written to the client config block are silently absent at
  runtime.

**What the installer does NOT need:**

- New `AgentOperation` fields that are pure schema additions — no user action
  required.
- Changes to response enrichment or analysis heuristics — runtime-only.
- New IDA-side tool actions — no install step needed.

**Wizard sections in order** (for orientation when adding to the right place):
1. Runtime source (snapshot/pypi/local)
2. CLI shim
3. Skills mode
4. Embedding backend choice + native lib detection + model auto-detect/download
5. **Reranker model** auto-detect/download ← right after embed, both are required
6. Rollback preference
7. Policy gates

## Removing a Tool or Operation

1. `grep -rn '"<name>"' src/ docs/ tests/ .agents/ --include="*.py" --include="*.md"`
2. Delete/remove from: tool file, `_TOOL_ACTIONS`, `TOOL_ARG_SCHEMAS`, `TOOL_DESCRIPTIONS`,
   `agent_operations.py`, `policy.py` (READ_ONLY_ACTIONS / WRITE_IDB_TOOLS), tests
3. Run `python scripts/generate_tool_skills.py` and update README + wiki

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
