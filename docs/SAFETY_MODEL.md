# Safety Model

`ida-pro-mcp` is a local, deterministic bridge between MCP clients and IDA Pro. It gives agents structured access to IDA analysis and mutation APIs, so the safety model is based on local trust, explicit capability boundaries, and reviewable tool calls.

## Core assumptions

- The MCP client is running locally or in an environment controlled by the user.
- The IDA bridge is local-only and binds to `127.0.0.1`.
- The host process starts each IDA runtime with a per-session token and includes that token in bridge requests.
- The project does not embed or operate a cloud LLM service.
- Any agent behavior comes from the external MCP client.

## Capability classes

### Read/discovery

Examples: metadata, names, xrefs, imports, strings, decompilation, CFG, search, summaries.

These should be preferred for initial exploration and are the safest default class.

### Write/mutation

Examples: rename, comment, type application, patching, segment edits, function edits, annotation, bulk operations.

These can permanently affect an IDB. Prefer dry-run modes where available, then apply with narrow arguments.

### Local execution and filesystem

Examples: Python/IDC execution, file read/write, plugin execution.

These are intentionally powerful local-user capabilities. They should be documented clearly and used only with trusted MCP clients and prompts.

## Public release guidance

Before enabling broad public use, maintainers should keep these confidence signals healthy:

- version consistency between package metadata and runtime health
- generated tool docs synchronized with schema data
- smoke CI for imports, schemas, and generated docs
- clear documentation for dangerous actions
- local bridge authentication enabled by default
- explicit limits for batch and bridge payload sizes

## Recommended agent behavior

Agents should:

1. Start with read-only discovery.
2. Use compact/paginated calls for large outputs.
3. Batch only deterministic calls.
4. Ask for explicit confirmation before high-impact writes unless operating under a trusted automation policy.
5. Record important findings in bookmarks or the blackboard.
6. Avoid mental address arithmetic; use the provided calculation/memory tools.

## Known dangerous surfaces

The following are not vulnerabilities by themselves, but must be treated as trusted-user operations:

- `misc(action="python")`
- `misc(action="idc")`
- `misc(action="write_file")`
- `misc(action="plugin_run")`
- debugger control
- memory writes
- patching and bulk IDB mutation
