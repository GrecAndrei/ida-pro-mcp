# IDA Pro MCP

Give an LLM agent a working seat at IDA Pro.

This is an [MCP](https://modelcontextprotocol.io) server that exposes IDA Pro's
analysis to a model as 41 exact-schema operations — decompile, cross-reference,
search, rename, annotate — plus a findings workspace so the model's conclusions
survive across turns instead of living in a context window.

It runs deterministic IDA SDK calls. There is no LLM service behind it, and
nothing about your binary leaves the machine.

> **Alpha (0.9.x).** The agent interface is still moving. Pin a commit if you
> depend on it.

---

## Why this instead of a thin SDK wrapper

**Every operation has an exact schema.** The surface is `ida_decompile(address)`,
not `tool(action="decompile", ...)`. Models don't infer argument shapes, so they
don't burn turns on `INVALID_ARGS`. `ida_help(topic="ida_decompile")` returns the
contract over MCP, so it works in clients with no filesystem access.

**Decompilation comes with structure, not just text.** `ida_decompile` returns
pseudocode *plus* a bounded evidence block: CFG shape, resolved call targets,
ctree control points, and local data-flow. `ida_disassemble` returns the CFG and
call-target portion without starting Hex-Rays. A model reasoning about a function
gets the graph, not only the listing.

**Semantic search runs locally or says it can't.** Function embeddings use a local
GGUF model through `llama-server`. If the model or server is unavailable, semantic
operations return an explicit unavailable result — they never fall back to a
different vector space, and never hand back a zero vector dressed as a score. The
index records model, dimension, and prompt format, and rebuilds when any changes.

**Findings are evidence-backed and durable.** `ida_write_finding` records a claim
against an address with confidence and supporting evidence, into a per-session
SQLite workspace with an append-only audit trail. Concurrent updates merge
evidence under a write lock rather than overwriting it. `ida_next_target` ranks
what to look at next.

**Mutations are gated, and the gate is yours.** Anything that writes to the IDB
requires an explicit `risk_ack`. Policy strictness comes from the operator, via
`IDA_MCP_POLICY_MODE` or `~/.config/ida-pro-mcp/policy.json`; a session can tighten
it but never relax it. See [SAFETY_MODEL.md](SAFETY_MODEL.md).

**Concurrent sessions stay separated.** Each MCP connection owns the sessions it
opened. Another client cannot drive, switch to, or kill a session it did not open,
and disconnecting tears down the `idat` processes that connection started.

---

## Install

```bash
python install.py
```

That builds the runtime environment, locates IDA, configures supported MCP
clients, and installs the portable `ida-pro-mcp` skill for Claude Code, Codex,
and OpenCode.

**Requirements:** IDA Pro 9.2+, Python 3.11+. Runtime dependencies are four
packages (`tomli-w`, `yara-python`, `requests`, `numpy`) — no torch, no
transformers.

From source:

```bash
git clone https://github.com/GrecAndrei/ida-pro-mcp.git
cd ida-pro-mcp
pip install -e .
python -u -m ida_pro_mcp.host.server
```

---

## Quick start

```jsonc
// Open a binary
{"name": "ida_open_binary", "arguments": {"binary_path": "/path/to/binary"}}

// Orient
{"name": "ida_overview",      "arguments": {}}
{"name": "ida_session_state", "arguments": {}}

// Find and read code
{"name": "ida_find",       "arguments": {"query": "recv", "limit": 20}}
{"name": "ida_decompile",  "arguments": {"address": "0x401000"}}
{"name": "ida_xrefs_to",   "arguments": {"address": "0x401000"}}

// Record what you concluded
{"name": "ida_write_finding", "arguments": {
    "title": "packet receive handler",
    "content": "Parses inbound data before dispatching on the command byte.",
    "address": "0x401000",
    "confidence": 0.8}}

// Writes need an acknowledgement
{"name": "ida_rename", "arguments": {
    "address": "0x401000", "name": "handle_recv", "risk_ack": true}}
```

A typical path through the surface:

```text
ida_open_binary → ida_session_state → ida_overview → ida_find
  → ida_decompile / ida_disassemble / ida_xrefs_to → ida_write_finding
```

---

## The operations

| Group | Operations |
|---|---|
| **Session** | `open_binary`, `close_session`, `session_state`, `session_status`, `session_health` |
| **Discovery** | `overview`, `find`, `list_functions`, `list_imports`, `list_strings`, `semantic_search`, `index_functions`, `index_status`, `cancel_index` |
| **Code** | `decompile`, `disassemble`, `xrefs_to`, `callers`, `callees` |
| **Findings** | `write_finding`, `update_finding`, `list_findings`, `search_findings`, `next_target`, `analysis_brief` |
| **Edit** | `rename`, `comment`, `change_function`, `create_function` |
| **Calculation** | `calc_eval`, `calc_convert`, `calc_deref`, `calc_offset`, `calc_align`, `calc_bitops`, `calc_chain`, `calc_resolve` |
| **Support** | `help`, `continue`, `python` |
| **Workflow** | `batch` |

All prefixed `ida_`. Full contracts in [docs/TOOLS_REFERENCE.md](docs/TOOLS_REFERENCE.md),
or ask the server: `ida_help(query="strings")`.

The earlier broad `tool(action=...)` API still exists for old scripts —
set `IDA_MCP_TOOL_SURFACE=legacy`. It is a compatibility backend, not the
supported contract.

---

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `IDA_MCP_TOOL_SURFACE` | `agent` | `agent` for the `ida_*` operations, `legacy` for the old catalog |
| `IDA_MCP_RESPONSE_MODE` | `compact` | `full` for unabridged payloads |
| `IDA_MCP_POLICY_MODE` | `assist` | `off`, `permissive`, `assist`, `enforce` — operator baseline |

### Local embeddings

Semantic search and full indexing are optional. Default profile is BGE Code v1;
Zembed 1 is opt-in and non-commercial.

| Profile | Dims | License | Notes |
| --- | ---: | --- | --- |
| `bge-code-v1` | 1536 | Apache-2.0 | Default. Supply a local GGUF. |
| `zembed-1` | 2560 | CC-BY-NC-4.0 | ~2.5 GB at Q4_K_M; slower on CPU. |

```bash
# managed download, explicit opt-in
python install.py --embed-profile zembed-1 --download-embed-model \
  --accept-model-license --install-llama-server

# or point at your own GGUF
python install.py --embed-profile zembed-1 --embed-model /path/to/model.gguf

# check a configuration without opening IDA
python install.py --embedder-doctor --embed-profile zembed-1
```

The model starts only for explicit indexing, semantic search, or anchor refresh.
Ordinary tool calls never spin it up. One request in flight per server; a timed-out
request recycles that server rather than queueing behind it, and indexing returns a
resumable cursor to pass back to `ida_index_functions`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `IDA_MCP_EMBED_PROFILE` | `bge-code-v1` | Selects prompts and expected model profile |
| `IDA_MCP_EMBED_MODEL` | auto-detect | Path to the GGUF model |
| `IDA_MCP_EMBED_SERVER_BIN` | auto-detect | Path to `llama-server` |
| `IDA_MCP_EMBED_THREADS` | adaptive | CPU threads, from available affinity |
| `IDA_MCP_EMBED_BATCH` | `1` | Initial indexing batch size; grows on success |
| `IDA_MCP_EMBED_MAX_BATCH` | adaptive | Ceiling for automatic batch growth |
| `IDA_MCP_EMBED_MAX_REQUESTS` | `512` | Recycle a server after this many requests |
| `IDA_MCP_EMBED_MAX_RSS_MB` | adaptive | RSS recycle limit; `0` derives one from model size |
| `IDA_MCP_EMBED_IDLE_TIMEOUT` | `15` | Seconds to keep the server after its last request; `0` disables |

---

## Development

```bash
ruff check .
python scripts/check_schema_integrity.py
python scripts/generate_tool_skills.py
pytest -q
```

`host/agent_operations.py` is the single source of truth: `tools/list`, `ida_help`,
the installed skill, and `docs/TOOLS_REFERENCE.md` are all generated from it. Change
an operation, then regenerate — CI checks for drift.

Live IDA integration tests need a local IDA install and a target binary; they skip
otherwise. See [AGENTS.md](AGENTS.md) for conventions and
[ARCHITECTURE.md](ARCHITECTURE.md) for the layout.

---

## Credits

Portions of `ida_mcp/utils.py` and the vendored `ida_mcp/zeromcp` package come from
[ida-pro-mcp by mrexodia](https://github.com/mrexodia/ida-pro-mcp) (MIT), which is
also where the idea of driving IDA over MCP came from. `zeromcp` keeps its own
LICENSE alongside the sources.

FindCrypt signatures and the threat corpus are fetched from their upstream projects
by the installer.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
