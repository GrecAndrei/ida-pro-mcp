# Live IDA integration testing

`pytest -q` intentionally does not start IDA. The public agent surface has a
separate opt-in test package that runs the real stdio MCP server, launches
IDA, and exercises every advertised `ida_*` operation through JSON-RPC.
All suites are marked `live_ida` and skip unless `IDA_MCP_LIVE_TEST=1`.

```bash
IDA_MCP_LIVE_TEST=1 IDA_MCP_LIVE_IDADIR=/path/to/ida \
  pytest -q tests/integration
```

The runner compiles a temporary ELF fixture with known functions, caller and
callee relationships, imports, strings, and a safe mutation target. It uses a
temporary runtime directory, so the checkout and existing IDBs are untouched.
`IDA_MCP_LIVE_IDADIR` (or `IDADIR`/`IDA_DIR`) selects the IDA install;
`IDA_MCP_RUNTIME=idalib` selects the idalib backend and
`IDA_MCP_LIVE_IDAT=/path/to/idat64` selects a native idat run.

Ordinary live calls time out in 15s (override with `IDA_MCP_LIVE_CALL_TIMEOUT`).
Do not raise that to hundreds of seconds — a hung IDA RPC must fail the test,
not stall the suite. The indexing suite is the exception: it uses a 180s
budget because embedding/decompile work is actually slow.

A healthy catalog + behavior + extended run on the tiny fixture should finish
in a few minutes. If it is still going after ~10 minutes, an RPC is hung.

## Suites (~368 tests, IDA 9.2+; idat and idalib where supported)

| Suite | Tests | What it proves |
| --- | --- | --- |
| `test_agent_surface_live.py` | 8 | Session lifecycle, indexing (incl. the full background decompile index), semantic search, and continuation tokens. The original live suite. |
| `test_agent_surface_catalog_live.py` | 104 | One test per operation in `AGENT_OPERATIONS`: every `ida_*` op must answer correctly with its documented example, or fail with a *coded* error (never a protocol error, never an exception). Pins graceful expectations where the environment makes them deterministic (e.g. `GOVERNANCE_BLOCKED` for the hard-blocked `ida_patch_bytes`, `TRUNCATION_TOKEN_INVALID` for a bogus token). |
| `test_agent_surface_behavior_live.py` | 66 | Deep behavior: exact decompile/disassembly shapes, calc semantics, type round-trips (declare/get/struct/enum/TIL export-import), findings lifecycle, mutation→verify→restore round-trips, undo transactions, snapshots, batch bindings/chaining, the r2 sidecar, firmware heuristics, and the python tool. |
| `test_agent_surface_extended_live.py` | 170 | Extra live coverage on a shared session: discovery filters/pagination, public-contract edges (legacy names rejected, `address` not `addr`, missing `risk_ack`), query language, calc, findings, layout edits behind snapshots, batch public names, python/idc, firmware carve, session/type/search edges, and a dedicated emulate start/step/stop session. |
| `test_ida_live_integration.py` | 20 | Legacy `tool(action=...)` surface (server spawned with `IDA_MCP_TOOL_SURFACE=legacy`): custom detectors, search analyze scopes, emulate lifecycle. |

Run a single suite with:

```bash
IDA_MCP_LIVE_TEST=1 IDA_MCP_LIVE_IDADIR=/path/to/ida \
  pytest -q tests/integration/test_agent_surface_behavior_live.py
```

The catalog smoke proves *every* operation answers correctly with its
documented example; the behavior suite proves the operations do the *right
thing*. The two suites share one module-scoped session per module and use a
deterministic fixture, so runs are repeatable — a failing suite usually means
a real product bug (this is how the 9.3/9.4 API drift bugs in undo
transactions, snapshots, TIL import/export, and `FlowChart` construction were
found and fixed).

## Semantic coverage

Semantic indexing uses the configured local embedding profile. By default this
is `qwen3-embedding-0.6b`; an explicit Zembed run can be selected without
changing the installed client configuration:

```bash
python scripts/run_live_agent_surface.py --ida-dir /path/to/ida \
  --embed-profile zembed-1 --embed-model /path/to/zembed-1-Q4_K_M.gguf
```

The suite also starts a separate real-IDA session with embeddings disabled and
verifies that indexing fails clearly instead of reporting a nonexistent index.
For a CPU model comparison, run the suite once per profile in a clean runtime
directory and record total indexing time, peak `llama-server` RSS, and the
top semantic hits for the same queries. Zembed 1 is CC-BY-NC-4.0 and must only
be used where that non-commercial license is acceptable.

It is intentionally opt-in. A missing or unusable IDA install fails an
explicit live run, while ordinary unit/contract test runs skip it.
