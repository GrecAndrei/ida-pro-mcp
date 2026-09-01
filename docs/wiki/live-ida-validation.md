# Live IDA validation

Fake IDB and host tests are useful for fast feedback, but they do not establish
that an operation behaves correctly inside a real IDA runtime. Live integration
tests are opt-in and require a licensed local IDA installation and a target
binary.

## What to validate live

When a change touches IDA-side behavior, validate the smallest relevant path:

- session creation and analysis completion;
- decompilation, disassembly, and xrefs;
- the intended IDB mutation and its persisted result;
- snapshot or undo behavior when rollback is involved;
- retrieval against the selected backend and model;
- architecture-specific behavior for firmware or raw blobs.

Record the IDA version, runtime mode, binary, retrieval backend, and model when
reporting results. Do not present fake-test results as live IDA behavior.

## Run the live scope

The live tests live under `tests/integration/` and are intentionally not part
of the fast default suite. Follow the repository's
[Live IDA testing](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/LIVE_IDA_TESTING.md)
instructions for the required environment and runner options.

The basic invocation is:

```bash
IDA_MCP_LIVE_TEST=1 IDA_MCP_LIVE_IDADIR=/path/to/ida \
  pytest -q tests/integration
```

Use `IDADIR` or `IDA_DIR` instead of `IDA_MCP_LIVE_IDADIR` when that is how the
IDA installation is exposed. `IDA_MCP_LIVE_IDAT` can select an executable
directly. The tests compile a temporary ELF fixture when no test binary is
provided; set `IDA_MCP_LIVE_BINARY` to use an existing fixture instead.

A normal development loop can still run the non-live suite:

```bash
pytest -q --basetemp=.pytest_tmp
```

Run the integration scope separately only after configuring the licensed IDA
installation and target binary described by the live-testing guide.

## Validate from the MCP surface

For a manual smoke test:

1. Open the target with `ida_open_binary`.
2. Poll `ida_session_status`.
3. Call `ida_overview`.
4. Read one known function with `ida_decompile`.
5. Verify a reference with `ida_xrefs_to`.
6. If testing a mutation, snapshot first, acknowledge the operation, re-read
   the result, and restore the snapshot if it was only an experiment.
7. Call `ida_session_health` before closing the session.

For a live failure, include the operation name, minimal arguments, expected and
actual result, IDA version, Python version, operating system, and relevant
runtime/backend details.

The repository metadata and README require IDA Pro 9.2 or newer. The optional
idalib runtime path is experimental and requires an IDA 9.3-or-newer install
with its idalib Python environment. The normal offline test suite and fake-IDB
tests do not validate behavior inside a live IDA process.

References: [live-testing guide](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/LIVE_IDA_TESTING.md),
[plugin metadata](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/ida-plugin.json),
[version source](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/src/ida_pro_mcp/_version.py).
