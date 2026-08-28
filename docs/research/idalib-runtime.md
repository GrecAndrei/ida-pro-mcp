# idalib as the MCP runtime — evaluation & design

Status: **adopted as an opt-in backend** (2026-08-12). Spawn-idat stays
the default; `IDA_MCP_RUNTIME=idalib` runs sessions inside the idalib
kernel.  Verified live: the full integration suite passes under idalib on
**both 9.3.260421 and 9.4.260714** (42 passed / 8 skipped each, matching
the idat legs), and the runtime matrix runs all four legs
(scripts/run_ida_matrix.py --idalib).

## What shipped

- `ida_pro_mcp/idalib_worker.py` — worker process: imports `idapro`
  (must be the first IDA import, hence a top-level module — the `ida_mcp`
  package `__init__` imports `sync`/`ida_kernwin` and would break the
  first-import rule), `open_database(file, run_analysis, args,
  enable_history=True)`, then `runpy.run_path(server_script.py,
  run_name="__main__")` so the existing RPC listener + main-thread dispatch
  loop run unmodified.  On the host's shutdown RPC the `__main__` block
  returns and the worker performs `close_database(save=True)` (flush on
  exit).
- Host seam (`host/server/server_runtime.py`): `IDA_MCP_RUNTIME=idalib`
  swaps the idat spawn for `python -m ida_pro_mcp.idalib_worker` with the
  same `IDA_MCP_*` env, port handoff, ping protocol, leases and teardown —
  the host treats the worker exactly like an idat runtime.  Preload load
  args extracted into `_preload_ida_args(session)` so both backends load
  with the same architecture flags; the idalib worker receives them via
  `IDA_MCP_IDALIB_OPEN` (`-o` is only passed for new databases — idalib
  refuses an existing output with rc=2).
- Snapshot/undo mapping: idalib exposes no `ida_loader.save_snapshot`/
  `restore_snapshot` — `analysis(snapshot/restore_snapshot)` feature-
  detects this and falls back to `ida_undo.create_undo_point` /
  `perform_undo` (LIFO restore; verified live on 9.4).  Undo history is
  enabled per session by `open_database(enable_history=True)`.
- Installer: wizard section "IDA session runtime backend" (idat
  recommended / idalib experimental), `--ida-runtime {idat,idalib}` CLI
  flag, `find_idalib_python_dir`/`activate_idalib` helpers, and
  `IDA_MCP_RUNTIME` written into the client config env by
  `build_stdio_config(ida_runtime=...)`.
- Matrix: `run_ida_matrix.py --idalib` runs the integration suite under
  idalib per install (activating idalib per install; skips installs
  without idalib/python); the self-hosted workflow passes `--idalib`.

## The question

Today the server spawns one `idat` process per session
(`host/server/server_runtime.py`, `sync.py` executes scripts via
`IDAPython_ExecScript` over an RPC socket). IDA 9.4's idalib grew
`execute_sync()` + async event processing, auto-activation at install,
bundling with IDA Home, database flush on exit, and revived
`gen_disasm_text` — the pieces that previously made idalib unsuitable.
Should the runtime become idalib-in-process?

## Verified facts (from an IDA 9.4 idalib installation)

- `idalib/python/idapro-0.0.9-py3-none-any.whl` ships the `idapro`
  package. Loading it: `import idapro` must be the **first import** in the
  process; it refuses to load inside a running IDAPython
  (`IDAPYTHON_VERSION` guard in `__init__.py`).
- Activation: `py-activate-idalib.py [-d <install_dir>]` records the
  install; the package locates `libidalib.so` under it
  (`idapro.config.get_ida_install_dir`).
- Python surface is minimal: `idapro.open_database(file, run_auto_analysis,
  args=None, enable_history=False) -> int` and
  `idapro.close_database(save=True)`. Everything else is the regular
  `ida_*` API usable directly after open (example `idacli.py` calls
  `ida_segment`/`ida_funcs`/`ida_undo` straight after
  `open_database(file, True)`).
- `open_database(run_auto_analysis=True)` blocks through auto-analysis in
  the demo; the async path (`execute_sync` + event pump) is the C++ API
  (`idalib.hpp` in the SDK) surfaced for embedding use.
- The example also shows the value add: `ida_undo.create_undo_point(...)`
  before analysis, `ida_undo.perform_undo()` to roll back a session —
  cheap snapshot semantics for free.

## What the current spawn-idat model buys us (don't lose this)

| property | idat-per-session | idalib-in-process |
|---|---|---|
| crash isolation | idat dies → session only; server survives | any IDA crash takes the server down |
| memory | one IDB per process, reclaimed on close | N IDBs in one process; peak = Σ sessions |
| concurrency | per-session processes, natural parallelism | one IDA kernel; must serialize via execute_sync + event pump |
| licensing/setup | works with any detected install | needs idapro whl + activation per install (9.4+; 9.2/9.3 unchanged — installs stay) |
| plugin loading | full IDA (kernwin stubs), `-S` scripts, all processor modules | kernel-only; GUI/kernwin-dependent plugins unavailable |

## The design (if adopted later)

Phase 1 — runtime abstraction, not a rewrite:

1. Introduce `RuntimeBackend` with two implementations:
   `SpawnIdatBackend` (today's model, stays default) and
   `IdalibBackend` (new). `server_runtime.py` already centralizes
   spawn/exec/reap; the abstraction is a thin seam over
   `start_session` / `exec_script` / `read_mem` / `kill`.
2. `IdalibBackend` runs a dedicated worker process per IDA version
   (idalib is one-process-one-kernel; multiple sessions share a worker,
   multiplexed through `execute_sync`). Worker contract:
   - `import idapro` first; activate via `py-activate-idalib.py -d <install>`.
   - open databases with `enable_history=True` (undo points per session).
   - each RPC becomes `execute_sync(closure)` on the kernel thread; the
     event pump (`process_events`) runs between closures so auto-analysis
     and timer events progress.
   - `close_database(save=True)` on session close — the 9.4 flush-on-exit
     fix removes the "changes lost" trap.
3. Feature flag `IDA_MCP_RUNTIME=idalib` (opt-in), default spawn-idat.
   The migration suite (`scripts/run_ida_matrix.py`) gains a matrix leg
   running the integration suite under the idalib backend.
4. Keep `sync.py`'s execute_sync marshaling as-is for spawned runtimes
   (it already speaks the same request/response shape; the backend only
   changes where closures run).

## Decision (revised)

Adopted as an opt-in backend behind `IDA_MCP_RUNTIME=idalib`; spawn-idat
remains the default.  Rationale: the worker reuses server_script.py's
listener + main-thread dispatch loop verbatim (no RPC protocol change),
which made the port cheap enough to ship behind a flag.  idat is still the
right default — crash isolation and the 9.2 floor matter more than the
idalib wins (undo points, no process spawn, flush-on-exit) for interactive
use — but the idalib path is now continuously validated by the matrix
instead of being design prose.

Known trade-offs of the current idalib implementation:
- One worker per session (matching spawn-idat resilience: a worker crash
  takes the session down, the host recovers/restarts it; the server
  survives).  Multi-session-on-one-worker (DB swap) is NOT implemented —
  idalib is one-kernel-per-process and swapping databases would require
  resetting per-IDB Python state (netnode handles, LRU caches).
- `open_database(run_auto_analysis=True)` blocks through auto-analysis
  before the RPC listener binds, so the host's startup ping timeout
  (IDA_MCP_STARTUP_TIMEOUT, default 240s) covers the open.
- Revisit multi-session batching when: (a) multi-session throughput on one
  box becomes the bottleneck, (b) a runtime feature (e.g.
  `gen_disasm_text`) is needed that spawned idat can't reach, or (c) the
  9.2 floor rises.

## Acceptance criteria for the future port

- [x] `IDA_MCP_RUNTIME=idalib` runs the full integration suite on 9.4
      (and 9.3): 42 passed / 8 skipped on both, matrix-validated
- [x] session crash inside idalib (bad script) does not take the worker
      down — per-session workers + host recovery give spawn-idat-equivalent
      resilience (worker restart + session retry)
- [ ] two concurrent sessions on one worker (execute_sync serialization)
      — NOT implemented; requires DB-swap + per-IDB state reset (see
      Decision above)
- [x] `ida_undo` snapshot/restore mapped to the existing
      `ida_idb_snapshot` surface — `analysis(snapshot/restore_snapshot)`
      falls back to `ida_undo.create_undo_point`/`perform_undo` (LIFO)
      when `ida_loader.save_snapshot` is absent; history enabled per
      session
- [x] installer: idapro whl install + activation surfaced in the wizard
      (wizard section + `--ida-runtime` flag + `IDA_MCP_RUNTIME` in the
      client config env)
