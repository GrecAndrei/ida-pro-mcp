# idalib as the MCP runtime — evaluation & design (draft)

Status: **evaluated, not adopted** (2026-08-12). This doc is the design
write-up the tracking doc requires before any porting. It exists so a
future attempt starts from verified facts instead of release-note prose.

## The question

Today the server spawns one `idat` process per session
(`host/server/server_runtime.py`, `sync.py` executes scripts via
`IDAPython_ExecScript` over an RPC socket). IDA 9.4's idalib grew
`execute_sync()` + async event processing, auto-activation at install,
bundling with IDA Home, database flush on exit, and revived
`gen_disasm_text` — the pieces that previously made idalib unsuitable.
Should the runtime become idalib-in-process?

## Verified facts (from ~/ida-pro-9.4/idalib)

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

## Decision

Not adopted now. The spawn-idat model is crash-isolated, version-agnostic
(9.2 floor), and license-simple; the integration suite passes live on both
9.3 and 9.4 (2026-08-12 matrix run). idalib's wins (undo points, no
process spawn, flush-on-exit) matter for long-running batch farms, not
interactive sessions. Revisit when: (a) multi-session throughput on one
box becomes the bottleneck, (b) a runtime feature (e.g. `gen_disasm_text`)
is needed that spawned idat can't reach, or (c) the 9.2 floor rises.

## Acceptance criteria for the future port

- [ ] `IDA_MCP_RUNTIME=idalib` runs the full integration suite on 9.4
- [ ] session crash inside idalib (bad script) does not take the worker
      down (worker restart + session retry, matching spawn-idat resilience)
- [ ] two concurrent sessions on one worker (execute_sync serialization)
- [ ] `ida_undo` snapshot/restore mapped to the existing
      `ida_idb_snapshot` surface
- [ ] installer: idapro whl install + activation surfaced in the wizard
      (AGENTS.md installer touchpoints apply: new backend binary)
