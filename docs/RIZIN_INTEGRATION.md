# Rizin / radare2 Integration (Architecture A)

Decision record for adopting a host-side, subprocess-only **r2** engine as the
pre-IDA and IDA-sidecar triage backend. This is Phase 0/1 of the integration
roadmap; Phases 2-5 are deliberately deferred (see
[Roadmap](#roadmap-phases-2-5-deferred)).

The engine is a *hypothesis tier*, not an authority: **r2 proposes, IDA
disposes**. Every result is advisory metadata for the agent to reason over;
nothing it returns is written back into the IDB by the host.

## License posture

| Component | License | Constraint |
|---|---|---|
| `ida-pro-mcp` (host) | GPL-3.0 | — |
| radare2 (`r2`, `rabin2`) | GPL-3.0 | green light |
| Rizin (`rz`, `rz-bin`) | LGPL-3.0 | green light |
| unicorn (CPU emulation lib) | GPL-2.0-only | **never** import into `ida_pro_mcp/**` |

The engine spawns a child process and speaks to it over argv/stdout only. It
never links, imports, or embeds the engine, so the GPL/LGPL boundary is clean.
Two hard rules keep it that way:

1. **Never bundle the engine in the wheel.** The installer may offer an
   optional `--with-r2` flag that installs a distro package, but the Python
   package itself ships no r2/rz binaries.
2. **Never import unicorn anywhere under `ida_pro_mcp/**`.** A future
   emulation op would have to live behind an optional extra that the default
   install does not pull in, and even then it must remain a separate optional
   dependency — not a hard import.

## Five hard conditions (all met)

1. **Subprocess-only** — every op is a per-call stateless one-shot
   (`rz -q -c` / `r2 -q -c`) over the raw binary path.
2. **Default-off** — no engine is required to run the server. `status` is a
   feature test: an absent engine is an expected state, not an error.
3. **No engine in the wheel** — see license posture.
4. **`ida_r2_*` never writes the IDB** — Phase 1 ships only read-only ops;
   IDB-writing r2 paths are refused by the handler (`ACTION_NOT_FOUND`).
5. **Explicit user `analysis_options` override wins** — a session's resolved
   `processor`/`bitness`/`endian`/`baseaddr` always beats r2's guesses
   (`load_hints` reports `arch_context_applied`).

## Why not Architecture B or C

- **Architecture B (independent query backend)** — a long-lived server the
  host also talks to. Rejected: extra daemon to supervise, same subprocess
  cost, and it duplicates the one-shot results without adding anything for the
  Phase-1 op set.
- **Architecture C (in-process `librizin`)** — would require bundling/binding
  the C library, pulling the LGPL boundary into the process, complicating the
  wheel, and risking the unicorn/GPL-2.0-only trap. Rejected.

## Subprocess hardening

- **Scrubbed env** — the child inherits only `PATH`, `HOME`, `LANG`,
  `LC_ALL`, and `R2_NOPLUGINS=1`. `IDA_MCP_SESSION_TOKEN` and every other
  host secret are never passed down.
- **No shell interpolation** — the target path and commands travel as argv
  elements; a hostile filename cannot reach a shell.
- **Restricted cwd** — the child runs in the target file's own directory (or
  a throwaway temp dir), never the server's cwd.
- **Wall-clock cap** — `IDA_MCP_R2_TIMEOUT_SEC` (default 30s) bounds every
  one-shot; a runaway becomes `R2_TIMEOUT`.
- **Target canonicalization** — mirrors the memory-tool allow-root rules:
  `realpath` resolution, `os.path.commonpath` containment inside the allowed
  root (`IDA_MCP_MEMORY_ROOT`, else the target's own directory), and rejection
  of symlink components. A path that escapes returns `INVALID_ARGS`.
- **`R2_NOPLUGINS`, not `cfg.sandbox`** — `cfg.sandbox=true` breaks file
  opening in r2 6.1.6 (verified). `R2_NOPLUGINS` disables plugin loading and is
  portable across radare2 and Rizin. `io.sandbox` vs `cfg.sandbox` semantics
  across r2/rz versions remain unverified (research paper §10.2 note 7) — the
  scrubbed env and read-only ops are the primary hardening anyway.

## Phase 1 op scope (`ida_r2_*`)

All ops return the standard host envelope (`make_error` /
`is_error_result`). Resolved binary comes from a session reference (without
the runtime-alive / safe-mode-clear requirement — r2 only needs the raw file)
or a standalone `binary_path`.

| Op | Action | What it does |
|---|---|---|
| `ida_r2_status` | `status` | Engine availability feature-test (`rz -v`/`r2 -v`). No binary/session needed. |
| `ida_r2_bininfo` | `bininfo` | `rz-bin -Ij`/`-ej` metadata: filetype, arch, endian, bits, machine, entries. |
| `ida_r2_load_hints` | `load_hints` | bininfo + host-side raw-arch heuristics; explicit caller context wins. |
| `ida_r2_disassemble_hypothesis` | `disassemble_hypothesis` | rv32/rv64/thumb/metapc over one window + disagreement offsets. |
| `ida_r2_vxrefs` | `vxrefs` | Raw pointer-width LE/BE word scan for a target value (the `/v` gap). |

`vxrefs` is the Phase-1 answer to the research finding that IDA never creates
data xrefs for raw pointer tables in an un-analyzed blob. It scans the file
bytes with `bytes.find` (memchr-class), so unaligned occurrences are found, and
the auto-width mode prefers the pointer width with more hits.

`disassemble_hypothesis` is the "likely mis-decode" signal: the same bytes are
decoded under four ISAs and every offset where at least two decoders disagree
is reported. RISC-V hypotheses set no `asm.endian` variable (radare2's riscv
module hard-codes little-endian and rejects it).

## Wiring

- **Dispatch** — `server_dispatch.py` routes `tool_name == "r2"` to the host
  handler *before* the IDA fallthrough; without this branch the r2 tool would
  forward to IDA, which has no r2 backend. `r2/vxrefs` and
  `r2/disassemble_hypothesis` are `LONG_RUNNING_ACTIONS` (subprocess work).
- **Safe mode** — all five ops are read-only and are explicitly *allowed*
  while a session's IDA auto-analysis is still running.
- **Server** — `ServerR2Mixin` composes into `IDAMCPServer` ahead of the
  dispatch mixin.
- **Ops registration** — the public `ida_r2_*` agent ops are registered by
  WO-REG; the `r2` tool schema is already present in the tools catalog
  (`action`/`binary_path`/`addr`/`value`/`count`/`limit`).

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `IDA_MCP_R2_BIN` | `rz` → `r2` on PATH, else `r2` | Engine binary |
| `IDA_MCP_R2_BININFO_BIN` | `rz-bin` → `rabin2`, else `rabin2` | Metadata binary |
| `IDA_MCP_R2_TIMEOUT_SEC` | `30.0` | Per-one-shot wall-clock cap (seconds, min 1) |
| `IDA_MCP_R2_ESIL_MAX_STEPS` | `0` (unused in Phase 1) | Reserved for a future emulation op |
| `IDA_MCP_R2_PRE_ANALYSIS` | `true` | Reserved for a future load-time hook |
| `IDA_MCP_MEMORY_ROOT` | none | Optional allow-root for r2 targets |

## Error codes

`R2_ENGINE_START_FAILED`, `R2_TIMEOUT`, `R2_PROCESS_DIED` (runtime category),
and `R2_BINARY_NOT_FOUND` (user category, hint mentions the engine path). An
absent engine in `status` is *not* an error — it is `{ok: true,
available: false}`.

## Tests

- `tests/host/test_swarm_p09_r2_engine.py` — hermetic fake-r2 shim subprocess
  + contract tests. Runs in the base CI matrix with no r2 installed; the
  real-engine tests `skipif` no `rz`/`r2` is on PATH.
- `tests/host/test_safe_mode.py` — the r2 read ops are in the safe-mode
  *allowed* list.
- `.github/workflows/standalone-tests.yml` — optional job that `apt install`s
  `rz` and runs the r2 regression file against the real engine.

## Roadmap (Phases 2-5 deferred)

- **Phase 2** — r2-derived feedback into IDA *manually* (agent applies a
  candidate name/comment to the IDB via the existing `modify` tools). Still no
  r2 write path.
- **Phase 3** — r2 *read-only* ops on analyzed IDBs (using the session's
  architecture context against a *copy*/the raw file), still subprocess-only.
- **Phase 4** — optional interactive engine session (`r2 start`/`attach`) for
  human triage, classified `NETWORK_OR_PROCESS_ACTIONS` in the policy registry.
- **Phase 5** — emulation/ESIL op (if ever), only behind an optional extra,
  never touching the wheel and never importing unicorn into `ida_pro_mcp/**`.
