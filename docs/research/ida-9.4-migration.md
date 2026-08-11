# IDA 9.4 Migration Tracking

Status: **in progress** (started 2026-08-11)
Target release: IDA 9.4 (build 9.4.260714, July 14 2026)

## Sources of truth

- Release notes: `docs.hex-rays.com/release-notes/9_4` (local PDF copy in
  `~/Downloads/docs.hex-rays.com-IDA 94 Hex-Rays Docs.pdf`)
- SDK: `https://github.com/HexRaysSA/ida-sdk` cloned at `~/ida-sdk`,
  HEAD == `IDA_SDK_VERSION 940`, tag `v9.4.0-release`. The full `include/`,
  `module/`, `ldr/`, `plugins/`, `idalib/` trees are now public.
  Note: RISC-V / Hexagon / MCore / TriCore processor modules are **not**
  open-sourced — they ship only as compiled `.so` inside the IDA install.
- API surface diff: derived from `~/ida-pro-9.3/python/ida_*.py` vs
  `~/ida-pro-9.4/python/ida_*.py` (IDAPython is the contract our tools
  actually call).

## Environment

- `~/ida-pro-9.4` and `~/ida-pro-9.3` installed side by side.
- Installer discovery verified on 9.4: `detect_ida_installs()` reports
  `IDA 9.4.260714.951e98a4 pro (x64)` — version parsing works unchanged.

## What 9.4 changes for this project

### Deprecations (the bulk of the work)

IDAPython 9.4 introduces `_ida_deprecated` machinery and marks **118
functions** deprecated. Old names still work but emit one
`DeprecationWarning` per process each. The replacements are **EA-based
APIs that avoid returning IDA-allocated pointers** — this is a semantic
change, not a rename: instead of `get_func(ea)` handing back a `func_t *`
to poke at, you ask for exactly what you need (`get_func_start(ea)`,
`get_func_entry_info`, iterators like `function_item_iterator_t`).

All EA-based replacements are **9.4-only** (verified absent from the 9.3
`python/` tree).

Call sites in `ida_mcp/` hitting deprecated APIs (~300 total):

| sites | deprecated | 9.4 replacement |
|------:|------------|-----------------|
|   193 | `ida_funcs.get_func` | `get_func_start` / `get_func_entry_info` |
|    46 | `ida_segment.getseg` | `get_segment_info` (7 sites migrated 2026-08-11; the rest read `segment_t` attrs `segment_info_t` lacks and stay on the legacy call) |
|    29 | `ida_segment.get_segm_name` | `get_segment_name` (25 sites migrated 2026-08-11) |
|  13+5 | `ida_funcs.get_func_cmt` / `set_func_cmt` | EA variants |
|     3 | `ida_hexrays.decompile_func` | `decompile_function` |
|   ~10 | segment/frame/hidden-range misc (`get_spd`, `add_segm_ex`, `move_segm`, `get_next_seg`, `calc_thunk_func_target`, `tinfo_t.get_func_frame`, ...) | EA variants |

### New API surface worth adopting

- **`ida_indexer`** (new module, 33 symbols) — the Jump Anywhere backend.
  Candidate to power `ida_find` / query-lang with a maintained native index
  instead of our linear scans in `tools/search/basic.py`.
- **`ida_dscu`** (new module, 265 symbols) — programmatic access to the new
  Dyld Shared Cache infrastructure (`dscu.h` in the SDK).
- `ida_loader.import_module()` now officially exposed (we already call it).
- `ida_lines.add_sourcefiles()` batch API + `get_sourcefile_by_ea()` —
  pairs with the new compilation-unit function folders; our opaque-blob
  loader path could attach CU structure.
- `ida_funcs`: `set_func_flag()`, `get_prev/next_function_addr()`,
  `set_function_name_if_jumpfunc()`, `add_regarg_ea()`, function iterators,
  `FUNC_OUTLINE` for processor-marked outlined functions.
- New IDP events: `ev_query_unmapped_address`, `ev_load_unmapped_address`,
  `ev_sanitize_name`, `ev_should_handle_switch`, `ev_get_stkarg_parts`;
  `codegen_t::should_handle_switch()` hook.
- `ida_strlist.get_strlist_item_ex` / `string_info_ex_t` with
  `decompiler_string` field — **decompiler-recovered strings now land in the
  strings list** (lazily, per decompiled function). Watch `ida_list_strings`
  semantics on 9.4.

### Behavioral changes to validate

- **RISC-V**: `auipc` no longer merged too eagerly (our GP/constant-recovery
  workaround territory), "a bunch of decoding bugs", pair-operand handling,
  RV64 `ADDIW` sign-extension, `c.addiw rd=x0`, `c.` prefix printing,
  Zcmp/Zcmt/Zclsd + Hazard3 (RP2350) + Soteria extensions, `shXadd`
  jump-table detection, decompiler microcode spec fixes, GDB-backend RISC-V
  debugging. Nothing about raw-blob arch detection or automatic GP setup —
  **our inference layer stays load-bearing** for headerless blobs.
- **Decompiler quality (free upgrades)**: memcpy→assignment folding,
  better UDT/array arg recognition, phi-diamond→if/else, `Edit type...`.
- **Rust/Go/Swift**: rustc version + crates in header, `CM_CC_RUST`,
  Go pclntab for PIE ELF, Swift ABI recognition (`__swiftself`,
  `__swiftthrows`, `__swiftasync`).
- **Performance**: faster frame analysis, xref write cache, DWARF loading.

### Runtime-model options (evaluate, don't adopt blindly)

- **idalib grew up**: `execute_sync()` + async event processing,
  auto-activation at install, bundled with IDA Home, database flush on
  exit, `gen_disasm_text` revived. This is the missing piece that made
  idalib unsuitable as our runtime. Long-term alternative to the
  spawn-`idat`-per-session model (`server_runtime.py`, `sync.py`'s
  execute_sync marshaling). Needs a design doc before any porting.
- **IDA Domain API v0.5.0**: microcode + pseudocode access, object
  store/retrieve. An alternative stable surface to track.
- `idat -Ohexrays:-Dname=value` — decompiler defines from CLI for spawned
  runtimes.
- IDAPython now detects uv/anaconda/homebrew Pythons and warns on
  libpython/venv mismatch — align `installer/runtime.py` (currently no
  uv/conda awareness) instead of keeping parallel logic.
- Fixed: "a failed ida_* module import made all of IDAPython unusable",
  `gen_microcode()` memory leak.

## Compat strategy (decided 2026-08-11)

The installer detects installs and the user picks one; the runtime runs
inside that install and knows its kernel version (`sync.py` already parses
`ida_major`/`ida_minor`). So compatibility is **runtime branching against
the selected install**, not a floor bump — 9.2/9.3 keep working.

Implementation: `src/ida_pro_mcp/ida_mcp/compat.py` feature-detects each
API family once at import (`hasattr`, self-heals across point releases) and
exposes wrappers preserving the old call contracts. Call sites migrate
family by family. When the floor eventually rises to 9.4, the wrappers
collapse to direct calls and the module is deleted.

## Work items

- [x] Verify installer detection against 9.4 (works, no changes needed)
- [x] Clone SDK, confirm `v9.4.0-release`, diff IDAPython surface
- [x] `ida_mcp/compat.py` skeleton + capability flags
- [x] Migrate `decompile_func` → `decompile_function` (3 sites:
      `utils.refresh_decompiler_ctext`, `code_helpers` incl. its retry
      path) — the worked example; `tests/ida_mcp/test_compat.py` pins
      selection on both fake surfaces
- [x] Segment getters family (`getseg`, `get_segm_name`, `get_segm_class`,
      `set_segm_name`, `move_segm`, `get_segm_by_name`, `add_segm_ex`) —
      compat wrappers + 37 migrated call sites across 13 tool files
      (details below); `get_first_seg`/`get_next_seg` are NOT migrated in
      this pass (see note) and `add_segm_ex`/`move_segm` have no
      `ida_segment.`-prefixed call sites
- [ ] Function-comment family (`get_func_cmt`, `set_func_cmt`,
      `update_func`) — ~20 sites
- [ ] **`get_func` epic** — 193 sites; not mechanical: sites that only need
      `start_ea` go to `get_func_start`; sites holding `func_t *` need
      `get_func_entry_info` / iterators. Wrapper must preserve the
      `None` vs `BADADDR` contract (`get_func` returns `None`;
      `get_func_start` returns `BADADDR`).
- [ ] `ida_list_strings` behavior check on 9.4 (decompiler strings now
      included lazily)
- [ ] RISC-V validation: run `tests/fixtures/riscv_blob.bin` (and a real
      firmware) through 9.4; confirm the auipc/decoding fixes; document
      which of our workarounds are still needed
- [ ] Evaluate `ida_indexer` for `ida_find` / query-lang
- [ ] Evaluate idalib `execute_sync()` runtime (design doc first)
- [ ] Installer: align Python detection with 9.4's uv/conda/homebrew
      support
- [ ] CI matrix: run the suite against both 9.3 and 9.4 runtimes

## Notes

- **Segment getters family — what was actually migrated (2026-08-11).**
  `ida_mcp/compat.py` gained `get_segment(ea)`, `get_segment_name(ea, flags)`,
  `get_segment_class(ea)`, `set_segment_name(ea, name, flags)`,
  `move_segment(ea, to, flags)`, and `get_segment_ea_by_name(name)` — all
  feature-detected off `HAS_EA_SEGMENT`, all preserving None-on-miss. Migrated
  37 `ida_segment.`-prefixed call sites: 26 `get_segm_name`, 4
  `get_segm_class`, 1 `set_segm_name`, 1 `get_segm_by_name`, plus 4
  `getseg`→`get_segment` (imports_deep ×3, idb_summary comment count) and 1
  `getseg`+`get_segm_name` collapse (code_helpers shellcode-prologue check).
  **Left on the legacy call (audit rule — the returned object's `segment_t`
  attributes that the surrounding code reads do not exist on
  `segment_info_t`, which exposes its fields only via `get_*()` methods, not
  properties):** `code_helpers.py` getseg at 1149/1319/1427 and `idb.py` getseg
  at 275/448 and `memory.py`/`modify.py` getseg — all read `.perm` (or
  `.type`/`.align`/`.bitness`). `get_segm_by_name` HAS a sanctioned 9.4
  replacement — `get_segment_ea_by_name(name)` (returns start EA, BADADDR on
  miss); the wrapper unwraps BADADDR back to None. `add_segm_ex` has a
  replacement (`add_segment_ex(si: segment_info_t)`) but the only call sites
  (segments.py add, firmware.py carve) use the `idaapi.add_segm_ex` spelling
  and read `seg.perm` after the call, so they were left for a later pass;
  `move_segm` similarly has only `idaapi.move_segm` call sites.
- **`get_first_seg`/`get_next_seg` caveat.** The task premise stated these were
  not deprecated, but they DO appear in the authoritative list
  (`/tmp/ida94_deprecated.txt` lines 37/56) and the 9.4 stub keeps them with
  EA replacements `get_first_segment_ea()`/`get_next_segment_ea(ea)`.
  **Follow-up landed (2026-08-11):** compat gained `get_first_segment_ea()` /
  `get_next_segment_ea(ea)` wrappers (BADADDR→None normalized) and
  `funcs.py::_try_map_raw_runtime_addr` was migrated. `search/core.py:352`
  (`iter_segments`) was NOT migrated: its loop reads `.perm` off the same
  descriptor, so it belongs to the deferred segment-attribute batch below.
- **Compat wrappers resolve `ida_segment` via `sys.modules` at call time**
  (`_ida_segment()` helper), not the import-time global. The host test harness
  swaps `sys.modules["ida_segment"]` per test while `compat` can stay cached
  (imported during test collection, e.g. via test_swarm_t11's module-level
  `intelligence` load, so it lands in the conftest's frozen session snapshot);
  a stale global made the legacy fallbacks hit the wrong module.
- **Test updates alongside the migration (AGENTS.md: update tests with the
  behavior change):** the compat `get_segment_name` legacy fallback calls
  `get_segm_name(seg, flags)` — matching the real IDA signature — and
  re-fetches via `ida_segment.getseg`, so test mocks that mocked
  `ida_segment.get_segm_name`/`idaapi.getseg` but not `ida_segment.getseg`
  (or used 1-arg `get_segm_name` lambdas) were updated: raw_blob_fake.py and
  the p02/p07/p13/p14/q05a/t07/t08/t09/t14 swarm tests. The host test
  `test_auto_reanalyze_text_segments.py` execs live `analysis.py` helper
  source, so its namespace gained a `_compat` stub mirroring the legacy
  fallback.
- The earlier `~/Downloads/ida-sdk-linux.tar.gz` is the SDK repo's CI-built
  sample binaries (their CI "splits release assets per component"), not the
  SDK itself — the GitHub clone supersedes it.
