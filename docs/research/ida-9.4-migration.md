# IDA 9.4 Migration Tracking

Status: **in progress** (started 2026-08-11)
Target release: IDA 9.4 (build 9.4.260714, July 14 2026)

## Sources of truth

- Release notes: `docs.hex-rays.com/release-notes/9_4` (local PDF copy in
  `<ida-docs>/docs.hex-rays.com-IDA 94 Hex-Rays Docs.pdf`)
- SDK: `https://github.com/HexRaysSA/ida-sdk` cloned at `~/ida-sdk`,
  HEAD == `IDA_SDK_VERSION 940`, tag `v9.4.0-release`. The full `include/`,
  `module/`, `ldr/`, `plugins/`, `idalib/` trees are now public.
  Note: RISC-V / Hexagon / MCore / TriCore processor modules are **not**
  open-sourced — they ship only as compiled `.so` inside the IDA install.
- API surface diff: derived from `~/ida-pro-9.3/python/ida_*.py` vs
  `~/ida-pro-9.4/python/ida_*.py` (IDAPython is the contract our tools
  actually call).

## Environment

- IDA 9.4 and 9.3 installed side by side.
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
- [x] Function-comment family — turned out to be a non-issue:
      `idc.get_func_cmt`/`idc.set_func_cmt` are already EA-based and NOT
      deprecated in 9.4 (no `_ida_deprecated` marker in idc.py). The only
      real sites were `ida_funcs.update_func` ×2 in funcs.py, migrated to
      the `_compat.get_func_flags` + `_compat.set_func_flags` composition
      (9.4's `set_func_flags(ea, flags)` is the EA replacement)
- [x] **`get_func` epic** — DONE (2026-08-11, three delegated batches):
      ~168 of ~193 call sites migrated to `_compat.get_func_start` /
      `get_func_info` / `get_func_flags` across all 26 files, incl.
      `error_handling.py` (guarded import keeps host-side pure-stdlib
      loadability) and the `_get_prev_func`/`_get_next_func` helpers in
      code_helpers.py (now EA-or-None on all versions). **25 sites remain
      legacy by design** — they hold `func_t *` across a boundary:
      FlowChart ×7 (graph 324/403, code_helpers 1221/1414/1433, code 837,
      combinators 828), get_prototype ×8 (code 369/380/887, data 186,
      funcs 592/663, annotation 487/527, code 554), get_frame ×1
      (code_helpers 1256), frame helpers ×2 (stack_analysis 129,
      utils 476 — read `.frame`), thunk path ×1 (code 453 — `.flags` +
      `calc_thunk_func_target`, itself deprecated), internal signature ×1
      (code 1454 `_trace_argument_origin` — tests pin the func-object
      param), FlowChart/metadata ×3 (intelligence 502/640/851), and
      utils.py:281 (`fn.get_name()` method call). These need a
      FlowChart/frame/prototype/thunk API audit — a separate batch.
- [x] **`func_t`-holding remnant audit** — DONE (2026-08-11): every audit
      target had an answer. FlowChart accepts an `ea_range_t` in place of
      `func_t *` on all versions (precedent: `graph._build_range_chart`) →
      `_compat.get_flow_chart(ea)`. `calc_thunk_func_target` → 9.4
      `calc_thunk_function_target(fi)` → `_compat.calc_thunk_target(ea)`.
      `ida_frame.get_spd` → `get_func_spd(func_ea, ea)` → `_compat.get_spd`.
      `pfn.frame` → `func_entry_info_t.get_frame_id()` → `_compat.get_frame_id`.
      Our own `utils.get_prototype(fn)` → `_compat.get_prototype_string(ea)`.
      `fn.get_name()`/`func.size()` were plain EA-derivable. All 25 sites
      migrated; the only func_t-bound code left is the struc-based frame
      member walk (code_helpers `ida_funcs.get_frame`, stack_analysis
      `_get_frame_or_error`) — 9.4 REMOVED `ida_frame.get_frame` outright,
      so that path needs a `get_func_frame_ea` + tinfo/udt member
      iteration rewrite (both sites degrade gracefully today).
- [x] **tinfo-based stack-frame walk** — DONE (2026-08-11): `_compat.frame_members(func_ea)` / `_compat.frame_size(func_ea)` replaced the last `ida_frame.get_frame` (removed in 9.4) / `ida_struct` (module gone) sites. 9.4 path: `ida_frame.get_func_frame_ea(tif, func_ea)` → `udt_type_data_t` walk (gaps skipped, bit→byte normalization) + `get_frame_size_ea`. Legacy path mirrors both old call sites exactly: frame via `ida_frame.get_frame` → `ida_funcs.get_frame` → `idc.get_frame_id`+`ida_struct.get_struc`; members via the canonical `struc_t.members` list (NOT `get_member(i)` — that takes a byte offset); names via `ida_frame` → `ida_struct` → `idc` `get_member_name`; sizes via `get_member_size` → `member.size` → `eoff-soff`. stack_analysis.py (all 10 actions) and code_helpers.py migrated; 3 new compat dispatch tests. `types.py` struct editing was already 9.4-ready (tinfo `add_udm`/`del_udm`/`rename_udm`/`set_udm_type` fallbacks gated by `_has_classic_struct_api()`).
- [x] `ida_list_strings` behavior check on 9.4 — DONE (2026-08-12): the
      string-list API is unchanged (`get_strlist_qty`/`get_strlist_item`
      verified live on the 9.4 runtime; neither is deprecated). 9.4 adds
      `get_strlist_item_ex(string_info_ex_t)` with the
      `decompiler_string` field — decompiler-recovered strings land in the
      list lazily per decompiled function, so string counts may grow after
      decompilation. No code change needed; watch the summary counts.
- [x] RISC-V validation — DONE (2026-08-12, live headless 9.3 vs 9.4 on
      `tests/fixtures/riscv_blob.bin`): instruction decode is byte-identical
      except the documented `c.` prefix for compressed instructions
      (`c.mv`/`c.j`/`c.addi`/`c.sd`/`c.lw`/`c.sw`/`c.ld`/`c.ret`/`c.addw`).
      `auipc gp, 80000h` still decodes as auipc + mv (no over-merge);
      lui-based `%hi/%lo` constant recovery resolves identically.
      **Finding + fix:** the processor-option mechanism does not exist in
      idat (`idc.set_processor_options` absent on 9.3/9.4, probed 7 modules
      each; `ida_idp.process_config_directive("gp=...")` is rejected by the
      plugin with "Illegal keyword"; the sreg seams
      (`split_sreg_range`, 9.4 `set_default_sreg_value_ea`) return False for
      GP because x3 is not a segment register).  The plugin therefore
      creates GP-relative data refs against an implicit GP of 0 — the raw
      sign-extended displacement (`ld a3, -7FFFFFE0h` → ref to
      0xffffffff80000020 instead of 0x40).  Implemented
      `arch_utils._riscv_gp_fix_refs()`: scans segments for `o_displ`
      operands whose base is x3/GP, computes `target = GP + disp` (XLEN
      mask), and re-points the stale refs via `ida_xref.del_dref` +
      `add_dref` (`dr_R` loads / `dr_W` stores); unmapped targets skipped,
      existing correct refs untouched, refs from a previous GP value
      cleaned.  `set_gp`/`set_riscv_gp` now report `refs_fixed` /
      `refs_skipped`; reanalysis is only queued on the (GUI-only)
      directive path.  **Validated live on BOTH 9.4 and 9.3**: 3 fixture
      refs re-pointed 0x40/0x48/0x50, `xrefs_to` resolves, GP re-set moves
      them and cleans the stale ones.
- [x] **`get_arch()` regression found during GP work** (2026-08-12):
      `idaapi.get_inf_structure` was removed in 9.4, so `get_arch()` (and
      every arch-gated behavior) silently returned "unknown" on 9.4 —
      missed by the earlier disasm validation because it never exercised
      the inf API.  Fixed: `_proc_name_and_bitness()` prefers
      `ida_ida.inf_get_procname`/`inf_get_app_bitness` (present in 9.3 and
      9.4), falls back to the legacy structure and finally
      `idc.get_inf_attr(INF_PROCNAME)`; confirmed live (`riscv` →
      `riscv64`).
- [x] `memory_model` open-binary option — RESOLVED (2026-08-12): IDA 9.x
      removed the memory-model attribute from the API (no
      `ida_ida.inf_set_mtype`, no `idc.INF_MTYPE`, no `idainfo.mtype`;
      the MT_* constants are gone — verified live on both 9.3 and 9.4).
      `server_script._apply_pre_analysis_options` now maps the documented
      host encoding (0=flat, 1=16-bit segmented, 2=32-bit segmented) to
      the old MT_* values (MT_FLAT=6 / MT_16=3 / MT_32=4) and applies it
      only if a future IDA reintroduces `inf_set_mtype`, otherwise emits
      an explicit warning instead of silently dropping it.  The
      `processor_options` pre-analysis path also gained the
      `ida_idp.process_config_directive` fallback (the only
      processor-option API present in the idat runtime on 9.3/9.4).
- [x] Evaluate `ida_indexer` for `ida_find` / query-lang — DONE
      (2026-08-12), **not adopted**: `ida.cfg` documents
      `ENABLE_INDEXER = YES // Enabled by default but disabled under batch
      mode`, and our runtime is batch mode — live probe on 9.4 confirms
      `indexer_is_enabled() == False` and `indexer_match_all` returns None.
      The indexer is the Jump Anywhere GUI backend; the linear scans in
      `tools/search/` remain the right implementation for headless MCP.
- [x] Evaluate idalib `execute_sync()` runtime — DONE (2026-08-12),
      **not adopted**; design doc at `docs/research/idalib-runtime.md`
      with verified facts (idapro whl, `open_database`/`close_database`
      surface, activation script, undo-point value) and the future port's
      acceptance criteria. Spawn-idat stays default: crash isolation,
      9.2 floor, license simplicity, and the live integration suite passes
      on both 9.3 and 9.4.
- [x] Installer: align Python detection with 9.4's uv/conda/homebrew
      support — DONE (2026-08-12): `installer/runtime.py` gains
      `python_environment_kind()` (uv/conda/homebrew/pyenv/asdf/system,
      path+env based); `main.py` warns on 9.4+ installs when the venv
      builder runs on a managed interpreter, and records `python_kind` in
      the report. Host unit test added.
- [x] CI matrix: run the suite against both 9.3 and 9.4 runtimes — DONE
      (2026-08-12): `scripts/run_ida_matrix.py` discovers every install
      (installer discovery) and runs `tests/integration` per install with
      IDA_DIR pinned; `.github/workflows/ida-runtime-matrix.yml` is a
      self-hosted-only `workflow_dispatch` job (guard-tested) since
      licensed IDA cannot be provisioned on GitHub-hosted runners.
      **Validated live: 42 passed / 8 skipped on BOTH 9.3.260421 and
      9.4.260714.**
- [x] **Bonus bug found during validation** (2026-08-12): `modify.py`
      `create_strlit` passed `ea + size` (an end address) as the *length*
      argument to `ida_bytes.create_strlit(start, len, strtype)` — on real
      IDA this defines a string spanning to the segment end (verified
      live: a 6-byte request created a 64-byte string) or fails outright.
      Fixed to pass `size`; test fakes (p03, p11, raw_blob_fake) updated
      to model the real signature. Version-agnostic, surfaced by 9.4
      validation.

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
  **Attribute-reading sites — now migrated (2026-08-11):**
  `_compat.get_segment_perm/type/align/bitness(ea)` accessors were added
  (9.4: `segment_info_t.get_*()` methods; 9.3: `segment_t` attributes) and
  all pure attribute-read sites moved over: code_helpers.py (1149/1319/
  1427), idb.py (275/448), memory.py (173), modify.py (54), search/core.py
  `iter_segments`, gadgets.py ×5, analysis.py ×3, data.py:372, types.py:52,
  graph.py:49/71, calc.py:652/679, firmware.py:706, and 8 segments.py
  read sites.   `get_segm_by_name` HAS a sanctioned 9.4
  replacement — `get_segment_ea_by_name(name)` (returns start EA, BADADDR on
  miss); the wrapper unwraps BADADDR back to None.
  **Mutation sites — now migrated (2026-08-11):** `update_segm` turned out
  NOT to be deprecated, and `segment_info_t` has a full `set_*` surface
  (incl. `set_comb`/`set_color`), so `_compat.set_segment_attr` stages
  setters + commits via `set_segment_info` on 9.4 and keeps
  setattr+`update_segm` on <= 9.3; `_compat.add_segment` likewise wraps
  `add_segment_ex(segment_info_t)` / `add_segm_ex(segment_t)`. This closed
  the last five `getseg` sites (`_find_segment`, `set_attr`, `set_perms`,
  `move`), both `add_segm_ex` sites (segments.add, firmware.carve) and the
  `move_segm` site. A repo-wide sweep over all 118 deprecated names now
  finds zero real call sites outside compat.py (remaining regex matches:
  `idc.get_func_cmt`/`idc.get_segm_name`/`idc.get_type`, which are
  EA-based and NOT deprecated — the deprecated entries are the
  pointer-based `ida_funcs`/`ida_segment` spellings — plus `tinfo_t`
  constructors and local variables named `func`).
- **`get_first_seg`/`get_next_seg` caveat.** The task premise stated these were
  not deprecated, but they DO appear in the authoritative list
  (`<scratch>/ida94_deprecated.txt` lines 37/56) and the 9.4 stub keeps them with
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
