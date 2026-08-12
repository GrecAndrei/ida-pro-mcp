# RISC-V raw-blob firmware recipe

How to open and analyze an opaque RISC-V firmware image — a headerless `.bin`
(raw flash dump, no ELF/PE headers) — with the `ida_*` operation surface, and
how the committed test fixture (`tests/fixtures/riscv_blob.bin`) exercises the
whole path.

An opaque RISC-V blob is the hard case: IDA's bin loader maps the file as one
flat segment at a guessed base, there is no loader metadata, no vector table
markup, no entry points, and the architecture is genuinely ambiguous on first
read. The recipe below walks the operations in dependency order and shows what
each returns on the fixture so you know what "sane" looks like.

## TL;DR

1. `ida_overview()` / `ida_session_state()` → the profile reports
   `file_kind: raw`, `raw_binary_mode: true`, a riscv-first candidate with an
   RV64 lean, and `inferred_load_base: 0x80000000` when the dominant lui/auipc
   hi20 resolves.
2. `ida_analysis(action="set_architecture", processor="riscv", bitness=64)`
   → switches the processor and emits RISC-V arch hints (incl. the GP note).
3. `ida_analysis(action="set_gp", gp="0x80002000")` → sets the global pointer
   so GP-relative xrefs resolve, queues reanalysis.
4. `ida_segments(action="sreg_set", start="0x80000000", reg="GP", value=...)`
   → same GP value via the segment-register seam (pick one; both write the
   same processor state).
5. `ida_analysis(action="add_entry", addr=..., ordinal=..., name=...)` →
   promote a bootstrapped reset-vector / ISR candidate to a real entry.
6. `ida_modify(action="create_data", addr=..., item_type="array", count=...)`
   and `ida_modify(action="create_strlit", addr=..., size=..., strtype="c")`
   → lay pointer arrays and string literals over the raw bytes so the blob
   becomes analyzable without redeclaring types.
7. `ida_disassemble` / `ida_decompile` on the seeded functions; `ida_r2_*`
   triage ops when the embedded disassembler needs a second opinion.

## Architecture inference on a raw blob

`ida_overview`'s `architecture_profile` (and the host helper
`infer_binary_arch_profile`) runs a magic-header check first (ELF/PE/Mach-O
return early), then falls into the raw path:

- **Cortex-M heuristic** — if the first 8 bytes look like a LE SP + Thumb
  reset vector (`0x2000xxxx` stack, odd reset vector), it guesses ARM/Thumb.
- **Opcode-density + embedding + validity scan** — otherwise it blends RV/ARM/
  MIPS opcode density, a byte-2gram embedding against arch prototypes, and an
  instruction-validity scan.  On the fixture this ranks **riscv/64 0.732**,
  riscv/32 0.366, mipsb 0.224, mipsl 0.222.
- **RISC-V gating** — RISC-V is only a candidate when the RV opcode density
  clears a floor and the instruction-validity ratio is high enough.  Without
  compressed (`-mattr=+c`) instructions, `ret` assembles to a 4-byte `jalr`
  and the RV density collapses below the floor, so the blob shadows to MIPS.
  The fixture therefore uses the C extension on purpose.
- **Bitness** — RV64 is inferred from aligned `ld`/`sd` (funct3 `0b011` on
  the 0x03/0x23 opcodes); RV32 from `lw`/`sw`.  A lopsided split (0.732 vs
  0.366) is a clear call and is **not** flagged `ambiguous`.
- **Load base** — the dominant hi20 of aligned `lui`/`auipc` words gives
  `load_base: 0x80000000`.  Compressed instructions shift `auipc` off
  alignment, so the fixture aligns the GP-init sites to keep the scan honest.

The profile is deliberately honest: `warning: "raw blob; arch unverified — set
architecture explicitly"` and `entrypoints_note` (no headers → no entry
points) are present so the agent does not trust the guess blindly.

### Vector table / load-base candidates (the WO-F1 seam)

The fixture's trap vector table at offset `0x08` holds six LE u32 absolute VAs
into the 0x80000000-linked image (`0x80000020`, `0x80000078`, `0x80000094`,
`0x80000058`, `0`, `0`).  These are the exact pointers
`ida_analysis(action="...")`'s entry bootstrap (`_bootstrap_raw_entry_points`)
and the sreg/data authoring ops consume:

- `add_entry` promotes a candidate to a real IDA entry (`ida_entry.add_entry`).
- `create_data(item_type="array")` lays 4 dwords over the table.
- `set_gp` / `sreg_set GP` make the GP-relative `lw`/`ld` in the ISRs resolve.

## Working pattern, step by step

### 1. Open the blob

```
ida_open_binary(binary_path="/path/to/fw.bin", processor="riscv", bitness=64, baseaddr="0x80000000")
```

For raw blobs, pass the base and arch hints up front when you already know
them; otherwise `ida_open_background` + `ida_session_status` and let the
profile guide the explicit `set_architecture` later.  On a genuinely opaque
blob the loader will not know the processor, so the explicit set is the
supported path.

### 2. Read the profile

`ida_overview()` returns `architecture_profile` with (on the fixture):

```
current:           processor metapc, bitness 32, endian little, file_type raw
raw_binary_mode:   true
inferred_from_binary:
  file_kind:       raw
  looks_like_code: true
  candidates[0]:   {processor: riscv, bitness: 64, confidence: 0.732}
  candidates[1]:   {processor: riscv, bitness: 32, confidence: 0.366}
  load_base:       0x80000000
  reason:          ... dominant lui/auipc base 0x80000000
inferred_load_base: 0x80000000
raw_binary_warning: raw blob; arch unverified ...
entrypoints_note:   no entry points detected (raw blob / no vector table) ...
```

`firmware_detected` (overview/state payload) derives from
`bool(raw_binary_mode)`; the state payload's fallback heuristic flags any
`file_type` in `{raw, unknown, bin, binary, obj}` or `file_type_id` in
`{0, 2, 17}`.

### 3. Set the architecture explicitly

```
ida_analysis(action="set_architecture", processor="riscv", bitness=64, endian="little")
```

Returns `{ok, applied: {processor: {value: riscv, previous: metapc, result: true},
bitness: 64, arch_hints: {ptr_size: 8, riscv_note: "RISC-V: GP (x3) unresolved?
run analysis(action='set_gp', gp=...) ..."}}}`.  The `riscv_note` is the 
wiki-recipe breadcrumb: set GP next.

### 4. Set the global pointer (GP, x3)

```
ida_analysis(action="set_gp", gp="0x80002000")
```

`set_gp` is RISC-V-only; on a non-RISC-V target it returns
`INVALID_ARGS`/`only valid for RISC-V`.  On success it persists the value in
a netnode so it survives IDB reload (reanalysis is queued only on the
GUI-directive path — see below).  The `_APPLIED_RISCV_GP` cache means a
re-apply is skipped after the first successful set this session.

**Headless behavior (verified live on 9.3 and 9.4, 2026-08-12):**
`idc.set_processor_options` does not exist in the idat runtime, and
`ida_idp.process_config_directive("gp=...")` is rejected by the RISC-V
plugin ("Illegal keyword"), so no processor-option mechanism is available.
Instead the tool **re-points the GP-relative data refs itself**: IDA decodes
GP-relative loads/stores as `o_displ` operands whose base is x3/GP and
creates data refs against an implicit GP of 0 — the raw sign-extended
displacement (e.g. `ld a3, -7FFFFFE0h` gains a ref to `0xffffffff80000020`
instead of `0x40`).  `set_gp` scans the segments, computes
`target = GP + disp` masked to the XLEN, and re-points each stale ref
(`ida_xref.del_dref` + `add_dref`, `dr_R` for loads / `dr_W` for stores).
Unmapped targets are skipped; existing correct refs (GUI-style resolution)
are left alone; changing GP cleans up the refs created for the previous
value.  The response reports `refs_fixed` / `refs_skipped`, and
`xrefs_to` / `ida_calc` then resolve correctly in headless sessions.

> **No sreg seam exists for GP** (verified live on 9.3/9.4): RISC-V
> registers zero segment registers (`ida_idp.get_sreg_names()` empty;
> `split_sreg_range`/`set_default_sreg_value_ea` reject x3 as "wrong
> segment register number"), so `ida_segments(action="sreg_set", reg="GP")
> ` errors out — the ARM-Thumb-style `T` seam does not apply to GP.  Use
> `set_gp` (above) instead.

`sreg_get` on an untouched register returns `value: BADSEL` (-1); `sreg_set`
on an unmapped address is rejected with `ADDRESS_NOT_MAPPED`.

### 5. Bootstrap entry points

For raw blobs with no entry points, `_bootstrap_raw_entry_points` scans the
image head: the reset-vector `j`/`jal` branch at offset 0 (or the
`auipc`+`jalr` long branch), then LE u32, BE u32, and LE u16 (compressed c.j)
ISR pointer tables.  On the fixture this seeds the reset handler
(`0x80000020`) plus the vector-table ISR targets (`0x80000078`,
`0x80000094`, `0x80000058`) as code, wraps them in functions, and registers
them via `ida_entry.add_entry`.

Promote one to a named entry:

```
ida_analysis(action="add_entry", addr="0x80000020", ordinal=1, name="reset")
```

### 6. Author data over the raw bytes

```
ida_modify(action="create_data", addr="0x80000008", item_type="array", count=4)
# -> {ok, item_type: array, count: 4, size: 16, end: 0x80000018}

ida_modify(action="create_strlit", addr="0x800000c5", size=6, strtype="c")
# -> {ok, size: 6, length: 6}
```

`create_data` item types: `byte|word|dword|qword|pointer|array` (`array` lays
`count` dword elements — ideal for a vector/MMIO table).  `create_strlit`
covers `[addr, addr+size)` with `strtype` `c|c16|c32`.  Unknown `item_type` /
missing `size` return `INVALID_ARGS`.

### 7. Triage with r2/rz when needed

For headerless blobs the `ida_r2_*` ops (bininfo, load hints) give a second
opinion on the base/size.  `bin.rawstr=true` and a forced base
(`-B 0x80000000`) make radare2 report the mapping the same way the arch
profile infers it.

## Fixture provenance

`tests/fixtures/riscv_blob.bin` is a **300-byte** RV64IMAC firmware slice
assembled with LLVM's integrated assembler.  It is the regression fixture for
the opaque-blob tests (`tests/ida_mcp/raw_blob_fake.py`,
`tests/ida_mcp/test_swarm_p11_opaque_raw.py`,
`tests/host/test_swarm_p12_opaque_raw.py`); a byte change invalidates those
tests' offset constants and inference-confidence assertions.

Layout (loaded at 0x80000000):

| Offset | Size | Contents |
| --- | --- | --- |
| 0x00 | 4 | Reset vector `j reset_handler` (`jal x0, +0x20` = `0x0200006f`) |
| 0x04 | 4 | Reserved (mtvec shadow) |
| 0x08 | 24 | Trap vector table: LE u32 `[0x80000020, 0x80000078, 0x80000094, 0x80000058, 0, 0]` |
| 0x20 | 20 | `reset_handler`: `auipc gp,0x80000; addi gp,gp,0; auipc ra,0; jalr ra,0xe(ra); j isr_default` |
| 0x34 | 36 | `main`: RV64 `ld`/`addw`/`sd` + `lui a1,0x10003` + `lw`/`sw` UART + `ret` |
| 0x58 | 32 | `isr_default`: GP init + UART write |
| 0x78 | 28 | `isr_timer`: GP init + RV64 `ld`/`sd` on mtime `0x02004000` |
| 0x94 | 16 | `isr_uart`: GP init + `lw` UART status |
| 0xA4+0x00 | 4 | rodata `uart_base` = `0x10003000` |
| 0xA4+0x04 | 8 | rodata `timer_reg` = `0x02004000` |
| 0xA4+0x0c | 16 | rodata `gpio_cfg` bytes |
| 0xA4+0x1c | 4 | `_fw_version` = `"v1.0"` |
| 0xA4+0x21 | 6 | `_msg` = `"RV64FW"` |
| 0xA4+0x40 | 64 | `hex_table` ASCII lookup |

SHA-256: `f3c9d855fae753d74297011ede7e93d77ff3c82ada9b99e6fa1bbd68e16cb074`

### Build recipe

Requires LLVM (`llvm-mc`, `llvm-objcopy`):

```
llvm-mc -triple=riscv64 -mattr=+c -filetype=obj -o riscv_blob.o riscv_blob.S
llvm-objcopy -O binary --only-section=.text riscv_blob.o text.bin
llvm-objcopy -O binary --only-section=.rodata riscv_blob.o rodata.bin
cat text.bin rodata.bin > tests/fixtures/riscv_blob.bin
```

Two gotchas that shaped the fixture:

1. **`-mattr=+c` is required** — without it `ret` assembles to a 4-byte
   `jalr` and the RV opcode density drops below the RISC-V gate, so inference
   returns a MIPS candidate instead.
2. **Extract `.text` and `.rodata` separately, then `cat`** — a multi-section
   `--only-section` run reorders output and puts rodata first.

Also note the alignment discipline: `auipc gp` sites inside `isr_timer` and
`isr_uart` are 4-byte aligned (via `.balign 4, 0` before the labels) so the
load-base hi20 scan sees them; compressed instructions would otherwise shift
them off-alignment and `load_base` would not resolve.

### Assembly source

The authoritative source is stored at build time in `/tmp/rvbuild/riscv_blob.S`
(not committed — the committed artifact is the `.bin`).  Full listing:

```asm
# riscv_blob.S -- RV64IMAC bare-metal firmware slice (raw .bin, no ELF header).
    .text
    .option norelax
    .globl _start

# Reset vector: the first instruction of the image.
_start:                                     # 0x00
    .option norvc
    j     reset_handler                     # reset-vector jal (jal x0) -> +0x20
    .option rvc
    .balign 4, 0
    .zero 4                                 # 0x04  reserved (mtvec shadow)

# Trap vector table: LE u32 absolute VAs into the 0x80000000-linked image.
_isr_table:                                 # 0x08
    .word 0x80000020                        # default trap handler  (reset_handler)
    .word 0x80000078                        # timer ISR             (isr_timer)
    .word 0x80000094                        # UART  ISR             (isr_uart)
    .word 0x80000058                        # spare                 (isr_default)
    .word 0                                 # reserved
    .word 0                                 # reserved

reset_handler:                              # 0x20
    auipc gp, 0x80000                       # GP init: hi20 0x80000000 (load base)
    addi  gp, gp, 0
    auipc ra, 0                             # auipc/jalr long-branch init
    jalr  ra, 0xe(ra)                       # 0x26 + 0xe = 0x34 -> main
    j     isr_default                       # fallback if main returns
    .balign 4, 0
    .zero 4                                 # 0x30  pad

main:                                       # 0x34
    addi  sp, sp, -16
    sd    ra, 8(sp)
    ld    a3, 0(gp)                         # RV64 gp-relative loads
    ld    a4, 8(gp)
    addw  a3, a3, a4
    sd    a3, 16(gp)
    lui   a1, 0x10003                       # UART0 base 0x10003000
    addi  a1, a1, 0
    lw    a2, 0(a1)                         # read UART status
    addi  a2, a2, 1
    sw    a2, 0(a1)                         # write UART data
    ld    ra, 8(sp)
    addi  sp, sp, 16
    ret                                     # c.jr ra

isr_default:                                # 0x58
    auipc gp, 0x80000
    addi  gp, gp, 0
    addi  sp, sp, -16
    sd    ra, 8(sp)
    lui   a0, 0x10003
    addi  a0, a0, 0
    li    a1, 0x58                          # 'X'
    sb    a1, 4(a0)
    ld    ra, 8(sp)
    addi  sp, sp, 16
    ret

    .balign 4, 0
isr_timer:                                  # 0x78
    auipc gp, 0x80000
    addi  gp, gp, 0
    addi  sp, sp, -16
    sd    ra, 8(sp)
    lui   a0, 0x2004                        # mtime base 0x02004000
    addi  a0, a0, 0
    ld    a1, 0(a0)                         # RV64 load
    addi  a1, a1, 1
    sd    a1, 0(a0)                         # RV64 store
    ld    ra, 8(sp)
    addi  sp, sp, 16
    ret

    .balign 4, 0
isr_uart:                                   # 0x94
    auipc gp, 0x80000
    addi  gp, gp, 0
    lui   a0, 0x10003
    addi  a0, a0, 0
    lw    a1, 0(a0)
    ret

    .section .rodata
uart_base:                                  # 0x00
    .word 0x10003000
timer_reg:                                  # 0x04
    .dword 0x02004000
gpio_cfg:                                   # 0x0c
    .byte 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    .byte 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
_fw_version:                                # 0x1c
    .asciz "v1.0"
_msg:                                       # 0x21
    .asciz "RV64FW"
    .balign 8, 0
    .space 32                               # reserved config flash
hex_table:                                  # 0x40
    .ascii "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

## Related

- [Segments](tools/segments.md) — segment-register (sreg) seam, GP round-trip
- [Workflow](tools/workflow.md) — `batch`, `reanalyze`
- [LIVE_IDA_TESTING](../LIVE_IDA_TESTING.md) — when you need a live IDA runtime
