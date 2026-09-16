# Segments

Inspect and manage binary segments and architecture segment registers.

Segments define memory layout, address ranges, permissions, and classes (e.g. CODE, DATA, BSS).
Segment registers govern memory addressing modes on segmented architectures (x86 `CS`/`DS`, ARM `T`, RISC-V `GP`).

---

## Operations Overview

| Operation | Purpose | Required Arguments |
| --- | --- | --- |
| `ida_list_segments` | List all segments with name, address range, size, permissions, class, and bitness. | — |
| `ida_add_segment(start, end, name)` | Create a new segment. Optional: `sclass` (`CODE`, `DATA`, `BSS`, `CONST`, `STACK`, `XTRN`). | `start`, `end`, `name`, `risk_ack` |
| `ida_set_segment_attrs(address, attr, value)` | Update one segment attribute: `name`, `align`, `comb`, `perm`, `bitness`, `type`, or `color`. | `address`, `attr`, `value`, `risk_ack` |
| `ida_sreg_get(start, reg)` | Read the current segment-register value mapping for a code address. | `start`, `reg` |
| `ida_sreg_list(start)` | List the segment-register mappings and change points in effect for an address. | `start` |
| `ida_sreg_set(start, reg, value)` | Set the segment-register mapping for a code address or range. | `start`, `reg`, `value`, `risk_ack` |

---

## 1. Managing Memory Segments

### Listing Segments

```json
{"name": "ida_list_segments"}
```

Returns segment names, start/end addresses, permissions (e.g. `"r-x"`, `"rw-"`), class, and bitness (16/32/64).

### Defining New Segments

When analyzing raw firmware blobs or carving MMIO peripheral memory regions that IDA did not automatically map:

```json
{
  "start": "0x40000000",
  "end": "0x40010000",
  "name": "MMIO_UART",
  "sclass": "DATA",
  "risk_ack": true
}
```

### Changing Segment Permissions & Attributes

To mark a segment read-only or change its alignment:

```json
{
  "address": "0x40000000",
  "attr": "perm",
  "value": "r--",
  "risk_ack": true
}
```

Supported attributes: `perm`, `name`, `align`, `comb`, `bitness`, `type`, `color`.

---

## 2. Segment Registers (`sreg_*`)

On architectures with mode-switching or register-relative addressing:

- **ARM / Thumb mode**: The `T` register toggles between ARM (0) and Thumb (1) instruction decoding.
- **x86 segmented mode**: `CS`, `DS`, `ES`, `FS`, `GS`, `SS` selectors.
- **RISC-V Global Pointer (GP)**: Sets the base address for GP-relative offsets (`x3`).

### Reading and Listing Segment Registers

- `ida_sreg_get(start="0x1000", reg="T")`: Returns the selector value at address `0x1000`.
- `ida_sreg_list(start="0x1000")`: Lists all registered segment register values for the range.

### Setting Segment Registers

```json
{
  "start": "0x1000",
  "end": "0x2000",
  "reg": "T",
  "value": 1,
  "risk_ack": true
}
```

After modifying segment registers, IDA queues reanalysis for the affected region so instructions and cross-references disassemble correctly.
