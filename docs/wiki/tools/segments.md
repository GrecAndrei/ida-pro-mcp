# Segments

Inspect and manage binary segments — their address ranges, permissions, and class.

| Operation | Purpose | Required |
| --- | --- | --- |
| `ida_list_segments()` | List all segments with name, address range, size, permissions, class, and bitness. | — |
| `ida_add_segment(start, end, name)` | Create a new segment. Optional: `sclass` (CODE/DATA/BSS/etc.). | `start`, `end`, `name`, `risk_ack` |
| `ida_set_segment_attrs(address)` | Update a segment's name, permissions (`rwx`/`r-x`/`rw-`), class, or bitness. `address` is any address inside the segment. | `address`, `risk_ack` |

## Working pattern

1. `ida_list_segments` to see the current segment map — useful for raw firmware
   where IDA may not have carved the correct regions.
2. `ida_add_segment` to define MMIO regions, ROM/RAM boundaries, or any range
   IDA did not create automatically.
3. `ida_set_segment_attrs` to fix up permissions or class on an existing segment
   (e.g. mark a data region as `r--` after confirming it is read-only).

## Notes

- Segment writes require `risk_ack: true`.
- `start` and `end` are hex strings (e.g. `"0x20000000"`, `"0x20010000"`).
- `sclass` values: `CODE`, `DATA`, `BSS`, `CONST`, `STACK`, `XTRN`.
- For firmware with a single flat ROM segment IDA will usually auto-create it;
  use these operations when you need to split it or add synthetic regions.
