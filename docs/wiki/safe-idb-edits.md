# Safe IDB edits and rollback

IDB mutations persist in the database. Every public operation that mutates the
IDB requires `risk_ack: true`, and operator policy can deny a call even when
the acknowledgement is present. Findings are stored in the separate
investigation workspace. Treat the acknowledgement as an explicit review
boundary, not a way to bypass policy.

## Prefer reversible analysis first

Before changing the IDB:

1. Read the target with `ida_decompile`, `ida_disassemble`, and references.
2. Verify the address and current name or bytes.
3. Record the reasoning in a finding.
4. Take a named snapshot for experiments.
5. Make the smallest change.
6. Re-read the result and save the IDB if the change is intended.

A snapshot can be created with `ida_idb_snapshot(name="...")`. Restore with
`ida_idb_restore_snapshot`, passing the returned `snapshot_id` or an
`ordinal` (`0` is the most recent snapshot). The undo-history fallback restores
in LIFO order.

## Common reviewed edits

- `ida_rename` for a reviewed symbol name;
- `ida_comment` for a local explanation;
- `ida_rename_local` for a decompiler local;
- `ida_apply_type` or `ida_declare_type` only after inspecting the existing
  type information;
- `ida_publish_findings` for reviewed, confirmed workspace conclusions.

Publishing does not overwrite a name someone else applied through the normal
publish path, but direct rename operations still change the IDB directly.

## Group a change

For a batch that should be treated as one unit, bracket it with
`ida_undo_begin` and `ida_undo_end`. The response reports the mechanism used;
on IDA 9.x the implementation may use an undo point rather than the older
transaction API.

If a mutation fails part way through, stop and inspect the IDB before trying
again. For experiments, restore the snapshot rather than attempting to
reconstruct several edits manually.

## High-risk operations

Be especially careful with:

- `ida_patch_bytes`, which changes bytes in the IDB and is not undone through
  the MCP surface;
- `ida_undefine`, which clears annotations across a range;
- function boundary and code/data interpretation changes;
- type and segment changes that alter later analysis;
- `ida_close_session`, which tears down the live IDA session;
- `ida_publish_findings`, when it would add names or comments at scale.

Verify raw bytes with `ida_read_bytes` before and after a patch. Use a snapshot
before destructive reinterpretation. After an intentional mutation, use
`ida_save_idb` so the work is not lost if IDA exits.

## A rollback sequence

For an experiment, make the rollback point explicit:

```text
ida_idb_snapshot(name="before_experiment", risk_ack=true)
ida_undo_begin(risk_ack=true)
ida_rename(address="0x401000", name="reviewed_name", risk_ack=true)
ida_comment(address="0x401000", comment="reviewed note", risk_ack=true)
ida_undo_end(risk_ack=true)
ida_decompile(address="0x401000")
ida_idb_restore_snapshot(snapshot_id="before_experiment", risk_ack=true)
```

The restore call is itself destructive and requires acknowledgement. Snapshot
restore uses the IDA snapshot mechanism where available; the idalib fallback
uses the undo history, so use the returned snapshot information and do not
assume that an ordinal has the same meaning across runtime modes. There is no
per-patch undo operation exposed through the MCP surface. Take a snapshot and,
where appropriate, keep an external copy of the original IDB before patching.

## Policy

The operator baseline is controlled by `IDA_MCP_POLICY_MODE` or
`~/.config/ida-pro-mcp/policy.json`. A session may tighten policy, but it cannot
relax the operator's setting. See the maintained
[safety model](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/guide/safety-model.md)
for trust-boundary detail.

References: [generated edit-operation reference](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/TOOLS_REFERENCE.md),
[IDA-side edit implementation](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/src/ida_pro_mcp/ida_mcp/tools/modify.py).
