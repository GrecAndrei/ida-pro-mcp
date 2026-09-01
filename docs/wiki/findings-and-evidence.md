# Findings, evidence, and conflicts

The investigation workspace is persistent and binary-scoped. Within the
configured workspace, sessions for a byte-identical binary use the same
SHA-256-keyed store, so a finding can outlive one MCP connection or one IDA
runtime. A changed binary is a different analysis target; stale-code handling
applies when the code at an existing address changes.

## Write useful claims

A useful finding says what was observed and how strongly it is supported. Keep
the claim narrower than the evidence when necessary:

```json
{"name": "ida_write_finding", "arguments": {
  "title": "dispatches command byte",
  "content": "The function reads one byte from the parsed packet and selects a handler.",
  "kind": "finding",
  "status": "confirmed",
  "address": "0x401000",
  "confidence": 0.8,
  "evidence": [
    {"type": "call", "value": "recv", "address": "0x401024", "weight": 1.0}
  ]
}}
```

Use `hypothesis`, `question`, `task`, or `decision` when those kinds better
describe the item. Use `proposed` only where the proposal machinery creates it;
ordinary agent writes do not create proposed items directly.

## Record evidence, not just conclusions

Evidence should point back to something another analyst can inspect:

- a call target or cross-reference;
- an address containing the relevant instruction;
- a string or constant;
- a control-flow relationship;
- a raw-byte observation;
- a related finding or decision.

Confidence is an assessment, not proof. A high-confidence claim can still become
stale when the code changes.

## Handle uncertainty and dead ends

Use `ida_mark_examined` when a target has been read and judged:

- `boring` for a wrapper or library routine with no relevance;
- `interesting` when it deserves a finding or follow-up;
- `unclear` when the evidence is insufficient.

Do not convert “not observed” into “impossible.” Record the boundary of the
inspection in the note or finding.

## Revise without erasing history

Use `ida_update_finding` to revise content or transition a lifecycle state.
When a conclusion is rejected, include the reason. The workspace preserves the
audit trail and does not silently replace a disagreement with the higher
confidence value.

Conflicting claims remain visible. Use `ida_list_findings`,
`ida_search_findings`, `ida_analysis_brief`, and
`ida_next_target(strategy="conflict")` to review them.

## Stale findings

Findings are anchored to a digest of the code at the address. If that code
changes, the finding is marked stale rather than silently treated as current.
Review stale entries before relying on them or publishing them again.

## Export and IDB synchronization

Use `ida_export_findings(format="json")` for a full-fidelity machine-readable
handoff or `format="markdown"` for a report. Use a path only when the client
and local policy permit writing that file.

`ida_publish_findings` writes confirmed findings into the IDB as repeatable
comments and, where appropriate, names still-auto-named functions. Run a
dry-run first. `ida_import_annotations` performs the reverse direction by
adopting existing IDB names and comments as confirmed findings.

References: [generated operation reference](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/TOOLS_REFERENCE.md),
[blackboard store](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/src/ida_pro_mcp/host/stores/blackboard_store.py),
[blackboard/IDB sync](https://github.com/GrecAndrei/ida-pro-mcp/tree/master/src/ida_pro_mcp/host/server).
