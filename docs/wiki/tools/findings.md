# Findings

Persistent, binary-scoped investigation workspace: claims, evidence, hypotheses,
conflict resolution, frontier targeting, and reviewed IDB synchronization.

Findings survive session closures and IDB rebuilds. Byte-identical copies of a binary
automatically share the same investigation store.

---

## Operations Overview

| Operation | Purpose | Required Arguments |
| --- | --- | --- |
| `ida_write_finding` | Record or merge a typed claim, hypothesis, question, task, or decision with evidence. | `title`, `kind`, `status` |
| `ida_mark_examined(address, verdict)` | Record that an address was inspected, including dead ends (`verdict="boring"`). | `address`, `verdict` |
| `ida_list_findings` | List workspace items with lifecycle, kind, and category filters. | — |
| `ida_search_findings(query=...)` | Search workspace items by keywords or semantic meaning. | `query` |
| `ida_update_finding(entry_id=...)` | Revise an item's content, confidence, or transition its lifecycle status. | `entry_id` |
| `ida_next_target` | Suggest what to analyze next using a named strategy (`unresolved`, `frontier`, `stale`, `conflict`, `coverage`). | Deterministic eligibility first; optional Jev/custom may attach an `advisory_ranking` crumb. Full evidence card / disagreement flag are **Planned**. |
| `ida_analysis_brief` | Summarize confirmed knowledge, open questions, conflicts, stale claims, and coverage. | — |
| `ida_export_findings` | Export findings as machine-readable JSON or human-readable Markdown (`format="markdown"`). | — |
| `ida_publish_findings` | Write confirmed findings into the IDB as repeatable comments and symbol names. | `risk_ack` |
| `ida_import_annotations` | Adopt names and comments already in the IDB as confirmed findings. | — |

---

## 1. Recording Findings & Evidence

```json
{
  "name": "ida_write_finding",
  "arguments": {
    "title": "AES Key Expansion",
    "content": "Expands 128-bit key into 11 round keys using the AES S-box table.",
    "kind": "finding",
    "status": "confirmed",
    "address": "0x401500",
    "confidence": 0.9,
    "tags": ["crypto", "aes"],
    "evidence": [
      {"type": "call", "value": "sbox_lookup", "address": "0x401540", "weight": 1.0},
      {"type": "constant", "value": "0x1b", "address": "0x401560", "weight": 0.8}
    ]
  }
}
```

Kinds: `finding`, `hypothesis`, `question`, `task`, `decision`, `examined`.
Lifecycle statuses: `open`, `confirmed`, `resolved`, `rejected`.

---

## 2. Tracking Examined Functions & Dead Ends

```json
{
  "name": "ida_mark_examined",
  "arguments": {
    "address": "0x402200",
    "verdict": "boring",
    "note": "Standard libc memcpy thunk; no custom validation."
  }
}
```

Marking an uninteresting function as `boring` prevents autonomous agents and future analysts from wasting time re-reading it.

---

## 3. Guiding Analysis: Frontier & Next Target

`ida_next_target(strategy=...)` suggests the highest-priority function or address to inspect next:

- `unresolved` (default): Focuses on open questions and unverified hypotheses.
- `frontier`: Traverses unexamined callers and callees of confirmed findings.
- `coverage`: Frequently called functions that have not yet been examined.
- `conflict`: Contradicting findings that require reconciliation.
- `stale`: Claims whose underlying code or instructions changed after they were recorded.

---

## 4. IDB Publishing & Import

- `ida_import_annotations`: Run early in a session to import existing symbols and comments from the IDB into structured findings.
- `ida_publish_findings(dry_run=true)`: Preview comments and names that will be added to the IDB.
- `ida_publish_findings(risk_ack=true)`: Commit the confirmed findings back to the IDB.

See [Investigation Core Guide](../core/investigation.md) and [Frontier Guide](../core/frontier.md) for deeper workflow details.
