# Investigation Workspace

Findings live in a persistent, **binary-scoped** workspace (SQLite): every
session of the same binary — including byte-identical copies — shares one
investigation, and findings survive session close, rebuild, and new sessions.

## Items

Each item has:

- `kind` — what role it plays: `finding`, `hypothesis`, `question`, `task`,
  `decision`, or `examined` (a read-and-judged address with a verdict).
- `status` — lifecycle: `open`, `confirmed`, `resolved`, `rejected`.
- `title`, `content`, `category`, `confidence` (0–1), `priority` (0–1),
  `tags`, `address`, and structured `evidence` (`{type, value, address,
  weight}`).

Items that disagree are kept, not merged: an entry can carry
`conflicts_with` ids, and contradiction is surfaced rather than smoothed
over.

## Writing and revising

| Operation | Purpose |
| --- | --- |
| `ida_write_finding(title=...)` | Record or merge a claim, question, task, or decision with evidence. |
| `ida_mark_examined(address, verdict=...)` | Record that an address was read and judged (`boring`/`interesting`/`unclear`) — use this for dead ends too. |
| `ida_update_finding(entry_id=...)` | Revise content or transition lifecycle state (`resolved`/`rejected` with a reason). |

Writing a claim at an address also anchors it to the code that was there; if
that code later changes, the claim is flagged `stale` instead of being
silently wrong.

## Reading

| Operation | Purpose |
| --- | --- |
| `ida_list_findings(...)` | List items with kind/status/category/tag/address/confidence filters. |
| `ida_search_findings(query=...)` | Recall items by meaning or keywords. |
| `ida_analysis_brief(limit=...)` | Summarize confirmed knowledge, open questions, conflicts, stale claims, and coverage. |
| `ida_export_findings(...)` | Full-fidelity JSON or Markdown export (see below). |

## Export

`ida_export_findings` produces the findings format itself, so nothing is
lost in transit:

- `format=json` — `ida-findings-v1` snapshot with every field, evidence
  included; internal storage fields are stripped.
- `format=markdown` — grouped report by kind → status with content and
  evidence bullets.
- Pass `path` to write a file; otherwise content is returned inline.
- Filters: `kind`, `status`, `category`, `address`, `tag`,
  `min_confidence`, `include_resolved`, `include_contradicted`, `limit`.

## Landing conclusions in the IDB

`ida_publish_findings` writes confirmed findings back into the IDB as
repeatable comments and symbols (`[mcp:<entry_id>]` markers) and renames
still-auto-named functions — never overwriting an existing symbol. Run with
`dry_run: true` first; `risk_ack: true` confirms the mutation.
`ida_import_annotations` does the reverse: adopts names and comments already
in the IDB as confirmed findings.
