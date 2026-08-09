# Investigation Workspace

Findings live in a persistent, **binary-scoped** workspace (SQLite): every
session of the same binary — including byte-identical copies — shares one
investigation, and findings survive session close, rebuild, and new sessions.

## Items

Each item has:

- `kind` — what role it plays: `finding`, `hypothesis`, `question`, `task`,
  `decision`, or `examined` (a read-and-judged address with a verdict).
- `status` — lifecycle: `proposed`, `open`, `confirmed`, `resolved`,
  `rejected`. `proposed` is written only by the proposal machinery
  (`proposal_create`, the crawler, or a trace task); the 10 `ida_*` agent
  operations never write it directly — an agent accepts a proposal with
  `proposal_accept` / rejects it with `proposal_reject`.
- `title`, `content`, `category` (a plain string tag), `confidence` (0–1),
  `priority` (0–1), `tags`, `address`, and structured `evidence`
  (`{type, value, address, weight}`).

Items that disagree are kept, not merged: an entry can carry
`conflicts_with` ids (derived from `contradicts` links), and contradiction is
surfaced rather than smoothed over. `resolved` and `contradicted` are derived
read-time fields — the stored lifecycle is the single `status` column, so they
cannot drift apart.

## Writing and revising

| Operation | Purpose |
| --- | --- |
| `ida_write_finding(title=...)` | Record or merge a claim, question, task, or decision with evidence. |
| `ida_mark_examined(address, verdict=...)` | Record that an address was read and judged (`boring`/`interesting`/`unclear`) — use this for dead ends too. |
| `ida_update_finding(entry_id=...)` | Revise content or transition lifecycle state (`resolved`/`rejected` with a reason). |

Writing a claim at an address also anchors it to the code that was there; if
that code later changes, the claim is flagged `stale` instead of being
silently wrong.

## Proposals, crawler, and trace

The crawler and trace machinery never write directly to the analyst memory as
facts — they create real `proposed` entries that the agent accepts or rejects:

- `start_crawler` runs a bounded frontier crawler on the host task runner. It
  writes `kind='hypothesis', status='proposed'` entries and notifies with the
  real entry id (`proposal_id`), instructing you to call
  `proposal_accept(entry_id=...)` or `proposal_reject(entry_id=...)`.
- `trace_run` enqueues pending trace tasks and returns a task id immediately
  (non-blocking); `trace_status` reads the task rows. A run that gathered no
  evidence is marked `failed` and never satisfies the prove-phase gate.
- `proposal_accept(entry_id=..., dry_run=...)` verifies the proposal's spec and
  transitions it to `open` (or `confirmed`); `proposal_reject` marks it
  `rejected` with a reason. Patch proposals are never auto-verified.

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
