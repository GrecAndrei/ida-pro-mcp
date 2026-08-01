# QuickStart

Five minutes to your first finding.

## 1. Open a binary

```
ida_open_binary(binary_path="/path/to/sample")
```

You get a `session_id` back. If the response says `safe_mode: true`, the
binary is large and loaded in the background — poll `ida_session_status`
until `safe_mode` is false. Everything below that is manual small-area work
also works while analysis runs.

## 2. Orient

```
ida_overview
ida_list_imports
ida_list_strings
```

## 3. Read code

```
ida_decompile(address="0x401000")
ida_xrefs_to(address="0x401000")
```

## 4. Record

```
ida_write_finding(
  title="recv handler parses framed input",
  address="0x401000", kind="finding", status="confirmed",
  confidence=0.8, evidence=[{"type": "call", "value": "recv", "address": "0x401024"}])
```

Dead end instead? `ida_mark_examined(address="0x401000", verdict="boring", note="...")`.

## 5. Keep going

```
ida_next_target()            # what to look at next
ida_analysis_brief()         # what the workspace knows so far
ida_export_findings(format="markdown", path="report.md")   # handoff
ida_publish_findings(dry_run=true)   # then risk_ack=true to write to the IDB
```

## Docs

- [Sessions](core/sessions.md) — lifecycle, background loading, safe mode.
- [Investigation](core/investigation.md) — findings, lifecycle, export, IDB round-trip.
- [Frontier](core/frontier.md) — `ida_next_target` strategies.
- [Intelligence](core/intelligence.md) — semantic indexing and search.
- [Tools](tools/) — every operation by category.
- `ida_help(query="...")` — the exact contract of any operation, on demand.
