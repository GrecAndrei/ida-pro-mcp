# filter (removed)

The standalone `filter` tool was removed in 0.9.x.

It duplicated host response controls that already exist on every tool:

- wrapper actions: `pick`, `grep`, `head`, `tail`, `stats`, `next`
- response compaction / truncation on the host

Do not call `filter`. Use those wrappers or request a smaller `limit` on the source tool.

## Wrapper actions (accepted by every tool)

All wrappers run another action first (`source_action`, aliases: `on`,
`target_action`, `subaction`), then post-process its result. They return
structured `items` plus a line-oriented `matches` view.

| action | purpose | canonical controls |
|--------|---------|--------------------|
| `grep` | keep items whose content matches a pattern (regex if `grep_regex`) | `grep`/`pattern`, `grep_field`/`field`, `limit`/`offset`, `grep_case_sensitive`, `grep_invert` |
| `head` | keep first N items | `limit` (alias `head_n`), `offset`, `field` |
| `tail` | keep last N items | `limit` (alias `tail_n`), `field` |
| `pick` | project top-level fields | `pick_fields`, `pick_omit` |
| `stats` | summarize the payload (counts, field cardinality, content summary) | `field`, `stats_include_payload` |
| `next` | continue a truncated wrapper via its `next_token` | `next_token` (aliases `token`, `cursor`) |

Paginated wrappers (`grep`/`head`/`tail`) emit `next_token` when truncated;
pass it to `action='next'` to page forward. For tools that advertise a native
`limit`, `head` forwards `limit`/`offset` to the source for server-side paging.

The `truncation` tool is separate: it continues host response-truncation
tokens (`_continue.token`) emitted when a single response exceeded the context
budget, not wrapper pagination.
