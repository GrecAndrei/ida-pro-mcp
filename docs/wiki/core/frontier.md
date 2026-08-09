# Frontier

`ida_next_target(strategy=...)` suggests what to analyze next, with the
reason for each candidate. Strategies:

| Strategy | What it selects for |
| --- | --- |
| `unresolved` (default) | Open threads and unverified findings. |
| `stale` | Claims whose code changed after they were written. |
| `conflict` | Contradictions needing reconciliation. |
| `coverage` | Frequently-called functions nobody has read. |
| `frontier` | Unexamined callers/callees of confirmed findings. |

`query` reorders candidates by keyword overlap (never drops them); `limit`
caps the result. Use it between analysis steps to keep the investigation
moving, and record the outcome of each target with `ida_write_finding` or
`ida_mark_examined` — coverage, stale, and frontier strategies only work if
the workspace knows what has already been read.

When nothing matches, the response explains why (e.g. "nothing is open" for
`unresolved`) and suggests the strategy that would still yield work.

For opaque/raw binaries without a function inventory, `coverage` and the
`coverage`/`frontier` strategies return an explicit `note` (and
`coverage_pct=0`) instead of silently reporting an empty coverage — there is
no inventory to count, and the response says so rather than implying the
binary has been fully read.
