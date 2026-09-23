# Twin Board (**Planned** — experimental)

> Status: **Planned / experimental**. Implementation lives on
> `experimental/twin-board-v1`. Do **not** treat as shipped on `master` until
> landed + verifier poke + golden primary-order fixture.

Durable analysis object over two owned sessions **A (base)** and **B
(candidate)** — patch vs base, two firmware builds, clean vs infected.
Primary output is a deterministic delta board with a headline card; Jev is
sibling-only under the Jev v2 gate.

## Planned APIs

- `ida_twin_create({base_idb, candidate_idb, label?, match_strategy?, equality_predicate?})` → `twin_id`
- `ida_twin_status` / `ida_twin_close` / `ida_twin_refresh` (new generation)
- `ida_twin_board({twin_id, detail?, kinds?, cursor?, accept_advisory?})`
- `ida_twin_focus({twin_id, generation, row_id})` — expand one **frozen
  snapshot** row (read-only; no live re-diff, no A/B/twin writes)

## Locked contract (verifier + bake-in)

1. **Frozen match at create** — persist `{match_strategy, equality_predicate}`;
   `func_changed` = frozen predicate only (v1 default: normalized bytes hash).
2. **Immutable snapshot** — create/refresh mints a generation; `_continue`
   pages that generation only. Stale gen / closed session → hard error.
3. **No `severity_hint` on primary** — sort = `kind` + deterministic tie-break.
   Severity only on the Jev sibling card.
4. **Explicit `twin_id` allowlist (read-only)** — named readers only; mutations
   hard-reject `twin_id`. `ida_twin_focus` is allowlist-only.
5. **`applied` = client-order only** — never writes A/B/twin; opt-in via
   `accept_advisory_requested` only.
6. **Hard caps** (truncate with `truncated:true` + counts — never silently grow):
   xref cone callees ≤**16**, callers ≤**16**; `entropy_hotspots` ≤**8**;
   headline `top_import_deltas` ≤**8**. Advisory pools: triage **4** / normal
   **8** / deep **16**.
7. **Stable row ids:** `row_id = hash(kind, match_key)` on the frozen equality
   key. Collision within a generation → suffix `#2`, `#3`, … by primary sort.
   Across gens, same `match_key` → same base id; remapped partner → new id +
   `supersedes` (never reuse for a different match).
8. **Headline card** on every board:
   `{gen, counts_by_kind, top_import_deltas, entropy_hotspots, match_policy}`.

## Non-goals (v1)

Analysis Objects, 3-way twins, auto-rebase, silent cross-IDB writes, replacing
`ida_diff_sessions` / `ida_compare_functions` (they feed the board).

Bookkeeper marks this page **Shipped** only after land to `master` + poke +
golden primary-order fixture.
