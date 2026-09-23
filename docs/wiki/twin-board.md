# Twin Board (**Planned** — experimental)

> Status: **Planned / experimental**. Contract lives on branch
> `experimental/twin-board-v1`. Do not treat as shipped on `master` until
> landed and marked here.

Twin Board is a durable analysis object over two owned sessions **A (base)**
and **B (candidate)** — patch vs base, two firmware builds, clean vs infected.
Primary output is a **deterministic delta board**, not a one-shot diff call.

## Planned APIs

- `ida_twin_create({base_idb, candidate_idb, label?})` → `twin_id`
- `ida_twin_status` / `ida_twin_close` / `ida_twin_refresh`
- `ida_twin_board({twin_id, detail?, kinds?, cursor?})` → primary delta board
- `ida_twin_focus({twin_id, row_id})` — expand one snapshot row (read-only)

## Locked contract (verifier-amended)

1. **Frozen match at create** — persist `{match_strategy, equality_predicate}`;
   `func_changed` uses the frozen predicate only (v1 default: normalized bytes
   hash).
2. **Immutable snapshot** — create/refresh mints a generation; `_continue`
   pages that generation only. Stale gen / closed session → hard error.
3. **No `severity_hint` on primary** — sort = `kind` + deterministic tie-break.
   Severity only on Jev sibling card.
4. **Explicit `twin_id` allowlist (read-only)** — named readers only; mutations
   hard-reject `twin_id`.
5. **`applied` = client-order only** — never writes A/B/twin; opt-in via
   `accept_advisory_requested` only.
6. Caps: xref cone callees/callers **≤16** each; `entropy_hotspots` **≤8**.
7. Advisory pool caps reuse Jev v2: triage **4** / normal **8** / deep **16**.
8. Headline card on every board: `{gen, counts_by_kind, top_import_deltas,
   entropy_hotspots, match_policy}`.

## Non-goals (v1)

Analysis Objects, 3-way twins, auto-rebase, silent cross-IDB writes, replacing
`ida_diff_sessions` / `ida_compare_functions` (they feed the board).

Bookkeeper marks this page **Shipped** only after land to `master` + poke +
golden primary-order fixture.
