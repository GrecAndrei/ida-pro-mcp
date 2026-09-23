# Search and retrieval

Use deterministic lexical search for names, strings, imports, signatures, and
bounded function metadata. The compatibility operation `ida_semantic_search`
uses lexical signatures and may ask the explicitly configured Jev/custom
provider to score a small candidate set; it never requires a vector model.

## Function indexing

`ida_index_functions` stores bounded names, disassembly-derived signatures,
structural metadata, and token lists in the per-IDB `<idb-path>.signatures.db`
sidecar. A legacy `<idb-path>.embeddings.db` sidecar is migrated on first
access and retained if migration cannot be completed. It does not store raw
decompilation and does not download or start a model. `ida_index_status` and
`ida_cancel_index` report or stop background work.

## Provider scoring

Provider scoring is advisory and optional. `ida_intelligence_status` reports
whether Jev, custom, or disabled mode is selected. A disabled, unavailable,
malformed, timed-out, or budget-blocked provider leaves lexical order intact and
returns a structured advisory status rather than inventing a score. Successful
scoring returns a sibling `advisory_order` and bounded evidence card; the
primary list keeps deterministic order unless the caller explicitly sets
`accept_advisory=true`. This host-only option is available on
`ida_semantic_search` and `ida_next_target`, and is never sent to IDA.

The shared advisor stage uses `detail` to cap its candidate pool: triage keeps
up to 4 candidates, normal up to 8, and deep up to 16. Evidence records bounded
signatures, confidence, provider budget use, whether orders disagreed, and the
deterministic fail-closed order.

`ida_reranker_status` remains a compatibility alias for the typed-question
scoring capability. Vector-family clustering is intentionally not part of the
current public operation surface; use lexical search and structural filters.

## Privacy and network rules

Provider requests carry only compact metadata, bytes/disassembly samples, and
signatures. Credentials, prompts, completions, raw decompilation, and provider
bodies are not logged or persisted. Jev uses the fixed TypeSafe endpoint.
Custom cloud origins require an explicit HTTPS allowlist; HTTP is restricted to
explicitly enabled loopback endpoints.

## Usage

`ida_usage_status` reports safe request/token/cost totals. `ida_usage_report`
returns bounded metadata records for auditing. Unknown pricing is fail-closed
by default, and session/daily token and cost budgets are enforced before a
provider request is sent.

## Response detail dial (shipped, `4e83752`)

One public dial drives both response compaction and truncation budgets:
`detail=triage|normal|deep`.

- **triage** — half compact budgets (items/strings/chars), aggressive strip,
  truncation scale ×0.5
- **normal** — default compact budgets + truncation scale ×1
- **deep** — essentially no compact char budget (full mode), truncation scale ×2

QoL (`_qol_mode` / `qol_mode`: `tiny`→triage, `balanced`→normal, `debug`→deep)
is a pure alias of `detail` with no separate budget preload. Explicit `detail=`
always wins.

Deprecated aliases (still accepted, mapped into `detail`): `_compact` /
`compact`, `_response_mode` / `response_mode`. Advanced overrides only:
`_response_max_items`, `_response_max_string`, `_response_char_budget`,
`_response_batch_compact` — prefer `detail=` unless you need a one-off.

## Truncation and continuation (shipped)

Large tool responses may be compacted by the host truncation store
(`host/stores/truncation.py`). When truncated, the payload carries `_truncated`
and a first-class `_continue` envelope. Prefer `ida_continue` with that
envelope rather than re-running the original tool.

Shipped behavior today (truncation redesign (a)–(c)):

- Continuation tokens: ~1 hour sliding TTL (refreshed on access), LRU store
  capacity 500, scoped per connection/session owner.
- `_continue` envelope: required `reason` (why truncated / refused), store-bound
  opaque `cursor` / `next_cursor`, `fields` list, and `next` (`tool` + `args`)
  plus a human `hint` for how to fetch the next page.
- Pagination: `has_more`, `done`. Legacy `next_offset` / auto-advance still
  works; cursor path does not share a single `next_offset` across fields.
- Per-tool char/list budgets follow the shared `detail` dial (see above).
  Proof/evidence paths are allowlisted and never soft-truncated
  (`reason=policy_risk` when that is why nothing was cut).
- Every strict public `ida_*` operation accepts the optional `detail` enum;
  omitting it uses `normal`.
- `ida_continue` supports paging, `peek` (inspect without advancing),
  `summary`, and in-payload `pattern` search (optional regex).

## Planned (not shipped)

- Further truncation guidance polish beyond `reason` / `next` / `hint` if
  clients need a dedicated `why_truncated` alias
- Removing advanced `_response_max_*` / `_response_batch_compact` overrides
  from the public surface once clients all use `detail=`
