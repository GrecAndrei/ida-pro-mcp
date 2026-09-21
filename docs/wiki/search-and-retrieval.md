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
returns a structured advisory status rather than inventing a score.

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
