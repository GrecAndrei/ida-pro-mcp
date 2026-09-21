# Intelligence and providers

IDA Pro MCP keeps deterministic analysis and retrieval independent from model
availability. The only provider modes are `jev`, `custom`, and `disabled`.
There is no local, Gemini, or native-model fallback.

## Modes and configuration

- `disabled` is the default and keeps deterministic lexical indexing/search
  available without network access.
- `jev` calls TypeSafe Jev at the fixed endpoint
  `https://api.typesafe.ai/v1/systemone`. Set `TYPESAFE_API_KEY` (or the
  documented file form) and optionally `IDA_MCP_JEV_MODEL`.
- `custom` is explicit BYOK. Set `IDA_MCP_CUSTOM_BASE_URL`,
  `IDA_MCP_CUSTOM_ALLOWED_ORIGINS`, `IDA_MCP_CUSTOM_MODEL`, and a credential
  environment variable or file. Custom cloud origins must be HTTPS and must be
  listed explicitly. HTTP is allowed only for loopback origins when
  `IDA_MCP_CUSTOM_LOCAL_HTTP=1` is set.

Legacy embedding, Gemini, native, and reranker settings fail closed with
`PROVIDER_CONFIG_INVALID`; they are never silently translated into a provider.
Use `ida_intelligence_status` to inspect the selected mode, safe provider
identity, capabilities, and readiness. Credentials are not returned.

## Typed-question advisory boundary

Provider requests contain bounded JSON state and typed `choice`, `noul`, or
`score` questions. Context is compacted to metadata, bytes/disassembly samples,
and signatures. Raw decompilation, prompts, completions, and credentials are
never logged or persisted. Provider answers are advisory only: they cannot
invoke tools, authorize mutations, satisfy `risk_ack`, or write blackboard
findings. Deterministic IDA policy remains authoritative.

A missing Jev credential or unavailable Jev endpoint returns `JEV_UNAVAILABLE`.
Malformed provider responses return `PROVIDER_PROTOCOL_ERROR`; invalid mode,
origin, mapping, or conflicting settings return `PROVIDER_CONFIG_INVALID`.
Custom request/response mappings use a bounded, non-executable JSON mapping
syntax and cannot contain credentials.

## Deterministic indexing and search

`ida_index_functions` retains its compatibility name but stores bounded names,
disassembly, structural metadata, and lexical signatures only. The sidecar is
`<idb-path>.signatures.db`; first access migrates legacy
`<idb-path>.embeddings.db` storage and preserves it if migration fails. It does
not run a model or persist raw decompilation. Scope with `query`, `ranges`,
`start`/`end`, `address` + `radius`, `min_size`, and `max_size`. Use
`ida_index_status` and `ida_cancel_index` for background indexing.

`ida_semantic_search` is also a compatibility name. It performs deterministic
lexical signature search and can optionally ask Jev/custom to score a bounded
candidate pool. Provider failure, timeout, or budget blocking preserves the
lexical order and reports the advisory failure; it never turns an unavailable
provider into a fake semantic score.

`ida_next_target` uses the blackboard's deterministic strategy to choose the
eligible candidate set. When Jev/custom is ready, it may score and reorder a
bounded target pool; eligibility, evidence, mutation policy, and all writes
remain deterministic and analyst-controlled. Provider failure leaves the
original target order intact and is returned as advisory metadata.

`ida_reranker_status` reports the configured typed-question scoring capability
as a compatibility alias. Vector-family clustering is not part of the current
public operation surface; use lexical search and structural filters instead.

## Usage and budgets

`ida_usage_status` reports metadata-only request, token, and cost totals for a
session or day. `ida_usage_report` lists bounded attempt metadata: provider,
model, operation, token counts, latency, status, error code, and estimated cost
when pricing is known. It never stores request state or answer content.

The default proposed budgets are 100,000 session tokens / `$5`, 500,000 daily
tokens / `$20`, and bounded request/count limits. Warnings are emitted at 70%
and 90%. `IDA_MCP_JEV_BUDGET_MODE=block` hard-blocks over-budget requests;
`warn` records the warning and continues. Unknown pricing blocks by default;
explicitly opt in only when the operator accepts unpriced usage.

## RISC-V boundary

MCP does not replace IDA's RISC-V processor module, disassembly,
decompilation, register/CSR metadata, explicit architecture selection, or
explicit `analysis(action="set_gp")`. Host-side raw architecture and GP
hypotheses are bounded advisory data; Jev/custom may select among supplied
hypotheses, while disabled/unavailable providers fail closed and never mutate
the IDB. IDA's own analysis remains the authority.
