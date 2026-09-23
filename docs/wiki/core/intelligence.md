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

## Typed-question advisory boundary (shipped)

Hard boundary — document and enforce as current behavior:

- Typed questions only: `choice`, `noul`, and `score`.
- Host-side HTTP only (Jev fixed TypeSafe endpoint, or allowlisted custom).
- Compact signatures / metadata / bytes-disassembly samples only — no raw
  decompilation, prompts, completions, or credentials logged or persisted.
- Provider answers never authorize mutations, satisfy `risk_ack`, or write
  blackboard findings. Deterministic IDA policy remains authoritative.
- Disabled, unavailable, malformed, timed-out, or budget-blocked providers
  **fail closed** back to lexical / deterministic order with a structured
  advisory status — never invent a score.

Provider transport runs in the MCP host. For query expansion the host asks its
provider before the IDA RPC and sends only bounded expansion labels to the
deterministic search. For behavior search, function classification, gadget
classification, and reranking, IDA returns bounded candidate signatures and
the host asks the provider after the RPC. Provider configuration and credential
variables are removed from the IDA child environment.

Jev is **not** a single advisor stage today. Host call sites include
`ask_behavior`, `rank_targets`, typed-question rerank, and arch / GP /
load-base advisories (`host/intelligence/advisory.py` and related RPC hooks).

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
bounded target pool; eligibility, mutation policy, and all writes remain
deterministic and analyst-controlled. Provider failure leaves the original
target order intact. Ranking metadata is returned as an `advisory_ranking`
crumb (applied flag / scores / reason) — **not** a full evidence card.

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

## RISC-V / architecture advisory boundary

MCP does not replace IDA's RISC-V processor module, disassembly,
decompilation, register/CSR metadata, explicit architecture selection, or
explicit `analysis(action="set_gp")`. Host-side raw architecture and GP
hypotheses are bounded advisory data. Disabled/unavailable providers fail
closed and never mutate the IDB. IDA's own analysis remains the authority.

**Current footgun:** a successful arch advisory can still fill `processor` /
`bitness` / `endian` into the **inferred profile** (`arch_profile.py`). That
is not an IDB mutation and must not satisfy `risk_ack`, but operators should
treat auto-filled inferred fields as unverified. **Planned:** no arch
auto-fill into inferred profiles until the unified advisor stage, evidence
card, and disagreement flag ship.

## Planned (not shipped)

Label the following as product direction only — do not claim they exist in
the public contract yet:

1. **Single advisor stage** — deterministic pool → bounded Jev rank/choose →
   one return path (instead of peppered call sites).
2. **Real evidence card** — signatures seen, confidence, budget burn, and
   fail-closed lexical order in one structured card (beyond today's
   `advisory_ranking` crumbs).
3. **Disagreement flag** when Jev order differs from deterministic order.
4. **`triage` / `deep` session profiles** that change advisory budgets or
   depth (budget warn/block exists; profiles do not).
5. **No architecture auto-fill** into inferred profiles until (1)–(3) land.
