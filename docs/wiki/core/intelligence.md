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
- Shared compact investigation state can contain multiple function signatures,
  caller/callee relationships, IDs, and safe architecture metadata. Full raw
  decompilation, literal dumps, prompts, completions, and credentials are
  excluded from provider state and never persisted by the provider layer.
- Provider answers never authorize mutations, satisfy `risk_ack`, or write
  blackboard findings. Deterministic IDA policy remains authoritative.
- Disabled, unavailable, malformed, timed-out, or budget-blocked providers
  **fail closed** back to lexical / deterministic order with a structured
  advisory status — never invent a score.

Provider transport runs in the MCP host. For query expansion the host asks its
provider before the IDA RPC and sends only bounded expansion labels to the
deterministic search. For function behavior, `ContextAssembler` derives compact
signatures locally from the focus function and any caller/callee context
returned by `decompile_chain`. The packet includes API/crypto/risk labels,
bounded CFG/dataflow counts, and normalized branch cues when IDA provides
them. Literal values, comments, raw conditions, and full decompilation stay
local. One shared state then carries per-function behavior and priority
questions plus neighborhood-level next-evidence questions. The
`detail=triage|normal|deep` setting caps the pool at 4/8/16 functions; normal
and deep responses surface the typed result, while deep also includes it in
`context_pack`. The response names candidate IDs, includes a ranked advisory
order, and can suggest
one concrete provider-neutral `ida_*` follow-up for the MCP client to consider.
It never executes that operation. Other behavior, gadget, reranking,
architecture, and Blackboard paths also send
bounded signatures or metadata after deterministic IDA work. Provider
configuration and credential variables are removed from the IDA child
environment.

**Advisor stage (shipped, Jev v2 / `dd866be`):** host call sites
(`ask_behavior`, `rank_targets`, typed-question rerank, arch / GP / load-base)
route through `host/intelligence/advisor_stage.py` / `advisor_gate.py`
(`invoke_advisor`). Existing operation names are kept as a **shim**; a
future release may hard-break peppered paths. The gate caps candidate pools
from the shared `detail` setting, keeps deterministic order primary, and
returns a sibling `advisory_order` with an evidence card. `accept_advisory=true`
is the explicit opt-in that applies a valid reorder. The card records bounded
signatures, budget use, confidence, disagreement, and deterministic fail-closed
order.

**Neighborhood assessment (shipped):** the decompile context path sends the
focus function and compact signatures for observed callers/callees in one
shared provider request. The configured provider returns per-function behavior and
priority, a separately chosen next candidate, a deterministic evidence kind,
and an evidence-sufficiency score. An internal disagreement field records when
the candidate choice differs from the highest per-function priority. The host
may include a matching `ida_*` call as a suggestion; it never runs that call or
changes the IDB.

Background Blackboard organization uses the same gate after finding changes.
It recommends lanes for bounded findings and scores only observed xrefs and
relations already present in stored evidence or graph snapshots. The latest
result is surfaced through `ida_analysis_brief` / `workspace_brief` and stored
in Blackboard machinery; it does not edit findings, evidence, or links.

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
lexical order and reports the advisory failure. A successful score returns
`advisory_order` and an evidence card. Primary order remains lexical unless
the caller sends `accept_advisory=true`; the option is host-only and is not
sent to IDA.

`ida_next_target` uses the blackboard's deterministic strategy to choose the
eligible candidate set (primary order). When Jev/custom is ready, it may score
a bounded pool into sibling `advisory_order` under the advisor stage —
eligibility, mutation policy, and all writes remain deterministic and
analyst-controlled. Provider failure leaves the primary order intact with
`applied=false`. Ranking metadata is an evidence card (see below), not a
silent reorder of the primary list.

Callers can explicitly set `accept_advisory=true` to use a valid advisory
order as the primary list; the option remains host-side.

`ida_reranker_status` reports the configured typed-question scoring capability
as a compatibility alias. Vector-family clustering is not part of the current
public operation surface; use lexical search and structural filters instead.

## Usage and budgets

`ida_usage_status` reports metadata-only request, token, and cost totals for a
session or day. `ida_usage_report` lists bounded attempt metadata: provider,
model, operation, token counts, latency, status, error code, and estimated cost
when pricing is known. It never stores request state or answer content.

In explicit Jev mode, defaults allow up to 65,536 estimated input tokens per
request, 15,000,000 per session, and 140,000,000 per day, with the existing
`$5` / `$20` cost ceilings and request-count limits. Jev 1.13 is currently
listed at `$0.042` per million input tokens and free output; a 32,000-token call
is about `$0.001344`. The host allows a 96 KiB compact state and 256 KiB
serialized request by default, within TypeSafe's documented 64K total request
budget and 32K state-plus-longest-question limit. Override these limits with
the documented `IDA_MCP_JEV_*` settings if TypeSafe's terms change. Custom mode keeps its
separate conservative request defaults. Warnings are emitted at 70% and 90%;
`IDA_MCP_JEV_BUDGET_MODE=block` blocks over-budget requests, while `warn`
records the warning and continues. [TypeSafe model and pricing reference](https://docs.typesafe.ai/models).

## Advisor stage contract (shipped)

Primary list is **always** the deterministic pool order. Jev/custom lives only
in sibling `advisory_order`. Reordering the primary list requires explicit
opt-in via `accept_advisory_requested` (boolean / truthy strings only through
that helper — never raw `bool(args.get(...))`).

### Pool caps by `detail`

| `detail` | Cap |
|----------|-----|
| triage   | 4   |
| normal   | 8   |
| deep     | 16  |

### Evidence card (required on every advisory result)

Bounded fields: `signatures_seen` (≤16 entries; id/hash + ≤64-char preview
each), `budget_burn`, `confidence`, `fail_closed_order`, `applied`,
`disagreement`. No full signature blobs.

`disagreement=true` when `advisory_order` ≠ deterministic order; both orders
are retained. `applied=true` only with opt-in — never default soft authority.

### Architecture advisory

MCP does not replace IDA's RISC-V processor module, disassembly,
decompilation, register/CSR metadata, explicit architecture selection, or
explicit `analysis(action="set_gp")`. Host-side raw architecture and GP
hypotheses are bounded advisory data. Disabled/unavailable providers fail
closed and never mutate the IDB.

**Shipped:** arch advisory suggests only (`architecture_advisory` /
`inference_applied=false`). It does **not** write `processor` / `bitness` /
`endian` into the inferred spawn profile.

## Planned (not shipped)

1. **Hard-break** of peppered call-site names after the shim release —
   callers must use the advisor gate only.
2. **Twin Board** (experimental branch `experimental/twin-board-v1`) — durable
   two-IDB delta object; see [Twin Board](../twin-board.md) (Planned).
