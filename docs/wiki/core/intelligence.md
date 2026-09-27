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
`detail=triage|normal|deep` allows 16/32/64 candidates in single-question
workflows. A neighborhood candidate needs two questions plus three shared
questions, so those limits become 8/16/30 functions, capped again by the
selected provider's question limit. Normal and deep responses surface the
typed result, while deep also includes it in `context_pack`. The response
names candidate IDs, includes a ranked advisory order, and can suggest one
concrete provider-neutral `ida_*` follow-up for the MCP client to consider.
It never executes that operation. The evidence card's 16 short signature
previews are only a display limit; they do not reduce the analysis pool. Other
behavior, gadget, reranking,
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

## Turning the layer off

The whole intelligence layer is governed by `IDA_MCP_INTELLIGENCE_ENABLED`,
which is separate from the provider mode:

| Value | Effect |
|---|---|
| unset | follow `IDA_MCP_INTELLIGENCE_MODE` (itself defaulting to `disabled`) |
| `0` / `false` / `off` / `no` | **unconditional kill switch** — the layer is off |
| `1` / `true` / `on` / `yes` | the selected provider may run; this does not choose one |
| anything else | configuration error; the host fails closed |

A false value outranks everything: the mode environment variable, the persisted
`intelligence.json` state, and the `IDA_MCP_INTELLIGENCE_MODE` the installer
wrote into your client configuration. It also short-circuits leftover provider
settings, legacy settings, and mode-conflict errors, so turning the layer off
can never be blocked by other configuration. Mode *values* are still validated
first, so a typo is reported rather than silently treated as "off".

With the layer off no provider is constructed, no network request is attempted,
and `invoke` raises `INTELLIGENCE_DISABLED`. The deterministic version is what
remains: the primary candidate list is always the deterministic pool order,
heuristic and structural ranking still run, and `LexicalFunctionIndex` still
backs signature retrieval. Advisory results degrade to the fail-closed shape —
`advisory_order: null`, `applied: false`, `fail_closed_order` populated — so
operations degrade instead of failing.

Check the current posture with `ida_usage_status` or the provider status, which
report `intelligence_enabled`, `deterministic_only`, and `disabled_reason`
(`kill_switch` or `mode`).

The installer writes the resolved posture explicitly as
`IDA_MCP_INTELLIGENCE_ENABLED` in generated client configuration, so the
on/off state is one readable line. Pass `--intelligence-enabled` to arm a
selected provider, or `--intelligence-disabled` to force it off. Selecting a
provider in the interactive wizard installs it but does not arm it unless you
confirm.

## Usage and budgets

`ida_usage_status` reports metadata-only request, token, and cost totals for a
session or day. `ida_usage_report` lists bounded attempt metadata: provider,
model, operation, token counts, latency, status, error code, and estimated cost
when pricing is known. It never stores request state or answer content.

Jev is a metered provider, so spend is **opt-in**. The host never applies a
price by default: leaving `IDA_MCP_JEV_INPUT_USD_PER_MTOK` and
`IDA_MCP_JEV_OUTPUT_USD_PER_MTOK` unset leaves pricing unconfigured, and the
usage ledger blocks every Jev request *before transport* with
`reason="unknown_pricing"`. Setting both prices is the operator's explicit
acknowledgment that paid traffic is intended; setting
`IDA_MCP_JEV_ALLOW_UNKNOWN_PRICING=1` is the alternative acknowledgment for
operators who accept unpriced usage. `ida_usage_status` reports
`pricing_configured` so the gate state is visible. The installer offers the
published rate as a prompt and `--jev-input-usd-per-mtok` /
`--jev-output-usd-per-mtok` flags, and writes them only when supplied.

Budget defaults are shared across modes and are not raised automatically for
Jev: 2,048 output tokens per request, 100,000 tokens per session, 500,000 per
day, with `$5` / `$20` cost ceilings and 200/2,000 request-count limits. The
per-request *input* reservation is derived from the provider's configured
`max_input_chars` at the host's four-bytes-per-token estimate (262,144 chars
reserves 65,536 input tokens; 32,768 chars reserves 8,192), so a reservation is
never smaller than the packet a provider may receive, and identical input bounds
reserve identically for every mode. Raise any ceiling explicitly with
`IDA_MCP_JEV_*` or `IDA_MCP_INTELLIGENCE_*` environment variables.

Output is currently free, but the host reserves output tokens for its request
and total-token limits. Jev 1.13 is listed at `$0.042` per million input
tokens; at that rate, 32,000 input tokens cost about `$0.001344` and 64,000 cost
about `$0.002688`. These published figures were checked on 2026-09-24 and may
change, so treat them as a reference to confirm rather than a default the
server applies. They are carried in code as `JEV_REFERENCE_INPUT_USD_PER_MTOK`
and `JEV_REFERENCE_OUTPUT_USD_PER_MTOK` in
`host/intelligence/providers/config.py`, purely so the installer can offer them
as a prompt and let you confirm the figure. **The host never reads those
constants to price a request** — naming a price in your own environment is the
only way pricing becomes active. [TypeSafe model and pricing reference](https://docs.typesafe.ai/models).

TypeSafe documents a 64K combined state-and-questions context and a 32K limit
for state plus the longest individual question. The host allows up to a 120
KiB compact state, checks the state-plus-longest-question window against 128
KiB, and caps the serialized Jev request at 256 KiB by default. These are
four-byte-per-token host estimates, not the provider tokenizer; the usage
response is reconciled against the ledger. The provider can be configured with
smaller limits, and the host never lets a Jev request exceed these defaults.

## Environment variable reference

Every variable the intelligence layer reads, with the default that applies when
it is unset. Booleans accept `1`/`true`/`yes`/`on` and `0`/`false`/`no`/`off`; a
malformed boolean fails closed rather than being guessed at.

### Posture

| Variable | Default | Meaning |
| --- | --- | --- |
| `IDA_MCP_INTELLIGENCE_ENABLED` | unset (follow mode) | Kill switch. `0`/`false` disables the whole layer unconditionally and outranks every other configuration source. `1`/`true` permits the selected provider without choosing one. |
| `IDA_MCP_INTELLIGENCE_MODE` | `disabled` | Provider mode: `disabled`, `jev`, or `custom`. Values are validated, so a typo is reported. |
| `IDA_MCP_INTELLIGENCE_CONFIG` | unset | Path to an explicit provider config file, bypassing state discovery. |
| `IDA_MCP_INTELLIGENCE_PROVIDER` | unset | Provider selector in config files. |
| `IDA_MCP_INTELLIGENCE_BACKEND` | unset | Legacy backend selector; rejected rather than translated. |
| `IDA_MCP_JEV_MODEL` | unset | Model identifier for the Jev provider. |

### Pricing and the spend gate

| Variable | Default | Meaning |
| --- | --- | --- |
| `IDA_MCP_JEV_INPUT_USD_PER_MTOK` | unset | Input price per million tokens. **Unset means no price is applied and Jev requests are blocked before transport.** |
| `IDA_MCP_JEV_OUTPUT_USD_PER_MTOK` | unset | Output price per million tokens, same rule. |
| `IDA_MCP_JEV_ALLOW_UNKNOWN_PRICING` | unset | `1` accepts unpriced Jev usage instead of blocking it. |
| `IDA_MCP_JEV_BLOCK_UNKNOWN_PRICING` | `1` | Inverse of the above. `0` is equivalent to allowing unknown pricing. |
| `IDA_MCP_INTELLIGENCE_BLOCK_UNKNOWN_PRICING` | — | Mode-neutral alias for `IDA_MCP_JEV_BLOCK_UNKNOWN_PRICING`. |

### Budgets

Each of these has a mode-neutral `IDA_MCP_INTELLIGENCE_*` alias. The
`IDA_MCP_JEV_*` name takes precedence when both are set. Budgets are **shared
across modes** and are not raised automatically for Jev.

| Variable | Default | Meaning |
| --- | --- | --- |
| `IDA_MCP_JEV_BUDGET_MODE` | `block` | `block` refuses over-budget requests; `warn` allows them and reports. |
| `IDA_MCP_INTELLIGENCE_BUDGET_MODE` | — | Alias for the above. |
| `IDA_MCP_JEV_WARNING_THRESHOLDS` | `0.70,0.90` | Comma-separated fractions of a budget at which to warn. At most 16 values, each strictly between 0 and 1. |
| `IDA_MCP_INTELLIGENCE_WARNING_THRESHOLDS` | — | Alias for the above. |
| `IDA_MCP_JEV_REQUEST_INPUT_TOKENS` | derived | Input tokens reserved per request. Defaults to `max_input_chars / 4`, so a reservation is never smaller than the packet the provider may receive. |
| `IDA_MCP_INTELLIGENCE_REQUEST_INPUT_TOKENS` | — | Alias for the above. |
| `IDA_MCP_JEV_REQUEST_OUTPUT_TOKENS` | `2048` | Output tokens reserved per request. |
| `IDA_MCP_INTELLIGENCE_REQUEST_OUTPUT_TOKENS` | — | Alias for the above. |
| `IDA_MCP_JEV_SESSION_TOKEN_BUDGET` | `100000` | Total tokens per session. |
| `IDA_MCP_INTELLIGENCE_SESSION_TOKEN_BUDGET` | — | Alias for the above. |
| `IDA_MCP_JEV_DAILY_TOKEN_BUDGET` | `500000` | Total tokens per day. |
| `IDA_MCP_INTELLIGENCE_DAILY_TOKEN_BUDGET` | — | Alias for the above. |
| `IDA_MCP_JEV_SESSION_BUDGET_USD` | `5.0` | Cost ceiling per session. |
| `IDA_MCP_INTELLIGENCE_SESSION_BUDGET_USD` | — | Alias for the above. |
| `IDA_MCP_JEV_DAILY_BUDGET_USD` | `20.0` | Cost ceiling per day. |
| `IDA_MCP_INTELLIGENCE_DAILY_BUDGET_USD` | — | Alias for the above. |
| `IDA_MCP_JEV_SESSION_REQUEST_LIMIT` | `200` | Requests per session. |
| `IDA_MCP_INTELLIGENCE_SESSION_REQUEST_LIMIT` | — | Alias for the above. |
| `IDA_MCP_JEV_DAILY_REQUEST_LIMIT` | `2000` | Requests per day. |
| `IDA_MCP_INTELLIGENCE_DAILY_REQUEST_LIMIT` | — | Alias for the above. |

### Jev transport

| Variable | Default | Range | Meaning |
| --- | --- | --- | --- |
| `IDA_MCP_JEV_BASE_URL` | fixed TypeSafe endpoint | — | Override the endpoint. Custom origins require an explicit HTTPS allowlist. |
| `IDA_MCP_JEV_CONNECT_TIMEOUT` | `5.0` | 0.1–60 | Connect timeout in seconds. |
| `IDA_MCP_JEV_READ_TIMEOUT` | `30.0` | 0.1–300 | Read timeout in seconds. |
| `IDA_MCP_JEV_TIMEOUT` | `60.0` | 0.1–600 | Total request timeout in seconds. |
| `IDA_MCP_JEV_MAX_ATTEMPTS` | `3` | 1–5 | Attempts before giving up. |
| `IDA_MCP_JEV_MAX_INPUT_CHARS` | `262144` | 1024–1000000 | Largest input packet. Drives the derived input reservation. |
| `IDA_MCP_JEV_MAX_QUESTIONS` | `64` | — | Question ceiling for one request. |
| `IDA_MCP_JEV_MAX_RESPONSE_BYTES` | `1048576` | 1024–16777216 | Largest accepted response body. |

Legacy embedding, Gemini, native, and reranker settings are rejected with a
structured configuration error rather than silently translated, so a stale
configuration fails loudly instead of quietly changing behavior.
The typed API permits up to 255 Choice options, while this server limits a
request to 64 questions. Custom mode keeps its own configured limits. Warnings
are emitted at 70% and 90%;
`IDA_MCP_JEV_BUDGET_MODE=block` blocks over-budget requests, while `warn`
records the warning and continues.

## Advisor stage contract (shipped)

Primary list is **always** the deterministic pool order. Jev/custom lives only
in sibling `advisory_order`. Reordering the primary list requires explicit
opt-in via `accept_advisory_requested` (boolean / truthy strings only through
that helper — never raw `bool(args.get(...))`).

### Candidate windows by `detail`

Single-question workflows ask once per candidate:

| `detail` | Candidate cap |
|----------|---------------|
| triage   | 16            |
| normal   | 32            |
| deep     | 64            |

Neighborhood assessment asks two questions per candidate and three shared
questions:

| `detail` | Candidate cap | Questions |
|----------|---------------|-----------|
| triage   | 8             | 19        |
| normal   | 16            | 35        |
| deep     | 30            | 63        |

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
