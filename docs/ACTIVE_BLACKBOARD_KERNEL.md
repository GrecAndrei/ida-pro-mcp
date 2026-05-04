# Active Blackboard Kernel — Implementation Sheet

## The Problem

The LLM does not voluntarily use helpful context. Prompting it to "please consider the voids" or "note everything you see" fails because the LLM treats that as prompt injection or noise. We need a fundamentally different mechanism.

## Core Idea

**Build an Active Blackboard Kernel.**

The blackboard stops being a passive notebook and becomes a runtime memory bus that constrains the LLM's environment.

| Dimension | Old Blackboard | New Blackboard |
|---|---|---|
| Role | Passive memory | Active control layer |
| Behavior | Stores findings if the LLM writes them | Intercepts every tool call |
| Optional? | LLM may ignore it | Tool behavior depends on unresolved observations |
| Structure | Textual content blobs | Event-sourced with obligations and receipts |
| Retrieval | Read/list/search | Action-gated: important actions require resolved evidence receipts |

The LLM does not "use" the blackboard because it feels like it. The blackboard shapes the world the LLM is operating in.

---

## The Mechanism: Attention Receipts

Every useful feature produces an **obligation**.

| Feature | Obligation |
|---|---|
| VoidTracker finds unexamined import surface | `obligation: coverage_gap(import_surface)` |
| ShadowBlackboard finds failed prior hypothesis | `obligation: avoid_or_disprove(shadow_X)` |
| Benchmark says surprise-context improves outcomes | `obligation: inspect_surprise_feature(Y)` |
| Autogenic symbol appears across unrelated regions | `obligation: resolve_latent_bridge(S_123)` |
| Narrative gap exists | `obligation: connect_or_dismiss(gap_Z)` |

The LLM cannot satisfy these by saying "I acknowledge this." That is useless.

It satisfies them by producing an **action receipt**.

A receipt is created only when the LLM performs a tool action that materially interacts with the obligation.

| Obligation | Valid Receipt |
|---|---|
| Unexamined import surface | Calls import/data/search tool touching that surface |
| Failed C2 hypothesis warning | Uses code/xrefs/data to disprove or explicitly branches away |
| Latent bridge unresolved | Calls xrefs/callees/decompile on connected symbols |
| Narrative gap | Performs a dataflow/callgraph/strings lookup that connects two story nodes |
| Benchmark-favored feature ignored | Calls a tool that inspects that feature class |

The LLM cannot fake this with words. The server verifies receipts from tool calls.

---

## Tool Gating

High-impact tools should require receipts when obligations are unresolved.

**High-impact actions:**
- rename
- comment
- patch
- type application
- bookmark
- blackboard conclusion write
- report/finding export
- vulnerability claim
- malware behavior claim

**Example:**

The LLM wants to rename `sub_140001000` to `c2_init`.

The active blackboard checks:
- Is there a shadow warning saying similar symbols caused false C2 assumptions?
- Is there a void saying network evidence has not been examined?
- Is there a benchmark policy saying this type of rename fails unless imports/xrefs are checked?

If yes, the rename is not blindly accepted.

The server returns a tool-level constraint, not a prompt:

```json
{
  "ok": false,
  "blocked_by": ["obl_shadow_9a21", "obl_void_113f"],
  "required_receipts": ["prove_network_path", "inspect_connected_surface"]
}
```

This is not prompt injection. It is protocol semantics.

The LLM now has to interact with the environment correctly to proceed.

---

## Result Shaping

If gating everything is too harsh, use result shaping.

Instead of telling the LLM: "Please consider the voids."

Shape the next tool result so the void matters.

**Example:**

The LLM asks for `code.decompile`.

If attention debt is low:
- Return normal decompile.

If attention debt is high:
- Return decompile plus only the unresolved connected slices.
- Or return a smaller result focused around ignored latent symbols.
- Or reorder xrefs/callees by unresolved obligations.
- Or hide low-value repeated context and surface the ignored feature through the data layout.

Not prompt text. The feature changes the data the LLM receives.

The LLM uses the feature because the runtime made it part of the available evidence.

---

## Attention Debt

Every ignored high-value feature accumulates **attention debt**.

**Debt increases when:**
- Same tool/action repeats without resolving relevant obligations.
- LLM makes a claim without required evidence.
- LLM follows a known failed path.
- LLM ignores a feature benchmark says is useful.
- LLM adds conclusions while coverage voids remain.

**Debt decreases when:**
- Valid receipt is produced.
- Hypothesis is disproven.
- Void is explored.
- Latent bridge is connected/dismissed.
- Benchmark-favored feature is used and leads to progress.

**Debt controls enforcement level:**

| Debt Level | Runtime Behavior |
|---|---|
| 0 | Passive injection |
| 1 | Reorder results |
| 2 | Add required receipts |
| 3 | Degrade repeated tools |
| 4 | Block high-impact claims/actions |
| 5 | Force exploration branch before continuing |

This is how you make the LLM use things it "thinks" it does not need.

You don't persuade it. You make neglect expensive.

---

## Benchmarks Become Runtime Policy

Benchmarks should not be shown to the LLM as text.

They should become policy.

Benchmark output should answer:
- Which features improve downstream outcomes?
- Which features are frequently ignored?
- Which ignored features correlate with wrong conclusions?
- Which tool sequences benefit from cognitive features?
- Which obligations are worth enforcing?
- Which enforcement level improves results without slowing analysis too much?

Then write benchmark results into a policy table:

```text
feature_id
helpfulness_score
ignore_rate
failure_when_ignored
best_enforcement_level
tool_contexts_affected
```

**Example:**

Benchmark discovers:
- `surprising_findings` improves vulnerability triage by 34%.
- LLM ignores it 72% of the time.
- Ignoring it correlates with repeated search loops.

Runtime policy:

```text
When task=vuln_hunt and surprise_feature exists:
  enforcement = result_shaping
  if repeated search loop:
    enforcement = receipt_required
```

The LLM never needs to "read benchmark results." The benchmark changes the world.

---

## "Note Everything It Sees"

Do not ask the LLM to note things. Auto-note everything.

Every tool result gets passed through an **Observation Distiller** before the LLM even responds.

It creates:
- raw observation hash
- induced latent symbols
- structural motifs
- coverage touched
- possible obligations
- possible shadow matches
- causal timestamp
- benchmark feature hits

This is written to the active blackboard automatically.

The LLM can add interpretation, but it is not responsible for memory capture.

So the contract becomes:

| Old | New |
|---|---|
| LLM decides what to remember | Runtime remembers everything |
| LLM summarizes manually | Distiller creates structured observations |
| LLM may forget | Event log cannot forget |
| LLM chooses blackboard use | Blackboard intercepts all calls |

---

## What Part Of Blackboard Fixes This?

Not the current passive blackboard.

The fix is adding these tables:

```sql
observations
obligations
receipts
attention_debt
benchmark_policies
tool_effects
shadow_edges
coverage_surfaces
```

The active blackboard does four things:

1. **Observe** every tool result automatically.
2. **Generate obligations** from useful ignored features.
3. **Verify receipts** from real tool actions.
4. **Control future tool behavior** based on unresolved obligations.

That is what makes it matter.

---

## Implementation Shape

### 1. AttentionKernel
New host module.

Responsibilities:
- `observe_result(tool, action, args, result)`
- `generate_obligations(observation)`
- `preflight(tool, action, args)`
- `postflight(tool, action, result)`
- `resolve_receipts(tool, action, args, result)`
- `compute_attention_debt(session_id)`

### 2. Server Integration
Hook into tool execution:

Before tool call:
```python
decision = attention_kernel.preflight(tool, action, args)
```

Possible decisions:
- allow
- reorder
- shape
- require_receipts
- block_high_impact
- redirect_to_obligation

After tool call:
```python
attention_kernel.observe_result(tool, action, args, result)
attention_kernel.resolve_receipts(tool, action, args, result)
```

### 3. Blackboard Upgrade
Blackboard becomes event-sourced.

Each tool result creates an immutable observation row.

Each unresolved cognitive feature creates an obligation row.

Each valid resolving action creates a receipt row.

### 4. Benchmark Governor
Benchmark results update enforcement policy.

Not:
```text
Tell the LLM benchmark says X.
```

Instead:
```text
If benchmark says X helps and LLM ignores X, increase enforcement level for X.
```

### 5. High-Impact Action Gate
Rename/comment/patch/conclusion tools call:

```python
attention_kernel.require_receipts(...)
```

If unresolved obligations are relevant, the action is blocked or downgraded.

### 6. Result Shaper
For read-only tools, avoid blocking. Shape.

Examples:
- reorder xrefs by unresolved obligations
- crop huge decompile output around latent bridge regions
- include only unseen surfaces first
- prioritize surprising co-occurrences
- suppress repeated already-inspected material

---

## The Unusual Part

The LLM is no longer the center.

The center becomes:

```text
observations -> obligations -> receipts -> tool affordances -> outcomes -> policies
```

The LLM is just one actor moving through that environment.

If it ignores useful features:
- debt rises
- tools change
- actions require receipts
- repeated paths get devalued
- benchmark-proven features gain control weight

That is how we make it use what it thinks it does not need.

Not with prompts.

With physics inside the MCP runtime.
