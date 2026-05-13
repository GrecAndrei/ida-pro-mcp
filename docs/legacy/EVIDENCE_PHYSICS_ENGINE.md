# Evidence Physics Engine — Full Architecture Specification

## Overview

**Goal:** Replace the Active Blackboard Kernel's heuristic scaffolding with an evidence physics engine that discovers its own operational semantics from observations, interventions, and consequences. No fixed thresholds, no hardcoded tool categories, no string-prefix pattern matching, no presumed analyst correctness.

**Core Shift:**

```
Old: tool call -> extract bridges -> compare bridges -> obligations -> receipts -> debt

New: tool call -> observe world-state delta -> induce latent roles
      -> propose experiments -> test interventions -> update causal world model
      -> gate claims by evidence sufficiency
```

**Central Question:**

Not "Does this look similar enough?"  
But **"If this evidence were wrong, what cheap experiment would expose that?"**

---

## Principle 1: Distribution-Free Calibration (No Fixed Thresholds)

### Problem
All thresholds are arbitrary guesses: `result_sim >= 0.6`, `args_sim >= 0.4`, `diff <= 0x100`, `alpha = 0.2`, `expires = now + 600`. One size does not fit all binaries, architectures, analysts, or sessions.

### Solution: Online Conformal Calibration

For every decision type, maintain empirical distributions:

| Distribution | Source |
|---|---|
| `receipt_similarity_scores_when_correct` | Receipts that later proved useful |
| `receipt_similarity_scores_when_wrong` | Receipts later associated with disputes |
| `block_decisions_overridden` | Blocks the analyst disagreed with |
| `block_decisions_later_validated` | Blocks where later evidence supported the kernel |
| `shape_decisions_followed_by_progress` | Shaping followed by debt reduction |
| `shape_decisions_followed_by_looping` | Shaping followed by repeated tools |

**Thresholds become quantiles, not constants:**

| Decision | Threshold Rule |
|---|---|
| Resolve receipt | `score >= q10(correct_receipts)` — 10th percentile of scores known to be right |
| Block action | `expected_risk >= q80(historical_bad_actions)` — 80th percentile of risk scores from bad outcomes |
| Decay obligation | `relevance <= q20(active_obligations)` — 20th percentile of active obligation relevances |
| Shape result | `debt >= q50(session_debt_range)` — median debt for this session |

### Tables

```sql
calibration_events (
    id, session_id, ts, decision_type, features_json, score, chosen_action,
    later_outcome, outcome_ts
)

calibration_quantiles (
    decision_type TEXT, session_id TEXT, quantile REAL, value REAL,
    updated_ts REAL, samples INTEGER
)

decision_outcomes (
    decision_id, correctness_verdict, verdict_source, verdict_ts, override_count
)
```

### Process
1. Every decision logs to `calibration_events`.
2. A background calibrator recomputes quantiles periodically.
3. The kernel reads current quantiles before making thresholded decisions.
4. Cold start: use session-agnostic defaults until 30+ samples accumulated, then switch to session-local quantiles.
5. Cross-session: if session-local calibration is sparse, fall back to cross-session aggregate quantiles.

### Why This Fixes It
The system stops pretending one threshold fits all. It learns the local operating envelope.

---

## Principle 2: Dual-Ledger Memory (No Analyst Bias as Truth)

### Problem
Current: analyst overrides → reduce debt. This assumes the analyst is always correct. Analysts make mistakes. Override does not mean the system was wrong.

### Solution: Separate Preference from Truth

```
preference_ledger: what the analyst wanted
truth_ledger: what later evidence supported
```

Overrides do not immediately teach "this obligation was bad."

They create a **dispute** — a pending disagreement between analyst and kernel.

**Dispute lifecycle:**

| Stage | Status | Action |
|---|---|---|
| Created | unresolved | Kernel notes disagreement, no Q update |
| Evidence arrives | pending | Kernel gathers supporting/contradicting signals |
| Evidence resolves | resolved | Kernel updates enforcement based on actual outcome |
| No evidence | stalemate | Both sides record neutrality; enforcement unchanged |

**Evidence rules:**

| Later Outcome | Learning |
|---|---|
| Analyst override led to progress (debt drops, receipts accumulate) | Lower kind enforcement by 0.2α |
| Analyst override led to contradiction (shadow matches, claim revision) | Raise kind enforcement by 0.3α |
| Same override repeated with mixed outcomes | Split into context clusters, learn per-context |
| No evidence either way | Record neutrality, no change |
| External verification (other analyst, tool output) supports either side | Strong signal, α=0.5 |

### Tables

```sql
disputes (
    id, session_id, ts, obligation_id, analyst_action, kernel_reason,
    later_evidence_json, status, resolved_ts, verdict
)

dispute_evidence (
    id, dispute_id, evidence_type, evidence_json, supports_analyst BOOLEAN,
    confidence, ts
)

evidence_verdicts (
    dispute_id, verdict, confidence, reasoning, ts
)

analyst_preferences (
    session_id, context_signature, preference_type, preferred_action,
    strength, samples, updated_ts
)
```

### Novelty
The system becomes adversarial toward both itself and the analyst. It trusts neither. It waits for evidence.

---

## Principle 3: Semantics From Intervention (No Static Pattern Guessing)

### Problem
Structural proximity != semantic understanding. Two addresses being close doesn't mean they're related.

### Solution: Micro-Experiments

Every uncertain obligation generates small, cheap experiments:

| Obligation | Experiment |
|---|---|
| `coverage_gap(import_surface)` | "If I probe xrefs at suspected IAT boundary, will I discover new latent symbols?" |
| `shadow_warning(C2_claim)` | "If I check callees of this function, will I find evidence contradicting C2 behavior?" |
| `narrative_gap(crypto↛network)` | "If I trace data flow between these two latent clusters, will new connection edges appear?" |

The kernel does not ask the LLM to explore.  
It generates **experiment candidates** and makes them cheap (low debt, unshaped) or blocks claims until experiments resolve.

**Experiment schema:**

```json
{
  "experiment_id": "exp_91ab",
  "target_obligation": "obl_1234",
  "probe": {"tool": "code", "action": "xrefs_from", "args": {"addr": "latent-target"}},
  "falsifies_if": "no new bridge overlap AND no debt reduction",
  "confirms_if": "bridge overlap >= calibrated receipt threshold",
  "blind_cost": 0.3,
  "status": "pending"
}
```

### Tool Affordance Templates (NOT Hardcoded)

Templates are induced from historical tool behavior, not manually defined:

| Historical Observed Effect | Induced Template |
|---|---|
| `code.xrefs_from` consistently expands bridge set | "connectivity probe" |
| `search.string` consistently reveals new latent symbols | "symbol expansion probe" |
| `data.functions` consistently adds coverage | "surface expansion probe" |
| `code.decompile` consistently reduces obligation relevance | "evidence probe" |
| `graph.callgraph` consistently finds paths between distant nodes | "bridge probe" |

**Important:** These are NOT manually named templates. They are behavior clusters discovered by the tool affordance profiler (Principle 4).

### Tables

```sql
experiments (
    id, session_id, ts, obligation_id, probe_json, falsifies_if,
    confirms_if, blind_cost, status
)

experiment_results (
    experiment_id, outcome, evidence_json, cost, ts
)
```

### Why This Is Novel
Meaning becomes operational. A thing means what it causes the analysis environment to reveal.

---

## Principle 4: Tool Affordance Profiling (No Hardcoded Tool Categories)

### Problem
Current:

```python
READ_HEAVY_TOOLS = {"code", "data", "search", ...}
HIGH_IMPACT_ACTIONS = {"rename", "patch_asm", ...}
```

These are static priors. If a new tool is added, the kernel doesn't understand it. If a tool has both read and write effects, the category is wrong.

### Solution: Observable Effect Profiling

For every tool/action, pre/post snapshots of world state are compared to learn what the tool does.

**Effect dimensions:**

| Dimension | Measured As |
|---|---|
| `persistent_state_delta` | New/modified blackboard entries, renamed functions, patched bytes |
| `symbol_delta` | New latent symbols introduced |
| `obligation_delta` | Obligations resolved or created |
| `debt_delta` | Pre/post debt difference |
| `claim_delta` | New claims introduced or revised |
| `coverage_delta` | New covered surfaces |
| `connectivity_delta` | New graph edges between symbols/observations |
| `irreversibility` | Operations that cannot be undone |

**Effect vectors cluster into affordance types:**

| Affordance Type | Effect Signature |
|---|---|
| `exploration` | High symbol_delta, low persistent_state_delta |
| `claim_making` | High claim_delta, high irreversibility |
| `evidence_gathering` | High connectivity_delta, moderate symbol_delta |
| `state_modification` | High persistent_state_delta, high irreversibility |
| `navigation` | High coverage_delta but near-zero other deltas |
| `conclusion` | High claim_delta, multiple other deltas |

These affordance types are **discovered**, not defined.

### Tables

```sql
tool_effects (
    tool TEXT, action TEXT, effect_vector_json TEXT, sample_count INTEGER,
    last_seen REAL, updated_ts REAL
)

tool_affordance_clusters (
    cluster_id INTEGER, centroid_json TEXT, member_tools_json TEXT,
    sample_count INTEGER, label_derived TEXT
)

tool_action_deltas (
    id, session_id, ts, tool, action, pre_snapshot_json, post_snapshot_json,
    effect_vector_json
)
```

### Key Behavior
- New tools: profiled from their first 10 calls. Affordance type assigned from nearest cluster.
- Existing tools: online update of effect vectors, periodic reclustering.
- Decision making: instead of `if tool in READ_HEAVY_TOOLS`, use `if affordance(tool, action).result_shape_allowed`.

---

## Principle 5: Latent Role Induction (No String Prefix Assumptions)

### Problem
Current: `_hex_prefix()` checks for `0x`, `_symbol_prefix()` checks for `s_` and `b_`. These are priors baked into the code. Not all addresses start with `0x`. Not all identifiers conform to our naming.

### Solution: Behavioral Role Assignment

A token is not an "address" because it starts with `0x`.

A token is address-like if it **behaves** like a locator:

| Behavior | Role Signal |
|---|---|
| Appears as repeated target of tool call args | `locator` |
| Connects observations across tool calls | `bridge` |
| Contains many associated tokens | `container` |
| Resolves obligations when present | `evidence` |
| Causes disputes when used in claims | `claim` |
| Introduces new symbols when explored | `frontier` |
| Has consistent numerical neighbors | `address_range` |
| Appears in result structures not args | `output_reference` |

**Every token starts unknown.**

**Roles accumulate from behavioral evidence:**

```sql
token_roles (
    token TEXT, role TEXT, evidence_count INTEGER, confidence REAL, updated_ts REAL
)

role_evidence (
    token, role, evidence_type, tool_call_id, signal_strength, ts
)
```

**Role similarity replaces string prefix matching:**

```python
# OLD: check prefix
if s.startswith("0x") or s.startswith("s_") or s.startswith("b_"):
    out.add(s)

# NEW: check role confidence
if token_has_role(token, "locator", confidence=0.6) or \
   token_has_role(token, "bridge", confidence=0.4):
    out.add(token)
```

### Non-Lexical Tokens
Binary blobs, unnamed constants, offsets — all get roles from behavior. No text parsing required.

---

## Principle 6: Evidence-Preserving Slicing (No Blind Text Cropping)

### Problem
Cropping by character window or line count can hide critical evidence. A key instruction or string might be outside the window, and the LLM never sees it.

### Solution: Graph-Based Minimal Evidence Slice

Build a dependency graph over tool result chunks:

```text
nodes = chunks (lines, blocks, list items, JSON keys, labeled sections)
edges = control flow continuity, data dependency, co-reference, obligation anchor
```

**Node types:**

| Node Type | Source |
|---|---|
| `text_line` | Line from decompile/disasm output |
| `json_subtree` | JSON key-value from structured result |
| `reference_edge` | xref/caller/callee entry |
| `label` | Function name, comment, type annotation |
| `string_literal` | Extracted string |
| `control_node` | Branch, loop, call instruction |

**Edge types:**

| Edge Type | Meaning |
|---|---|
| `flows_to` | Control flow continuity |
| `references` | Data reference or symbolic reference |
| `anchors` | Contains obligation bridge |
| `introduces` | Introduces previously unseen latent symbol |
| `resolves` | Matches receipt evidence |
| `disputes` | Contradicts a claim |
| `high_centrality` | Graph centrality metric |

**Slice algorithm:**

1. Identify anchor nodes (those containing obligation bridges, latent symbols, receipt evidence).
2. Compute k-shortest paths between all pairs of anchors (preserve connectivity).
3. Include nodes with graph centrality > threshold (preserve structural hubs).
4. Include all nodes that `introduce` new latent symbols (preserve discovery).
5. Include all nodes that `dispute` active claims (preserve contradictions).
6. Include continuity edges where gap > 1 edge creates ambiguity.
7. If ambiguity remains after slicing, mark ambiguous regions with `[... potentially relevant but cut ...]` instead of hiding them.

**Safety rule:** If the kernel cannot prove a chunk is safe to omit, it keeps it.

### Tables

```sql
result_chunks (
    chunk_id, session_id, observation_id, chunk_type, content, chunk_index
)

chunk_graph_edges (
    source_chunk_id, target_chunk_id, edge_type, weight REAL
)

slicing_decisions (
    slicing_id, observation_id, kept_chunks_json, omitted_chunks_json,
    confidence, ts
)
```

---

## Principle 7: Proactive Frontier Planner (Not Just Reactive)

### Problem
Current: LLM gets stuck (3× same tool) → kernel notices → suggests alternatives. This is reactive. The damage is already done.

### Solution: Frontier-Based Proactive Planning

Maintain an **analysis graph**:

```
nodes = observations, latent symbols, obligations, receipts, claims, disputes
edges = co-occurrence, causality, tool transition, evidence support, contradiction
```

**Frontier computation:**
For every unresolved node, compute:

| Metric | Meaning |
|---|---|
| `expected_information_gain` | How many new latent symbols or edges would resolving this unlock? |
| `expected_debt_reduction` | How much debt would resolving this eliminate? |
| `expected_false_claim_prevention` | How many pending claims depend on this evidence? |
| `cost_estimate` | How many tool calls (on average) does this frontier require? |

**Frontier ranking:**

```text
score = info_gain × debt_reduction / cost
```

Highest score = best next action.

**Kernel behavior by frontier state:**

| Situation | Kernel Behavior |
|---|---|
| LLM repeats low-gain tool | Redirect toward highest-ranked frontier |
| LLM explores high-gain frontier | Reduce friction (lower debt, lighter shaping) |
| LLM makes high-impact claim | Require frontier receipts for related front nodes |
| Frontier node becomes stale | Decay its score; re-rank |
| LLM resolves frontier node | Record strong success reward; update per-kind Q |

### Tables

```sql
frontier_nodes (
    node_id, node_type, session_id, info_gain_score, debt_reduction_score,
    false_claim_score, cost_estimate, composite_score, updated_ts
)

frontier_edges (
    source_node_id, target_node_id, edge_type, weight
)

analysis_graph (
    node_id, node_type, properties_json, updated_ts
)
```

### Novelty
Not "you ignored useful info" — the runtime makes exploration cheap and inaction expensive.

---

## Principle 8: Counterfactual Policy Replay (Not Static Benchmark Tables)

### Problem
Benchmark policies are static rows. No mechanism to validate whether a policy actually improves outcomes.

### Solution: Offline Counterfactual Replay

Every session produces an event log.

The replay engine asks:

| Counterfactual | Measurement |
|---|---|
| What if receipt threshold were 0.5 instead of 0.6? | Debt resolution speed |
| What if obligation expiration were 300s instead of 600s? | Stale obligation rate |
| What if shaping were applied at debt 0.5 instead of 1.0? | Tool loop frequency |
| What if block threshold were higher for `coverage_gap`? | Override rate |

**Replay scoring:**

```text
would_debt_resolve_earlier
would_high_impact_action_be_blocked
would_repeated_loop_end
would_obligation_remain_stale
would_false_claim_be_prevented
would_analyst_override_event_occur
```

**Policy versioning:** Each calibration update creates a new policy version. Old versions are kept for replay comparison.

**Policy adoption:** If replay shows improvement on ≥3 sessions, auto-promote policy.

### Tables

```sql
policy_versions (
    version_id, created_ts, params_json, source
)

counterfactual_runs (
    run_id, policy_version, session_trace_id, outcome_json, ts
)

counterfactual_outcomes (
    metric_name, baseline_value, counterfactual_value, improvement, confidence
)
```

### Why This Matters
We get benchmark-driven policy learning without showing benchmarks to the LLM. No cloud training data required.

---

## Principle 9: Claim Ledger (High-Impact Outputs as Claims)

### Problem
Current system gates "actions" but doesn't understand that a rename, comment, or report is a **claim about the world**. Blocking an action is coarse. We need to block insufficiently-evidenced claims.

### Solution: Claims as First-Class Objects

Every high-impact output becomes a structured claim:

```json
{
  "claim_id": "clm_49fe",
  "subject": "latent_entity_0x55a1",
  "predicate": "role=c2_initializer",
  "confidence": 0.8,
  "supporting_receipts": ["rcp_a1b2", "rcp_c3d4"],
  "contradicting_shadows": ["obl_shdw_9a21"],
  "unresolved_dependencies": ["obl_void_113f"],
  "status": "pending"
}
```

**Supported predicates (induced, not hardcoded):**

| Predicate Type | Source |
|---|---|
| `role=X` | Label assigned to latent entity |
| `connects_to=Y` | Relationship between entities |
| `contains=Z` | Membership claim |
| `is_type=T` | Type application |
| `behavior=B` | Behavioral classification |
| `vulnerability=V` | Security finding |
| `malware_indicator=M` | Malicious behavior claim |
| `conclusion=C` | Free-form analytical conclusion |

These predicate types are discovered from analyst labeling behavior, not predefined.

**Preflight behavior:**

The kernel asks:
1. Does this claim have sufficient supporting receipts?
2. Does it contradict prior shadow warnings?
3. Does it have unresolved coverage dependencies?
4. Is the confidence justified by evidence volume?
5. Has this claim been made and revised before?

### Tables

```sql
claims (
    id, session_id, ts, subject, predicate, confidence, status
)

claim_support (
    claim_id, receipt_id, support_strength
)

claim_contradictions (
    claim_id, shadow_obligation_id, contradiction_type
)

claim_revisions (
    original_claim_id, revised_claim_id, revision_type, reason, ts
)
```

### Critical Design
The system does not parse `c2_init` as "C2 initializer." It treats the label as an opaque claim attached to a latent entity. The role name is meaningless to the kernel. The evidence is what matters.

---

## Principle 10: Self-Doubt Engine (Confidence-Aware Decisions)

### Problem
The kernel makes confident decisions with variable calibration quality. If the kernel is uncertain, it should intervene softly, not block hard.

### Solution: Decision Confidence as a Decision Modifier

Every decision carries:

```json
{
  "decision": "block_high_impact",
  "confidence": 0.73,
  "why": {
    "obligation_strength": 0.81,
    "kind_q_multiplier": 1.24,
    "policy_support": 0.66,
    "dep_graph_prediction": 0.42,
    "calibration_samples": 42,
    "dispute_density": 0.18,
    "unknown_unknown_score": 0.09
  }
}
```

**Confidence tiers and behavior:**

| Confidence | Decision Modification |
|---|---|
| > 0.9 | Block hard, no override suggestion |
| 0.7–0.9 | Block, but show evidence and suggest experiment |
| 0.5–0.7 | Shape/slow instead of block |
| 0.3–0.5 | Allow but log dispute preemptively |
| < 0.3 | Allow, kernel is unsure |

**Confidence sources:**

- `obligation_strength`: how relevant/urgent the obligation is
- `kind_q_multiplier`: how well-calibrated this obligation kind is
- `policy_support`: how strongly benchmark policies support this intervention
- `dep_graph_prediction`: confidence in co-resolution prediction
- `calibration_samples`: how many calibration events support this threshold
- `dispute_density`: how frequently similar decisions are overridden
- `unknown_unknown_score`: entropy of the situation (measured by session novelty)

### Tables

```sql
decision_confidence (
    decision_id, confidence_score, component_scores_json, ts
)

unknown_unknown_metrics (
    session_id, novelty_score, uncertainty_score, entropy_score, updated_ts
)
```

### Key Behavior
The system can say: "I am not confident enough to block. I will shape instead."

This prevents the kernel from being overbearing on unfamiliar analysis patterns.

---

## Module Architecture

### 1. `attention_kernel.py`
**Orchestrator.** Coordinates all sub-modules. Entry point for preflight/postflight. Maintains obligations, receipts, debt tables.

### 2. `calibration_engine.py`
**No fixed thresholds.** Maintains calibration event distributions and quantiles. Provides dynamic threshold queries. Background recalculation.

### 3. `tool_affordance_profiler.py`
**No hardcoded tool categories.** Learns what tools do from pre/post world-state deltas. Discovers affordance clusters. Provides classification queries.

### 4. `latent_role_inducer.py`
**No string prefix assumptions.** Assigns behavioral roles to tokens (locator, bridge, evidence, claim, frontier, container). No text parsing required.

### 5. `evidence_slicer.py`
**No blind text cropping.** Builds dependency graph over result chunks. Computes minimal evidence-preserving slice using graph centrality and obligation anchors.

### 6. `frontier_planner.py`
**Proactive, not reactive.** Maintains analysis graph. Computes frontier scores. Redirects/shapes toward high-information-gain actions.

### 7. `claim_ledger.py`
**Claims, not actions.** Tracks high-impact outputs as claims with predicates, evidence support, and contradictions. Gates claims on evidence sufficiency.

### 8. `policy_replay_engine.py`
**Counterfactual benchmarks.** Replays historical sessions under different policies. Auto-promotes policies that improve outcomes.

### 9. `dispute_engine.py`
**Dual-ledger memory.** Tracks analyst-vs-kernel disagreements. Resolves disputes with later evidence, not immediate override feedback.

### 10. `doubt_controller.py`
**Confidence-aware decisions.** Modifies intervention strength based on kernel's self-assessed confidence. Uses novelty/entropy metrics.

### 11. `experiment_generator.py`
**Intervention-based semantics.** Creates experiment candidates from unresolved obligations. Maps obligation types to probe actions using tool affordance templates.

---

## Runtime Flow

```
1.  Tool call arrives at server._execute_tool_inner

2.  ToolAffordanceProfiler.classify(tool, action)
    → Returns affordance type (exploration, claim_making, evidence_gathering, etc.)
    → Not from tool name — from historical effect vectors

3.  LatentRoleInducer.induce(args) 
    → Returns {token: {roles: [...], confidence: [...]}}
    → locator/claim/evidence/bridge roles assigned behaviorally

4.  ClaimLedger.detect_claim_intent(tool, action, args)
    → Returns claim object if this call creates/revises a claim
    → Null if not claim-related

5.  AttentionKernel.prefetch(session_id)
    → Gathers unresolved obligations, disputes, experiments, frontiers

6.  CalibrationEngine.get_thresholds(decision_type, session_id)
    → Returns dynamic thresholds for receipt resolution, blocking, shaping
    → Session-local quantiles, cross-session fallback

7.  FrontierPlanner.rank(session_id, current_tool, current_roles)
    → Returns ranked frontier nodes with expected information gain

8.  ExperimentGenerator.check(unresolved_obligations)
    → If obligations exist with no pending experiments, create experiments
    → Map obligation type to probe template (from affordance profiler)

9.  DoubtController.assess(decision_type, evidence)
    → Returns confidence score and component breakdown

10. Decision:
    allow | shape | redirect_to_experiment | require_frontier | block_claim | allow_with_dispute

11. Tool executes if allowed

12. ObservationDistiller.distill(result, args, tool, action)
    → Records observation with pre/post world-state snapshots
    → Updates tool effect vectors

13. EvidenceSlicer.slice(result, obligation_bridges, latent_roles)
    → Builds chunk graph, computes minimal evidence-preserving slice
    → If no obligation bridges, returns result unchanged

14. ReceiptEngine.validate(result_tokens, unresolved_obligations, dynamic_threshold)
    → Uses latent role similarity + calibrated threshold
    → Resolves obligations, creates receipts, logs similarity scores

15. DisputeEngine.resolve(session_id)
    → Checks pending disputes against new evidence
    → Updates obligation kind Q-values based on evidence verdicts (not just override)

16. ClaimLedger.update(claim, result_tokens, new_receipts)
    → Updates claim support/contradiction
    → Flags claims with insufficient evidence or unresolved dependencies

17. PolicyReplayEngine.queue(session_id)
    → Queues session trace for later counterfactual replay
    → No immediate computation

18. Return result to LLM (shaped/sliced/redirected as needed)
```

---

## Data Flow Diagram

```
┌─────────────┐    ┌──────────────────┐    ┌────────────────┐
│  Tool Call   │───▶│ Tool Affordance  │───▶│  Latent Role   │
│  (server.py) │    │    Profiler      │    │   Inducer      │
└─────────────┘    └──────────────────┘    └────────────────┘
                                                    │
┌─────────────┐    ┌──────────────────┐            │
│    Claim    │◀───│   Preflight      │◀───────────┘
│   Ledger    │    │   Orchestrator   │
└─────────────┘    └────────┬─────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
         ▼                  ▼                  ▼
┌────────────────┐  ┌──────────────┐  ┌──────────────────┐
│  Calibration   │  │   Frontier   │  │   Experiment     │
│    Engine      │  │   Planner    │  │   Generator      │
└────────────────┘  └──────────────┘  └──────────────────┘
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                    ┌───────▼───────┐
                    │    Doubt      │
                    │  Controller   │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │   DECISION    │
                    │ allow/shape/  │
                    │ block/redirect│
                    └───────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
              ▼             ▼             ▼
        Tool Executes  ████████████  Result Shaped
        (if allowed)   █ Blocked █   or Redirected
                       ████████████
              │
              ▼
┌─────────────────┐    ┌──────────────────┐    ┌────────────────┐
│   Observation   │───▶│    Evidence      │───▶│   Receipt      │
│   Distiller     │    │     Slicer       │    │   Validator    │
└─────────────────┘    └──────────────────┘    └────────┬───────┘
                                                        │
┌─────────────────┐    ┌──────────────────┐            │
│    Claim        │◀───│    Dispute       │◀───────────┘
│    Updater      │    │    Resolver      │
└─────────────────┘    └──────────────────┘
```

---

## State Tables Summary

| Table | Module | Purpose |
|---|---|---|
| `observations` | AttentionKernel | Immutable tool call event log |
| `obligations` | AttentionKernel | Pending evidence requirements |
| `receipts` | AttentionKernel | Satisfied evidence proofs |
| `attention_debt` | AttentionKernel | Session-level enforcement score |
| `calibration_events` | CalibrationEngine | Decision-outcome pairs for threshold learning |
| `calibration_quantiles` | CalibrationEngine | Dynamic decision thresholds |
| `decision_outcomes` | CalibrationEngine | Verdicts on kernel decisions |
| `disputes` | DisputeEngine | Analyst-kernel disagreements |
| `dispute_evidence` | DisputeEngine | Evidence supporting/rejecting disputes |
| `evidence_verdicts` | DisputeEngine | Resolved dispute outcomes |
| `analyst_preferences` | DisputeEngine | Per-session analyst behavior models |
| `tool_effects` | ToolAffordanceProfiler | Historical tool effect vectors |
| `tool_affordance_clusters` | ToolAffordanceProfiler | Discovered affordance clusters |
| `tool_action_deltas` | ToolAffordanceProfiler | Pre/post world-state snapshots |
| `token_roles` | LatentRoleInducer | Behaviorally-induced token roles |
| `role_evidence` | LatentRoleInducer | Evidence supporting role assignments |
| `result_chunks` | EvidenceSlicer | Decomposed result units |
| `chunk_graph_edges` | EvidenceSlicer | Dependency graph for slicing |
| `slicing_decisions` | EvidenceSlicer | Slice audit trail |
| `frontier_nodes` | FrontierPlanner | Ranked exploration targets |
| `frontier_edges` | FrontierPlanner | Analysis graph edges |
| `analysis_graph` | FrontierPlanner | Full analysis graph |
| `experiments` | ExperimentGenerator | Pending micro-experiments |
| `experiment_results` | ExperimentGenerator | Experiment outcomes |
| `claims` | ClaimLedger | Structured analytical claims |
| `claim_support` | ClaimLedger | Receipts supporting claims |
| `claim_contradictions` | ClaimLedger | Shadows contradicting claims |
| `claim_revisions` | ClaimLedger | Claim revision history |
| `policy_versions` | PolicyReplayEngine | Versioned policy snapshots |
| `counterfactual_runs` | PolicyReplayEngine | Replayed session traces |
| `counterfactual_outcomes` | PolicyReplayEngine | Policy comparison metrics |
| `decision_confidence` | DoubtController | Per-decision confidence scores |
| `unknown_unknown_metrics` | DoubtController | Session novelty/entropy |
| `benchmark_policies` | PolicyReplayEngine | Current live policy set |
| `overrides` | AttentionKernel | Analyst override events |
| `obligation_kind_q` | ObligationKindQLearner | Per-kind enforcement Q-values |
| `obligation_dependencies` | ObligationDependencyGraph | Co-resolution statistics |
| `episodes` | EpisodicLearner | Recorded tool call sequences |
| `pairs` | AutogenicSemanticField | Latent symbol co-occurrence |
| `symbols` | AutogenicSemanticField | Induced symbol table |

---

## Migration Path

### Phase 1: Calibration Engine + Doubt Controller
- Add `calibration_events`, `calibration_quantiles`, `decision_outcomes` tables.
- Instrument all existing threshold decisions with calibration logging.
- Add DoubtController that reads calibration quality and weakens interventions when uncalibrated.
- Existing behavior unchanged; decisions become confidence-tagged.

### Phase 2: Tool Affordance Profiler + Latent Role Inducer
- Add `tool_effects`, `tool_affordance_clusters`, `token_roles` tables.
- Add pre/post snapshot recording in `observe_result`.
- Replace `READ_HEAVY_TOOLS` and `HIGH_IMPACT_ACTIONS` with affordance queries.
- Replace `_extract_bridges` string prefix checks with role queries.
- Cold start: use existing string-prefix defaults as role hints with low confidence.

### Phase 3: Evidence Slicer + Frontier Planner
- Add `result_chunks`, `chunk_graph_edges`, `frontier_nodes` tables.
- Replace `SemanticCropper` with `EvidenceSlicer`.
- Add `FrontierPlanner` ranking and preflight integration.
- Existing `shape_result` becomes backup for low-confidence slices.

### Phase 4: Dispute Engine + Claim Ledger
- Add `disputes`, `claims` tables.
- Replace immediate Q-update on override with dispute creation.
- Gate high-impact actions with claim evidence checks.
- Existing blocking behavior remains as fallback.

### Phase 5: Policy Replay Engine
- Add `policy_versions`, `counterfactual_runs` tables.
- Add session trace archival.
- Implement offline replay runner.
- Auto-promote policies that show improvement.

---

## Acceptance Criteria

1. **No fixed thresholds** — all decision thresholds query calibration quantiles with session-local and cross-session fallback.

2. **No hardcoded tool categories** — tool behavior classified by affordance profiler from observed effect vectors.

3. **No string prefix assumptions** — token roles assigned from behavioral evidence (locator, bridge, evidence, claim).

4. **No blind cropping** — result slicing preserves evidence graph connectivity and obligation anchors.

5. **Proactive planning** — frontier planner ranks exploration targets by expected information gain; preflight redirects toward frontier.

6. **Analyst fallibility respected** — dual-ledger memory separates preference from truth; disputes resolve on evidence, not override.

7. **Claims gated** — high-impact outputs create claims; claims blocked if insufficiently evidenced regardless of action type.

8. **Self-doubt applied** — interventions weaken when confidence is low; the kernel can say "I'm not sure" and choose softer action.

9. **Policy learned from replay** — counterfactual replay over historical sessions auto-promotes beneficial policies.

10. **Semantics from intervention** — micro-experiments map obligations to probe actions; meaning is what the probe reveals.

11. **All 667+ existing tests still pass** — no regression in current behavior.

12. **New tests cover each module** — calibration, affordance profiling, role induction, evidence slicing, frontier planning, claim gating, dispute resolution, policy replay.

---

# Hard Problems & Edge Cases — Full Analysis

*This section was added after deeper analysis of every failure mode, edge case, and the bootstrap circular-dependency problem.*

---

## The Bootstrap Circular Dependency

### The Problem

The Evidence Physics Engine needs data to calibrate, but it needs calibration to make good decisions. Without calibration:

| Component | Cold-Start Behavior |
|---|---|
| CalibrationEngine | No samples → falls back to session-agnostic defaults (worse than current tuned values) |
| AffordanceProfiler | No clusters → all tools look the same |
| RoleInducer | No evidence → every token looks unknown; bridge extraction misses everything |
| Q-Learner | No samples → uniform enforcement multiplier of 1.0 |
| FrontierPlanner | No graph → no frontier nodes to rank |

A new user installing the system gets **worse behavior than the current heuristic scaffolding** for their first 3-5 analysis sessions. This is an adoption-killing problem.

### The Solution: Local Synthetic Analyst Lab

We cannot ask an LLM to label outcomes. We cannot use cloud training data. We cannot assume a human will hand-label calibration events.

Instead, we create a **self-bootstrapping laboratory** inside the project that generates its own calibration corpus locally by replaying controlled analysis traces over binaries and simulated tool outcomes.

```text
known/available binaries
  → run many analysis policies
  → observe tool-result deltas
  → create synthetic analyst traces
  → compare policies by evidence outcomes
  → produce bootstrap calibration DB
  → runtime starts with calibrated priors
  → real usage refines them
```

### Bootstrap Lab Module
`bootstrap_lab.py`

Runs deterministic "analysis games" against available binaries or test fixtures.

Each game has:
- Starting state
- Available tool affordances
- Policy variant
- Target objective
- Outcome scoring
- Trace log

**Example structural games (no malware concepts, no hardcoded knowledge):**

| Game | Objective |
|---|---|
| Game A: Find high-connectivity latent region | Discover the latent symbol with most graph edges |
| Game B: Resolve a coverage void | Explore an unseen surface and produce receipts |
| Game C: Avoid premature rename | Reach N receipts before any claim action |
| Game D: Connect two latent clusters | Trace data flow between induced symbol groups |
| Game E: Detect repeated low-gain loop | Identify and escape tool repetition |
| Game F: Evaluate evidence slicing quality | Verify that cropped output preserves key symbols |
| Game G: Validate receipt threshold | Vary receipt threshold, measure outcome |
| Game H: Dispute resolution | Create disputes, introduce evidence, measure resolution |

### Synthetic Analyst Policies

Instead of needing a human analyst, we simulate different analyst behaviors. These policies are not meant to be good — they create **behavioral diversity** so the engine learns which behaviors produce better evidence outcomes.

| Policy | Behavior |
|---|---|
| Greedy Relevance | Always follows highest-relevance latent symbol |
| Novelty Seeker | Follows least-seen latent symbol |
| Coverage Maximizer | Expands unexplored surfaces aggressively |
| Claim-Happy | Makes high-impact claims as early as possible |
| Skeptic | Requires N receipts before any claim action |
| Looper | Repeats locally useful tool beyond diminishing returns |
| Random Explorer | Chooses random valid tool action within constraints |
| Frontier Planner | Follows expected information gain |
| Shadow Ignorer | Ignores failed-hypothesis warnings entirely |
| Shadow Respecter | Resolves disputes before making claims |
| Depth-First Tracer | Follows deepest call chain before breadth |
| Breadth-First Mapper | Maps all callees before descending |

### Policy Tournament

Run all policies against the same initial condition:

```text
initial_state = binary fixture X
objective = resolve latent bridge cluster
policies = [greedy, novelty, coverage, claim_happy, skeptic, random, ...]
```

Score each trace:

```text
score =
  + receipts resolved
  + new latent symbols discovered
  + claims supported (not later revised)
  + disputes resolved
  + coverage expanded
  - false claims (later revised)
  - stale obligations
  - repeated low-gain loops
  - unsafe high-impact actions without receipts
  - excessive tool call cost per unit progress
  - hidden evidence (slicing lost critical chunks)
```

Now calibration has labels:

```text
this threshold timing produced better outcomes
this slicing policy preserved evidence better
this claim gate timing prevented false claims
this frontier scoring improved discovery rate
this receipt resolution threshold minimized false negatives
```

This gives the system meaningful priors without human labels, without cloud data, without LLM involvement.

### Bootstrap/Session Blending

On first run, if the user has no local history, load bootstrap priors. As real observations accumulate, blend from bootstrap to session-local:

```text
effective_prior =
  bootstrap_weight × bootstrap_model
  + user_weight     × user_model

bootstrap_weight = 1 / (1 + user_samples / k)
user_weight       = 1 - bootstrap_weight
k                 = calibration_blend_knee (default 20)
```

| User Samples | Bootstrap Weight | User Weight | Behavior |
|---|---|---|---|
| 0 | 1.00 | 0.00 | Pure bootstrap |
| 10 | 0.67 | 0.33 | Heavily bootstrap-biased |
| 20 | 0.50 | 0.50 | Equal blend |
| 50 | 0.29 | 0.71 | Mostly user-specific |
| 100 | 0.17 | 0.83 | Nearly fully personalized |

### Edge Cases for Bootstrap

**Bootstrap corpus is poor (generated from too few or atypical binaries):**
- Mark all bootstrap priors with low confidence.
- Prefer shaping over blocking when confidence is low.
- Require more local evidence before hard gates.
- Increase drift detection sensitivity.

**User workflow is structurally different from bootstrap games:**
- Drift detector notices repeated overrides/disputes.
- Bootstrap weight decays faster (k reduces to 10).
- User model takes priority earlier.

**No binaries available for bootstrap (headless/CI deployment):**
- Fall back to fixture-driven synthetic traces.
- Use minimum-viable calibration (wider quantile ranges).
- Flag low calibration quality; prefer soft shaping.

---

## Hard Problem 1: Calibration Without Ground Truth

### Failure Mode
The engine uses proxy outcomes (debt decreased, receipts resolved) to label decisions as good or bad. But proxies are noisy: debt can decrease by coincidence, receipts can be irrelevant, and analyst progress can happen despite bad kernel decisions.

### Solution: Multi-Signal Verdict Ensemble

A decision outcome is not judged by one signal. It is judged by a verdict ensemble with per-signal confidences:

```json
{
  "decision_id": "dec_123",
  "verdict": "helpful",
  "confidence": 0.74,
  "signals": {
    "debt_change":           { "value": 0.2,  "confidence": 0.6 },
    "receipt_quality":       { "value": 0.8,  "confidence": 0.9 },
    "claim_stability":       { "value": 0.9,  "confidence": 0.7 },
    "tool_cost":             { "value": -0.1, "confidence": 0.5 },
    "coverage_expansion":    { "value": 0.3,  "confidence": 0.4 },
    "frontier_resolution":   { "value": 0.5,  "confidence": 0.8 },
    "loop_reduction":        { "value": 0.0,  "confidence": 1.0 },
    "dispute_resolution":    { "value": 0.7,  "confidence": 0.6 },
    "override_later_validated": { "value": 0.0, "confidence": 0.9 }
  }
}
```

**Verdict rules:**

| Signal Pattern | Verdict |
|---|---|
| Multiple strong positive, no strong negative | `helpful` |
| Multiple strong negative, no strong positive | `harmful` |
| Strong signals disagree | `ambiguous` |
| All signals weak | `inconclusive` |
| One very strong signal, others neutral | Weighted by that signal |

**Action by verdict:**

| Verdict | Calibration Update |
|---|---|
| `helpful` | Record as positive sample for this threshold |
| `harmful` | Record as negative sample |
| `ambiguous` | Store as dispute evidence; do not update threshold |
| `inconclusive` | Store for later replay; do not update threshold |

### Edge Cases

**All signals disagree with each other:**
- Mark verdict `ambiguous`.
- Do not update hard thresholds.
- Store as dispute evidence with all signals logged.
- Queue for counterfactual replay to see if a different threshold would have changed outcome.

**All signal confidences are low:**
- Mark verdict `inconclusive`.
- Use only for soft shaping policy, never for blocking thresholds.
- Record session novelty/entropy as context for later clustering.

**One signal dominated but was wrong (later discovered):**
- When later evidence contradicts the initial verdict, issue a verdict revision.
- Re-calibrate retroactively with revised labels.
- This is only possible after dispute resolution or counterfactual replay.

---

## Hard Problem 2: Analyst Can Be Wrong

### Failure Mode
Current system: analyst overrides → kernel reduces debt → learns the obligation kind is over-eager. But the analyst might be wrong. The override might be premature. The blocked action might actually have been a bad idea.

### Solution: Dispute Lifecycle With Delayed Evidence

Override creates a **dispute**, not a learning update.

**Dispute states:**

| State | Meaning | Action |
|---|---|---|
| `unresolved` | No evidence either way | Kernel notes disagreement, no Q update |
| `evidence_pending` | Experiment generated, awaiting result | Queue for resolution after experiment completes |
| `analyst_supported` | Later evidence supports the analyst | Lower kind enforcement by 0.2α |
| `kernel_supported` | Later evidence supports the kernel | Raise kind enforcement by 0.3α |
| `ambiguous` | Mixed or conflicting later evidence | Record neutrality, split into context clusters |
| `expired_unresolved` | No evidence within session window | Slight preference adjustment only (0.05α), no truth update |

**Evidence that can resolve a dispute:**

| Evidence Type | Supports | Contradicts |
|---|---|---|
| New receipt connecting entity to supporting evidence | Analyst (action was justified) | Kernel (evidence was sufficient) |
| Claim later revised by analyst | Kernel (original claim was premature) | Analyst (action should have been blocked) |
| Shadow warning matches re-emerge | Kernel (blocked path would have been wrong) | Analyst (override was unwise) |
| Tool loop after override | Kernel (analyst moved to productive path) | Kernel (analyst got stuck) |
| Debt drops significantly after override | Analyst (override was productive) | Kernel (block was unnecessary) |
| Different analyst reaches same conclusion | (depends on timing and evidence) | (depends on timing and evidence) |

### Separation of Models

| Model | What It Tracks | Updated By |
|---|---|---|
| `truth_model` | Was the evidence sufficient for this action? | Evidence verdicts only |
| `preference_model` | Does this analyst dislike this kind of intervention? | Override frequency + analyst behavior patterns |
| `policy_model` | Should this kind of obligation be enforced? | Counterfactual replay + tournament results |

**Override updates `preference_model` immediately but `truth_model` only after evidence.**

### Edge Cases

**Analyst overrides and never returns to the same latent entity:**
- Dispute expires as `unresolved`.
- No truth update. No policy update.
- Preference model records "this analyst tends to override this kind" (weak signal).
- Future similar obligations get softer enforcement for this analyst only.

**Analyst repeatedly overrides same kind across different entities:**
- Preference model strengthens → "this analyst strongly dislikes this intervention."
- Truth model remains neutral (no evidence per override).
- Policy model notes high override rate → marks as "investigate in replay."
- Replay engine can test: "what if we didn't enforce this kind for this analyst?"

**Analyst override later causes direct contradiction (shadow warning matches, claim revision):**
- Kernel truth model score increases for that obligation kind.
- Similar future obligations get stronger enforcement.
- Future overrides of this kind require higher analyst preference confidence to soften.

**Multiple analysts (same session or cross-session) disagree on same kind:**
- Disputes are per-session but kind-Q aggregates.
- High variance in override rate across sessions → lower policy confidence.
- Split into context clusters: "this kind works differently in behavioral_analysis vs threat_analysis."

---

## Hard Problem 3: Self-Reinforcing Bad Learning (Ouroboros)

### Failure Mode
The system learns from its own decisions. If it makes a systematic error early in its life, that error propagates:
- Wrong calibration quantiles → wrong thresholds → wrong decisions
- Wrong decisions → wrong outcome labels → wrong calibration updates
- The system converges to a consistent but wrong local optimum.

There is no external correction mechanism. A human overseer could review calibration events, but that defeats the purpose of an autonomous system.

### Solution: Epistemic Separation + No Self-Referential Loops

**Four separated models that never directly overwrite each other:**

```text
descriptive model: what happened (observations, deltas, receipts)
preference model:  what analyst wanted (overrides, patterns, frequency)
policy model:      what improved outcomes (tournament, replay, comparison)
truth model:       what evidence supported (verdicts, disputes, revisions)
```

**Each model has its own update rules and its own evidence requirements.**

**Policy updates require agreement from multiple models:**

```text
analyst override alone          → preference update only (not truth, not policy)
override + later progress       → policy update (analyst was right, block was wrong)
override + later contradiction  → truth update against analyst (analyst was wrong)
tournament comparison           → policy update (this threshold outperformed alternatives)
evidence verdict from dispute   → truth update (evidence arrived, dispute resolved)
```

**No model may update another model without passing through an evidence gate.**

### Cross-Model Validation Gate

Before a policy change takes effect:

```text
1. Does truth model agree?
     → Check: does this change have support in verified evidence?
2. Does policy model agree?
     → Check: does replay show improvement on historical traces?
3. Does preference model agree?
     → Check: is this change consistent with analyst behavior?
4. Are all models confident enough?
     → Check: each model's confidence > minimum threshold
5. Has this change been tried before?
     → Check: policy version history for oscillation
```

If any gate fails: keep current policy, log disagreement, queue for deeper replay.

If all gates pass: apply policy change with auto-promotion.

### Edge Cases

**All four models disagree:**
- Increase global uncertainty.
- Use soft shaping only (never hard block).
- Queue for extended counterfactual replay.
- Do not auto-promote any policy variant.

**One model is very confident but the other three are uncertain:**
- Weight by confidence.
- Confident model gets veto power only if its confidence exceeds q90.
- Otherwise, require convergence.

**Policy was promoted but later replay shows regression:**
- Auto-rollback: revert to previous policy version.
- Record why: "policy v14 was promoted based on 12 traces; later 40-trace replay showed regression."
- Increase minimum sample requirement for future promotions of this kind.

**Bootstrap priors conflict with accumulated user evidence:**
- User evidence wins after blend threshold (100+ samples).
- Bootstrap weight is already near-zero.
- Policy model records "bootstrap prior was suboptimal for this analyst."

---

## Hard Problem 4: Fixed Tool Categories

### Failure Mode
Hardcoded `READ_HEAVY_TOOLS` and `HIGH_IMPACT_ACTIONS` in the current kernel are brittle. If a new tool is added, the kernel doesn't understand it. If a tool has both read and write effects, the category is wrong.

### Solution: Tool Affordance Profiling

Every tool/action gets an effect vector computed from pre/post world-state snapshots:

```text
effect_vector = [
  state_delta,           // new/modified blackboard entries, renamed functions, patched bytes
  symbol_delta,          // new latent symbols introduced
  coverage_delta,        // new covered surfaces discovered
  claim_delta,           // new claims introduced or revised
  irreversibility,       // operations that cannot be undone
  debt_delta,            // pre/post debt difference
  receipt_delta,         // obligations resolved
  connectivity_delta,    // new graph edges between latent entities
  dispute_delta,         // disputes created or resolved
  information_gain_delta // entropy reduction in frontier graph
]
```

**Clustering into affordance types:**

| Affordance Type | Effect Signature |
|---|---|
| `exploration` | High symbol_delta + coverage_delta, low state_delta + irreversibility |
| `claim_making` | High claim_delta + irreversibility, low connectivity_delta |
| `evidence_gathering` | High connectivity_delta + receipt_delta, moderate symbol_delta |
| `state_modification` | High state_delta + irreversibility, low symbol_delta |
| `navigation` | High coverage_delta only, near-zero other deltas |
| `conclusion` | High claim_delta + state_delta, multiple other deltas elevated |
| `observation` | Near-zero all deltas (passive information intake) |
| `uncertain` | New tool, fewer than 10 samples |

These affordance types are **discovered** via online clustering, not defined by name.

### Replacement for Current Hardcoded Lists

```python
# OLD:
if tool in READ_HEAVY_TOOLS:
    decision = "shape"
if action in HIGH_IMPACT_ACTIONS:
    decision = "block_high_impact"

# NEW:
affordance = profiler.classify(tool, action)
if affordance in ("exploration", "evidence_gathering"):
    decision = "allow" if debt < dynamic_threshold else "shape"
if affordance in ("claim_making", "state_modification", "conclusion"):
    if claim_ledger.has_insufficient_evidence():
        decision = "block_claim"
    elif affinity.is_high():
        decision = "require_frontier"
```

### Edge Cases

**New tool with no profiling history:**
- Classify as `uncertain`.
- `uncertain` tools cannot hard-block unless they produce state deltas detected in real-time.
- First 10 calls are profiled with conservative shaping only.
- After 10 samples, the affordance clusterer assigns a type.

**Tool has mixed behavior (depends on action/args):**
- Profile separately: `bulk.rename` vs `bulk.export_annotations` are different affordances.
- Cluster by (tool, action, argument_shape) tuples, not just tool name.
- Argument shape: presence of addr, query, limit, confidence, tags.

**Tool lies or returns malformed result:**
- Mark observation with `low_observability`.
- Reduce confidence in effect vector.
- Avoid using its results to resolve receipts until observability is restored.
- If observability stays low for 20+ calls, flag in frontier graph as "untrustworthy observation source."

**Affordance clusters drift over time (tool behavior changes):**
- Exponential moving average of effect vectors.
- If drift exceeds 2σ from historical mean, create new cluster candidate.
- Old cluster retained for backward comparison; replica engine can test which cluster is "better."

---

## Hard Problem 5: Prefix-Based Token Roles

### Failure Mode
The current bridge extraction checks `startswith("0x")`, `startswith("s_")`, `startswith("b_")`. These are string-prefix priors baked into the code. Not all addresses start with `0x`. Not all internal identifiers conform to our naming.

### Solution: Latent Role Induction From Behavior

A token is not an address because of its prefix. It becomes locator-like because of how it participates in analysis.

**Role evidence signals:**

| Role | Behavioral Evidence |
|---|---|
| `locator` | Appears as repeated target of tool call args; causes focused follow-up; has numerical neighbors; appears in xref-like structures |
| `bridge` | Connects multiple observations; appears in both args and results; co-occurs with other bridges in receipt pairs |
| `evidence` | Appears in receipt-producing results; reduces obligation relevance; supports claims |
| `claim` | Appears in rename/comment/report/bookmark target; changes persistent state; is the subject of a label application |
| `container` | Contains many child tokens in structured results; appears as JSON/dict key; has sub-elements |
| `frontier` | High connectivity potential but unresolved; appears in high-entropy regions of the graph; has few exploration receipts |
| `output_reference` | Appears only in result text, not args; has not yet been the target of a focused follow-up |
| `unknown` | No role evidence accumulated yet (default for all new tokens) |

**Every token starts as `unknown`. Roles accumulate from behavioral evidence.**

**Role confidence:**
```text
confidence(role) = evidence_count_for_role / (evidence_count_for_role + evidence_count_for_other_roles + smoothing)
```

### Replacement for String Prefix Checks

```python
# OLD:
if s.startswith("0x") or s.startswith("s_") or s.startswith("b_"):
    out.add(s)

# NEW:
role_map = role_inducer.classify(token)
if role_map.get("locator", 0) > 0.6:
    out.add(token)
elif role_map.get("bridge", 0) > 0.4:
    out.add(token)
elif role_map.get("evidence", 0) > 0.7:
    out.add(token)
# Unknown tokens ignored until they earn a role
```

### Edge Cases

**One-time token (appears in a single observation, never recurs):**
- Stays `unknown`.
- Cannot carry hard decisions or become an obligation bridge.
- Can still appear in result slicing as context, but not as an anchor.

**Token appears only in result text (never in args):**
- Candidate `output_reference` role.
- Needs the analyst to follow up (use as args target) to become `locator`.
- Low confidence until role is confirmed.

**Token is common noise (appears everywhere, low specificity):**
- High frequency but low information gain.
- Entropy check: if token appears in >50% of observations, downweight.
- Can become `container` role (structural, not meaningful) but not `bridge` or `evidence`.

**Token changes role over time (was locator, now evidence):**
- Role evidence accumulator supports multiple roles with different confidences.
- A token can be both `locator` (it is queried) and `evidence` (it resolves obligations).
- Role conflict (two high-confidence roles) is allowed; it doesn't cause errors.

**Cold-start: no behavioral evidence for any token:**
- Use bootstrap role priors from the Bootstrap Lab.
- If no bootstrap available: treat all non-trivial tokens as `unknown` with a small baseline.
- Preference model records "early tokens were unclassified" → reduces confidence of early decisions.

---

## Hard Problem 6: Evidence Slicing Can Hide Critical Context

### Failure Mode
Current SemanticCropper can crop away the actual vulnerability, the dangerous API call, or the contradictory evidence. The LLM never sees what was removed.

### Solution: Loss-Bounded Evidence Slicing

Before omitting a chunk, the slicer must prove its safety.

**Safety proof rules — at least one of these must be true to omit a chunk:**

| Rule | Condition |
|---|---|
| `no_latent_roles` | chunk contains zero tokens with any latent role |
| `no_path_to_anchor` | no graph path exists from this chunk to any obligation anchor |
| `duplicate_equivalent` | chunk is semantically duplicate of a kept chunk (same role structure) |
| `low_centrality` | chunk centrality in the chunk graph is below q10 of all chunk centralities |
| `no_claim_dispute_relation` | chunk does not appear in any claim support or dispute evidence |
| `fully_redundant_info` | chunk's latent symbol set is a subset of symbols in kept chunks |

**If none of these rules fire: keep the chunk.**

**If any rule fires but confidence is low: keep the chunk.**

### Chunk Graph Structure

```text
chunk types: text_line, json_subtree, reference_entry, label, string_literal, control_node

edge types:
  flows_to          — control flow continuity
  references        — data reference or symbolic reference
  anchors           — contains obligation bridge token
  introduces        — introduces previously unseen latent symbol
  resolves          — matches receipt evidence
  disputes          — contradicts an active claim
  high_centrality   — graph centrality exceeds threshold
  continuations     — text or structure continuity (cannot break mid-function)
```

**Slice algorithm:**

1. Identify anchor chunks (obligation bridges, latent symbols, receipt evidence, claim subjects).
2. Compute k-shortest paths between all pairs of anchors (preserve connectivity).
3. Include chunks with graph centrality > threshold (preserve structural hubs).
4. Include all `introduces` edges (preserve discovery).
5. Include all `disputes` edges (preserve contradictions).
6. Include minimum `continuations` path to keep syntax valid.
7. For each candidate-omit chunk: safety proof must succeed.
8. If ambiguity remains after slicing: mark ambiguous regions with `[... potentially relevant but cut ...]`.

### Edge Cases

**Huge output where everything is relevant:**
- Do not over-crop.
- Return multi-page slice with continuation token for LLM pagination.
- Include slice confidence: `{confidence: 0.92, omitted: 3400, kept: 1600}`.

**No clear obligation anchors (early analysis phase):**
- Avoid slicing entirely.
- Return original compacted result (current behavior).
- Log "slicing skipped — insufficient anchors" for later calibration.

**Contradictory evidence:**
- Always preserve contradiction chunks (both sides of the dispute).
- Mark the preserved chunk as `disputes` edge in the graph.
- Never omit a chunk that could resolve a pending dispute.

**Slicer removes a chunk that later turns out to be critical:**
- Dispute resolution detects this (evidence was hidden → analyst made wrong claim).
- Slicer policy is penalized in verdict ensemble.
- Calibration updates: "this kind of result at this debt level should be less aggressively sliced."

**One very large chunk (e.g., 4000-line function body) dominates output:**
- Break into sub-chunks at natural boundaries (basic blocks, function calls, labels).
- Apply safety rules per sub-chunk.
- If a sub-chunk fails all safety proofs, keep it.

---

## Hard Problem 7: Counterfactual Replay Explosion

### Failure Mode
Naively replaying all policies over all sessions is combinatorially expensive. A 100-call session under 5 policy variants = 500 tool-call simulations. Each simulation requires reconstructing world-state and computing hypothetical outcomes. If this runs synchronously, it blocks the server.

### Solution: Bounded Replay Sampling + Background Worker

**Replay only high-signal moments, not entire sessions:**

| Replay Trigger | Why |
|---|---|
| Decisions near calibration thresholds (within ±10%) | These are the decisions where a slightly different threshold would change the outcome |
| Disputed decisions | Where analyst and kernel disagreed |
| High-debt moments (debt > 3.0) | Where blocking/shaping had maximum impact |
| High-impact actions (claims, patches, renames) | Where a wrong decision has the most consequence |
| Tool loops (3+ same tool) | Where shaping could have broken the loop |
| Stale obligations (expired unresolved) | Where decay timing matters |
| Claim revisions | Where a claim was later changed |
| Frontier resolutions | Where exploration policy affected discovery |

**Sampling budget per session:**
- Maximum 20 replay moments per session.
- Each moment replayed under 3 best-performing policy variants (not all 12).
- Best variants determined by aggregate policy scores from previous replays.

**Execution:**
- Synchronous replay only for the current decision's threshold calibration (fast — 1-5ms).
- Batch replay of full moments runs in a background thread after session ends.
- Results applied to next session's policy, not current session.

### Edge Cases

**Too few replay samples (new session, no history):**
- Keep current policy.
- Do not auto-promote any policy variant.
- Log "insufficient replay data for policy optimization."

**Replay result conflicts with real analyst preference:**
- Store as `dispute` between preference model and policy model.
- Do not silently override the analyst's demonstrated workflow.
- If replay shows policy improvement but analyst behavior contradicts it → mark as "preference divergence" for later investigation.

**Long sessions (500+ tool calls):**
- Segment into episodes (natural breaks: phase changes, session pauses, large debt shifts).
- Replay only episode windows, not the full session.
- Episode boundaries: when debt changes by >2.0, when phase_hint changes, when no high-impact actions for 10+ calls.

**Background replay takes too long:**
- Queue system: most critical moments replayed first.
- If a session starts before previous replay finishes: use best-available policy, queue rest.
- Maximum background replay time per session: 30 seconds wall clock.

---

## Hard Problem 8: Claim Gating Without Semantic Parsing

### Failure Mode
The kernel cannot understand that `c2_init` means C2 or that `decrypt_buffer` means crypto. It shouldn't need to — but it does need to gate claims on evidence sufficiency without parsing their semantic content.

### Solution: Claims as Opaque Evidence-Backed Assertions

The content of a label does not matter. The kernel does not parse `c2_init`.

A rename is:

```text
claim: latent_entity_{hash_of_target} has been assigned label_{hash_of_label}
```

The kernel asks structural questions, not semantic ones:

| Question | Signal |
|---|---|
| Has the target entity been explored? | Observation count touching entity > N |
| Do receipts exist for this entity? | Receipts with bridges matching entity roles > 0 |
| Are there unresolved high-relevance shadow warnings touching this entity? | Shadows with bridge overlap > 0 |
| Are there unresolved high-relevance coverage voids touching this entity? | Voids with bridge overlap > 0 |
| Has this entity been labeled before and then revised? | Claim revision history for this entity |
| Has a similar entity (same latent symbol cluster) been labeled similarly and the label stuck? | Cross-entity claim stability in same cluster |
| Is the analyst labeling rapidly (bulk rename session)? | Claim velocity in recent window |
| Does this label contradict a previously made claim? | Contradiction check against claim ledger |

**Claim states:**

| State | Meaning | Gate Behavior |
|---|---|---|
| `pending` | Not yet evaluated | Allow if confidence below claim gate threshold |
| `provisional` | Low confidence, temporary label | Allow always (analyst exploring) |
| `supported` | Has sufficient evidence receipts | Allow |
| `contradicted` | Against shadow or prior claim | Block; require disprove or explicit override |
| `premature` | Insufficient exploration | Block; require frontier resolution |

### Edge Cases

**Analyst uses temporary names (e.g., `tmp_check_this`, `sub_140001000_fixme`):**
- These are `provisional` claims.
- Do not require full evidence.
- Do not gate or block provisional claims.
- If later renamed to a substantive label, the provisional claim is revised and the substantive claim gets gated normally.

**Bulk renaming session (50 functions renamed in rapid succession):**
- Claim velocity is high → each claim gets lower individual confidence requirement.
- But aggregate evidence must exist (e.g., functions were explored earlier).
- If no prior exploration: individual claims become `premature`.
- Bulk claims with no receipts: all blocked or marked `provisional`.

**Label is subsequently revised (from `c2_init` to `debug_init`):**
- Original claim marked `revised`.
- Revision reason recorded.
- If revision reason is "label was wrong": calibrate — this entity type should have required more evidence before labeling.
- If revision reason is "new evidence changed understanding": no penalty — claim gates were appropriate, new evidence legitimately changed the answer.

**Label is made on an entity that the kernel has never seen:**
- Entity has no latent role confidence.
- Claim marked `premature` with high confidence.
- Block claim; suggest exploration experiment first.

---

## Hard Problem 9: Cold Start (Revisited After Bootstrap)

Even with the Bootstrap Lab, edge cases remain for the transition from bootstrap priors to live user behavior.

### Non-Bootstrap Cold Start (No Lab Available)

If bootstrap lab cannot run (no binaries, headless CI, minimal deployment):

- All tools start as `uncertain` affordance.
- All tokens start as `unknown` role.
- All thresholds use wide default quantiles (q10 = 0.2, q80 = 0.7).
- Kernel confidence is uniformly low for first 30 decisions.
- Low confidence → soft interventions only (shape, never block).
- After 30 decisions: enough calibration events to compute session-local quantiles.
- After 100 decisions: affordance clusters form, role evidence accumulates.

**This is acceptable because low-confidence mode never hard-blocks. The worst case is the kernel is passive for 20-30 tool calls, which is fine — the LLM can operate without kernel guidance initially.**

### Drift Detection

When user behavior diverges from bootstrap priors:

| Signal | Drift Detected? |
|---|---|
| Override rate on calibrated obligation kind > 2σ above bootstrap expected | Yes |
| Receipt resolution ratio outside bootstrap 90% CI | Yes |
| Claim revision rate > bootstrap q90 | Yes |
| Tool affordance cluster assignments differ from bootstrap by >1 cluster centroid distance | Yes |
| Session novelty score > bootstrap q95 | Yes |

If drift detected:
- Bootstrap blend weight halves.
- If drift persists across 3 sessions: bootstrap weight approaches zero.
- User model takes over.

### Edge Cases

**User changes behavior mid-session (e.g., switches from naming to hunting):**
- Drift detector segments session into episodes.
- Bootstrap blend resets per episode boundary.
- Previous episode's user model carries forward into next episode.

**User has an unusual but correct workflow that defies bootstrap:**
- Drift detector fires.
- But outcome signals are positive (receipts, coverage, claim stability).
- Verdict ensemble disagrees with drift detector.
- Resolution: keep bootstrap but reduce confidence; user model accumulates faster.

---

## Hard Problem 10: Novel Binary / Novel Workflow

### Failure Mode
The system enters unknown territory where all priors (bootstrap or learned) are poorly calibrated.

### Solution: Unknown-Unknown Detector

**Novelty signals:**

| Signal | Measurement |
|---|---|
| New token rate | Tokens with no role evidence / total tokens per observation |
| Low role confidence | Mean role confidence across all tokens < 0.3 |
| Low affordance confidence | Affordance cluster assignment confidence < 0.5 |
| High dispute density | Open disputes / total obligations > 0.3 |
| High frontier entropy | Entropy of frontier node scores > 2σ above session average |
| Calibration sample mismatch | Current decision's feature vector > 2σ from nearest calibration sample |
| High override rate | Overrides per 10 tool calls > 3 |

**Unknown-unknown score (UUS):**

```text
UUS = weighted_average([
  (new_token_rate,          0.25),
  (1 - mean_role_confidence, 0.20),
  (dispute_density,          0.15),
  (frontier_entropy_ratio,   0.15),
  (calibration_mismatch,     0.15),
  (override_rate,            0.10)
])
```

**Behavior by UUS:**

| UUS Range | Behavior |
|---|---|
| 0.0–0.3 | Normal operation; all gates active |
| 0.3–0.5 | Reduce blocking threshold by 0.5; prefer shaping |
| 0.5–0.7 | Disable hard blocking; shape only; increase slicing conservatism |
| 0.7–0.9 | Passive mode: log observations but do not intervene; increase experiment diversity |
| 0.9–1.0 | Emergency mode: do not block; do not shape; log everything for later calibration |

### Edge Cases

**Adversarial LLM tries to exploit uncertainty mode:**
- High-impact actions still require minimum evidence receipts even in uncertainty mode.
- The UUS gates shape/block decisions, not safety-critical state changes.
- Irreversible actions always require receipts regardless of UUS.

**System oscillates between normal and uncertainty mode:**
- Hysteresis: once in uncertainty mode, require 2× normal evidence to exit.
- Prevents rapid mode switching from confusing the LLM.
- Log oscillation events for developer investigation.

**Everything is unknown for too long (entire session in uncertainty):**
- After 50 tool calls in uncertainty mode: generate summary of what WAS learned (even if low confidence).
- Bootstrap lab can be invoked to run targeted games on the novel binary's structure.
- If bootstrap lab produces even weak calibration: promote to low-confidence normal mode.

---

# Revised Implementation Order (With Bootstrap)

With the Bootstrap Lab solving cold-start, the implementation order changes:

## Phase 0: Snapshot + Bootstrap Lab

**Before any behavior changes:**
- Freeze current kernel behind a feature flag (`IDA_MCP_USE_EVIDENCE_ENGINE=0` keeps current behavior).
- All new systems are opt-in until proven.
- Policy versioning infrastructure.

**Build the Bootstrap Lab first:**
- Deterministic trace runner over test fixtures.
- Policy tournament with all synthetic analyst behaviors.
- Scoring system with multi-signal verdicts.
- Bootstrap DB writer (calibration, affordances, roles, policies).
- Bundle bootstrap DBs with the project.

**Why first:** Every other module needs priors. Building the lab first means all modules start calibrated.

## Phase 1: Calibration Engine + Self-Doubt Controller

- Replace fixed thresholds with quantile lookup (backed by bootstrap priors).
- Add calibration event logging to all existing decisions.
- Add DoubtController that reads calibration quality and weakens interventions proportionally.
- Session-local quantile computation; bootstrap blend formula.

## Phase 2: Tool Affordance Profiler + Latent Role Inducer

- Add pre/post snapshot recording in every `observe_result`.
- Profile tool effects from the first call.
- Replace `READ_HEAVY_TOOLS` and `HIGH_IMPACT_ACTIONS` with affordance queries.
- Replace `_extract_bridges` prefix checks with role-based classification.
- Cold start: bootstrap priors provide initial roles and affordances.

## Phase 3: Evidence Slicer + Frontier Planner

- Replace `SemanticCropper` with loss-bounded `EvidenceSlicer`.
- Build analysis graph from observation/role/claim tables.
- Compute frontier scores and integrate into preflight for redirect/shape decisions.
- Generate experiment candidates for unresolved obligations.

## Phase 4: Claim Ledger + Dispute Engine

- Replace immediate Q-update on override with dispute creation.
- Gate high-impact actions with claim evidence sufficiency checks.
- Delayed evidence verdicts for dispute resolution.
- Separate truth, preference, and policy models.

## Phase 5: Policy Replay Engine

- Session trace archival upon session close.
- Background replay worker on high-signal moments.
- Policy comparison and auto-promotion with confidence gates.
- Cross-session policy aggregation.

---

# The Ten Rules (Architecture Invariants)

These must never be violated. Any code review must check these.

1. **Never promote a policy without counterfactual evidence.**
   — Policy changes require replay validation or tournament comparison. No ad-hoc updates.

2. **Never learn truth directly from analyst override.**
   — Override updates preference model only. Truth model requires evidence verdicts.

3. **Never hard-block under low confidence.**
   — If kernel confidence < 0.5, fall back to shape or passive mode. Blocking requires high certainty.

4. **Never crop unless omission is justified.**
   — Every omitted chunk must pass at least one safety proof rule. If unsure, keep it.

5. **Never treat token spelling as semantic role.**
   — Role comes from behavior, not from prefix. `0x` is not a role. A token earns its role from how analysis uses it.

6. **Never trust a single outcome signal.**
   — All verdicts use multi-signal ensembles. Single-signal verdicts are invalid.

7. **Always preserve fallback behavior.**
   — Every new system is opt-in behind an env flag until proven. Current kernel behavior is the fallback.

8. **Always version policies.**
   — Every calibration update and policy change creates a versioned snapshot. Rollback must be possible.

9. **Always separate preference, truth, and policy.**
   — These are different things. They update from different evidence. They must not contaminate each other.

10. **Always let uncertainty weaken enforcement.**
    — High UUS, low confidence, low sample counts → softer interventions. The kernel knows what it doesn't know.
