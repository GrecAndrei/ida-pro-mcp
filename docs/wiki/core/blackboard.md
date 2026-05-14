# Blackboard Architecture

The blackboard is the persistent knowledge layer of ida-pro-mcp. It has three components that work together:

1. **BlackboardStore** — flat findings table (hypotheses, IOCs, vulns, regions, etc.)
2. **KnowledgeGraph** — structured firmware understanding (systems, structs, state machines, gaps, attack surface, peripherals)
3. **AnalysisEngine** — background pipeline that writes to both

## How It Works

```
IDA analysis
    ↓
AnalysisEngine (8 stages, background thread)
    ↓ writes
BlackboardStore + KnowledgeGraph
    ↓ triggers
notifications/resources/updated → ida://state refreshes
    ↓
LLM reads ida://state → narrative story → oriented in one shot
LLM reads ida://proposals → approves batch actions
```

The LLM never needs to poll. The engine pushes.

## BlackboardStore

SQLite table with 28 columns. Key design decisions:

- **Flat by design** — every finding is a row, queryable by category/addr/tag/confidence
- **Evidence chains** — each entry has a `evidence` JSON field: `[{type, value, weight, ts}]`. Confidence is calibrated from evidence weights, not set arbitrarily.
- **Source typing** — `source_type` distinguishes `engine_classifier` from `human` from `engine_taint`. The LLM can weight them differently.
- **Versioning** — `version` increments on every update. Detect when a finding has been revised.
- **Time decay** — `next_target` applies `exp(-age_days * 0.05)` so old hypotheses don't dominate the priority queue.
- **Rejection feedback** — rejected proposals write `resolved=1` dead_end entries. The engine won't re-propose the same address.

## KnowledgeGraph

Six separate SQLite tables in the same `.blackboard.db` file:

| Table | Purpose |
|---|---|
| `kg_systems` | Call-graph clusters implementing one capability (e.g. "Packet RX pipeline") |
| `kg_structs` | Inferred data structures with member offsets and access sites |
| `kg_state_machines` | Detected state machines with transitions and handlers |
| `kg_gaps` | Expected-but-not-found capabilities with hints and candidates |
| `kg_attack_surface` | Reachability from external inputs with fuzz priority |
| `kg_peripherals` | MMIO peripheral map with register access patterns |

Separate tables (not JSON blobs in the blackboard) because each has different query patterns:
- Gaps are queried by priority
- Structs are queried by offset pattern overlap
- Attack surface is queried by reachability

Access via `ida://knowledge/*` resources or directly via `KnowledgeGraph` in Python.

## AnalysisEngine Stages

Runs in a background thread per session, started after indexing completes.

| Stage | Trigger | What it does |
|---|---|---|
| 1. Classifier sweep | Every 60s | BehaviorClassifier on unnamed functions → `rename_batch` proposals |
| 2. Contradiction monitor | Reactive | Cosine scan on new entries → flags cross-category conflicts |
| 3. Taint tracer | Reactive | IOC/import sources → BFS through xrefs → dangerous sinks → `vuln` entries |
| 4. Cross-session matcher | Reactive | New embeddings vs other session `*.embeddings.db` → name import proposals |
| 5. Crawler feed | Reactive | Auto-accepts high-confidence (>0.75) crawler proposals |
| 6. Entropy scan | Every 120s | Byte entropy per segment → high-entropy regions → `region` entries |
| 7. Auto-tag propagate | Every 300s | Propagates tags from high-conf entries to same-address entries |
| 8. Knowledge graph | Every 90s | System discovery, struct inference, state machine detection, peripheral detection, gap filling, narrative regeneration |

## GapEngine

Encodes domain knowledge about what a binary type must contain.

**WiFi firmware** (10 gaps): Packet RX interrupt handler, 802.11 frame classifier, WPA2 key derivation, 4-way handshake handler, beacon parser, channel switching, power management state machine, host interface (SDIO/SPI/USB), regulatory domain table, firmware version string.

**Router firmware** (3 gaps): NAT/firewall, DHCP server, DNS resolver.

**BLE firmware** (2 gaps): GATT server, L2CAP handler.

**Generic** (3 gaps): Hardware init sequence, interrupt vector table, memory allocator.

Gaps are seeded on first analysis. The engine tries to fill them by keyword-matching blackboard entries against gap hints. Filled gaps increase the coverage percentage shown in `ida://state`.

## NarrativeEngine

Generates a plain-text firmware analysis story from KG + blackboard state. Written to a `narrative` category entry every 2 minutes.

`ida://state` returns this narrative as `text/plain` when available (with a compact JSON header for machine parsing). After a context reset, the LLM reads one resource and knows:

- What binary this is (arch, size, type)
- What systems have been found and their coverage
- What gaps remain (expected but not found)
- Attack surface and known vulns
- Exactly what to do next (single recommended action)

## Proposal Interface

The engine generates proposals that the LLM approves or rejects in batch:

| Type | What it proposes |
|---|---|
| `rename_batch` | Rename N unnamed functions based on BehaviorClassifier |
| `annotation_batch` | Add comments to N functions |
| `cross_session` | Import names from a previous session (similarity > 0.85) |
| `vuln` | Taint trace found a dangerous sink |
| `hypothesis` | Engine believes X about address Y |

Read `ida://proposals` → call `blackboard(action="accept_proposal", scope="all")` to apply the whole batch. One call applies 15 renames.

Rejected proposals write `dead_end` entries with `resolved=1` so the engine doesn't re-propose the same addresses.

## UsageIntelligence

Passive observer that mines audit JSONL logs and learns from LLM behavior:

- **SequenceModel** — Markov chain over `(tool, action)` pairs. Predicts what the LLM will call next.
- **EffectivenessModel** — EMA scoring of tool combinations by productive outcome. "decompile → classify → blackboard.write" = 0.73 effectiveness.
- **DriftDetector** — Detects stuck patterns: `ANALYZE_WITHOUT_RECORD` (many decompile calls, no blackboard writes), `REPEATED_ADDR` (same address analyzed 4+ times), `HIGH_ERROR_RATE`, `LOOP`.

Pushes `notifications/message` on warning signals. Read `ida://usage` for the global report.

## File Layout

```
~/.local/state/ida-pro-mcp/
  {session_id}.blackboard.db     ← BlackboardStore + KnowledgeGraph (same file)
  {session_id}.proposals.db      ← ProposalStore
  {session_id}.embeddings.db     ← FunctionEmbeddingIndex
  audit/YYYY-MM/audit_YYYY-MM-DD.jsonl  ← AuditLogger (mined by UsageIntelligence)
```

## MCP Resources

| URI | Returns |
|---|---|
| `ida://state` | Narrative story (text/plain) or JSON stats |
| `ida://proposals` | Pending engine proposals |
| `ida://blackboard` | All active findings |
| `ida://blackboard/next_target` | Priority-ranked next addresses |
| `ida://blackboard/iocs` | IOC entries |
| `ida://blackboard/hypotheses` | Hypothesis entries |
| `ida://blackboard/regions` | Memory region annotations |
| `ida://knowledge` | KG summary |
| `ida://knowledge/systems` | Identified systems |
| `ida://knowledge/structs` | Inferred data structures |
| `ida://knowledge/gaps` | Open and filled gaps |
| `ida://knowledge/attack_surface` | Attack surface map |
| `ida://knowledge/peripherals` | Peripheral map |
| `ida://knowledge/state_machines` | Detected state machines |
| `ida://usage` | Usage intelligence report |
