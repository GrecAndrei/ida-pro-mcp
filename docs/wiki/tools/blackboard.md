# blackboard

Firmware RE knowledge base and persistent working memory. SQLite-backed, survives context resets. The engine writes to it automatically; you read from it to stay oriented.

**Read `ida://state` first** — it returns a narrative built from the blackboard. Read `ida://blackboard/next_target` for the highest-priority address to analyze next.

## Categories

| Category | Purpose |
|---|---|
| `hypothesis` | Unconfirmed beliefs about a function or region |
| `vuln` | Vulnerability findings (taint traces, dangerous sinks) |
| `ioc` | Indicators of compromise (IPs, keys, URLs, magic bytes) |
| `region` | Annotated memory regions (driver boundaries, subsystems) |
| `dead_end` | Resolved/skip markers — excluded from `next_target` |
| `dependency` | "Must understand X before Y" task graph |
| `data_flow` | Register/variable state at a function boundary |
| `cross_session` | Matches from previous session embedding indexes |
| `narrative` | Auto-generated analysis story (written by engine) |
| `general` | Catch-all |

## Core CRUD

```json
{"name": "blackboard", "arguments": {"action": "write", "title": "AES key schedule", "category": "hypothesis", "addr": "0x401000", "confidence": 0.8, "evidence": [{"type": "constant", "value": "0x63636363", "weight": 0.9}]}}
{"name": "blackboard", "arguments": {"action": "read", "entry_id": "abc12345"}}
{"name": "blackboard", "arguments": {"action": "list", "category": "vuln", "include_resolved": false}}
{"name": "blackboard", "arguments": {"action": "search", "query": "crypto key schedule", "top_k": 5}}
{"name": "blackboard", "arguments": {"action": "update", "entry_id": "abc12345", "confidence": 0.95}}
{"name": "blackboard", "arguments": {"action": "delete", "entry_id": "abc12345"}}
{"name": "blackboard", "arguments": {"action": "stats"}}
{"name": "blackboard", "arguments": {"action": "prune", "min_q_value": 0.3, "older_than_days": 7}}
```

## Lifecycle Actions

```json
{"name": "blackboard", "arguments": {"action": "contradict", "entry_id": "abc12345", "reason": "Found it calls malloc — not a custom allocator"}}
{"name": "blackboard", "arguments": {"action": "resolve", "entry_id": "abc12345"}}
```

- `contradict` — marks an entry as disproved. Stays visible but flagged; excluded from `next_target` by default.
- `resolve` — marks as dead end. Excluded from `next_target`. Use when you've confirmed a function is uninteresting.

## Priority Queue

```json
{"name": "blackboard", "arguments": {"action": "next_target", "limit": 5}}
```

Returns the highest-priority unexplored addresses. Score = `confidence × category_boost × time_decay × (1 + xref_boost)`.

- Time decay: score halves every ~14 days — old hypotheses don't dominate
- Xref boost: more callers = higher priority
- Entropy boost: high-entropy regions get +15%
- Blocked entries (unresolved `depends_on`) are deprioritized
- When blackboard is sparse, seeds from xref-ranked unnamed functions

## Evidence & Calibration

```json
{"name": "blackboard", "arguments": {"action": "add_evidence", "entry_id": "abc12345", "evidence_type": "constant", "evidence_value": "0x63636363", "evidence_weight": 0.9}}
{"name": "blackboard", "arguments": {"action": "calibrate", "entry_id": "abc12345"}}
```

- `add_evidence` — append a structured evidence record `{type, value, weight}`. Types: `constant`, `string`, `import`, `xref`, `decompile`, `classifier`, `taint`, `cross_session`, `human`
- `calibrate` — recalculate `confidence` as weighted average of evidence records. Marks entry as `calibrated=1`.

## Campaign Summary

```json
{"name": "blackboard", "arguments": {"action": "campaign_summary"}}
```

Returns: total/active/resolved/contradicted counts, top findings by category, IOCs, vulns, source type breakdown, evidence count, and a `recommended_next_action` string.

## Tag Propagation

```json
{"name": "blackboard", "arguments": {"action": "auto_tag_propagate"}}
```

Propagates tags from high-confidence (>0.8) entries to other entries at the same address. Run after a batch of classifier results to spread behavior tags.

## Background Crawler

```json
{"name": "blackboard", "arguments": {"action": "start_crawler"}}
{"name": "blackboard", "arguments": {"action": "crawler_status"}}
{"name": "blackboard", "arguments": {"action": "accept", "proposal_id": "p1234"}}
{"name": "blackboard", "arguments": {"action": "reject", "proposal_id": "p1234"}}
{"name": "blackboard", "arguments": {"action": "stop_crawler"}}
```

The crawler follows xrefs from known blackboard addresses, classifies reachable unnamed functions with BehaviorClassifier, and proposes them via `notifications/message`. Rejected proposals write `dead_end` entries so the engine doesn't re-propose.

## Engine Proposals (Batch)

```json
{"name": "blackboard", "arguments": {"action": "accept_proposal", "proposal_id": "pid123", "scope": "all"}}
{"name": "blackboard", "arguments": {"action": "accept_proposal", "proposal_id": "pid123", "scope": "selected", "selected_ids": ["a", "b"]}}
{"name": "blackboard", "arguments": {"action": "reject_proposal", "proposal_id": "pid123"}}
```

The analysis engine generates `rename_batch`, `cross_session`, `vuln`, and `annotation_batch` proposals. Read `ida://proposals` to see pending ones. `accept_proposal` applies them to IDA (renames, comments). `reject_proposal` dismisses and writes rejection feedback.

## IOC Writing

```json
{"name": "blackboard", "arguments": {"action": "write", "title": "Hardcoded C2 IP", "category": "ioc", "ioc_type": "ip_port", "ioc_value": "192.168.1.1:8080", "addr": "0x401234", "confidence": 0.99}}
```

IOC types: `ip_port`, `url`, `domain`, `crypto_key`, `crypto_iv`, `magic_bytes`, `file_path`, `registry_key`

## Region Writing

```json
{"name": "blackboard", "arguments": {"action": "write", "title": "WiFi driver region", "category": "region", "addr": "0x80410000", "addr_end": "0x80420000", "entropy": 7.2, "confidence": 0.8}}
```

## Dependency Graph

```json
{"name": "blackboard", "arguments": {"action": "write", "title": "Must understand 0x8040100 before 0x8041200", "category": "dependency", "addr": "0x8041200", "depends_on": "0x8040100"}}
```

Entries with `depends_on` pointing to an unresolved address are deprioritized in `next_target`. Once the dependency is resolved, the blocked entry gets a 1.5× priority boost.

## MCP Resources

| URI | Contents |
|---|---|
| `ida://blackboard` | All active (non-resolved, non-contradicted) entries |
| `ida://blackboard/next_target` | Priority-ranked next addresses |
| `ida://blackboard/iocs` | IOC entries |
| `ida://blackboard/hypotheses` | Hypothesis entries |
| `ida://blackboard/regions` | Memory region annotations |
| `ida://blackboard/{category}` | Entries by category |

## Schema Fields

| Field | Type | Purpose |
|---|---|---|
| `id` | TEXT | 8-char UUID prefix |
| `category` | TEXT | Entry type (see Categories above) |
| `title` | TEXT | Short description |
| `content` | TEXT | Full evidence/reasoning |
| `addr` | TEXT | Primary address (hex string) |
| `addr_end` | TEXT | End address for regions |
| `confidence` | REAL | 0.0–1.0, calibrated from evidence |
| `source_type` | TEXT | `engine_classifier`, `engine_taint`, `engine_cross_session`, `human`, `crawler` |
| `evidence` | JSON | `[{type, value, weight, ts}]` |
| `version` | INT | Incremented on every update |
| `entropy` | REAL | Byte entropy 0–8 |
| `xref_count` | INT | Number of callers |
| `resolved` | INT | 1 = dead end, excluded from next_target |
| `contradicted` | INT | 1 = disproved |
| `ioc_type` | TEXT | IOC classification |
| `ioc_value` | TEXT | IOC value |
| `depends_on` | TEXT | Address this entry is blocked on |
| `register` | TEXT | Register name (data_flow entries) |
| `reg_type` | TEXT | Register type annotation |
