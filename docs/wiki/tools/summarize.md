# summarize

Generates structured summaries and reports from binary analysis data without requiring additional LLM round-trips.

## Actions
- `binary` — high-level binary summary (purpose, architecture, key characteristics)
- `function` — summarize a single function including behavior_tags; params: `address`
- `segment` — summarize a segment's contents; params: `segment`
- `imports_by_category` — group and summarize imports by functional category
- `strings_by_category` — group and summarize strings by type/purpose
- `complexity` — summarize complexity distribution across functions
- `call_hierarchy` — summarize call graph structure; params: `address`, `depth`
- `data_flow` — summarize data flow for a function; params: `address`
- `security_posture` — summarize security-relevant findings (mitigations, vulns, crypto)
- `statistics` — raw numerical statistics about the binary
- `report` — assemble a full structured report from blackboard + binary analysis

## Examples

```json
{"name": "summarize", "arguments": {"action": "function", "address": "0x401000"}}
```

```json
{"name": "summarize", "arguments": {"action": "report"}}
```

## Notes
- `report` assembles data entirely from the blackboard and deterministic analysis — no LLM round-trips needed for data gathering. Best used after substantial analysis has populated the blackboard.
- `function` includes `behavior_tags` from BehaviorClassifier, giving semantic labels alongside structural summary.
- Use `security_posture` as a quick triage entry point to identify the most security-relevant areas before deep-diving.
