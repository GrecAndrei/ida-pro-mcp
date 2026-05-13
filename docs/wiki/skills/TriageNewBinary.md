# Skill: Triage New Binary

**Goal:** Understand what a binary does in <10 tool calls.

## Key Sequence

```
agent(action="cluster")
  → threat_hunt(action="quick")
  → summarize(action="report")
  → blackboard(action="search", query="...")
```

## When to Use

- First encounter with an unknown binary
- Need quick classification before deep analysis
- Prioritizing which binaries to analyze in a batch

## Smart Features Used

| Feature | Role |
|---------|------|
| BehaviorClassifier | Groups functions by behavior (zero-shot, bge-code-v1) |
| FunctionEmbeddingIndex | Powers similarity search for naming |
| Blackboard | Auto-captures all findings, enables cross-session correlation |

## Minimal Example

```json
{"name": "batch", "arguments": {"calls": [
  "session:create binary_path=/path/to/bin",
  "agent:cluster",
  "threat_hunt:quick",
  "summarize:report"
]}}
```

Then search blackboard for related prior work:

```json
{"name": "blackboard", "arguments": {"action": "search", "query": "similar_indicator"}}
```

## Exit Criteria

- Binary type and threat level known
- Major behavioral clusters identified
- Decision made: deep-dive or deprioritize
