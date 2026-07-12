# Workflow: Triage an Unknown Binary

## Goal

Go from unknown binary to actionable understanding in a single pass.

## Steps

### 1. Create session

```json
{"name": "session", "arguments": {"action": "create", "binary_path": "/path/to/binary"}}
```

### 2. Gather baseline metadata

```json
{"name": "batch", "arguments": {"calls": [
  "idb:meta",
  {"name": "data", "action": "imports"},
  {"name": "data", "action": "strings", "count": 100}
]}}
```

### 3. Build the semantic index

```json
{"name": "intelligence", "arguments": {"action": "index_fast"}}
```

Indexes functions for semantic search and behavior classification.

### 4. Classify the binary

```json
{"name": "classify", "arguments": {"action": "binary"}}
```

### 5. Run fast triage

```json
{"name": "workflow", "arguments": {"action": "triage_fast"}}
```

### 6. Generate summary report

```json
{"name": "summarize", "arguments": {"action": "report"}}
```

### 7. Drill into interesting clusters

For each interesting cluster address:

```json
{"name": "code", "arguments": {"action": "decompile", "address": "0x..."}}
{"name": "classify", "arguments": {"action": "function", "address": "0x..."}}
```

### 8. Suggest names for unnamed functions

```json
{"name": "funcs", "arguments": {"action": "suggest_names"}}
```

Uses FunctionEmbeddingIndex cosine similarity to propose meaningful names. Rename propagation will then suggest names for callees automatically.

### 9. Search blackboard for prior findings

```json
{"name": "blackboard", "arguments": {"action": "search", "query": "relevant keyword"}}
```

The blackboard auto-captures findings from all previous steps. Search it to correlate with prior sessions.

## Expected Outcome

- Binary classified by type and threat level
- Functions grouped by behavior
- Key functions named and annotated
- Findings persisted to blackboard for future reference
