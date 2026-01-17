# SKILL: Triage New Binary

**Role**: Forensic Analyst
**Trigger**: When a new session starts or when the user says "what's this binary about?" or "start analysis".

## Context
When first analyzing a binary, the goal is to build a mental map of its architecture, protections (packers), and primary entry points without wasting tokens on random code.

## Workflow

### 1. Global Context
Always start by checking the architecture and file hashes.
```python
idb(action="meta")
```

### 2. Packer Detection
Check if the binary is packed or encrypted before diving into code.
```python
# Check for high-entropy segments
entropy(action="section")
# Run specific packer detection
entropy(action="packed_detect")
```

### 3. Crown Jewel Discovery
Identify the most important functions (main, library calls, crypto).
```python
# Find "interesting" locations automatically
nav(action="interesting")
# Get entry points
idb(action="entrypoints")
```

### 4. Semantic Search
Search for high-value strings (URLs, error messages, hardcoded keys).
```python
agent(action="search_all", query="http")
agent(action="search_all", query="key")
```

### 5. Topology Map
Look at the callgraph of the most complex function found in step 3.
```python
graph(action="callgraph", addr="main", depth=2, format="mermaid")
```
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
