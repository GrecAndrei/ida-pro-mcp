# llm_helpers

Context-optimized helpers for LLM agents. Start with `bootstrap` if the model is unfamiliar with this MCP, then `cheatsheet`.

## Quick Start

```json
{"name": "llm_helpers", "arguments": {"action": "bootstrap"}}
{"name": "llm_helpers", "arguments": {"action": "cheatsheet"}}
```

Returns a complete, up-to-date reference of every tool with concrete examples. Read this at the start of any analysis session.

---

## Core Actions

### bootstrap
Opinionated first-turn playbook for unfamiliar LLMs. Returns concrete `first_calls` and operating rules to prevent random decompile-first loops.

### cheatsheet
Full tool reference with concrete examples, organized by task. Read this first.

### context_window
Show current token usage and remaining budget. Params: `addr` (optional, for function context).

### function_digest
Compact one-line summary of a function. Params: `addr`.

### binary_digest
High-level binary overview: sections, imports, entry points, architecture.

### explain_address
Human-readable explanation of what lives at an address. Params: `addr`.

### suggest_next
Recommend next analysis steps based on session history. Params: `history` (optional).

### progress_report
Summarize what has been analyzed and what remains. Params: `history` (optional).

### focus_area
Identify the most promising area to investigate next. Params: `query` (optional goal).

### question_answer
Answer a natural-language question about the binary. Params: `query`.

### compact
Reduce tool output to fit context window. Params: `query` (text to compact).

### enrich
Add confidence scores and suggested next actions to any tool output.

### guided_analysis
Step-by-step analysis guidance for a specific goal. Params: `query`, `addr`.

---

## Security Analysis Actions

### dangerous_pattern_explainer
Explain why a code pattern is dangerous, what exploitation looks like, and how to mitigate it.

```json
{"name": "llm_helpers", "arguments": {"action": "dangerous_pattern_explainer", "addr": "0x401000"}}
```

Returns: `dangerous_patterns` list with `api`, `vuln_type`, `why_dangerous`, `exploitation`, `mitigation`. Also runs BehaviorClassifier for additional context.

**When to use**: When `code(smart_decompile)` returns dangerous_patterns or when taint finds a sink.

### api_contract_extractor
Infer what a function expects (preconditions) and returns (postconditions) by analyzing all call sites.

```json
{"name": "llm_helpers", "arguments": {"action": "api_contract_extractor", "addr": "0x401000"}}
```

Returns: `call_patterns` (how callers use it), `return_patterns`, `inferred_contract` with behavior tags.

### global_state_influence_mapper
Map which global variables a function reads and writes.

```json
{"name": "llm_helpers", "arguments": {"action": "global_state_influence_mapper", "addr": "0x401000"}}
```

Returns: `reads`, `writes` lists with addr/name/size, `summary` ("pure function" or lists modified globals).

### interprocedural_data_lineage_graph
Trace how data flows from a source through function calls to sinks. Delegates to `taint(action='paths')`.

```json
{"name": "llm_helpers", "arguments": {"action": "interprocedural_data_lineage_graph", "addr": "0x401000", "query": "recv"}}
```

---

## Classification Actions

### function_role_classifier
Classify a function's architectural role: entry_point, callback, handler, parser, dispatcher, wrapper, crypto_primitive, etc.

```json
{"name": "llm_helpers", "arguments": {"action": "function_role_classifier", "addr": "0x401000"}}
```

Combines structural signals (callers=0 → entry_point, 1 callee → wrapper, 15+ callees → dispatcher) with BehaviorClassifier embeddings.

Returns: `primary_role`, `confidence`, `all_roles[]`, `callers`, `callees`, `size`.

### behavioral_signature_search
Find all functions matching a behavioral signature using BehaviorClassifier (bge-code-v1 embeddings).

```json
{"name": "llm_helpers", "arguments": {"action": "behavioral_signature_search", "query": "network_http", "limit": 20}}
```

More precise than `search(action='behavior')` — decompiles each function and runs the full classifier.

---

## Comparison / Diff Actions

### semantic_diff_explainer
Explain behavioral differences between two functions using embedding cosine distance + BehaviorClassifier tag diff.

```json
{"name": "llm_helpers", "arguments": {"action": "semantic_diff_explainer", "addr": "0x401000", "query": "0x402000"}}
```

Returns: `embedding_similarity`, `shared_behaviors`, `only_in_a`, `only_in_b`, `summary`.

---

## Search Actions

### decompile_disasm_consistency_search
Find functions where decompiler output and disassembly disagree on call structure.

```json
{"name": "llm_helpers", "arguments": {"action": "decompile_disasm_consistency_search", "limit": 20}}
```

### argument_semantics_search
Find functions where an argument has a specific semantic role.

```json
{"name": "llm_helpers", "arguments": {"action": "argument_semantics_search", "query": "buffer pointer", "addr": "1"}}
```

### path_constrained_search
Find functions reachable from a start address, optionally filtered by behavior tag.

```json
{"name": "llm_helpers", "arguments": {"action": "path_constrained_search", "addr": "0x401000", "query": "crypto"}}
```

### cross_artifact_correlation_search
Correlate findings across strings, names, imports, and blackboard by query. Returns unified ranked results.

```json
{"name": "llm_helpers", "arguments": {"action": "cross_artifact_correlation_search", "query": "AES"}}
```

---

## Planning Actions

### intent_tool_compiler
Translate a natural-language analysis goal into a multi-step tool call sequence.

```json
{"name": "llm_helpers", "arguments": {"action": "intent_tool_compiler", "query": "find all network input handlers"}}
```

### adaptive_query_planner
Plan multi-step queries adapting to the current binary type and evidence.

### question_type_router
Route a question to the appropriate analysis workflow (vulnerability_triage, crypto_analysis, protocol_reconstruction, etc.).

---

## Workflow

Recommended session start:
```
1. llm_helpers(action='bootstrap')             → concrete onboarding calls + rules
2. llm_helpers(action='cheatsheet')            → full tool reference
3. ida://state                                 → current analysis state + next actions
4. ida://blackboard/frontier                   → ranked unvisited functions
5. code(action='smart_decompile', addrs='...') → analyze top frontier target
6. blackboard(action='write', ...)             → record findings (triggers label propagation)
```
