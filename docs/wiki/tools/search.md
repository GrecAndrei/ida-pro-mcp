# SEARCH Tool Manual

## What It Does
Provides broad binary search capabilities: bytes, strings, names, instruction/text searches, references, smart lookup, callgraph lookups, API usage, vulnerability heuristics, constant hunting, and decompiled-code search.

## Actions
- `bytes`, `string`, `immediate`, `name`, `insns`, `text`, `operand`, `comment`
- `data_ref`, `code_ref`, `regex`, `func_by_sig`
- `find`, `callers`, `callees`, `api`
- `vulnerable`, `constants`, `decompiled`

## Key Parameters
- `action`: One of `bytes|string|immediate|name|insns|text|operand|comment|data_ref|code_ref|regex|func_by_sig|find|callers|callees|api|vulnerable|constants|decompiled`.
- `pattern`: Primary pattern/value/target for most actions.
- `query`: Alias for `pattern`.
- `limit`: Max returned lines.
- `offset`: Skip first N matches.
- `start`, `end`: Optional bounded range (must be provided together).
- `case_sensitive`: Applies to string/text/regex-like matching flows.
- `include_context`: Adds extra disasm/function context in results.
- `include_items`: Include structured `items` arrays (default: `false`).
- `include_breakdown`: Include extra grouped summaries for multi-source actions (`find`, `api`, `vulnerable`).

## Global Wrapper Actions
- All action-based tools support wrapper actions:
  - `action="grep"`: run `source_action`, then filter lines.
  - `action="pick"`: run `source_action`, then keep only top-level fields from `pick_fields`.
  - `action="head"` / `action="tail"`: run `source_action`, then keep first/last `head_n`/`tail_n` rows.
  - `action="stats"`: run `source_action`, then return payload statistics.
  - `action="next"`: continue from `next_token` when a previous response was truncated.
- Shared source-action aliases: `source_action`, `on`, `target_action`, `subaction`.

## Response Contract
- Global pagination fields are now consistent on advanced actions: `offset`, `count`, `total`, `truncated`.
- `matches`: newline-joined compact lines for quick LLM consumption.
- `items`: structured records are opt-in (`include_items=true`) for deterministic tool chaining.
- Hard cap: `limit` is clamped to `500` to prevent runaway context usage.

## Major Upgrades
- `find`: now ranks mixed results (xrefs, names, imports, strings) and returns `type_totals`.
- `callers`/`callees`: now rank by call frequency, support `offset`, and include structured `items`.
- `api`: now supports multi-API wildcard matches and returns `matched_apis` summary with usage ranking.
- `vulnerable`: now includes severity scoring, `type_totals`, and stable pagination.
- `constants`: switched to a single-pass instruction scan (faster/more complete), full `offset` support.
- `decompiled`: supports smart matching modes (plain/glob/regex-like), with paginated structured output.
  - New guardrails: `addr` (function scope), `timeout_ms`, `max_functions`, `sample`, `sample_max_funcs`.
  - Returns scan metadata: `scanned_functions`, `scan_limit`, `timed_out`, and `analysis_truncated` when bounded.

## Examples
```python
search(action="bytes", pattern="55 8B EC", limit=50)
search(action="string", pattern="license", case_sensitive=False)
search(action="immediate", pattern="0x10001", include_context=True)
search(action="find", pattern="malloc")
search(action="find", pattern="malloc", include_items=True, include_breakdown=True)
search(action="callers", pattern="main")
search(action="api", pattern="*CreateProcess*")
search(action="vulnerable", limit=100, include_context=True)
search(action="constants", start="0x401000", end="0x410000")
search(action="decompiled", pattern="memcpy\\s*\\(", limit=20)
search(action="decompiled", addr="0x401000", pattern="strcpy", timeout_ms=12000)
search(action="grep", source_action="find", pattern="malloc", grep="imports")
search(action="head", source_action="vulnerable", head_n=25)
search(action="pick", source_action="find", pattern="malloc", pick_fields="matches,total")
```

## Failure Modes
- Missing `pattern` for actions that require it.
- Invalid range when only one of `start`/`end` is provided.
- Invalid numeric/regex input (`immediate`, `regex`, `decompiled`).
- Target resolution failures for `data_ref`, `code_ref`, `callers`, `callees`, `api`.
- Some actions are heuristic and may produce false positives.
- Any action can return truncated pages (`truncated=true`) when `limit` is reached.
