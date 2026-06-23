# predictor

Deterministic prediction and strategy suggestions using session state.

## Actions
- `suggest_next_tool` — suggest the next tool to call; params: `context` (optional)
- `detect_stuck` — detect if analysis is stuck/looping
- `suggest_focus` — suggest where to focus next
- `suggest_next_address` — suggest next address to analyze
- `risk_of_stall` — estimate risk of analysis stalling
- `recommend_bundle` — bundle next-tool + focus + address + stall-risk recommendations in one response
- `explain_decision` — explain why a target tool/action was suggested

## Examples
```json
{"name": "predictor", "arguments": {"action": "suggest_next_tool"}}
```
```json
{"name":"predictor","arguments":{"action":"recommend_bundle","context":"network beacon c2","limit":3}}
```

## Notes
- Uses session activity log for prediction.
- `suggest_focus` and `suggest_next_address` now also use embedding-index lookups when `context` is provided, returning semantic target candidates even with sparse blackboard state.
- `detect_stuck` helps agents break out of unproductive loops.
- All predictions are deterministic (no LLM inference).
