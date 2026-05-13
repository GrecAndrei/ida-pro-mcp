# predictor

Deterministic prediction and strategy suggestions using crystallized skills and session state.

## Actions
- `suggest_next_tool` — suggest the next tool to call; params: `context` (optional)
- `detect_stuck` — detect if analysis is stuck/looping
- `suggest_focus` — suggest where to focus next
- `suggest_next_address` — suggest next address to analyze
- `risk_of_stall` — estimate risk of analysis stalling
- `explain_decision` — explain why a suggestion was made; params: `suggestion_id`

## Examples
```json
{"name": "predictor", "arguments": {"action": "suggest_next_tool"}}
```
```json
{"name": "predictor", "arguments": {"action": "detect_stuck"}}
```

## Notes
- Uses crystallized skills (MemRL Q-values) and session activity log.
- `detect_stuck` helps agents break out of unproductive loops.
- All predictions are deterministic (no LLM inference).
