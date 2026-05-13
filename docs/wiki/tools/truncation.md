# truncation

Continues a previously truncated response that exceeded the character budget.

## Actions
- `continue` — retrieve the next chunk of a truncated response. Optional `token` (continuation token from previous response)

## Examples
```json
{"name": "truncation", "arguments": {"action": "continue"}}
```

## Notes
- Only use when a previous response indicated truncation with a continuation token.
- Prefer narrowing queries (filters, smaller `count`) over repeated continuation calls.
