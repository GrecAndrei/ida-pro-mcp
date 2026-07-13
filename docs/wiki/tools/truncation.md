# truncation

Continues a previously truncated response that exceeded the character budget.

## Actions
- `continue` — retrieve the next chunk of a truncated response. Pass the `token` from `_continue.token`. If `_continue.fields` contains multiple names, `field` is required and must exactly match one of those names. `offset` and `count` are optional.

## Examples
```json
{"name": "truncation", "arguments": {"action": "continue", "token": "ABC123", "field": "code"}}
```

## Notes
- Only use when a previous response indicated truncation with a continuation token.
- Read `_continue.fields` before continuing. Select a field explicitly when more than one field is listed.
- Prefer narrowing queries (filters, smaller `count`) over repeated continuation calls.
