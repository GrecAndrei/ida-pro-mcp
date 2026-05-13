# filter

JQ-like post-processing filter applied to any tool output for field selection and transformation.

## Actions
- `filter` — apply a filter expression to a previous tool result; params: `expression`, `source_tool`, `source_action`, `source_args`

## Examples
```json
{"name": "filter", "arguments": {"action": "filter", "expression": ".functions[] | select(.size > 100) | .name", "source_tool": "data", "source_action": "functions"}}
```

## Notes
- Runs the source tool first, then applies the filter expression to its output.
- Expression syntax follows JQ-like path/select/projection semantics.
- Useful for reducing large outputs to only the fields you need.
