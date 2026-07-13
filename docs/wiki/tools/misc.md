# misc

Utility operations: script execution, file I/O, signature loading, plugin management, and cache stats.

The default agent surface exposes Python execution as `ida_python`; use
`ida_python(code="...", risk_ack=true)` for an explicitly acknowledged
IDA-side expression or script. The action-specific operation is policy-gated
and does not require the legacy `action="python"` wrapper.

## Actions
- `python` — execute Python code in IDA context. Params: `code`
- `idc` — execute IDC script. Params: `code`
- `load_sig` — load a FLIRT signature file. Params: `path` or `name`
- `cache_stats` — show internal cache statistics
- `read_file` — read a file from disk. Params: `path`, optional `offset`, `size`
- `write_file` — write content to a file. Params: `path`, `content`
- `plugin_list` — list available IDA plugins
- `plugin_run` — run an IDA plugin. Params: `name`, optional `args`

## Examples
```json
{"name": "misc", "arguments": {"action": "python", "code": "print(idaapi.get_imagebase())"}}
```
```json
{"name": "misc", "arguments": {"action": "plugin_list"}}
```

## Notes
- `python` and `idc` execute arbitrary code in the IDA process — use with care.
- The legacy `plugins` tool name is an alias for `misc` (plugin_list/plugin_run actions).
- `write_file` is a write operation subject to guardrail strict mode.
