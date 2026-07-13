# IDA Pro MCP Quick Start

The default MCP surface uses exact `ida_*` operations. Their schemas are
complete; use `ida_help` when an operation needs more explanation.

## Open and orient

```json
{"name":"ida_open_binary","arguments":{"binary_path":"/path/to/binary"}}
{"name":"ida_session_state","arguments":{}}
{"name":"ida_overview","arguments":{}}
```

`ida_session_state` reports current analysis progress. Poll
`ida_session_status` when IDA is still analyzing; do not call the removed
`analysis(action='wait')` action.

## Find and inspect code

```json
{"name":"ida_find","arguments":{"query":"main","limit":10}}
{"name":"ida_decompile","arguments":{"address":"0x401000"}}
{"name":"ida_disassemble","arguments":{"address":"0x401000","limit":80}}
```

Pass addresses from results verbatim. Build an index before semantic search:

```json
{"name":"ida_index_functions","arguments":{}}
{"name":"ida_semantic_search","arguments":{"query":"function that decrypts strings","mode":"quick"}}
```

## Save findings and make edits

```json
{"name":"ida_write_finding","arguments":{"title":"recv handler","content":"Parses inbound packets.","address":"0x401000","confidence":0.8}}
{"name":"ida_rename","arguments":{"address":"0x401000","name":"handle_recv","risk_ack":true}}
```

Use `ida_next_target` for prioritized next work and `ida_continue` for a
truncated result. For help, call `ida_help(topic="ida_decompile")`.
