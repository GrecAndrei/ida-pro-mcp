# TRACE Tool Manual

## What It Does
Reads and controls IDA debugger trace data (trace entries, clearing traces, trace option toggles).

## Actions
- `get`: Returns trace events (`idx`, `addr`, `type`) up to `count`, optionally filtered by exact `addr` string.
- `clear`: Clears current debugger trace buffer.
- `set_options`: Enables/disables instruction/function/basic-block tracing when supported by the IDA build.

## Key Parameters
- `action`: `get|clear|set_options`.
- `addr`: Optional exact address filter for `get` (expects same hex string form as emitted entries).
- `count`: Max events for `get`.
- `enable_insn`, `enable_func`, `enable_bblk`: Optional booleans for `set_options`.

## Examples
```json
{"name":"trace","arguments":{"action":"get","count":200}}
```

```json
{"name":"trace","arguments":{"action":"set_options","enable_insn":true,"enable_func":true,"enable_bblk":false}}
```

```json
{"name":"trace","arguments":{"action":"clear"}}
```

## Failure Modes
- Requires active debugger session for all actions.
- Older/newer IDA builds may lack trace APIs; `get` can return not-implemented.
- Some toggle flags/functions are build-dependent; `set_options` may partially apply or fail as unsupported.
- Unknown action returns invalid-args error.
