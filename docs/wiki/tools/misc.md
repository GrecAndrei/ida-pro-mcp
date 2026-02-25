# MISC Tool Manual

## What It Does
Hosts utility operations: execute Python/IDC snippets, schedule FLIRT signature load, inspect cache stats, perform local file read/write, and run host health diagnostics.

## Actions
- `python`: Execute Python expression/script in IDA context.
- `idc`: Evaluate IDC expression/script.
- `load_sig`: Plan FLIRT signature application by name.
- `cache_stats`: Return read-only cache statistics if cache module exists.
- `read_file`: Read host file as text or hex-encoded binary.
- `write_file`: Write host file as text or from hex-encoded binary.
- `plugin_list`: Enumerate available plugins (filesystem-backed where runtime APIs are limited).
- `plugin_run`: Execute a plugin by `name` with optional integer `arg`.
- `health`: Run host/runtime diagnostics (cache dir, IDA path, session/runtime status, wiki availability). Does not require an active session.

## Key Parameters
- `action`: One of `python|idc|load_sig|cache_stats|read_file|write_file|plugin_list|plugin_run|health`.
- `expr` / `code`: Script input for `python` and `idc` (either accepted).
- `name`: Required by `load_sig`.
- `name`: Required by `plugin_run` (plugin name).
- `arg`: Optional integer argument for `plugin_run`.
- `path`: Required by `read_file` and `write_file`.
- `content`: Required by `write_file`.
- `encoding`: Optional text encoding; use `binary` for hex mode.
- `verbose`: Optional boolean for `health`; includes per-runtime detail when true.

## Examples
```python
misc(action="python", expr="idc.get_func_name(here())")
misc(action="idc", expr="GetDisasm(here())")
misc(action="load_sig", name="vc32")
misc(action="cache_stats")
misc(action="read_file", path="/tmp/report.txt")
misc(action="read_file", path="/tmp/blob.bin", encoding="binary")
misc(action="write_file", path="/tmp/out.txt", content="hello")
misc(action="write_file", path="/tmp/out.bin", content="9090", encoding="binary")
misc(action="plugin_list")
misc(action="plugin_run", name="Hex-Rays Decompiler", arg=0)
misc(action="health")
misc(action="health", verbose=True)
```

## Failure Modes
- Missing required `expr/code`, `name`, `path`, or `content`.
- Syntax/runtime exceptions from executed Python/IDC code.
- Invalid binary hex input for `write_file`.
- File not found/not-file for `read_file`.
- Unknown action returns error payload.
