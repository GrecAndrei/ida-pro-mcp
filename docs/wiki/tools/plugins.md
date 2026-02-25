# PLUGINS Tool Manual (Legacy Alias)

## What It Does
`plugins` is maintained for compatibility. Primary plugin operations now live under `misc`.

## Actions
- Legacy alias only.
- Use `misc(action="plugin_list")`.
- Use `misc(action="plugin_run", name="...", arg=0)`.

## Key Parameters
- `action`: legacy `list|run` still accepted.
- `name`: plugin display/internal name (legacy `run` or `misc(plugin_run)`).
- `arg`: integer plugin argument (legacy `run` or `misc(plugin_run)`).

## Examples
```python
misc(action="plugin_list")
misc(action="plugin_run", name="Hex-Rays Decompiler", arg=0)
```

## Failure Modes
- `list` returns `NOT_IMPLEMENTED` on newer IDA versions.
- Missing `name` for `run`.
- Plugin not found by `find_plugin`.
- Plugin run failure reported by IDA.
