# PLUGINS Tool Manual

## What It Does
Runs IDA plugins by name and exposes plugin-list behavior where supported by the installed IDA version.

## Actions
- `list`: Attempt to list plugins.
- `run`: Execute a plugin by name.

## Key Parameters
- `action`: One of `list|run`.
- `name`: Required for `run`; plugin display/internal name.
- `arg`: Integer argument passed to plugin entry (`run_plugin`).

## Examples
```python
plugins(action="list")
plugins(action="run", name="Hex-Rays Decompiler", arg=0)
```

## Failure Modes
- `list` returns `NOT_IMPLEMENTED` on newer IDA versions.
- Missing `name` for `run`.
- Plugin not found by `find_plugin`.
- Plugin run failure reported by IDA.
