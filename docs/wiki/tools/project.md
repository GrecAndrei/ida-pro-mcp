# PROJECT Tool Manual

## What It Does
Handles IDB/project lifecycle and filesystem operations exposed through the MCP tool layer.

## Actions
- `save`: Save current database.
- `close`: Close current database (headless-only support).
- `open`: Open database/binary path (headless-only support path).
- `load_binary`: Load additional binary data at an optional base address.
- `list_recent`: Return recent files list.
- `get_cwd`: Return current working directory.
- `set_cwd`: Change working directory.
- `list_dir`: List directory entries.
- `exists`: Check path existence/type.
- Legacy compatibility:
  - `read`/`write` are routed to `misc(read_file/write_file)`.
  - `sessions` is deprecated; use `session` tool.
  - `batch` remains host-level (use `batch` + `session` tools).

## Key Parameters
- `action`: One of `save|close|open|load_binary|list_recent|get_cwd|set_cwd|list_dir|exists`.
- `path`: File/directory path (required by path-based actions).
- `base_addr`: Optional base address for `load_binary`.
- `content`: File content for `write`; optional mode payload for `open`.

## Examples
```python
project(action="save")
project(action="open", path="/samples/dropper.exe")
project(action="load_binary", path="/tmp/blob.bin", base_addr="0x500000")
project(action="list_dir", path="/samples")
misc(action="read_file", path="/tmp/notes.txt")
misc(action="write_file", path="/tmp/notes.txt", content="triage complete")
```

## Failure Modes
- Path validation failure (`validate_path_safe`).
- Missing required `path` values.
- `open`/`close` may return `NOT_IMPLEMENTED` outside headless capabilities.
- Legacy `sessions`/`batch` return guidance errors.
