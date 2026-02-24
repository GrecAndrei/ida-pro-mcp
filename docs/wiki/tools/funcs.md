# FUNCS Tool Manual

## What It Does
Creates, removes, inspects, and updates function definitions, including naming, comments, and filtered/paginated listings.

## Actions
- `create`: Define function at address (optional explicit end, flags, name).
- `delete`: Delete function containing/addressed by `addr`.
- `set_flags`: Replace function flags.
- `set_name`: Rename function (alias: `rename`).
- `add_comment`: Set function comment.
- `list`: Filtered/paginated function list.
- `info`: Detailed metadata for one function.

## Key Parameters
- `action`: One of `create|delete|set_flags|set_name|rename|add_comment|list|info`.
- `addr`: Required for all except pure listing operations.
- `end`: Optional explicit end for `create`.
- `name`: Used by `set_name`/`rename`; optional on `create`.
- `flags`: Used by `set_flags`; optional add-on when creating.
- `force`: For `create`, allows deleting overlaps/containing function conflicts.
- `comment`, `repeatable`: For `add_comment`.
- `query`, `named_only`, `offset`, `count`: `list` controls.
- `include_prototype`, `include_stack`: richer output for `list`/`info`.

## Examples
```python
funcs(action="create", addr="0x401000", end="0x401120", name="init", force=True)
funcs(action="delete", addr="0x401050")
funcs(action="set_name", addr="0x401000", name="process_packet")
funcs(action="add_comment", addr="0x401000", comment="decrypt stage", repeatable=True)
funcs(action="list", query="*crypto*", named_only=True, offset=0, count=50, include_prototype=True)
funcs(action="info", addr="0x401000", include_prototype=True, include_stack=True)
```

## Failure Modes
- Invalid/missing addresses.
- Create conflicts inside existing function when `force=False`.
- Address cannot be converted into code for creation.
- Function not found for delete/flag/info paths.
- Rename rejected due naming constraints.
