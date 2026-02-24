# EDIT Tool Manual

## What It Does
Provides a unified write-entry point that routes common edits to underlying tools (`modify`, `data_ops`, `funcs`, `bulk`).

## Actions
- `rename`: Rename symbol at `addr`.
- `comment`: Set comment text at `addr`.
- `type`: Apply type declaration at `addr`.
- `patch`: Patch bytes or assemble-and-patch instruction.
- `create_func`: Create function at `addr`.
- `bulk`: Run bulk rename/comment/type operations.

## Key Parameters
- `action`: One of `rename|comment|type|patch|create_func|bulk`.
- `addr`: Required for all non-`bulk` actions.
- `value`: Required for `rename`, `comment`, `type`, `patch`.
- `items`: Required for `bulk`; list of operation objects.
- `subaction`: For `bulk`, defaults to `rename`.
- `args`:
  - `patch`: use `{"asm": true}` to route to assembler patch path.
  - `comment`/`bulk`: forwarded to underlying tool as extra args.

## Examples
```python
edit(action="rename", addr="0x401000", value="parse_config")
edit(action="comment", addr="0x401050", value="decrypt loop")
edit(action="type", addr="0x401000", value="int __cdecl(int,char**)")
edit(action="patch", addr="0x401234", value="90 90")
edit(action="patch", addr="0x401234", value="xor eax, eax", args={"asm": True})
edit(action="create_func", addr="0x401000")
edit(action="bulk", subaction="rename", items=[{"addr": "0x401000", "value": "init"}])
```

## Failure Modes
- Missing required `addr`, `value`, or `items`.
- Unknown `action` or unsupported `subaction` downstream.
- Patch failures from assembler/byte patch backend.
- Bulk/modify/func creation errors are returned from routed tools.
