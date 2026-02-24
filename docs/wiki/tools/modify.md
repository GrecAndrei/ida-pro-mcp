# MODIFY Tool Manual

## What It Does
Applies direct database edits at a target address: rename symbols, add comments, apply types, and patch assembled instructions.

## Actions
- `rename`: Rename the item at `addr`.
- `comment`: Add comment text at `addr` (`regular`, `repeatable`, `anterior`, `posterior`).
- `set_type`: Parse and apply a C type declaration at `addr`.
- `patch_asm`: Assemble and patch one or more instructions at `addr` (semicolon-separated allowed).

## Key Parameters
- `action`: One of `rename|comment|set_type|patch_asm`.
- `addr`: Target address.
- `value`: Main payload (new name/comment/type/instruction text).
- `name`: Alias for `value` when `action=rename`.
- `text`: Alias for `value` when `action=comment`.
- `type_str`: Alias for `value` when `action=set_type`.
- `asm`: Alias for `value` when `action=patch_asm`.
- `comment_type`: `regular|repeatable|anterior|posterior` for comment writes.

## Examples
```python
modify(action="rename", addr="0x401000", value="init_config")
modify(action="comment", addr="0x401023", text="auth gate", comment_type="repeatable")
modify(action="set_type", addr="0x401080", type_str="int __cdecl parse(char *buf);")
modify(action="patch_asm", addr="0x401120", asm="nop; nop; nop")
```

## Failure Modes
- Missing `value` (or missing alias for the selected action).
- Invalid `addr`.
- Invalid symbol name during `rename`.
- Type parse/apply failure during `set_type`.
- Assembly failure in `patch_asm` (partial patching may already be applied before failure).
