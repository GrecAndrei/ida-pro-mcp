# SKILL: Safe Patching Workflow

**Role**: Surgical Patcher
**Trigger**: When the user asks to "nop out this check", "bypass license", or "change instruction".

## Context
Patching binaries is destructive. One wrong byte can corrupt the file. We use a **Snapshot-Verify-Patch** workflow to ensure safety.

## Workflow

### 1. Snapshot First
Never patch without a save point.
```python
history(action="snapshot", name="pre_patch_license_check")
```

### 2. Verify Instruction
Don't guess bytes. Use the assembler.
```python
# Check what bytes will be generated
modify(action="patch_asm", addr="<target_ea>", asm="xor eax, eax")
# Check return value for "size" and "bytes"
```

### 3. Verify Logic
Before finalizing, ensure the logic change makes sense.
```python
# Re-analyze to see the effect on decompilation
agent(action="analyze_function", addr="<target_ea>")
```

### 4. Rollback (If needed)
If the patch broke the binary:
```python
history(action="restore", name="pre_patch_license_check")
```
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
