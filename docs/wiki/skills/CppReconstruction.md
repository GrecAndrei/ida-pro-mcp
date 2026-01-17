# SKILL: C++ Class Reconstruction

**Role**: Forensic C++ Architect
**Trigger**: When the user asks to "fix class X", "recover vtable", or "identify object structures".

## Context
Decompiled C++ code often appears as raw pointers (`v1 + 8`, `v1 + 16`) or generic `void*` arguments. To make it readable, we must reconstruct the `class` structure and its `vtable`.

## Workflow

### 1. Locate the VTable
If you see assignments like `*(_QWORD *)this = 0x140005080;` in a constructor, `0x140005080` is likely the VTable.

```python
# Create the VTable struct automatically
structs(action="reconstruct_vtable", addr="0x140005080", name="VTable_Player")
```

### 2. Identify Fields
Look for memory accesses relative to the `this` pointer.
```python
# Analyze field usage
structs(action="recover", addr="<constructor_addr>")
```

### 3. Create the Class Struct
Once you know the VTable and fields, create the C struct.
```python
# Import the class definition directly
decl = """
struct Player {
    VTable_Player *vtable;
    int health;
    float position[3];
};
"""
types(action="import_header", decl=decl)
```

### 4. Apply to Code
Apply the new type to the `this` pointer in the methods.
```python
# Fix the constructor's first argument
types(action="apply", addr="<constructor_addr>", decl="Player *this", kind="local", name="this")
```
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
