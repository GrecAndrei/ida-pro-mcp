# BULK Tool Manual

Batch operations for high-efficiency modifications.

## Actions
### Supported Actions
- rename
- comment
- apply_type
- rename_stack
- import_annotations
- export_annotations


### `comment`
Create or update a comment at the specified address.

### `apply_type`
Apply types to multiple items.

### `import_annotations`
Import annotations in bulk.

### `rename` / `comment`
Rename the specified symbol or address.
Perform many operations in one turn.
*   **Args**: `items` (list of `{addr, value}` dicts).

### `rename_stack`
Rename stack variables in bulk.
Renames multiple stack variables in a function. 
*   **Args**: `items` (list of `{addr, old, new}` dicts).

### `export_annotations`
Export annotations in bulk.
Saves all your work (names and comments) to a JSON file. Use this for backing up your analysis.

## Best Practices
Always use `bulk` when you have more than 3 things to change. It saves significant context window and execution time.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
