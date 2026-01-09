# NAV Tool Manual

Database navigation and discovery of "interesting" locations.

## Actions
### Supported Actions
- goto
- cursor
- interesting


### `cursor`
Return current cursor position.

### `goto`
Navigate to an address.
Moves the "virtual cursor" to a specific address and returns the surrounding context.

### `interesting`
Return interesting locations.
Heuristic scan for common reverse-engineering targets:
*   Standard library functions (`strcpy`, `malloc`).
*   Known anti-analysis patterns.
*   Encryption/Decryption loops.

## Best Practices
Use `interesting` as your second call (after `idb.meta`) to identify your initial points of interest.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
