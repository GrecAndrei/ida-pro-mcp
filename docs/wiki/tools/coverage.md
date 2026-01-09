# COVERAGE Tool Manual

Import and analyze code execution traces (DrCov, Lighthouse).

## Actions
### Supported Actions
- import_drcov
- import_lighthouse
- highlight
- report
- uncovered
- filter


### `import_lighthouse`
Import lighthouse coverage data.

### `highlight`
Highlight covered code in the database.

### `uncovered`
List uncovered basic blocks.

### `import_drcov`
Import a drcov coverage file.
Imports a DynamoRIO `.drcov` file.

### `filter`
Filter coverage results.
Filters a list of candidate addresses against the actual execution trace.
*   **Args**: `path` (file), `addresses` (list of hex strings).
*   **Best for**: Narrowing down search results. If you search for "password" and find 100 functions, use `filter` to see which one *actually ran* during your test.

### `report`
Generate a coverage report.
Generates a per-block coverage report for a specific function.
*   **Args**: `addr` (optional). Defaults to the binary entry point.

## Strategy
Coverage is the best way to focus an LLM's limited context. By filtering for only executed code, you prevent the AI from wasting time analyzing dead code or irrelevant error handlers.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
