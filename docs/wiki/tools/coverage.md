# COVERAGE Tool Manual

## What It Does
Import and analyze code coverage data from various sources.

## Actions
- `import_drcov`: Import DynamoRIO drcov coverage file.
- `import_lighthouse`: Import Lighthouse-compatible coverage file.
- `highlight`: Color covered addresses/functions.
- `report`: Return coverage summary metrics.
- `uncovered`: List uncovered code regions/functions.
- `filter`: Filter loaded coverage data by scope.

## Key Parameters
- `action` (required): Operation selector.
- `path` (default `None`): Filesystem path for import/export input.
- `addr` (default `None`): Target address or function start (hex string).
- `color` (default `'green'`): Color name/value used by coloring or highlighting actions.
- `addresses` (default `None`): Address list used by `filter` to test execution hits.

## Examples (JSON call snippets)
```json
{
  "tool": "coverage",
  "args": {
    "action": "import_drcov",
    "path": "./run.drcov"
  }
}
```
```json
{
  "tool": "coverage",
  "args": {
    "action": "report"
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `path (coverage file) required`
- `INVALID_ARGS`: `addresses list required`
- `FILE_NOT_FOUND`: `No coverage data loaded`
- `INVALID_ARGS`: `path required`
- `FILE_NOT_FOUND`: `File not found: {path}`
- `FUNCTION_NOT_FOUND`: `No function found at {target}`
- `IDA_ERROR`: `Could not analyze function`
- `INVALID_ARGS`: `Unknown action: {action}`
