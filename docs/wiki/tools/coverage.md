# coverage

Imports, visualizes, and analyzes code coverage data from dynamic analysis tools.

## Actions
- `import_drcov` — Import DynamoRIO coverage files (.drcov); params: `path`
- `import_lighthouse` — Import Lighthouse coverage format; params: `path`
- `highlight` — Color-highlight covered/uncovered basic blocks in IDB; params: `color`, `clear`
- `report` — Generate coverage summary report; params: `format`
- `uncovered` — List functions/blocks with zero coverage; params: `threshold`
- `filter` — Filter coverage by module, function, or address range; params: `module`, `address`, `function`
- `function_coverage` — Per-function coverage percentage breakdown; params: `sort`, `min_coverage`
- `gaps` — Identify coverage gaps (unreached code between covered regions); params: `address`
- `compare` — Diff two coverage sets (e.g., different inputs); params: `path_a`, `path_b`
- `merge` — Merge multiple coverage files into unified set; params: `paths`

## Examples
```json
{"name": "coverage", "arguments": {"action": "import_drcov", "path": "/traces/run1.drcov"}}
```
```json
{"name": "coverage", "arguments": {"action": "uncovered", "threshold": 0.1}}
```

## Notes
- Import coverage first, then use `highlight`/`report`/`gaps` for visualization and analysis.
- `compare` is useful for differential fuzzing analysis (which inputs reach new code).
- `merge` combines multiple runs for cumulative coverage assessment.
