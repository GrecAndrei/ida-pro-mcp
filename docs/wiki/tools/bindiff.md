# bindiff

Cross-version binary comparison via function fingerprints. **Does not require Google BinDiff.**

## Workflow

1. Open build A:
   ```json
   {"name":"bindiff","arguments":{"action":"snapshot","path":"/tmp/build_a.snap.json"}}
   ```
2. Open build B (new session or replace binary):
   ```json
   {"name":"bindiff","arguments":{"action":"diff","snapshot":"/tmp/build_a.snap.json"}}
   ```
3. Match renamed functions:
   ```json
   {"name":"bindiff","arguments":{"action":"function_match","snapshot":"/tmp/build_a.snap.json","threshold":0.6}}
   ```
4. Deep-dive one function:
   ```json
   {"name":"bindiff","arguments":{"action":"patch_analysis","addr":"0x401000","snapshot":"/tmp/build_a.snap.json"}}
   ```

## Actions

| Action | Params | Result |
| --- | --- | --- |
| `snapshot` | `path` (recommended), `max_functions`, `include_full` | Fingerprints all functions; with `path` writes JSON and returns path only |
| `diff` | `snapshot` or `path` | new / removed / modified with deltas |
| `function_match` | `snapshot`, `threshold` | multi-heuristic pairs (name, hash, strings, callees, CFG) |
| `patch_analysis` | `addr`, `snapshot` | block-level + security notes for one function |
| `summary` | `snapshot` | stats + security-oriented categories |

## Notes

- Prefer `path=` on snapshot so agents do not pull multi-MB function maps into context.
- For Google BinDiff UI / `.BinExport` protobuf files, use `export(action='binexport', path=...)`.
- Same-IDB structural compare remains on the `compare` tool.
