# taint

Forward taint analysis from user-controlled sources to dangerous sinks. Finds exploitable data-flow paths (buffer overflows, command injection, format string bugs) and writes confirmed findings to the blackboard automatically.

## Actions

### sources

List all taint sources present in the binary (imported functions that accept external input).

```json
{"name": "taint", "arguments": {"action": "sources"}}
```

Returns: `sources` list with `name`, `addr`, `category` (network/file/env/user_input), `xref_count`.

Built-in source categories:
- **network**: `recv`, `recvfrom`, `read`, `fread`, `fgets`, `gets`
- **env**: `getenv`
- **win32**: `ReadFile`, `RegQueryValue`, `GetCommandLine`
- **blackboard IOCs**: any `ioc` entries in the blackboard with `ioc_type=input`

---

### sinks

List dangerous sinks reachable from a source via call-graph BFS.

```json
{"name": "taint", "arguments": {"action": "sinks", "source": "recv", "max_depth": 5}}
```

Parameters:
- `source` — source function name or address (optional; omit to scan all sources)
- `max_depth` — BFS depth limit (default 5)

Returns: `sinks` list with `name`, `addr`, `vuln_type`, `path_length`, `via` (intermediate functions).

Built-in sink → vuln_type mappings:
| Sink | Vuln Type |
|------|-----------|
| `memcpy`, `memmove` | `buffer_overflow` |
| `strcpy`, `strcat`, `sprintf`, `vsprintf` | `buffer_overflow` |
| `system`, `popen`, `execve` | `command_injection` |
| `printf`, `fprintf`, `syslog` | `format_string` |
| `gets`, `scanf` | `buffer_overflow` |
| `RegSetValue` | `registry_injection` |

---

### trace

Forward taint from a specific address or source function. Writes `vuln` entries to the blackboard for confirmed paths.

```json
{"name": "taint", "arguments": {"action": "trace", "addr": "0x401000", "source": "recv", "max_depth": 4}}
```

Parameters:
- `addr` — function address to start from (optional; uses source import if omitted)
- `source` — source function name (e.g. `recv`)
- `max_depth` — BFS depth (default 4)

Returns:
- `paths` — list of call-graph paths from source to sink
- `vulns` — confirmed vulnerabilities with `source`, `sink`, `vuln_type`, `path`, `confidence`
- `blackboard_written` — number of entries auto-written

Each path entry: `[source_addr, intermediate_func, ..., sink_addr]`

**Auto-blackboard**: confirmed paths are written as `vuln` category entries with `confidence=0.85`, `source_type="taint_engine"`.

---

### paths

Full call-graph paths from source to all reachable sinks. More exhaustive than `trace`.

```json
{"name": "taint", "arguments": {"action": "paths", "source": "recv", "max_depth": 6, "max_paths": 20}}
```

Parameters:
- `source` — source function name
- `max_depth` — BFS depth (default 6)
- `max_paths` — cap on returned paths (default 20)

Returns: `paths` list, each with `source`, `sink`, `vuln_type`, `call_chain`, `depth`, `has_dataflow` (whether decompiler variable graph confirms direct data flow).

`has_dataflow=true` means the decompiler variable graph shows the source return value flows directly into the sink argument — high confidence finding.

---

### report

Full taint report: all sources → all reachable sinks in one call.

```json
{"name": "taint", "arguments": {"action": "report", "max_depth": 4, "max_paths": 50}}
```

Parameters:
- `max_depth` — BFS depth per source (default 4)
- `max_paths` — total path cap (default 50)

Returns:
- `findings` — deduplicated list of `{source, sink, vuln_type, path, confidence}`
- `total` — total findings count
- `sources_checked` — number of sources scanned
- `high_confidence` — findings where `has_dataflow=true`
- `summary` — plain-text summary for LLM consumption

---

## Integration with smart_decompile

`code(action="smart_decompile")` automatically calls `taint(action="trace")` when it detects network input APIs (`recv`, `recvfrom`, `read`, `fread`, `fgets`, `gets`, `getenv`, `scanf`) in the function's API calls. The result is embedded in `suggested_next_actions` with actual path and vuln data — not just a suggestion.

```json
{
  "suggested_next_actions": [
    {
      "action": "taint(trace) — COMPLETED",
      "source": "recv",
      "paths_found": 2,
      "vulns_found": 1,
      "top_vuln": {"sink": "memcpy", "vuln_type": "buffer_overflow", "confidence": 0.85}
    }
  ]
}
```

---

## Workflow

Typical firmware RE taint workflow:

```
1. taint(action="sources")                    → find what accepts external input
2. taint(action="report", max_depth=5)        → full scan, auto-writes blackboard
3. blackboard(action="list", category="vuln") → review confirmed findings
4. code(action="smart_decompile", addrs=["0x..."])  → deep analysis of flagged functions
5. taint(action="paths", source="recv", max_depth=8) → exhaustive path search
```

---

## Blackboard integration

`trace` and `report` auto-write `vuln` category entries:

```json
{
  "category": "vuln",
  "title": "buffer_overflow: recv→memcpy at 0x401234",
  "addr": "0x401234",
  "confidence": 0.85,
  "source_type": "taint_engine",
  "tags": ["taint", "buffer_overflow", "recv"]
}
```

These entries appear in `blackboard(action="next_target")` with high priority (vuln category boost × confidence).

---

## Limitations

- Call-graph BFS only — does not track data flow through memory (heap aliasing, global variables)
- `has_dataflow` check uses decompiler variable graph: only works when Hex-Rays is available and the path is ≤2 hops
- Does not track taint through indirect calls (function pointers, vtables) unless IDA has resolved them
- `max_depth` > 6 may be slow on large binaries; use `taint(action="sinks")` first to narrow scope
