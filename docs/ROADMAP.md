# Roadmap — cut, contract, pin

Status target: honest **0.9.x** alpha, not a pretend 1.0.

## Goals

1. Agent finishes real RE with **≤17 advertised tools**
2. Args **hard-fail** if unknown (no silent strip)
3. Host behavior pinned by tests that **exist on the tree**
4. Docs/version match reality

## Tiers

### Tier A — `ADVERTISED_TOOLS` (tools/list default)

`session`, `analysis`, `code`, `funcs`, `search`, `data`, `modify`, `types`,
`memory`, `segments`, `idb`, `misc`, `intelligence`, `blackboard`, `graph`,
`batch`, `truncation`

### Tier B — callable, not advertised

Power surfaces: `debug`, `ctree`, `microcode`, `firmware_view`, `trace_analysis`,
`yara_hunt`, `bindiff`, `emulate`, `struct_recover`, `coverage`, `gadgets`, …

### Tier C — merge or kill (ongoing)

| Surface | Policy |
| --- | --- |
| `blackboard` | **Canonical durable notebook** for findings |
| `wiki` | Docs only (unadvertised) |
| `knowledge` | Cross-session chip/symbol KB (unadvertised) |
| `threat_hunt` / `classify` / bulk `summarize` | Prefer `search` + `binary_info` / explicit advanced tools |
| `workflow` + macros + `batch` | Prefer `batch` for multi-call; workflow stays advanced |
| `string_ops` / fat `protocol` | Advanced / unadvertised |

Compact action enums (`ADVERTISED_ACTIONS`) shrink tools/list for `session`,
`search`, `intelligence`, `blackboard`, `code`, `funcs`, `misc`. Full
`TOOL_ACTIONS` remain accepted at call time.

## Done / in progress

- [x] Reject unknown RPC kwargs (`INVALID_ARGS`)
- [x] Version `0.9.0` + alpha classifier
- [x] Search consolidation path (`search/semantic.py`, drop semantic/smart_bundle as first-class)
- [x] Admit search/funcs knobs that were stripped
- [x] Tier A advertise list
- [x] Compact action enums for tools/list
- [x] Remove broken `sideband-capsule` entry point
- [x] Remove standalone `filter` tool (duplicate of pick/grep/head wrappers)
- [x] Extract `prepare_rpc_args` + pin with real helper tests
- [x] Fix pytest testpaths so root contract tests run
- [x] Restore curated host/integration pins
- [ ] Further Tier C module deletion after cold-path proof
- [ ] Full host test suite rebuild (selective, not 84k-line graveyard)
- [ ] Decompose runtime/session/trace hotspots behind their existing contract tests

## Core agent path

```
session.create → analysis (wait/analyze as needed) →
intelligence.index_fast (optional) →
search.find | search.nl → code.decompile/smart_decompile →
modify / funcs annotate → blackboard.write → idb.save → session.close
```

Smoke: `scripts/smoke_core_path.py` (live IDA; optional).

## Non-goals (for now)

- New tools / new actions on bloated tools
- Resurrecting SchemaBoot / federation / crystallizer
- Claiming 1000+ tests without the files on disk
