# Wiki Index

The wiki documents the current `ida_*` operation surface. The legacy
`tool(action=...)` API is a compatibility backend, not the supported
contract. Full contracts for every operation live in
[docs/TOOLS_REFERENCE.md](../TOOLS_REFERENCE.md) (generated from
`host/agent_operations.py`); this wiki is the narrative layer.

## Getting Started

- [QuickStart](QuickStart.md)

## Core

- [Sessions](core/sessions.md) — lifecycle, background loading, safe mode, RPC concurrency
- [Investigation](core/investigation.md) — findings, kinds, lifecycle, evidence, export, IDB round-trip
- [Frontier](core/frontier.md) — `ida_next_target` strategies
- [Intelligence](core/intelligence.md) — semantic indexing and search
- [RISC-V raw-blob firmware](riscv_firmware.md) — recipe for opaque headerless firmware analysis

## Tools

- [Session](tools/session.md) — open/close/switch/status/health
- [Discovery](tools/discovery.md) — overview, find, functions, strings, imports
- [Code](tools/code.md) — decompile, disassemble, xrefs, callers, callees, read_bytes, callgraph
- [Findings](tools/findings.md) — write/list/search/update/export/publish
- [Edit](tools/edit.md) — rename, comment, create/change function, patch_bytes, rename_local
- [Types](tools/types.md) — list/get/declare/apply types (structs, enums, typedefs)
- [Segments](tools/segments.md) — list/add/set_attrs
- [Signatures](tools/signatures.md) — FLIRT list_sigs/apply_sig
- [Calculation](tools/calculation.md) — eval, offset, convert, deref, chain, align, bitops
- [Support](tools/support.md) — help, continue, python
- [Workflow](tools/workflow.md) — batch
