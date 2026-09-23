# Wiki Index

IDA Pro MCP is easiest to use as a short, evidence-driven workflow. These
pages explain how to install it, connect a client, inspect a binary, preserve
findings, and make reviewed IDB changes.

## Start here

- [Install and run your first session](getting-started.md)
- [Configure an MCP client](client-configuration.md)
- [A practical reverse-engineering workflow](reverse-engineering-workflow.md)
- [Findings, evidence, and conflicts](findings-and-evidence.md)
- [Safe IDB edits and rollback](safe-idb-edits.md)

## When something needs explaining

- [Search and retrieval](search-and-retrieval.md)
- [Sessions and troubleshooting](sessions-troubleshooting.md)
- [Live IDA validation](live-ida-validation.md)
- [Reference and FAQ](reference-faq.md)

## Detailed reference

## Tool Reference Manuals

- [Discovery](tools/discovery.md) — 23 operations: reconnaissance, deterministic retrieval, provider status, usage, and raw-byte inspection.
- [Code](tools/code.md) — 11 operations: decompilation, disassembly, call graphs, cross-session function diffing, whole-binary diff triage, and emulation.
- [Edit](tools/edit.md) — 34 operations: names, comments, function boundaries, patching, System.map imports, type/segment edits, snapshots, and transactions.
- [Types](tools/types.md) — Struct, enum, and typedef declarations, struct/enum member edits, and TIL import/export.
- [Segments](tools/segments.md) — Segment layout, attributes, permissions, and segment-register (`sreg`) mappings.
- [Findings](tools/findings.md) — 10 operations: persistent investigation workspace, evidence recording, and IDB publishing.
- [Session](tools/session.md) — 12 operations: session lifecycle, background opening, health diagnostics, and Agent SSO.
- [Calculation](tools/calculation.md) — 8 operations: address math, pointer chains, alignments, conversions, and bitwise operations.
- [Signatures](tools/signatures.md) — FLIRT signature inspection and application.
- [Support](tools/support.md) — `ida_help`, pagination continuation (`ida_continue`), and IDAPython escape hatch (`ida_python`).
- [Workflow](tools/workflow.md) — Sequential multi-operation macro execution (`ida_batch`).

## Core Architecture & Concepts

- [Sessions Core Guide](core/sessions.md) — Process management, safe mode gate, lease files, and RPC concurrency.
- [Investigation Workspace](core/investigation.md) — Binary-scoped knowledge store, item kinds, lifecycle states, and evidence models.
- [Frontier Guide](core/frontier.md) — Target selection strategies (`unresolved`, `frontier`, `stale`, `conflict`, `coverage`).
- [Intelligence Guide](core/intelligence.md) — Jev/custom/disabled providers, typed-question privacy, budgets, lexical retrieval, and shipped advisor stage.
- [Twin Board (Planned)](twin-board.md) — Durable two-IDB delta board on experimental/twin-board-v1 (not shipped).
