# The Master RE Strategy Guide

This guide outlines the standard operating procedure for analyzing a binary using the IDA Pro MCP.

## Phase 1: Reconnaissance (The First 5 Minutes)
1.  **Metadata**: Call `idb.meta` to check architecture, entry point, and image size.
2.  **Global Sweep**: Use `agent.search_all` with generic terms (e.g. "key", "auth", "http") to find low-hanging fruit.
3.  **Triage Targets**: Check `nav.interesting` for unusual instructions (`syscall`, `cpuid`) that hint at anti-debug or core logic.

## Phase 2: Static Mapping
1.  **Function Analysis**: Use `agent.analyze_function` on the entry point or interesting callers.
2.  **Type Reconstruction**: If you find a structure being used (offset-based access like `[eax+10h]`), run `structs.recover` followed by `types.apply`.
3.  **Annotation**: As you discover logic, use `modify.rename` or `bulk.rename` immediately. Never leave a `sub_XXXX` nameless once you understand it.

## Phase 3: Dynamic Verification
1.  **Debugging**: Use `debug.start` and `debug.add_bp` to verify your static assumptions.
2.  **Execution Trace**: Run a snippet with `emulate.appcall` if you just need to see the result of a single calculation without a full debug session.

## Phase 4: Final Forensic Report
1.  **Signature Generation**: Use `patterns.generate` to save your findings for future binaries.
2.  **Export**: Use `bulk.export_annotations` to backup your work.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
