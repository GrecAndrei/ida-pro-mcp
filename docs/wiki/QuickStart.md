# IDA MCP Quick Start

Welcome to the autonomous reverse engineering engine.

## Core Principles
1.  **Sessions First**: Always use `session(action='create')` to associate with a binary before running other tools.
2.  **Triage with Agent**: Start with `agent(action='context_pack')` for any new target.
3.  **Wiki is your Friend**: If a tool returns an error or you need syntax, call `wiki(topic='tool_name')`.

## Documentation Categories
1.  **core/**: Low-level IDA concepts (Addresses, Segments, Database).
2.  **tools/**: Individual manuals for all tool modules (including analysis and batch).
3.  **skills/**: High-level multi-tool workflows (e.g. `skills/MalwareForensics`).
4.  **workflows/**: Strategic approaches to reverse engineering.

## Common Workflows
*   **Malware Forensics**: See `wiki(topic='skills/MalwareForensics')`.
*   **Vulnerability Hunt**: See `wiki(topic='skills/VulnerabilityHunting')`.
*   **C++ Reconstruction**: See `wiki(topic='skills/CppReconstruction')`.
*   **Surgical Patching**: See `wiki(topic='skills/PatchingWorkflow')`.
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
