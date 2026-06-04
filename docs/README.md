# Documentation Map

This folder is the canonical documentation source for `ida-pro-mcp`.

## Active documentation

- `../README.md`: project overview, install, architecture, runtime behavior.
- `TOOLS_REFERENCE.md`: full generated tool/action/argument reference from live schemas.
- `TECHNICAL_REFERENCE.md`: implementation-level architecture and runtime details.
- `design/SEMANTIC_MEMORY.md`: local-first semantic memory architecture and capsule workflow.
- `CARTOGRAPHER_MU.md`: Cartographer-mu semantic engine design.
- `OPENCODE_SETUP.md`: OpenCode-specific integration/configuration notes.
- `reference/`: external reference material (IDA headless scripting).
- `wiki/`: in-tool documentation consumed by the `wiki` MCP tool.
  - `wiki/tools/*.md`: per-tool manuals generated from live tool metadata.
  - `wiki/QuickStart.md`: concise operational quickstart.
  - `wiki/INDEX.md`: generated index of available wiki topics.
  - `wiki/skills/*`, `wiki/workflows/*`, `wiki/core/*`: analyst workflows and reference content.

## Regeneration model

- Tool reference and wiki tool manuals are generated from `ida_mcp_stdio.py` metadata and schema builders.
- If tool actions/args change, regenerate docs before publishing changes.

## Recommended reading order

1. `../README.md`
2. `wiki/QuickStart.md`
3. `TOOLS_REFERENCE.md`
4. `TECHNICAL_REFERENCE.md`
