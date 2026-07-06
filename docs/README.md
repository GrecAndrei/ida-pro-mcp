# Documentation Map

This folder is the canonical documentation source for `ida-pro-mcp`.

## Active documentation

- `../README.md` — project overview, install, architecture, tool surface, runtime behavior
- `OPENCODE_SETUP.md` — OpenCode-specific configuration and skills
- `POLICY.md` — governance policy reference
- `TECHNICAL_REFERENCE.md` — implementation-level architecture and runtime details
- `TOOLS_REFERENCE.md` — generated tool/action/argument reference from live schemas
- `wiki/` — in-tool documentation consumed by the `wiki` MCP tool
  - `wiki/QuickStart.md` — concise operational quickstart
  - `wiki/INDEX.md` — generated index of available wiki topics
  - `wiki/tools/*.md` — per-tool manuals

## Regeneration

Tool reference and wiki tool manuals are generated from schema metadata in `src/ida_pro_mcp/host/schemas_data.py`. Skills are generated from the same source.

After tool actions or descriptions change:
```bash
python scripts/check_schema_integrity.py
ida-pro-mcp-install --only skills
```

## Recommended reading order

1. `../README.md`
2. `wiki/QuickStart.md`
3. `TOOLS_REFERENCE.md`
4. `TECHNICAL_REFERENCE.md`
