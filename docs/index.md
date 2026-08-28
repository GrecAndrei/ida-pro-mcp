# Documentation

This folder is the canonical documentation source for `ida-pro-mcp`.

Start with the [project README](../README.md) and [repository instructions](../AGENTS.md),
then use the guides for architecture, safety, contributing, use cases,
versioning, and releases.

## Guides

- [Project README](../README.md) — overview, install, tool surface, runtime behavior
- [Architecture](guide/architecture.md) — module boundaries and runtime data flow
- [Safety model](guide/safety-model.md) — trust boundaries and mutation controls
- [Use cases](guide/use-cases.md) — supported analysis workflows
- [Versioning](guide/versioning.md) — release scheme and checklist
- [Roadmap](guide/roadmap.md) — planned compatibility work
- [OpenCode setup](OPENCODE_SETUP.md) — OpenCode-specific configuration and skills
- [Policy](POLICY.md) — governance policy reference
- [Technical reference](TECHNICAL_REFERENCE.md) — implementation-level architecture and runtime details

## Reference

- [Tool reference](TOOLS_REFERENCE.md) — generated tool/action/argument reference from
  `host.agent_operations.AGENT_OPERATIONS`
- [Wiki](wiki/) — in-tool documentation consumed by the `wiki` MCP tool
  - `wiki/QuickStart.md` — concise operational quickstart
  - `wiki/INDEX.md` — index of available wiki topics (hand-authored)
  - `wiki/tools/*.md` — per-tool manuals (hand-authored)
- [IDA headless scripting](reference/IDA_Headless_Scripting.txt) — background reference on IDA 9.2
  headless automation and the IDAPython module surface

## Operations

- [Live IDA testing](LIVE_IDA_TESTING.md)
- [Rizin integration](RIZIN_INTEGRATION.md)
- [Benchmarks](../benchmarks/README.md)
- [Research notes](research/)

## Regeneration

`TOOLS_REFERENCE.md` and the `.agents/skills/` skill files are generated from
`host.agent_operations.AGENT_OPERATIONS` by `scripts/generate_tool_skills.py`.
The wiki manuals are hand-authored. The installer's `--only skills` phase only
copies the pre-generated skills into place — it does **not** regenerate them.

After operation schemas or descriptions change:
```bash
python scripts/check_schema_integrity.py
python scripts/generate_tool_skills.py
ida-pro-mcp-install --only skills
```

## Recommended reading order

1. [Project README](../README.md)
2. [Wiki quickstart](wiki/QuickStart.md)
3. [Tool reference](TOOLS_REFERENCE.md)
4. [Technical reference](TECHNICAL_REFERENCE.md)
