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

## Releases

- [Release Notes (v1.0.0a1)](releases/v1.0.0a1.md) — Genesis alpha release overview and capabilities
- [Release Description Template](releases/TEMPLATE.md) — Mandatory template for all future release notes

## Operations

- [OpenCode setup](operations/opencode-setup.md) — OpenCode-specific configuration and skills
- [Live IDA testing](operations/live-ida-testing.md) — live IDA matrix and idat/idalib runner
- [Rizin integration](operations/rizin-integration.md) — Rizin / r2 cross-validation
- [Benchmarks](../benchmarks/README.md) — latency and throughput benchmarks
- [Research notes](research/) — historical and migration research

## Reference

- [Official Project Wiki](https://github.com/GrecAndrei/ida-pro-mcp/wiki) — complete user guides, client setup, and RE workflows
- [Tool reference](TOOLS_REFERENCE.md) — generated tool/action/argument reference from
  `host.agent_operations.AGENT_OPERATIONS`
- [Technical reference](reference/technical-reference.md) — implementation-level architecture and runtime details
- [Policy reference](reference/policy.md) — governance policy reference
- [IDA headless scripting](reference/IDA_Headless_Scripting.txt) — background reference on IDA 9.2
  headless automation and the IDAPython module surface
- [Wiki mirror](wiki/) — in-tool documentation consumed by the `wiki` MCP tool
  - `wiki/QuickStart.md` — concise operational quickstart
  - `wiki/INDEX.md` — index of available wiki topics (hand-authored)
  - `wiki/tools/*.md` — per-tool manuals (hand-authored)

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
