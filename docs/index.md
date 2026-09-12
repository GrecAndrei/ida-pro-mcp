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

- [Release Notes (v1.0.0a2)](releases/v1.0.0a2.md) — Cross-session comparison and production hardening
- [Release Notes (v1.0.0a1)](releases/v1.0.0a1.md) — Genesis alpha release overview and capabilities
- [Release Description Template](releases/TEMPLATE.md) — Mandatory template for all future release notes

## Operations

- [OpenCode setup](operations/opencode-setup.md) — OpenCode-specific configuration
- [Live IDA testing](operations/live-ida-testing.md) — live IDA matrix and idat/idalib runner
- [Rizin integration](operations/rizin-integration.md) — Rizin / r2 cross-validation
- [Benchmarks](../benchmarks/README.md) — latency and throughput benchmarks
- [Research notes](research/) — historical and migration research

## Reference

- [Official Project Wiki](https://github.com/GrecAndrei/ida-pro-mcp/wiki) — complete user guides, client setup, and RE workflows
- [Technical reference](reference/technical-reference.md) — implementation-level architecture and runtime details
- [Policy reference](reference/policy.md) — governance policy reference
- [IDA headless scripting](reference/IDA_Headless_Scripting.txt) — background reference on IDA 9.2
  headless automation and the IDAPython module surface
- [Wiki mirror](wiki/) — in-tool documentation consumed by the `wiki` MCP tool
  - `wiki/QuickStart.md` — concise operational quickstart
  - `wiki/INDEX.md` — index of available wiki topics (hand-authored)
  - `wiki/tools/*.md` — per-tool manuals (hand-authored)

## Live discovery

There is no checked-in operation reference snapshot. The running server is
the contract: `tools/list` enumerates every `ida_*` operation with its
schema, and `ida_help(topic="...")` returns exact arguments and an example.
The wiki manuals below are hand-authored.

After operation schemas or descriptions change:
```bash
python scripts/check_schema_integrity.py
```

## Recommended reading order

1. [Project README](../README.md)
2. [Wiki quickstart](wiki/QuickStart.md)
3. [Technical reference](reference/technical-reference.md)
