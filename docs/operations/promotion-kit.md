# Promotion kit

This page contains reusable, factual copy for promoting the current alpha release.
Keep claims synchronized with `README.md` and the current release notes before reuse.

## Short post

IDA Pro MCP gives AI agents deterministic, local-first access to IDA Pro through
99 strict-schema operations: decompilation, cross-references, raw-binary inspection,
optional semantic search, and an evidence-backed findings workspace.

The current release is `v1.0.0a3` and is alpha software. Testers and technical
feedback are welcome:
https://github.com/GrecAndrei/ida-pro-mcp

## Community link-post title

IDA Pro MCP with deterministic agent operations and evidence-backed findings

## Longer community introduction

I have been building an alternative IDA Pro MCP implementation focused on
deterministic tool contracts rather than a broad free-form action endpoint. The
default surface currently exposes 99 strict-schema `ida_*` operations covering
headless sessions, decompilation, disassembly, cross-references, raw-binary
inspection, optional local semantic search, and a durable findings workspace.

The host runs outside IDA and communicates with an IDA-side runtime over a local
bridge. Normal analysis does not require a hidden LLM service, and IDB-changing
operations remain policy-gated. The project supports IDA Pro or IDA Home 9.2+
and multiple MCP clients.

This is still alpha software, so I am especially interested in installation
feedback, real-world compatibility reports, and examples where the strict tool
surface helps or gets in the way.

Repository and release artifacts:
https://github.com/GrecAndrei/ida-pro-mcp

## Positioning guardrails

- Describe the project as community-built, not official or endorsed by Hex-Rays.
- Say `local-first`, not fully offline: the connected MCP client may send context
  to its configured model provider.
- State the alpha status prominently.
- Do not imply that fake-IDA tests prove live behavior.
- Distinguish the project by its deterministic schemas, safety policy, session
  architecture, and evidence-backed findings workspace.
