# IDA Pro MCP

IDA Pro MCP connects an MCP client to IDA Pro for repeatable analysis, a
binary-scoped investigation workspace, and reviewed IDB annotations.

This project is Alpha (`1.0.0a1`) — see the [v1.0.0a1 Genesis Release Notes](v1.0.0a1-Release-Notes) for the full feature breakdown. It exposes 107 deterministic, strict-schema `ida_*` operations supporting Hex-Rays decompilation, cross-references, type management, firmware detection, and multi-agent configuration across 22+ coding tools.

## Start here

1. [Install and run a first session](getting-started)
2. [Connect an MCP client (Cursor, Claude Code, OpenClaw, Pi, Hermes, etc.)](client-configuration)
3. Explore the [v1.0.0a1 Release Notes](v1.0.0a1-Release-Notes)
4. Follow the [practical IDA workflow](reverse-engineering-workflow)
5. Record conclusions in [findings and evidence](findings-and-evidence)
6. Review [safe IDB changes and rollback](safe-idb-edits) before mutating an
   IDB

Use [Navigation](Navigation) to choose a task. For exact operation arguments,
call `ida_help` from the client or read the repository's generated
[TOOLS_REFERENCE.md](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/TOOLS_REFERENCE.md).

The wiki explains the working path; it is not a replacement for the generated
operation contracts. If a workflow page and the current operation reference
disagree, follow the operation reference and report the discrepancy before
publishing a change.

## What persists

Findings, evidence, conflicts, examination verdicts, and stale-code markers
are stored in the investigation workspace. Publishing is a separate, reviewed
step that copies eligible findings into the IDB as comments and, where
appropriate, names.

## Safety boundary

IDB-writing operations and destructive session actions require an explicit
`risk_ack: true`, and operator policy can still deny them. Treat IDB changes as
changes to the analysis database, not as temporary chat annotations.

References: [README.md](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/README.md),
[safety model](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/guide/safety-model.md).
