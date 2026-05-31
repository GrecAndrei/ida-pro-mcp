# Security Policy

## Supported versions

Security fixes are intended for the latest public release branch and the default branch.

## Scope

`ida-pro-mcp` is a local automation bridge for IDA Pro. It exposes powerful local capabilities through MCP, including IDA database mutation, debugger interaction, filesystem access, plugin execution, and optional Python/IDC execution inside the IDA process.

This project does **not** run a backend cloud LLM service. Any LLM behavior comes from the MCP client connected to this local server.

## Local trust model

The IDA runtime bridge binds to `127.0.0.1` and is intended for local use only. The host process starts the IDA runtime with a per-session token (`IDA_MCP_SESSION_TOKEN`) and includes that token in bridge requests.

Treat the following actions as high impact:

- `misc(action="python")`
- `misc(action="idc")`
- `misc(action="write_file")`
- `misc(action="plugin_run")`
- patching, renaming, typing, segment, memory, debugger, and bulk-edit actions

Only connect MCP clients and agents you trust. Do not run this server against untrusted prompts with write-capable tools enabled unless you understand the consequences.

## Reporting vulnerabilities

Please report suspected vulnerabilities privately before publishing details. Include:

- affected commit/version
- operating system and IDA version
- reproduction steps
- expected vs actual behavior
- whether arbitrary file access, code execution, IDB corruption, or privilege boundary crossing is involved

If a public GitHub Security Advisory workflow is enabled for this repository, use that. Otherwise contact the maintainer through the repository owner profile.

## Out of scope

The following are expected capabilities when explicitly enabled or invoked by a trusted local user/agent:

- executing Python/IDC inside IDA
- reading/writing local files through file tools
- running installed IDA plugins
- modifying the active IDB
- launching or controlling local IDA processes

Security issues should involve unintended access, missing authorization, unsafe defaults, persistence outside the documented runtime directories, token leakage, bypass of guardrails, or denial-of-service conditions beyond documented limits.
