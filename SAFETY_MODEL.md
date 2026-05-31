# Safety Model

## Purpose

This document defines the practical safety model for `ida-pro-mcp` and how risk is reduced during normal use.

## System Boundaries

Primary components:
- Host MCP server process
- IDA-side bridge script
- Local transport between host and IDA
- Tool dispatch and argument normalization layer

Trust boundaries:
- User and local operator input
- MCP client requests
- Host to IDA RPC channel
- Filesystem and project workspace access

## Assets to Protect

- Local machine integrity where host/IDA runs
- Reverse engineering project data and annotations
- Analysis outputs (comments, names, types, patch actions)
- User privacy (paths, local identifiers, sensitive artifacts)

## Threat Model

Key threat classes considered:
- Unauthorized local RPC requests to IDA bridge
- Oversized or malformed request payloads causing instability
- Dangerous tool invocations with destructive side effects
- Metadata drift causing incorrect tool contracts and unsafe automation
- Accidental leakage of local/private information in repository artifacts

## Current Safety Controls

### 1) Bridge authentication

- Host generates an ephemeral per-session token (`IDA_MCP_SESSION_TOKEN`).
- RPC requests include the token.
- IDA bridge validates token using constant-time comparison.

Outcome: reduces risk of unauthorized local request injection.

### 2) Request size limits

- IDA bridge enforces a maximum inbound RPC request size (`IDA_MCP_MAX_RPC_REQUEST_BYTES`).
- Truncated/oversized requests are rejected with structured errors.

Outcome: reduces memory abuse and malformed payload handling risk.

### 3) Schema and metadata integrity checks

- Tool actions/descriptions are centralized in `schemas_data.py`.
- CI runs schema integrity validation and generated-doc drift checks.

Outcome: reduces contract mismatch and unsafe dispatch behavior from stale metadata.

### 4) Regression testing

- Static and AST regression tests enforce critical tool contract expectations.
- CI test matrix validates behavior on multiple Python versions.

Outcome: catches safety regressions before release.

### 5) Repository hygiene

- Local-only artifacts and private path leaks are removed/ignored.
- Release metadata and license policy are explicitly maintained.

Outcome: lowers accidental disclosure risk.

## Operational Safety Guidance

- Prefer least-privilege runtime environments for host and IDA.
- Do not expose the bridge to untrusted networks.
- Keep dependencies and Python runtime patched.
- Review high-impact actions (patching, type mass-updates, script execution) before applying.
- Treat imported traces, scripts, and external inputs as untrusted.

## Residual Risk

Residual risk remains in areas where the system executes complex analysis or code-like payloads in a highly privileged desktop RE environment. This project aims to reduce risk with bounded inputs, explicit checks, and repeatable validation, but cannot eliminate all local execution risk.

## Future Hardening

- Optional stricter allowlists for high-risk actions
- Additional request rate and concurrency limits per transport channel
- Expanded governance checks for patch/type/rename bulk operations
- Periodic threat-model review with each minor release
