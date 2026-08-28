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

### 3) Tools/filesystem access control

- Memory tool validates paths against an allow root (`IDA_MCP_MEMORY_ROOT`, defaults to IDB dir).
- All paths are canonicalised via `os.path.realpath`; symlinks outside the root are rejected.
- Read/write operations are capped at 64 MB per request.
- Error paths return sanitised messages (no `traceback.format_exc()`).

Outcome: prevents arbitrary file read/write via the `/memory` tool surface. (`[FIXED: 1A.1]`)

### 4) Federation / blackboard path control

- Federation (blackboard_federate) was removed in the intelligence-theater cut. (`[FIXED: 1D.1]`)

### 5) RPC request size limits (host side)

- Host-side `_send_rpc_raw` enforces a maximum RPC request/response size (`IDA_MCP_MAX_RPC_BYTES`, default 64 MB).
- Complements the existing IDA-side `IDA_MCP_MAX_RPC_REQUEST_BYTES` check for defence in depth.

Outcome: reduces OOM risk from oversized payloads on the host. (`[FIXED: 1A.2]`)

### 6) BYPASS_SYNC scoping

- `BYPASS_SYNC` is no longer set unconditionally at module import (`server_script.py:36`).
- A `bypass_sync()` context manager in `sync.py` scopes the bypass to the specific thread/call site.

Outcome: the `@idaread`/`@idawrite` safety net is active by default. (`[FIXED: 1A.4]`)

### 7) Concurrency controls

- `_session_inflight_calls` increment/decrement is protected by `_runtime_lock` to prevent lost-update races.
- The idle-index worker always sees an accurate in-flight counter.

Outcome: eliminates false idle detection during concurrent tool calls. (`[FIXED: 2C]`)

### 8) Schema and metadata integrity checks

- Tool actions/descriptions are centralized in `schemas_data.py`.
- CI runs schema integrity validation and generated-doc drift checks.

Outcome: reduces contract mismatch and unsafe dispatch behavior from stale metadata.

### 9) Regression testing

- Static and AST regression tests enforce critical tool contract expectations.
- CI test matrix validates behavior on multiple Python versions.
- Concurrency stress tests (`test_concurrency.py`) verify lock-protected shared state.

Outcome: catches safety regressions before release.

### 10) Repository hygiene

- Local-only artifacts and private path leaks are removed/ignored.
- Release metadata and license policy are explicitly maintained.
- Classifier downgraded from `Production/Stable` to `Alpha`.

Outcome: lowers accidental disclosure risk; honest about maturity.

### 11) Policy mode is operator-owned

- The baseline comes from `IDA_MCP_POLICY_MODE`, then `~/.config/ida-pro-mcp/policy.json`, then `assist`.
- A session-level mode may only *tighten* that baseline (`policy.strictest`).
- `session(action='create')` no longer accepts a `policy_mode` argument. It previously did, undeclared by any schema, while classifying as a read — so one unacknowledged call could set `mode=off` for the session.

Outcome: the policy engine cannot be disabled by a request.

### 12) Session ownership checks cannot fail open

- `_ensure_client_owns_session` lives on `ServerClientStateMixin`, which every mixin performing the check inherits.
- Call sites invoke it directly. Looking it up with `getattr(..., None)` previously let the check be skipped on any object that had not inherited it.

Outcome: a cross-client session access is always rejected, not conditionally.

### 13) Runtime ownership leases are published atomically

- A lease is written to a temporary file and hard-linked into place.
- Creating the lease with `O_CREAT|O_EXCL` and writing afterwards made it briefly readable while empty; a concurrent claimer then saw no owner, removed it, and both processes believed they held the IDB.

Outcome: exclusive IDB ownership is actually exclusive.

### 14) Failed process termination is reported as failure

- `session(action='kill')` returns a structured error, with the pid, when the process survived SIGTERM and SIGKILL.
- It previously returned `{"ok": true}` regardless, implying the IDB lock had been released when it had not.

Outcome: callers do not reopen an IDB that is still locked.

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
