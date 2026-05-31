# Sideband Capsules (Experimental v0)

## Concept

> A Sideband Capsule is a portable, policy-aware reverse-engineering workspace that can materialize tools only when needed.

This repository remains `ida-pro-mcp` today. The capsule work is introduced as internal architecture under the current package without renaming the project.

IDA Pro is the first backend/reference backend, not necessarily the long-term product boundary.

## Why Capsules Exist

The existing project already has rich session, policy, and installer data, but this state is spread across runtime files and client configs. Capsules provide a portable workspace container with:

- explicit manifest and trust metadata
- deterministic storage for install/session/audit records
- backend and client profile metadata
- auditable note and event timelines

## Why SQLite

v0 uses a SQLite-backed `.sideband` file because it is:

- portable and inspectable with standard tooling
- transaction-safe for append/update workflows
- good for structured JSON-bearing records without extra services
- easy to verify (`PRAGMA integrity_check`)

## v0 Safety and Trust Model

The v0 trust model is explicit from day one:

- trust states: `untrusted`, `inspected`, `trusted-local`, `trusted-signed`, `quarantined`
- local `init` creates capsules as `trusted-local`
- trust metadata includes `contains_executable_payloads` and `last_verified_at`

Important safety boundary:

> A Sideband Capsule may eventually contain executable runtime payloads, but v0 does not execute embedded payloads. Inspection and verification must remain safe read-only operations.

## v0 Non-Goals

This iteration intentionally does not:

- replace the installer or MCP server architecture
- execute embedded payloads
- implement FUSE/mounting or custom binary wrappers
- claim sandboxing or malware safety guarantees

## v0 Scope

Capsule v0 includes:

- SQLite schema and migrations
- manifest/meta storage and verification
- install report/session/audit/note storage
- optional content-addressed blob metadata + payload storage
- CLI for `init`, `inspect`, `verify`, `add-report`, `add-note`, `export-manifest`

Test coverage includes unit tests and optional real-IDA integration probes:

- `tests/test_capsule_store.py`
- `tests/test_capsule_cli.py`
- `tests/test_capsule_installer_integration.py`
- `tests/integration/test_capsule_real_ida.py` (requires licensed IDA and integration env)

## Roadmap

Planned follow-on work:

- capsule-backed MCP sessions
- installer materialization graph
- analysis deltas
- evidence cards
- analysis-only export
- backend-neutral adapters
- optional executable wrapper
- signed capsules
- capsule diff/replay
