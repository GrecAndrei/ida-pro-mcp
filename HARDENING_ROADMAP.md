# IDA Pro MCP Hardening Roadmap

This roadmap captures a stability-first, tool-surface-cleanup-first program for the current repo state.

## Objectives

1. Reduce cross-layer breakage between host orchestration, schema catalog, and IDA runtime bridge.
2. Keep docs, schema metadata, and tools/list behavior in lockstep.
3. Prioritize deterministic execution and test-backed confidence for high-complexity flows.

## Current High-Risk Areas

1. Tool-surface drift:
   - `docs/TOOLS_REFERENCE.md` and `docs/TECHNICAL_REFERENCE.md` have historically drifted from live `schemas_data.py`.
   - Risk: onboarding confusion, invalid assumptions in agent playbooks, stale operational docs.
2. Runtime observability gaps:
   - `misc.health` previously exposed only a minimal catalog snapshot.
   - Risk: weak diagnostics when tool-surface or action-surface mismatches occur.
3. Cross-layer orchestration complexity:
   - Workflow planning/execution, blackboard policy gating, and runtime lifecycle create high coupling.
   - Risk: regressions that pass narrow unit tests but fail integrated analysis sessions.

## This Turn: Implemented

1. Added tool-surface observability in `misc.health`:
   - Registered/advertised/hidden tool counts.
   - Wrapper actions list.
   - Action-surface metrics: total actions, max-actions tool, and per-tool counts in verbose mode.
2. Added regression tests for health catalog data:
   - `tests/test_misc_health_catalog.py`.
3. Added docs/schema consistency guards:
   - `tests/test_docs_surface_consistency.py` ensures docs counts match live schema counts.
4. Updated stale docs counts to current schema values:
   - `docs/TOOLS_REFERENCE.md`.
   - `docs/TECHNICAL_REFERENCE.md`.

## Phase Plan

### Phase 1: Catalog Integrity (Immediate)

1. Keep schema counts and docs synchronized via CI test gates.
2. Add structured catalog digest to `misc.health` (future enhancement: hash + generation timestamp).
3. Enforce alias/action-collision checks in tests (future enhancement).

### Phase 2: Runtime Stability and Recovery

1. Expand integration tests for:
   - Session create/switch/restart with stale runtime recovery.
   - Blackbox-like workflow execution under `continue_on_error` modes.
   - Blackboard strict policy gates across mixed tool calls.
2. Add deterministic failure taxonomy coverage for bridge failures and IDA exits.

### Phase 3: Tool Surface Cleanup

1. Audit overlapping actions/aliases by frequency and risk.
2. Mark low-value legacy aliases for deprecation windows.
3. Keep host normalization permissive only where ambiguity is low.

### Phase 4: Operations and Documentation

1. Publish a single canonical architecture page for host-vs-IDA responsibilities.
2. Keep generated tool/reference docs tied to schema generation in CI.
3. Add troubleshooting playbooks for top failure classes:
   - IDA startup/library init failures.
   - Session-to-runtime mismatch.
   - Raw-binary architecture inference misses.

## Success Metrics

1. Zero doc/schema count drift on `main`.
2. Stable `misc.health` diagnostics for tool/action surface and runtime state.
3. Increased integration confidence in workflow + blackboard + runtime lifecycle paths.
4. Reduced ambiguity in tool aliases/actions over time.
