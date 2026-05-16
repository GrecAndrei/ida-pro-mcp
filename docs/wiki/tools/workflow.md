# workflow

Deterministic orchestration façade for multi-step analysis plans and execution.

## Core Run Actions
- `triage_fast` — fast first-pass triage (firmware-aware).
- `malware_deep` — deeper malware-focused sequence.
- `vuln_audit` — exploit/vulnerability-oriented sequence.
- `recon_sweep` — broad orientation + structured retrieval + protocol + posture.
- `patch_review` — xref/dependency review around one target address.

## Planning & Control Actions
- `catalog` — list available workflows/capabilities.
- `plan` — return dry-run plan for one workflow action.
- `explain` — dry-run plan + per-step rationale.
- `estimate` — complexity/risk/category projection for a plan.
- `compose` — merge multiple workflow plans with dedup + source annotations.
- `prioritize` — reorder a plan by strategy (`original`, `coverage`, `risk_first`).
- `audit_plan` — validate/score a plan before execution.
- `execute_plan` — execute a provided/generated plan through batch.

## Examples
```json
{"name":"workflow","arguments":{"action":"plan","workflow_action":"recon_sweep","profile":"deep"}}
```
```json
{"name":"workflow","arguments":{"action":"compose","workflow_actions":["triage_fast","vuln_audit"],"priority_mode":"coverage"}}
```
```json
{"name":"workflow","arguments":{"action":"execute_plan","workflow_action":"triage_fast","continue_on_error":true}}
```

## Notes
- `dry_run`, `include_tools`, and `exclude_tools` work across planning paths.
- `triage_fast`/`recon_sweep` auto-inject firmware orientation steps when firmware is detected.
- `workflow_meta` is preserved across compact/full/output projection modes.
