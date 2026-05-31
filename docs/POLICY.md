# Policy Layer

`ida-pro-mcp` is powerful because it gives MCP clients structured access to IDA Pro. That power should be bounded by deterministic policy controls rather than by vague intent detection alone.

The host policy model is intentionally simple:

1. Classify each tool/action pair by capability risk.
2. Apply a policy mode.
3. Require explicit acknowledgement for high-impact actions.
4. Emit auditable decisions.
5. Treat semantic or embedding-based classifiers as advisory signals, not final authority.

## Policy modes

`IDA_MCP_POLICY_MODE` should use one of these values when integrated into dispatch:

| Mode | Behavior |
| --- | --- |
| `permissive` | Allow calls, but warn/audit high-risk actions. |
| `assist` | Default public-friendly mode. Read-only calls pass; high-risk calls require explicit acknowledgement. |
| `enforce` | Blocks disallowed purposes and requires acknowledgement for risky/unknown actions. |

## Risk tiers

The policy helper uses these capability tiers:

| Tier | Meaning |
| --- | --- |
| `read` | Read-only analysis/discovery. |
| `write_idb` | Mutates the IDA database: names, comments, types, annotations, functions, segments, etc. |
| `destructive` | Deletes, clears, resets, patches, or otherwise destructively changes state. |
| `filesystem_read` | Reads local files. |
| `filesystem_write` | Writes local files. |
| `local_code_exec` | Executes Python, IDC, plugins, or equivalent local code inside IDA. |
| `debugger` | Controls debugger state or interacts with a debug target. |
| `network_or_process` | Starts processes or interacts with network/process surfaces. |
| `unknown` | Tool/action is not classified and should be treated conservatively. |

## Explicit acknowledgements

High-impact actions should require an explicit acknowledgement flag such as `_risk_ack=true` before execution in `assist` or `enforce` mode.

Example:

```json
{
  "name": "misc",
  "arguments": {
    "action": "python",
    "code": "print('hello from IDA')",
    "_purpose": "firmware_analysis",
    "_risk_ack": true
  }
}
```

Without acknowledgement, the policy result should return `require_ack` with a reason explaining the risk tier.

## Purposes

Recognized legitimate purposes include:

- `oss_audit`
- `release_verification`
- `vulnerability_triage`
- `firmware_analysis`
- `game_modding`
- `preservation`
- `malware_triage_defensive`
- `legacy_documentation`
- `education`
- `general_research`

Disallowed purposes include:

- `cheating`
- `piracy`
- `drm_circumvention`
- `unauthorized_multiplayer_tampering`
- `unauthorized_access`
- `credential_theft`
- `exploit_development`

In `enforce` mode, disallowed purposes should be blocked. In softer modes, they should produce warnings or acknowledgement requirements depending on the action.

## Semantic classification

Embedding or LLM-based intent classification can help identify ambiguous requests, but it should not be the core safety mechanism.

Good use:

- add advisory flags such as `possible_cheating`, `possible_drm_circumvention`, or `unclear_authorization`
- recommend a stricter mode
- ask for human review before high-impact actions

Bad use:

- automatically allowing dangerous actions because a classifier thinks they are safe
- replacing deterministic checks for local code execution, filesystem writes, debugger control, or destructive IDB mutation

## Audit records

Every policy-relevant decision should be auditable. A compact record should include:

```json
{
  "event": "policy_decision",
  "session_id": "SID_...",
  "decision": "require_ack",
  "risk": "local_code_exec",
  "tool": "misc",
  "action": "python",
  "mode": "assist",
  "purpose": "firmware_analysis",
  "requires_ack": true,
  "reasons": ["Action risk tier 'local_code_exec' requires explicit acknowledgement."],
  "flags": []
}
```

## Integration guidance

The policy helper in `src/ida_pro_mcp/host/policy.py` is designed to be called before dispatching a tool action. A minimal integration path is:

1. Read mode from `IDA_MCP_POLICY_MODE`, defaulting to `assist`.
2. Read `_purpose` and `_risk_ack` from tool arguments.
3. Evaluate `evaluate_policy(tool, action, mode=..., purpose=..., ack=...)`.
4. If decision is `block`, return a structured policy error.
5. If decision is `require_ack`, return a structured acknowledgement-required error.
6. If decision is `warn` or `allow`, continue and log `build_audit_record(...)`.

The deterministic helper can be integrated without enabling any semantic classifier.
