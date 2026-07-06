#!/usr/bin/env python3
"""Deterministic host-side policy helpers for high-impact MCP actions.

The policy layer is intentionally boring: it classifies tool/action pairs into
risk tiers, applies explicit mode rules, and returns structured decisions.  Any
semantic or embedding-based classifier should feed *hints* into this module;
final allow/block/ack decisions should remain deterministic.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class PolicyMode(StrEnum):
    """Policy strictness for host-side tool execution."""

    PERMISSIVE = "permissive"
    ASSIST = "assist"
    ENFORCE = "enforce"
    OFF = "off"


class RiskTier(StrEnum):
    """Capability risk tiers used for deterministic gating."""

    READ = "read"
    WRITE_IDB = "write_idb"
    DESTRUCTIVE = "destructive"
    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    LOCAL_CODE_EXEC = "local_code_exec"
    DEBUGGER = "debugger"
    NETWORK_OR_PROCESS = "network_or_process"
    UNKNOWN = "unknown"


class PolicyDecision(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    REQUIRE_ACK = "require_ack"
    BLOCK = "block"


READ_ONLY_TOOLS = {
    "abi",
    "analysis",
    "binary_info",
    "bookmarks",
    "calc",
    "cfg_analysis",
    "classify",
    "code",
    "compare",
    "coverage",
    "crypto_id",
    "ctree",
    "data",
    "entropy",
    "export",
    "filter",
    "firmware_view",
    "graph",
    "history",
    "idb",
    "imports_deep",
    "knowledge",
    "lumina",
    "microcode",
    "nav",
    "patterns",
    "project",
    "protocol",
    "search",
    "session",
    "stack_analysis",
    "string_ops",
    "summarize",
    "symbols",
    "threat_hunt",
    "trace_analysis",
    "truncation",
    "types",
    "wiki",
    "workflow",
    "yara_hunt",
}

WRITE_IDB_TOOLS = {
    "annotation",
    "blackboard",
    "bulk",
    "data_ops",
    "fixups",
    "funcs",
    "governance",
    "hooks",
    "modify",
    "segments",
}

DESTRUCTIVE_ACTIONS = {
    "clear",
    "delete",
    "drop",
    "erase",
    "patch",
    "patch_asm",
    "remove",
    "reset",
    "truncate",
}

WRITE_ACTIONS = {
    "add",
    "annotate",
    "apply",
    "apply_type",
    "auto_comment",
    "auto_comment_function",
    "cleanup",
    "comment",
    "create",
    "import",
    "label",
    "make_code",
    "make_data",
    "merge",
    "rename",
    "rename_stack",
    "set_attr",
    "set_flags",
    "set_name",
    "set_options",
    "set_perms",
    "set_type",
    "tag",
    "update",
    "write",
}

LOCAL_CODE_EXEC_ACTIONS = {
    ("misc", "python"),
    ("misc", "idc"),
    ("analysis", "plugin_run"),
    ("background", "script"),
}

FILESYSTEM_WRITE_ACTIONS = {
    ("memory", "write_file"),
    ("project", "write"),
}

FILESYSTEM_READ_ACTIONS = {
    ("memory", "read_file"),
    ("project", "read"),
}

READ_ONLY_ACTIONS = {
    ("funcs", "info"),
    ("funcs", "list"),
    ("funcs", "find_similar"),
    ("session", "health"),
    ("session", "create"),
    ("governance", "list_rules"),
    ("governance", "stats"),
    ("governance", "check"),
    ("funcs", "metrics"),
    ("funcs", "suggest_names"),
}

DEBUGGER_TOOLS = {"debug"}

DISALLOWED_PURPOSES = {
    "cheating",
    "credential_theft",
    "drm_circumvention",
    "exploit_development",
    "piracy",
    "unauthorized_access",
    "unauthorized_multiplayer_tampering",
}

RECOGNIZED_PURPOSES = {
    "defensive_triage",
    "education",
    "firmware_analysis",
    "game_modding",
    "general_research",
    "legacy_documentation",
    "malware_triage_defensive",
    "oss_audit",
    "preservation",
    "release_verification",
    "vulnerability_triage",
}


@dataclass(frozen=True)
class PolicyResult:
    decision: PolicyDecision
    risk: RiskTier
    tool: str
    action: str
    mode: PolicyMode
    purpose: str | None = None
    requires_ack: bool = False
    reasons: tuple[str, ...] = field(default_factory=tuple)
    flags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.decision in {PolicyDecision.ALLOW, PolicyDecision.WARN}

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "allowed": self.allowed,
            "risk": self.risk.value,
            "tool": self.tool,
            "action": self.action,
            "mode": self.mode.value,
            "purpose": self.purpose,
            "requires_ack": self.requires_ack,
            "reasons": list(self.reasons),
            "flags": list(self.flags),
        }


def normalize_mode(value: Any, default: PolicyMode = PolicyMode.ASSIST) -> PolicyMode:
    if isinstance(value, PolicyMode):
        return value
    raw_value = getattr(value, "value", value)
    raw = str(raw_value or default.value).strip().lower()
    try:
        return PolicyMode(raw)
    except ValueError:
        return default


def normalize_name(value: Any) -> str:
    return str(value or "").strip().lower()


def truthy(value: Any) -> bool:
    from .config import _coerce_bool
    return _coerce_bool(value, default=False)


def classify_tool_action(tool: Any, action: Any) -> RiskTier:
    tool_name = normalize_name(tool)
    action_name = normalize_name(action)
    pair = (tool_name, action_name)

    if pair in LOCAL_CODE_EXEC_ACTIONS:
        return RiskTier.LOCAL_CODE_EXEC
    if pair in FILESYSTEM_WRITE_ACTIONS:
        return RiskTier.FILESYSTEM_WRITE
    if pair in FILESYSTEM_READ_ACTIONS:
        return RiskTier.FILESYSTEM_READ
    if tool_name in DEBUGGER_TOOLS:
        return RiskTier.DEBUGGER
    if action_name in DESTRUCTIVE_ACTIONS:
        return RiskTier.DESTRUCTIVE
    if pair in READ_ONLY_ACTIONS:
        return RiskTier.READ
    if tool_name in WRITE_IDB_TOOLS or action_name in WRITE_ACTIONS:
        return RiskTier.WRITE_IDB
    if tool_name in READ_ONLY_TOOLS:
        return RiskTier.READ
    return RiskTier.UNKNOWN


def purpose_flags(purpose: Any) -> tuple[str, ...]:
    normalized = normalize_name(purpose)
    if not normalized:
        return ()
    flags = []
    if normalized in DISALLOWED_PURPOSES:
        flags.append("disallowed_purpose")
    elif normalized not in RECOGNIZED_PURPOSES:
        flags.append("unknown_purpose")
    return tuple(flags)


def evaluate_policy(
    tool: Any,
    action: Any,
    *,
    mode: Any = PolicyMode.ASSIST,
    purpose: Any = None,
    ack: Any = False,
    classifier_flags: Iterable[str] | None = None,
) -> PolicyResult:
    """Evaluate a deterministic policy decision for a tool/action call.

    Embedding or LLM classifiers may pass `classifier_flags`, but those flags
    only add reasons. Deterministic tool/action risk and explicit mode/ack rules
    decide whether the call is allowed, blocked, or requires acknowledgement.
    """

    tool_name = normalize_name(tool)
    action_name = normalize_name(action)
    policy_mode = normalize_mode(mode)
    normalized_purpose = normalize_name(purpose) or None

    if policy_mode == PolicyMode.OFF:
        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            risk=RiskTier.READ,
            tool=tool_name,
            action=action_name,
            mode=policy_mode,
            purpose=normalized_purpose,
            requires_ack=False,
            reasons=(),
            flags=(),
        )

    risk = classify_tool_action(tool_name, action_name)
    acknowledged = truthy(ack)

    flags = list(purpose_flags(normalized_purpose))
    for flag in classifier_flags or ():
        flag_s = normalize_name(flag)
        if flag_s and flag_s not in flags:
            flags.append(flag_s)

    reasons = []
    requires_ack = risk in {
        RiskTier.WRITE_IDB,
        RiskTier.DESTRUCTIVE,
        RiskTier.FILESYSTEM_WRITE,
        RiskTier.LOCAL_CODE_EXEC,
        RiskTier.DEBUGGER,
        RiskTier.NETWORK_OR_PROCESS,
        RiskTier.UNKNOWN,
    }

    if "disallowed_purpose" in flags:
        reasons.append(f"Purpose '{normalized_purpose}' is not allowed for this project policy.")
        if policy_mode == PolicyMode.ENFORCE:
            return PolicyResult(
                decision=PolicyDecision.BLOCK,
                risk=risk,
                tool=tool_name,
                action=action_name,
                mode=policy_mode,
                purpose=normalized_purpose,
                requires_ack=requires_ack,
                reasons=tuple(reasons),
                flags=tuple(flags),
            )

    if risk == RiskTier.READ and "unknown_purpose" not in flags:
        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            risk=risk,
            tool=tool_name,
            action=action_name,
            mode=policy_mode,
            purpose=normalized_purpose,
            requires_ack=False,
            reasons=tuple(reasons),
            flags=tuple(flags),
        )

    if requires_ack and not acknowledged:
        reasons.append(f"Action risk tier '{risk.value}' requires explicit acknowledgement.")
        decision = PolicyDecision.WARN if policy_mode == PolicyMode.PERMISSIVE else PolicyDecision.REQUIRE_ACK
    elif "unknown_purpose" in flags:
        reasons.append(f"Purpose '{normalized_purpose}' is not recognized; proceed only if authorized.")
        decision = PolicyDecision.WARN if policy_mode != PolicyMode.ENFORCE else PolicyDecision.REQUIRE_ACK
    else:
        decision = PolicyDecision.ALLOW

    return PolicyResult(
        decision=decision,
        risk=risk,
        tool=tool_name,
        action=action_name,
        mode=policy_mode,
        purpose=normalized_purpose,
        requires_ack=requires_ack and not acknowledged,
        reasons=tuple(reasons),
        flags=tuple(flags),
    )


def build_audit_record(result: PolicyResult, *, session_id: str | None = None) -> dict[str, Any]:
    """Build a compact audit record for policy-relevant calls."""

    return {
        "event": "policy_decision",
        "session_id": session_id,
        **result.to_dict(),
    }
