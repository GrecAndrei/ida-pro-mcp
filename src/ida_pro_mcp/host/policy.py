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
    "analysis",
    "bookmarks",
    "calc",
    "code",
    "ctree",
    "data",
    "graph",
    "idb",
    "imports_deep",
    "intelligence",
    "knowledge",
    "search",
    "session",
    "stack_analysis",
    "symbols",
    "truncation",
    "types",
    "wiki",
    "workflow",
}

WRITE_IDB_TOOLS = {
    "annotation",
    "batch",
    "blackboard",
    "firmware",
    "funcs",
    "governance",
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

# (tool, action) pairs that delete or destroy state but whose action name is
# not distinctive enough for DESTRUCTIVE_ACTIONS (e.g. generic `close`/`kill`).
# `session` is otherwise READ_ONLY_TOOLS, so these would sail through without
# ack — yet they genuinely delete data (close/kill tear down a runtime,
# rebuild does `os.remove(idb_path)`, bulk_delete/cleanup_stale/idle_purge
# delete sessions, restore_snapshot replaces the live DB).
DESTRUCTIVE_TOOL_ACTIONS: set[tuple[str, str]] = {
    ("session", "close"),
    ("session", "kill"),
    ("session", "rebuild"),
    ("session", "bulk_delete"),
    ("session", "cleanup_stale"),
    ("session", "idle_purge"),
    ("session", "restore_snapshot"),
    # bootstrap_prune_data deletes persisted outcomes, disputes, and
    # snapshots from the session's durable skills state, so it belongs in the
    # destructive tier (not merely WRITE_TOOL_ACTIONS).
    ("session", "bootstrap_prune_data"),
}

# (tool, action) pairs that mutate the IDB (or equivalent durable state) but
# whose tool sits in READ_ONLY_TOOLS and whose action name is not distinctive
# enough for WRITE_ACTIONS (e.g. load_sig, declare). Without this set these
# would sail through without ack — yet they genuinely write to the IDB or its
# symbol database.
WRITE_TOOL_ACTIONS: set[tuple[str, str]] = {
    ("analysis", "reanalyze"),
    ("analysis", "set_architecture"),
    ("analysis", "set_loader_options"),
    ("analysis", "set_processor"),
    ("analysis", "add_entry"),
    ("analysis", "snapshot"),
    ("analysis", "restore_snapshot"),
    ("calc", "persist"),
    ("knowledge", "import_symbols"),
    ("misc", "load_sig"),
    ("multi_session", "group_create"),
    ("multi_session", "group_link"),
    ("session", "add_note"),
    ("session", "archive"),
    ("session", "clear_notes"),
    ("session", "duplicate"),
    # Session-skills bootstrap actions mutate the durable skills.json state for
    # the session, so they must require ack rather than sailing through as READ
    # (session is otherwise a READ_ONLY tool). bootstrap_policy_reweight_history
    # is deliberately NOT here — it only reads back past reweight history — and
    # bootstrap_readiness_regression_guard only returns a recommended-actions
    # plan without persisting, so it stays excluded too.
    ("session", "bootstrap_policy_reweight"),
    ("session", "bootstrap_run_tournament"),
    ("session", "bootstrap_simulate_batch"),
    ("session", "bootstrap_snapshot"),
    ("session", "bootstrap_evaluate_alerts"),
    ("session", "bootstrap_apply_mitigation"),
    ("session", "bootstrap_init"),
    ("session", "bootstrap_ingest_outcome"),
    ("session", "bootstrap_open_dispute"),
    ("session", "bootstrap_resolve_dispute"),
    ("session", "bootstrap_update_baseline"),
    ("session", "bootstrap_autopilot"),
    ("session", "bootstrap_set_autopilot_policy"),
    ("session", "bootstrap_rollback_last_reweight"),
    ("session", "bootstrap_record_readiness"),
    ("session", "bootstrap_finalize_report"),
    ("session", "bootstrap_prune_data"),
    ("session", "log_activity"),
    ("session", "rate_skill"),
    ("session", "snapshot"),
    ("session", "unarchive"),
    ("session", "untag"),
    ("symbols", "load_dwarf"),
    ("symbols", "load_pdb"),
    ("modify", "create_data"),
    ("modify", "create_strlit"),
    ("modify", "undo_begin"),
    ("modify", "undo_end"),
    ("segments", "sreg_set"),
    ("types", "declare"),
    ("types", "import_header"),
    ("types", "propagate"),
    ("types", "set_prototype"),
    # Struct/enum member editing + TIL carry mutate the type library, which
    # sits in READ_ONLY_TOOLS, so they must be explicit to avoid READ.
    ("types", "struct_member_add"),
    ("types", "struct_member_del"),
    ("types", "struct_member_rename"),
    ("types", "struct_member_set_type"),
    ("types", "enum_member_add"),
    ("types", "enum_member_rename"),
    ("types", "enum_member_revalue"),
    # til_delete mutates the type library; without this entry it would fall
    # through to READ (types ∈ READ_ONLY_TOOLS) because "til_delete" is not a
    # DESTRUCTIVE_ACTION. til_import is listed below for defense-in-depth even
    # though FILESYSTEM_READ wins the classify order.
    ("types", "til_delete"),
    ("types", "til_import"),
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
    "change",
    "create",
    "force_offset",
    "import",
    "label",
    "make_code",
    "make_data",
    "merge",
    "rename",
    "rename_stack",
    "save_idb",
    "set_af",
    "set_attr",
    "set_flags",
    "set_gp",
    "set_name",
    "set_options",
    "set_perms",
    "set_type",
    "tag",
    "undefine",
    "update",
    "write",
}

LOCAL_CODE_EXEC_ACTIONS = {
    ("misc", "python"),
    ("misc", "idc"),
    ("misc", "reload"),
    ("analysis", "plugin_run"),
    ("misc", "plugin_run"),
}

FILESYSTEM_WRITE_ACTIONS = {
    ("misc", "write_file"),
    ("symbols", "export"),
    ("knowledge", "export_session"),
    ("types", "til_export"),
}

FILESYSTEM_READ_ACTIONS = {
    ("misc", "read_file"),
    ("types", "til_import"),
}

# Actions that start or attach an external process (or open a network channel).
# The r2 sidecar engine spawns a rizin subprocess; start/attach are the
# process-lifecycle operations. Forward-declared for when the engine lands
# them — they must never fall through to READ.
NETWORK_OR_PROCESS_ACTIONS: set[tuple[str, str]] = {
    ("r2", "start"),
    ("r2", "attach"),
}

READ_ONLY_ACTIONS = {
    ("funcs", "info"),
    ("funcs", "list"),
    ("funcs", "find_similar"),
    ("session", "health"),
    ("session", "create"),
    ("session", "create_background"),
    ("governance", "list_rules"),
    ("governance", "stats"),
    ("governance", "check"),
    ("funcs", "metrics"),
    ("funcs", "suggest_names"),
    ("segments", "list"),
    ("segments", "info"),
    ("segments", "find_code"),
    ("segments", "find_data"),
    ("segments", "compare"),
    ("segments", "analyze"),
    ("misc", "list_sigs"),
    ("misc", "cache_stats"),
    ("misc", "plugin_list"),
    ("misc", "health"),
    ("data", "read_bytes"),
    # Blackboard reads: blackboard is in WRITE_IDB_TOOLS, so without these
    # explicit overrides every blackboard action would require an ack even
    # though read/list/search/stats/frontier/next_target only query the store.
    # decision_card is deliberately NOT here — the host handler writes a new
    # card via store.write, so it stays WRITE_IDB.
    ("blackboard", "read"),
    ("blackboard", "list"),
    ("blackboard", "search"),
    ("blackboard", "stats"),
    ("blackboard", "frontier"),
    ("blackboard", "next_target"),
    ("blackboard", "coverage"),
    # Additional blackboard reads that only query the store (no writes):
    ("blackboard", "working_set"),
    ("blackboard", "state_health"),
    ("blackboard", "conflicts"),
    ("blackboard", "stale"),
    ("blackboard", "recall"),
    ("blackboard", "workspace_brief"),
    ("blackboard", "campaign_summary"),
    ("blackboard", "phase_status"),
    ("search", "comment"),
    # Raw-value and query-language search only read the IDB.
    ("search", "data_value"),
    ("search", "query_lang"),
    # Segment-register queries read the sreg map without mutating it.
    ("segments", "sreg_get"),
    ("segments", "sreg_list"),
    # auto_wait only blocks until the analysis queue is idle.
    ("analysis", "auto_wait"),
    # idb events/registers are pure metadata reads.
    ("idb", "events"),
    ("idb", "registers"),
    # Firmware shaping detect_*/rtos_scan only probe a raw blob; carve (which
    # bounds a region) stays WRITE_IDB via the firmware entry in WRITE_IDB_TOOLS.
    ("firmware", "detect_vector_table"),
    ("firmware", "detect_load_base"),
    ("firmware", "detect_mmio"),
    ("firmware", "rtos_scan"),
    # r2 sidecar queries are read-only triage (they spawn a local rizin to read
    # the file, but never mutate the IDB). r2 start/attach, when the engine
    # lands them, are classified by NETWORK_OR_PROCESS_ACTIONS instead.
    ("r2", "status"),
    ("r2", "bininfo"),
    ("r2", "load_hints"),
    ("r2", "disassemble_hypothesis"),
    ("r2", "vxrefs"),
    ("gadgets", "rop"),
    ("gadgets", "jop"),
    ("gadgets", "cop"),
    ("gadgets", "syscall"),
    ("gadgets", "write_what_where"),
    ("gadgets", "stack_pivot"),
    ("gadgets", "shellcode_space"),
    ("gadgets", "mitigations"),
    ("gadgets", "seh_handlers"),
    ("gadgets", "pivot_chains"),
    ("gadgets", "classify_chain"),
    ("gadgets", "semantic_find"),
    ("memory", "read"),
    ("memory", "hexdump"),
    ("memory", "search"),
    ("memory", "compare"),
    ("memory", "pointers"),
    ("memory", "entropy"),
    ("memory", "strings"),
    ("memory", "struct_walk"),
    ("memory", "histogram"),
    ("multi_session", "group_list"),
    ("multi_session", "cross_resolve"),
    ("multi_session", "cross_decompile"),
    ("multi_session", "cross_xrefs"),
    ("multi_session", "status"),
}


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


# Strictness ordering used to combine policy modes from different sources.
MODE_STRICTNESS: dict[PolicyMode, int] = {
    PolicyMode.OFF: 0,
    PolicyMode.PERMISSIVE: 1,
    PolicyMode.ASSIST: 2,
    PolicyMode.ENFORCE: 3,
}


def strictest(*modes: Any) -> PolicyMode:
    """Return the strictest of the given modes.

    Callers use this to combine an operator-set baseline with a mode that
    arrived over the wire, so that the wire value can only tighten policy.
    """
    resolved = [normalize_mode(mode) for mode in modes if mode]
    if not resolved:
        return PolicyMode.ASSIST
    return max(resolved, key=lambda mode: MODE_STRICTNESS.get(mode, 0))


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
    if pair in NETWORK_OR_PROCESS_ACTIONS:
        return RiskTier.NETWORK_OR_PROCESS
    if action_name in DESTRUCTIVE_ACTIONS:
        return RiskTier.DESTRUCTIVE
    if pair in DESTRUCTIVE_TOOL_ACTIONS:
        return RiskTier.DESTRUCTIVE
    if pair in WRITE_TOOL_ACTIONS:
        return RiskTier.WRITE_IDB
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
        # OFF still reports the real risk tier so the audit trail reflects what
        # the action would have been — only the gate itself is bypassed.
        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            risk=classify_tool_action(tool_name, action_name),
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
        RiskTier.FILESYSTEM_READ,
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
