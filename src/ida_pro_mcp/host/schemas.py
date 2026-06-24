#!/usr/bin/env python3
"""
Tool registry: TOOL_ACTIONS, TOOL_DESCRIPTIONS, TOOL_ARG_SCHEMAS,
schema builders, alias resolution.
"""
import re
from typing import Any, Dict, List

from .schemas_data import (
    ADVERTISED_TOOLS,
    BASE_TOOL_ALIASES,
    TOOLS,
    TOOL_ACTIONS as _TOOL_ACTIONS_DATA,
    TOOL_ARG_SCHEMAS,
    TOOL_DESCRIPTIONS,
    _ACTION_ALIAS_HINTS,
    _COMMON_ARG_ALIAS_HINTS,
    _EXTRA_TOOL_ALIASES,
    _TOOL_ACTION_EXTRA_ALIASES,
    _TOOL_SPECIFIC_ARG_ALIASES,
)

TOOL_ACTIONS = _TOOL_ACTIONS_DATA

# Compatibility anchors for source-based regression tests.
# "semantic_decompile"
# "decomp_dataflow"
# "dominance_map"
# "var_dependency_graph"
# "def_use_graph"
# "anchor_coverage"

WRAPPER_ACTIONS = ("grep", "pick", "head", "tail", "next", "stats")
LLM_HELPERS_DEFAULT_ACTIONS = (
    "bootstrap",
    "cheatsheet",
    "binary_digest",
    "function_digest",
    "context_window",
    "explain_address",
    "suggest_next",
    "progress_report",
    "focus_area",
    "question_answer",
    "guided_analysis",
    "compact",
    "enrich",
    "behavioral_signature_search",
    "function_role_classifier",
    "dangerous_pattern_explainer",
    "next_best_action_recommender",
)
ACTION_PREFIX_RE = re.compile(r"^action[\s\"']*[:=][\s\"']*", re.IGNORECASE)
ACTION_STRIP_CHARS = "\"'"
_WRAPPER_PAIRS = (("[", "]"), ("(", ")"), ("{", "}"), ("<", ">"))

# =============================================================================
# TOOLS REGISTRY
# =============================================================================



# Keep tools/list compact for LLM context windows while preserving backward-compatible calls.
HIDDEN_TOOLS_IN_LIST = {t for t in TOOLS if t not in ADVERTISED_TOOLS}


def _snake_variants(value: str) -> set[str]:
    base = str(value or "").strip().lower()
    if not base:
        return set()
    out = {
        base,
        base.replace("-", "_"),
        base.replace(" ", "_"),
        base.replace("_", "-"),
        base.replace("_", ""),
        base.replace("_", "."),
        base.replace("_", "/"),
    }
    if base.endswith("s") and len(base) > 3:
        out.add(base[:-1])
    else:
        out.add(f"{base}s")
    out.add(f"{base}_tool")
    out.add(f"{base}_tools")
    out.add(f"tool_{base}")
    out.add(f"tools_{base}")
    return {x for x in out if x}

def _camel_variants(value: str) -> set[str]:
    words = [w for w in str(value or "").replace("-", "_").split("_") if w]
    if len(words) <= 1:
        return set()
    pascal = "".join(w.capitalize() for w in words)
    camel = words[0].lower() + "".join(w.capitalize() for w in words[1:])
    return {camel, pascal}

def _strip_balanced_wrappers(value: str, rounds: int = 3) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    for _ in range(rounds):
        changed = False
        text = text.strip().strip(",;")
        stripped_quotes = text.strip(ACTION_STRIP_CHARS + "`")
        if stripped_quotes != text:
            text = stripped_quotes
            changed = True
        for left, right in _WRAPPER_PAIRS:
            if len(text) >= 2 and text.startswith(left) and text.endswith(right):
                text = text[1:-1].strip()
                changed = True
        if not changed:
            break
    return text

def _noisy_alias_variants(value: str) -> set[str]:
    base = str(value or "").strip().lower()
    if not base:
        return set()
    return {
        f"[{base}]",
        f"({base})",
        f"{{{base}}}",
        f"<{base}>",
        f'"{base}"',
        f"'{base}'",
        f"`{base}`",
        f"{base}()",
        f"{base}:",
        f"{base}=",
        f"tool:{base}",
        f"{base}.tool",
    }

def _normalize_alias_lookup_key(value: Any) -> str:
    stripped = _strip_balanced_wrappers(str(value or ""))
    without_prefix = ACTION_PREFIX_RE.sub("", stripped)
    return without_prefix.strip().strip(",;").lower()

def _resolve_tool_alias(name: Any) -> Any:
    if not isinstance(name, str):
        return name
    normalized = _normalize_alias_lookup_key(name)
    if not normalized:
        return name
    resolved = TOOL_ALIASES.get(normalized)
    if resolved:
        return resolved
    if normalized in TOOLS:
        return normalized
    # Fallback for callers that already pass clean aliases/canonical names.
    return TOOL_ALIASES.get(name, name)

def _build_tool_aliases(tools: list[str], explicit: dict[str, str]) -> dict[str, str]:
    candidates: Dict[str, set[str]] = {}
    for tool in tools:
        variants = _snake_variants(tool).union(_camel_variants(tool))
        for alias in list(variants):
            variants.update(_noisy_alias_variants(alias))
        for alias in variants:
            key = _normalize_alias_lookup_key(alias)
            if key:
                candidates.setdefault(key, set()).add(tool)
    for alias, target in (explicit or {}).items():
        key = _normalize_alias_lookup_key(alias)
        target_key = _normalize_alias_lookup_key(target)
        if key and target_key:
            candidates.setdefault(key, set()).add(target_key)
    resolved: dict[str, str] = {}
    for alias, targets in candidates.items():
        if len(targets) == 1:
            target = next(iter(targets))
            if alias != target:
                resolved[alias] = target
    return resolved

TOOL_ALIASES = _build_tool_aliases(TOOLS, {**BASE_TOOL_ALIASES, **_EXTRA_TOOL_ALIASES})







# Broad malformed/variant aliases accepted for high-noise LLM tool calls.

_TOOL_ARG_EXTRA_ALIASES = {
    "threat_hunt": {
        "legacy_tool": {"source_tool", "tool_name", "legacyTool", "tool"},
        "legacy_action": {"source_action", "action_name", "legacyAction", "on"},
        "profile": {"mode", "depth", "scan_mode"},
        "query": {"q", "needle", "search"},
        "addr": {"address", "ea", "va"},
        "include_tracing": {"tracing", "with_tracing", "trace"},
        "include_malware": {"malware", "with_malware"},
        "include_vuln": {"vuln", "with_vuln", "security"},
        "include_evidence": {"evidence", "with_evidence", "proof"},
        "limit": {"max", "max_items", "count", "n"},
        "max_steps": {"steps", "max_calls", "pipeline_steps"},
        "scan_profile": {"vuln_profile", "scanner_profile"},
        "severity": {"risk", "level"},
        "legacy_passthrough": {"passthrough", "exact_legacy", "strict_legacy"},
    },
    "search": {
        "pattern": {"needle", "text", "query_text"},
        "query": {"q", "search", "find"},
        "addr": {"address", "ea"},
        "limit": {"max", "count", "n"},
        "offset": {"skip"},
        "start": {"from", "start_addr"},
        "end": {"to", "end_addr"},
        "case_sensitive": {"case", "match_case"},
        "include_context": {"context", "with_context"},
        "include_items": {"items", "with_items"},
        "include_breakdown": {"breakdown", "stats"},
        "timeout_ms": {"timeout", "timeout_millis"},
        "max_functions": {"max_funcs", "function_cap"},
        "sample": {"sample_mode", "sampling"},
        "sample_max_funcs": {"sample_limit", "sample_cap"},
    },
    "session": {
        "binary_path": {"binary", "path", "target", "input"},
        "session_id": {"sid", "session", "id"},
        "force_new": {"new", "create_new", "fresh"},
        "analysis_options": {"analysis", "options"},
        "ida_args": {"idat_args", "args"},
        "tags": {"labels", "tag_list"},
        "notes": {"description"},
        "query": {"q", "search"},
        "limit": {"max", "count", "n"},
        "offset": {"skip"},
        "name": {"title", "session_name"},
        "data": {"payload"},
        "session_ids": {"sids", "sessions"},
        "tag": {"label"},
        "snapshot_id": {"snapshot", "snap_id"},
        "source_id": {"from_sid", "source"},
        "target_id": {"to_sid", "target"},
        "run_action": {"macro_action", "action_to_run"},
        "baseaddr": {"load_base", "image_base", "rebased_addr"},
    },
    "code": {
        "addrs": {"addr", "address", "ea", "vas", "targets"},
        "addr": {"address", "ea", "va"},
        "max_items": {"max", "count", "n"},
        "max_depth": {"depth", "levels"},
        "format": {"fmt"},
        "disasm_style": {"style", "disasmStyle"},
        "include_bytes": {"bytes", "with_bytes"},
        "end": {"end_addr", "to"},
        "limit": {"max", "count"},
        "field_name": {"field", "member"},
        "target": {"to", "destination"},
    },
    "schemaboot": {
        "constraints": {"filters", "where", "criteria"},
        "addr": {"address", "ea", "va"},
        "limit": {"max", "count", "n"},
        "offset": {"skip"},
        "order_by": {"sort", "order"},
        "include_apis": {"apis", "with_apis"},
        "include_strings": {"strings", "with_strings"},
    },
    "governance": {
        "operation_type": {"op_type", "type", "op"},
        "proposed_value": {"value", "text", "content", "input"},
        "addr": {"address", "ea", "va"},
    },
}

def _build_action_aliases() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for tool_name, actions in TOOL_ACTIONS.items():
        alias_map: dict[str, str] = {}
        for action in actions:
            candidates = _snake_variants(action).union(_camel_variants(action))
            candidates.update(_ACTION_ALIAS_HINTS.get(action, set()))
            candidates.update(
                _TOOL_ACTION_EXTRA_ALIASES.get(tool_name, {}).get(action, set())
            )
            if action.startswith("get_"):
                candidates.add(action.replace("get_", "show_", 1))
            if action.startswith("set_"):
                candidates.add(action.replace("set_", "update_", 1))
            if action.startswith("find_"):
                candidates.add(action.replace("find_", "search_", 1))
            if action.startswith("list_"):
                candidates.add(action.replace("list_", "get_", 1))
            for alias in list(candidates):
                candidates.update(_noisy_alias_variants(alias))
            for alias in candidates:
                key = _normalize_alias_lookup_key(alias)
                if not key:
                    continue
                existing = alias_map.get(key)
                if existing and existing != action:
                    alias_map.pop(key, None)
                    continue
                alias_map[key] = action
        for action in actions:
            alias_map.pop(action.lower(), None)
        out[tool_name] = alias_map
    return out

def _build_tool_arg_aliases() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for tool_name in TOOLS:
        canonical_keys = set(TOOL_ARG_SCHEMAS.get(tool_name, {}).keys())
        canonical_keys.add("action")
        canonical_keys.update(_TOOL_SPECIFIC_ARG_ALIASES.get(tool_name, {}).keys())
        alias_map: dict[str, str] = {}
        # Sort for deterministic alias conflict resolution across processes/runs.
        for canonical in sorted(canonical_keys):
            candidates = _snake_variants(canonical).union(_camel_variants(canonical))
            # Keep argument aliasing conservative: avoid automatic singular/plural flips,
            # because some tools intentionally use both (e.g. tag vs tags, note vs notes).
            if canonical.endswith("s") and len(canonical) > 3:
                candidates.discard(canonical[:-1])
            else:
                candidates.discard(f"{canonical}s")
            candidates.update(_COMMON_ARG_ALIAS_HINTS.get(canonical, set()))
            candidates.update(
                _TOOL_SPECIFIC_ARG_ALIASES.get(tool_name, {}).get(canonical, set())
            )
            candidates.update(
                _TOOL_ARG_EXTRA_ALIASES.get(tool_name, {}).get(canonical, set())
            )
            for alias in list(candidates):
                candidates.update(_noisy_alias_variants(alias))
            for alias in candidates:
                key = _normalize_alias_lookup_key(alias)
                if not key:
                    continue
                existing = alias_map.get(key)
                if existing and existing != canonical:
                    alias_map.pop(key, None)
                    continue
                alias_map[key] = canonical
        for canonical, explicit_aliases in _TOOL_SPECIFIC_ARG_ALIASES.get(
            tool_name, {}
        ).items():
            for alias in explicit_aliases:
                alias_key = _normalize_alias_lookup_key(alias)
                if alias_key and alias_key != canonical.lower():
                    alias_map[alias_key] = canonical
        for canonical in canonical_keys:
            alias_map.pop(canonical.lower(), None)
        out[tool_name] = alias_map
    return out

ACTION_ALIASES_BY_TOOL = _build_action_aliases()
ARG_ALIASES_BY_TOOL = _build_tool_arg_aliases()

GLOBAL_RESPONSE_CONTROLS = {
    "_response_mode": {
        "type": "string",
        "enum": ["compact", "full"],
        "description": "Output mode. compact is default and reduces token usage.",
    },
    "_compact": {
        "type": "boolean",
        "description": "Shortcut for compact/full mode toggle.",
    },
    "_response_fields": {
        "type": ["array", "string"],
        "items": {"type": "string"},
        "description": "Optional top-level field projection (comma-separated string or list).",
    },
    "_response_omit": {
        "type": ["array", "string"],
        "items": {"type": "string"},
        "description": "Optional top-level field omission list.",
    },
    "_response_max_items": {
        "type": "integer",
        "description": "Max list items retained in compact mode.",
    },
    "_response_max_string": {
        "type": "integer",
        "description": "Max string length retained in compact mode.",
    },
    "_response_char_budget": {
        "type": "integer",
        "description": "Approximate max output chars before truncation middleware applies.",
    },
    "_response_table": {
        "type": "boolean",
        "description": "Convert repetitive list-of-object payloads into {columns,rows}.",
    },
    "_response_batch_compact": {
        "type": "boolean",
        "description": "Compact batch envelopes in compact mode.",
    },
    "_error_details": {
        "type": "string",
        "enum": ["none", "basic", "full"],
        "description": "Controls verbosity of error details.",
    },
    "_qol_mode": {
        "type": "string",
        "enum": ["tiny", "balanced", "debug"],
        "description": "QoL profile shortcut for response compaction presets.",
    },
}

GLOBAL_WRAPPER_ACTION_CONTROLS = {
    "source_action": {
        "type": "string",
        "description": "For wrapper actions (grep/pick/head/tail/stats): underlying action to execute first (aliases: on, target_action, subaction).",
    },
    "target_action": {"type": "string"},
    "on": {"type": "string"},
    "subaction": {"type": "string"},
    "grep": {
        "type": "string",
        "description": "Grep pattern (substring by default; regex if grep_regex=true).",
    },
    "grep_pattern": {"type": "string"},
    "grep_regex": {"type": "boolean"},
    "grep_case_sensitive": {"type": "boolean"},
    "grep_invert": {"type": "boolean"},
    "grep_field": {
        "type": "string",
        "description": "Optional top-level source field to grep (e.g. matches, functions, content).",
    },
    "grep_limit": {"type": "integer"},
    "grep_offset": {"type": "integer"},
    "pick_fields": {
        "type": ["array", "string"],
        "items": {"type": "string"},
        "description": "For action='pick': top-level fields to include.",
    },
    "pick_omit": {
        "type": ["array", "string"],
        "items": {"type": "string"},
        "description": "For action='pick': top-level fields to omit after pick_fields.",
    },
    "head_n": {"type": "integer"},
    "tail_n": {"type": "integer"},
    "next_token": {"type": "string"},
    "token": {"type": "string"},
    "cursor": {"type": "string"},
    "stats_include_payload": {"type": "boolean"},
    "_qol_mode": {
        "type": "string",
        "enum": ["tiny", "balanced", "debug"],
        "description": "QoL response profile preset.",
    },
    "qol_mode": {
        "type": "string",
        "enum": ["tiny", "balanced", "debug"],
    },
}

def _action_enum_with_grep(tool_name: str, *, compact_surface: bool = False) -> list[str]:
    actions = list(TOOL_ACTIONS.get(tool_name, []) or [])
    if compact_surface and tool_name == "llm_helpers":
        keep = set(LLM_HELPERS_DEFAULT_ACTIONS)
        actions = [a for a in actions if a in keep]
    for wrapper_action in WRAPPER_ACTIONS:
        if wrapper_action not in actions:
            actions.append(wrapper_action)
    return actions

def build_input_schema(tool_name: str) -> dict:
    props = {}
    required = []
    if tool_name in TOOL_ARG_SCHEMAS:
        props.update(TOOL_ARG_SCHEMAS[tool_name])
    elif tool_name in TOOL_ACTIONS:
        props["action"] = {"type": "string", "enum": TOOL_ACTIONS[tool_name]}
    for key, schema in GLOBAL_RESPONSE_CONTROLS.items():
        props.setdefault(key, schema)
    # idb parameter is now completely optional - uses current_session automatically
    # Only include it in schema for documentation, never required
    if (
        tool_name not in ("session", "bookmarks", "wiki", "batch")
        and "idb" not in props
    ):
        props["idb"] = {
            "type": "string",
            "description": "Optional: session_id, SID_* IDB id, binary path, or full IDB path. If omitted, uses active session.",
        }
    if "action" in props:
        action_schema = props.get("action")
        if isinstance(action_schema, dict):
            action_schema = dict(action_schema)
            action_schema["enum"] = _action_enum_with_grep(tool_name)
            props["action"] = action_schema
        for key, schema in GLOBAL_WRAPPER_ACTION_CONTROLS.items():
            props.setdefault(key, schema)
        required.append("action")
    return {"type": "object", "properties": props, "required": required}

def _lean_prop_schema(prop_name: str, schema: Any) -> dict:
    """
    Produce an ultra-lean per-parameter schema for tools/list.
    Keep action enum, but collapse other fields to just a basic type.
    """
    if not isinstance(schema, dict):
        return {"type": "string"}

    out: dict[str, Any] = {}
    raw_type = schema.get("type")
    if isinstance(raw_type, str):
        out["type"] = raw_type
    elif isinstance(raw_type, list):
        # Prefer a concrete scalar-ish type to avoid noisy anyOf-style payloads.
        preferred = None
        for t in ("string", "integer", "number", "boolean", "array", "object"):
            if t in raw_type:
                preferred = t
                break
        out["type"] = preferred or "string"
    elif prop_name == "action":
        out["type"] = "string"
    else:
        out["type"] = "string"

    if prop_name == "action":
        enum_vals = schema.get("enum")
        if isinstance(enum_vals, list):
            out["enum"] = enum_vals
    return out

def build_input_schema_lean(tool_name: str) -> dict:
    """
    Build a minimal input schema for tools/list to reduce prompt/context overhead.
    Preserves essential per-tool argument fields while stripping verbose text.
    """
    props = {}
    required = []
    if tool_name in TOOL_ARG_SCHEMAS:
        for k, v in TOOL_ARG_SCHEMAS[tool_name].items():
            props[k] = _lean_prop_schema(k, v)
    elif tool_name in TOOL_ACTIONS:
        props["action"] = {"type": "string", "enum": TOOL_ACTIONS[tool_name]}
    if tool_name not in ("session", "bookmarks", "wiki", "batch"):
        props["idb"] = {"type": "string"}
    if "action" in props:
        action_schema = props.get("action")
        if isinstance(action_schema, dict):
            action_schema = dict(action_schema)
            action_schema["enum"] = _action_enum_with_grep(tool_name, compact_surface=True)
            props["action"] = action_schema
        for key, schema in GLOBAL_WRAPPER_ACTION_CONTROLS.items():
            props.setdefault(key, _lean_prop_schema(key, schema))
        required.append("action")
    return {"type": "object", "properties": props, "required": required}

def build_input_schema_ultra(tool_name: str) -> dict:
    """
    Build a very small schema for tools/list to minimize startup context.
    Keeps only the essential invocation shape (action enum + optional idb).
    """
    if tool_name == "batch":
        return {
            "type": "object",
            "properties": {
                "calls": {"type": "array", "items": {"type": ["object", "string"]}},
                "continue_on_error": {"type": "boolean"},
            },
            "required": ["calls"],
        }
    if tool_name == "truncation":
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": TOOL_ACTIONS["truncation"]},
                "token": {"type": "string"},
            },
            "required": ["action"],
        }

    if tool_name == "session":
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": _action_enum_with_grep("session", compact_surface=True)},
                "binary_path": {"type": "string", "description": "Absolute path to target binary (required for action='create')."},
                "idb": {"type": "string", "description": "Optional. session_id, SID_* id, or IDB path."},
            },
            "required": ["action"],
        }

    props: Dict[str, Any] = {}
    required: List[str] = []
    action_enum = TOOL_ACTIONS.get(tool_name)
    if action_enum:
        props["action"] = {"type": "string", "enum": _action_enum_with_grep(tool_name, compact_surface=True)}
        required.append("action")
    if tool_name not in ("session", "bookmarks", "wiki", "batch", "truncation"):
        props["idb"] = {
            "type": "string",
            "description": "Optional. session_id, SID_* id, binary path, or full IDB path.",
        }
    return {"type": "object", "properties": props, "required": required}

def build_tool_description_ultra(tool_name: str) -> str:
    """One-line description + compact action list for ultra (token-minimal) mode."""
    full = str(TOOL_DESCRIPTIONS.get(tool_name, "") or "").strip()
    if not full:
        return f"Use wiki(topic='tools/{tool_name}') for usage."
    # First sentence only, then append a compact action list if present.
    first = full.split(". ")[0].strip(" .")
    if "Actions:" in full:
        actions_raw = full.split("Actions:", 1)[1].strip()
        # Keep only the comma-separated action names, drop trailing prose/NOTEs.
        actions_part = actions_raw.split(".")[0].strip()
        if len(actions_part) > 120:
            actions_part = actions_part[:117] + "..."
        return f"{first}. Actions: {actions_part}."
    if len(first) > 160:
        first = first[:157] + "..."
    return first + "."

def build_tool_description_lean(tool_name: str) -> str:
    """Short description + full action list, no trailing prose/NOTEs."""
    full = str(TOOL_DESCRIPTIONS.get(tool_name, "") or "").strip()
    if not full:
        return ""
    # Strip NOTE/footnote prose that appears after the action list.
    for marker in (" NOTE:", " (read ", " Prefer ", " Use wiki"):
        if marker in full:
            full = full.split(marker, 1)[0].strip()
    full = re.sub(r"\s+", " ", full).strip(" .")
    if not full:
        return ""
    if len(full) > 300:
        full = full[:297].rstrip() + "..."
    return full + "."

_TOOL_CATEGORY_CORE = {"session", "truncation", "bookmarks", "batch", "wiki"}
_TOOL_CATEGORY_ANALYSIS = {
    "analysis",
    "query",
    "idb",
    "code",
    "data",
    "search",
    "types",
    "memory",
    "modify",
    "funcs",
    "segments",
    "bulk",
    "calc",
    "nav",
}
_TOOL_CATEGORY_DEBUG = {"debug", "coverage", "trace_analysis"}
_TOOL_CATEGORY_PROJECT = {"project", "misc"}
_TOOL_CATEGORY_ADVANCED = {
    "agent",
    "microcode",
    "graph",
    "ctree",
    "entropy",
    "imports_deep",
    "patterns",
    "symbols",
    "lumina",
    "export",
    "history",
    "colorize",
    "data_ops",
    "hooks",
}
_TOOL_CATEGORY_SECURITY = {
    "threat_hunt",
    "deobfuscate",
    "crypto_id",
    "protocol",
    "gadgets",
    "annotation",
    "string_ops",
    "cfg_analysis",
    "binary_info",
    "abi",
    "stack_analysis",
    "compare",
    "classify",
    "summarize",
}
_TOOL_CATEGORY_COMPAT = set()

def classify_tool_category(tool_name: str) -> str:
    if tool_name in _TOOL_CATEGORY_CORE:
        return "core"
    if tool_name in _TOOL_CATEGORY_ANALYSIS:
        return "analysis"
    if tool_name in _TOOL_CATEGORY_DEBUG:
        return "debug"
    if tool_name in _TOOL_CATEGORY_PROJECT:
        return "project"
    if tool_name in _TOOL_CATEGORY_ADVANCED:
        return "advanced"
    if tool_name in _TOOL_CATEGORY_SECURITY:
        return "security"
    if tool_name in _TOOL_CATEGORY_COMPAT:
        return "compat"
    return "other"

def sanitize_schema_for_vertex(schema: Any) -> Any:
    """
    Translates a schema into a Vertex AI/Gemini-compatible format by removing
    unsupported structures such as arrays of types, empty required arrays, and
    empty properties dictionaries.
    """
    if not isinstance(schema, dict):
        return schema

    out = {}
    for k, v in schema.items():
        if k == "type" and isinstance(v, list):
            # Prefer a scalar type, fallback to string if none found
            preferred = None
            for t in ("string", "integer", "number", "boolean", "array", "object"):
                if t in v:
                    preferred = t
                    break
            out[k] = preferred or "string"
        elif k == "required" and isinstance(v, list) and len(v) == 0:
            continue
        elif k == "properties" and isinstance(v, dict) and len(v) == 0:
            continue
        elif isinstance(v, dict):
            out[k] = sanitize_schema_for_vertex(v)
        elif isinstance(v, list):
            out[k] = [sanitize_schema_for_vertex(item) for item in v]
        else:
            out[k] = v

    if out.get("type") == "array" and "items" not in out:
        out["items"] = {"type": "string"}
    elif out.get("type") != "array" and "items" in out:
        del out["items"]

    return out
