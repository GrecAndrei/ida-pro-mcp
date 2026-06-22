#!/usr/bin/env python3
"""
Generate and verify 10k+ (typically 20k with defaults used in CI/task flow)
noisy-but-plausible action/arg variations that MCP should accept.

This script emits a JSON artifact with accepted/rejected variants by tool and target field.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _mk_server():
    import ida_mcp_stdio as host

    orig_detect = host.IDAMCPServer._detect_ida_dir
    orig_find = host.IDAMCPServer._find_idat
    host.IDAMCPServer._detect_ida_dir = lambda self: ""
    host.IDAMCPServer._find_idat = lambda self: ""
    try:
        server = host.IDAMCPServer()
    finally:
        host.IDAMCPServer._detect_ida_dir = orig_detect
        host.IDAMCPServer._find_idat = orig_find
    return server, host


def _wrappers(value: str) -> list[str]:
    return [
        value,
        value.upper(),
        value.lower(),
        f"[{value}]",
        f"({value})",
        f"{{{value}}}",
        f"<{value}>",
        f'"{value}"',
        f"'{value}'",
        f"`{value}`",
        f"{value}()",
        f"{value}:",
        f"{value}=",
        f"tool:{value}",
        f"{value}.tool",
        f" action:{value} ",
    ]


def _noisy_keys(key: str) -> list[str]:
    return [
        key,
        key.upper(),
        key.lower(),
        key.replace("_", "-"),
        key.replace("_", ""),
        f"[{key}]",
        f"({key})",
        f'"{key}"',
        f"'{key}'",
        f"{key}:",
        f"{key}=",
    ]


def _field_test_value(field: str) -> str:
    if "addr" in field or field in {"start", "end", "target"}:
        return "0x401000"
    if "id" in field:
        return "ABCD1234"
    if "path" in field:
        return "/tmp/test.bin"
    if "count" in field or "limit" in field or "offset" in field or "max" in field:
        return "16"
    if "profile" in field:
        return "balanced"
    if "severity" in field:
        return "high"
    if "name" in field:
        return "main"
    if "tag" in field:
        return "triage"
    if "query" in field or "pattern" in field:
        return "main"
    return "x"


def _iter_target_tools(host) -> list[str]:
    return ["threat_hunt", "search", "session", "code"]


def generate_variants(seed: int, max_cases: int) -> dict[str, Any]:
    random.seed(seed)
    server, host = _mk_server()
    out: dict[str, Any] = {"seed": seed, "tools": {}, "totals": {"cases": 0, "accepted": 0, "rejected": 0}}
    for tool in _iter_target_tools(host):
        actions = list(host.TOOL_ACTIONS.get(tool, []))
        arg_schema = host.TOOL_ARG_SCHEMAS.get(tool, {})
        action_aliases = host.ACTION_ALIASES_BY_TOOL.get(tool, {})
        arg_aliases = host.ARG_ALIASES_BY_TOOL.get(tool, {})
        tool_rows = []
        # Action normalization variants
        for action in actions:
            cands = set(_wrappers(action))
            for alias_key, alias_target in action_aliases.items():
                if alias_target == action:
                    cands.add(alias_key)
                    cands.update(_wrappers(alias_key))
            for cand in cands:
                args = {"action": cand}
                normalized = server._normalize_tool_call_args(tool, args)
                accepted = normalized.get("action") == action
                tool_rows.append(
                    {
                        "kind": "action",
                        "tool": tool,
                        "target": action,
                        "variant": cand,
                        "accepted": accepted,
                        "normalized": normalized.get("action"),
                    }
                )
        # Argument key/value normalization variants
        for canonical in sorted(arg_schema.keys()):
            if canonical == "action":
                continue
            test_value = _field_test_value(canonical)
            candidate_keys = set(_noisy_keys(canonical))
            for alias_key, alias_target in arg_aliases.items():
                if alias_target == canonical:
                    candidate_keys.add(alias_key)
                    candidate_keys.update(_noisy_keys(alias_key))
            value_variants = _wrappers(test_value)
            if canonical in {"addrs"}:
                value_variants.extend([f"[{test_value}]", f"[{test_value},{test_value}]"])
            for key_variant in candidate_keys:
                for value_variant in value_variants:
                    args = {"action": actions[0] if actions else "run", key_variant: value_variant}
                    normalized = server._normalize_tool_call_args(tool, args)
                    accepted = canonical in normalized
                    tool_rows.append(
                        {
                            "kind": "arg",
                            "tool": tool,
                            "target": canonical,
                            "variant": {"key": key_variant, "value": value_variant},
                            "accepted": accepted,
                            "normalized_has_key": canonical in normalized,
                        }
                    )
        random.shuffle(tool_rows)
        if len(tool_rows) > max_cases:
            tool_rows = tool_rows[:max_cases]
        accepted = sum(1 for row in tool_rows if row.get("accepted"))
        out["tools"][tool] = {
            "count": len(tool_rows),
            "accepted": accepted,
            "rejected": len(tool_rows) - accepted,
            "rows": tool_rows,
        }
        out["totals"]["cases"] += len(tool_rows)
        out["totals"]["accepted"] += accepted
        out["totals"]["rejected"] += len(tool_rows) - accepted
    return out


def compact_payload(payload: dict[str, Any], max_rows_per_tool: int) -> dict[str, Any]:
    compacted = {
        "seed": payload.get("seed"),
        "totals": payload.get("totals", {}),
        "tools": {},
    }
    for tool, data in (payload.get("tools") or {}).items():
        rows = list(data.get("rows") or [])
        accepted_rows = [r for r in rows if r.get("accepted")][: max_rows_per_tool // 2]
        rejected_rows = [r for r in rows if not r.get("accepted")][: max_rows_per_tool // 2]
        compacted["tools"][tool] = {
            "count": data.get("count", len(rows)),
            "accepted": data.get("accepted", 0),
            "rejected": data.get("rejected", 0),
            "sample_rows": accepted_rows + rejected_rows,
        }
    return compacted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--max-cases-per-tool", type=int, default=4000)
    parser.add_argument("--min-total-cases", type=int, default=10000)
    parser.add_argument("--max-rows-per-tool", type=int, default=40)
    parser.add_argument("--output", default="tests/artifacts/arg_action_variations.json")
    args = parser.parse_args()

    payload = generate_variants(seed=args.seed, max_cases=args.max_cases_per_tool)
    total = int(payload["totals"]["cases"])
    if total < args.min_total_cases:
        raise SystemExit(f"Generated only {total} cases, expected at least {args.min_total_cases}")
    payload = compact_payload(payload, max_rows_per_tool=max(2, args.max_rows_per_tool))

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {total} cases to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
# Tool sweep test plan generator
# This script generates a minimal safe call for each tool.

import json

TEST_ARGS = {
    "session": {"action": "status"},
    "idb": {"action": "overview"},
    "data": {"action": "functions", "count": 1},
    "code": {"action": "disasm", "addr": "0x140001000", "limit": 1},
    "search": {"action": "find", "pattern": "main"},
    "analysis": {"action": "get_options"},
    "imports_deep": {"action": "thunks"},
    "symbols": {"action": "status"},
    "patterns": {"action": "list_sigs"},
    "types": {"action": "list"},
    "memory": {"action": "read", "addr": "0x140001000", "size": 8},
    "calc": {"action": "eval", "expr": "0x10 + 0x20"},
    "nav": {"action": "cursor"},
    "binary_info": {"action": "headers"},
    "export": {"action": "headers"},
    "history": {"action": "list"},
    "segments": {"action": "list"},
    "funcs": {"action": "create", "addr": "0x140001000"},
    "data": {"action": "functions", "count": 1},
    "graph": {"action": "callgraph", "addr": "0x140001000", "format": "dot"},
    "ctree": {"action": "get", "addr": "0x140001000", "depth": 1},
    "bookmarks": {"action": "list"},
    "bulk": {"action": "export_annotations"},
    "debug": {"action": "threads"},
    "compare": {"action": "constants", "addr": "0x140001000", "addr2": "0x140001010"},
    "query": {"action": "data", "subaction": "functions", "count": 1},
    "misc": {"action": "health"},
    "project": {"action": "list_recent"},
    "governance": {"action": "stats"},
    "threat_hunt": {"action": "quick"},
    "annotation": {"action": "auto_comment", "addr": "0x140001000", "dry_run": True},
    "batch": {"calls": ["data:functions"]},
    "string_ops": {"action": "find_urls", "limit": 1},
    "schemaboot": {"action": "stats"},
    "turboquant": {"action": "stats"},
    "bridgerag": {"action": "stats"},
    "blackboard": {"action": "list"},
    "mbagcn": {"action": "stats"},
    "cfg_analysis": {"action": "complexity", "addr": "0x140001000"},
    "yara_hunt": {"action": "list_rules"},
    "deobfuscate": {"action": "detect_encoding"},
    "crypto_id": {"action": "identify"},
    "summarize": {"action": "binary"},
    "classify": {"action": "binary"},
    "protocol": {"action": "detect"},
    "gadgets": {"action": "mitigations"},
    "xref_analysis": {"action": "stats"},
    "coverage": {"action": "report"},
    "trace": {"action": "get"},
    "trace_analysis": {"action": "analyze_coverage"},
    "entropy": {"action": "packed_detect"},
    "comment_mgr": {"action": "list"},
    "static_trace": {"action": "list"},
    "colorize": {"action": "list"},
    "debug": {"action": "threads"},
}

print(json.dumps(TEST_ARGS, indent=2))
