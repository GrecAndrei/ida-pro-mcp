"""Regression: kwargs the in-IDA handlers read must be admitted by the schema.

The host dispatch arg-filter (server_dispatch.py:106-111) drops any kwarg not
in ``TOOL_ARG_SCHEMAS[tool]``. Earlier, many advertised actions read kwargs the
schema never admitted, so the knobs were silently stripped — features were
unreachable through MCP with no error (find_similar tuning, memory compare's
2nd address, the entire KG builder, etc.). This pins the admission of every
handler-read kwarg that was previously stripped, per tool/action.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.services import TOOL_ARG_SCHEMAS

# (tool, [kwargs that MUST be admitted because the handler reads them])
REQUIRED = {
    "funcs": ["limit", "min_score", "threshold", "top_k",
              "ea", "start", "function", "target", "end_ea", "stop"],
    "calc": ["query", "op"],
    "memory": ["end_addr", "depth", "pattern", "regex", "int_width", "addr1", "addr2"],
    "data": ["queries"],
    "segments": ["name2", "address", "addr", "ea", "segment",
                 "address2", "addr2", "ea2", "segment2",
                 "segment_name", "segment_name2"],
    "search": ["mode", "recipe", "intent", "semantic_min_score", "constraints",
               "target", "ea", "radius", "src", "dst"],
    "intelligence": ["include_resolved", "similar_top_k"],
    "blackboard": ["members", "entry_points", "exit_points", "size_bytes",
                   "hints", "gap_type", "binary_type", "gap_id", "filled_by",
                   "state_var", "states", "periph_type", "drivers",
                   "reachable_from", "input_type", "call_stack", "resolved"],
    "idb": ["audit_tail"],
    "misc": ["module", "modules"],
}


def test_required_kwargs_admitted():
    missing = []
    for tool, kwargs in REQUIRED.items():
        sch = TOOL_ARG_SCHEMAS.get(tool) or {}
        for k in kwargs:
            if k not in sch:
                missing.append(f"{tool}.{k}")
    assert not missing, f"schema regressed — stripped again: {missing}"


def test_intentionally_not_admitted_is_internal():
    # `tool`/`payload` belong to the internal suggest_next_steps helper, not
    # an advertised intelligence action — they must stay unadmitted.
    sch = TOOL_ARG_SCHEMAS.get("intelligence") or {}
    assert "tool" not in sch
    assert "payload" not in sch
