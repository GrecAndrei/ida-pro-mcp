"""Regression: analysis blocking/observe kwargs must be admitted by the schema.

The in-IDA analysis handler reads ``blocking``, ``wait``, ``pump``,
``poll_timeout`` (plus ``timeout``/``max_wait``) for its run+wait actions.
The host dispatch arg-filter (server_dispatch.py) drops any kwarg not in
``TOOL_ARG_SCHEMAS['analysis']``, so if these keys are absent from the schema
the knobs are silently stripped — callers passing ``blocking=true`` get
non-blocking behavior with no error. This pins their admission.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.services import TOOL_ARG_SCHEMAS


def test_analysis_schema_admits_blocking_knobs():
    sch = TOOL_ARG_SCHEMAS.get("analysis") or {}
    for key in ("blocking", "wait", "pump", "poll_timeout", "timeout", "max_wait"):
        assert key in sch, f"analysis schema must admit {key!r} (else dispatch silently strips it)"


def test_blocking_knobs_survive_dispatch_arg_filter():
    """Mirror of server_dispatch.py:106-111 arg-filter logic."""
    allowed = set((TOOL_ARG_SCHEMAS.get("analysis") or {}).keys())
    assert allowed, "analysis schema must be non-empty"
    rpc_args = {
        "action": "run",
        "blocking": True,
        "wait": True,
        "pump": True,
        "poll_timeout": 5,
        "timeout": 10,
        "max_wait": 30,
        "rogue_unlisted": "should_be_dropped",
    }
    filtered = {k: v for k, v in rpc_args.items() if k in allowed}
    for key in ("blocking", "wait", "pump", "poll_timeout", "timeout", "max_wait"):
        assert key in filtered, f"{key!r} was stripped by the dispatch arg-filter"
    assert "rogue_unlisted" not in filtered