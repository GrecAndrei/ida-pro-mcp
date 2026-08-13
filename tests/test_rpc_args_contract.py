"""Contract tests for prepare_rpc_args — the real admission path used by dispatch.

These call the shipped helper with real schema data (not a reimplementation).
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
assert str(SRC) in sys.path or sys.path.insert(0, str(SRC)) is None


@pytest.fixture(scope="module")
def rpc_args():
    return importlib.import_module("ida_pro_mcp.host.server.rpc_args")


@pytest.fixture(scope="module")
def schemas_data():
    return importlib.import_module("ida_pro_mcp.host.schemas_data")


@pytest.fixture(scope="module")
def errors():
    return importlib.import_module("ida_pro_mcp.host.errors")


class TestPrepareRpcArgs:
    def test_strips_underscore_host_controls(self, rpc_args, schemas_data, errors):
        out = rpc_args.prepare_rpc_args(
            "search",
            {
                "action": "find",
                "pattern": "recv",
                "_risk_ack": True,
                "risk_ack": True,
                "_response_mode": "compact",
            },
            schemas_data.TOOL_ARG_SCHEMAS,
        )
        assert not errors.is_error_result(out)
        assert "_risk_ack" not in out
        assert "risk_ack" not in out
        assert "_response_mode" not in out
        assert out["action"] == "find"
        assert out["pattern"] == "recv"

    def test_rejects_unknown_kwargs_with_names(self, rpc_args, schemas_data, errors):
        out = rpc_args.prepare_rpc_args(
            "search",
            {"action": "find", "pattern": "x", "totally_fake_kwarg": 1},
            schemas_data.TOOL_ARG_SCHEMAS,
        )
        assert errors.is_error_result(out)
        # Structured envelope carries code + unknown list
        code = (out.get("error") or {}).get("code") if isinstance(out.get("error"), dict) else out.get("code")
        # make_error shapes vary slightly — accept either nested or top-level
        blob = str(out)
        assert "INVALID_ARGS" in blob or code == errors.MCPError.INVALID_ARGS
        assert "totally_fake_kwarg" in blob
        details = out.get("details") or (out.get("error") or {}).get("details") or {}
        if details:
            assert "totally_fake_kwarg" in details.get("unknown", [])

    def test_admits_critical_search_and_funcs_keys(self, rpc_args, schemas_data, errors):
        search = rpc_args.prepare_rpc_args(
            "search",
            {
                "action": "nl",
                "pattern": "aes key schedule",
                "mode": "quick",
                "semantic_min_score": 0.1,
                "intent": "crypto",
            },
            schemas_data.TOOL_ARG_SCHEMAS,
        )
        assert not errors.is_error_result(search)
        assert search["mode"] == "quick"
        assert search["semantic_min_score"] == 0.1

        funcs = rpc_args.prepare_rpc_args(
            "funcs",
            {
                "action": "find_similar",
                "addr": "0x401000",
                "limit": 5,
                "min_score": 0.5,
                "top_k": 3,
            },
            schemas_data.TOOL_ARG_SCHEMAS,
        )
        assert not errors.is_error_result(funcs)
        assert funcs["limit"] == 5
        assert funcs["min_score"] == 0.5

    def test_graph_admits_action_and_address(self, rpc_args, schemas_data, errors):
        out = rpc_args.prepare_rpc_args(
            "graph",
            {
                "action": "callgraph",
                "address": "0x401000",
                "depth": 3,
                "format": "json",
            },
            schemas_data.TOOL_ARG_SCHEMAS,
        )
        assert not errors.is_error_result(out)
        assert out["action"] == "callgraph"
        assert out["address"] == "0x401000"

    def test_open_schema_passes_all_non_underscore(self, rpc_args, errors):
        # Empty schema map for the tool → no admission filter
        out = rpc_args.prepare_rpc_args(
            "unknown_tool_xyz",
            {"action": "x", "anything": 1, "_hidden": True},
            {},
        )
        assert not errors.is_error_result(out)
        assert out == {"action": "x", "anything": 1}


class TestAdvertisedSurface:
    def test_tier_a_bounds_and_completeness(self, schemas_data):
        adv = schemas_data.ADVERTISED_TOOLS
        assert 1 <= len(adv) <= 17
        for name in adv:
            assert name in schemas_data.TOOLS
            desc = schemas_data.TOOL_DESCRIPTIONS.get(name, "")
            assert isinstance(desc, str) and len(desc.strip()) > 10
            actions = schemas_data.TOOL_ACTIONS.get(name) or []
            assert len(actions) > 0, f"{name} has empty action list"

    def test_filter_tool_removed(self, schemas_data):
        assert "filter" not in schemas_data.TOOLS
        assert "filter" not in schemas_data.TOOL_ACTIONS
        assert "filter" not in schemas_data.TOOL_DESCRIPTIONS
        assert "filter" not in schemas_data.ADVERTISED_TOOLS
        tools_py = (
            REPO_ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "filter.py"
        )
        assert not tools_py.exists()


class TestDispatchUsesHelper:
    def test_dispatch_imports_prepare_rpc_args(self):
        src = (
            REPO_ROOT
            / "src"
            / "ida_pro_mcp"
            / "host"
            / "server"
            / "server_dispatch.py"
        ).read_text(encoding="utf-8")
        assert "from .rpc_args import prepare_rpc_args" in src
        assert "prepare_rpc_args(tool_name, kwargs, TOOL_ARG_SCHEMAS)" in src
        # Old silent-strip pattern must stay gone
        assert "if k in allowed}" not in src
