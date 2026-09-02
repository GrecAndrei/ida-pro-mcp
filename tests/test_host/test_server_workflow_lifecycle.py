"""Behavior coverage for workflow planning, execution, and catalogs."""

from __future__ import annotations

import importlib

from ida_pro_mcp.host.server.server_workflow import ServerWorkflowMixin

workflow_mod = importlib.import_module("ida_pro_mcp.host.server.server_workflow")


class WorkflowHost(ServerWorkflowMixin):
    def __init__(self):
        self._tools_list_cache = {}
        self.tool_surface = "agent"
        self.vertex_compat = False
        self.executed = []

    def _execute_tool(self, name, args):
        self.executed.append((name, args))
        if name == "idb" and args.get("action") == "summary":
            return {"functions": 4, "imports": 2}
        return {"ok": True, "tool": name, "action": args.get("action")}

    def _handle_batch(self, args):
        return {"ok": True, "batch_calls": args["calls"], "summary": {"count": len(args["calls"])}}

    def _normalize_batch_call(self, call, index):
        if not isinstance(call, dict):
            return None, {}, {"index": index}
        return call.get("name"), call.get("arguments", {}), None

    def _extract_batch_bindings(self, _args):
        return {}, None

    def _run_batch_steps(self, calls, _continue_on_error, _bindings, **_kwargs):
        return [
            {
                "index": index,
                "name": call["name"],
                "call_args": call["arguments"],
                "result": {"ok": True, "value": index},
                "elapsed_ms": 1,
            }
            for index, call in enumerate(calls)
        ]


def test_workflow_plan_filters_and_dry_run(monkeypatch):
    host = WorkflowHost()
    triage = host._handle_workflow(
        {
            "action": "triage_fast",
            "profile": "not-a-profile",
            "include_tools": "idb,data,unknown",
            "exclude_tools": ["data", "data"],
            "dry_run": True,
            "limit": 3,
        }
    )
    assert triage["ok"] is True
    assert triage["dry_run"] is True
    assert triage["workflow_meta"]["profile"] == "balanced"
    assert triage["workflow_meta"]["has_functions"] is True
    assert triage["workflow_meta"]["unknown_include_tools"] == ["unknown"]
    assert triage["workflow_meta"]["conflicting_tools"] == ["data"]
    assert all(step["name"] == "idb" for step in triage["planned_calls"])

    patch_missing = host._handle_workflow({"action": "patch_review", "dry_run": True})
    assert patch_missing["error"] is True
    assert patch_missing["code"] == "INVALID_ARGS"
    invalid = host._handle_workflow({"action": "not-real"})
    assert invalid["error"] is True
    assert invalid["code"] == "ACTION_NOT_FOUND"

    catalog = host._handle_workflow({"action": "catalog"})
    assert catalog["ok"] is True
    assert "triage_fast" in catalog["workflow_catalog"]
    assert catalog["supports_audit_plan_action"] is True


def test_workflow_executable_profiles_and_filter_failures():
    host = WorkflowHost()
    for action in ("malware_deep", "vuln_audit", "recon_sweep"):
        result = host._handle_workflow({"action": action, "dry_run": True, "profile": "deep"})
        assert result["ok"] is True
        assert result["dry_run"] is True
        assert result["planned_calls"]

    patch = host._handle_workflow(
        {
            "action": "patch_review",
            "addr": "0x401000",
            "dry_run": True,
            "include_tools": "code",
        }
    )
    assert patch["ok"] is True
    assert patch["workflow_meta"]["step_tools"] == ["code", "code", "code"]

    empty = host._handle_workflow(
        {
            "action": "patch_review",
            "addr": "0x401000",
            "exclude_tools": "code",
        }
    )
    assert empty["error"] is True
    assert empty["code"] == "INVALID_ARGS"

    host._execute_tool = lambda _name, _args: {"functions": 0, "imports": 0}
    no_functions = host._handle_workflow({"action": "triage_fast", "dry_run": True})
    assert no_functions["workflow_meta"]["has_functions"] is False
    assert any(step["arguments"]["action"] == "find" for step in no_functions["planned_calls"])


def test_workflow_plan_explain_estimate_and_prioritize(monkeypatch):
    host = WorkflowHost()
    plan = host._handle_workflow(
        {"action": "plan", "workflow_action": "patch_review", "addr": "0x401000"}
    )
    assert plan["ok"] is True
    assert plan["requested_action"] == "plan"
    assert plan["planned_action"] == "patch_review"
    assert plan["planned_calls"][0]["arguments"]["addr"] == "0x401000"

    explained = host._handle_workflow(
        {"action": "explain", "workflow_action": "patch_review", "addr": "0x401000"}
    )
    assert explained["ok"] is True
    assert len(explained["explained_steps"]) == 3
    assert "opcode-level" in explained["explained_steps"][0]["rationale"]

    class FakeEmbedder:
        def embed_vector(self, _text):
            return [1.0, 0.0]

        @staticmethod
        def cosine(_left, _right):
            return 0.42

    core = importlib.import_module("ida_pro_mcp.host.intelligence.core")
    monkeypatch.setattr(workflow_mod, "EMBEDDING_FIRST_MODE", True)
    monkeypatch.setattr(core, "BgeCodeEmbedder", FakeEmbedder)

    estimated = host._handle_workflow(
        {"action": "estimate", "workflow_action": "patch_review", "addr": "0x401000"}
    )
    assert estimated["ok"] is True
    assert estimated["estimate"]["complexity"] == "low"
    assert estimated["estimate"]["unique_tool_count"] == 1
    assert estimated["estimate"]["risk_score"] > 0

    calls = [
        {"name": "search", "arguments": {"action": "vulnerable"}, "source_count": 1},
        {"name": "idb", "arguments": {"action": "overview"}, "source_count": 3},
        {"name": "data", "arguments": {"action": "functions"}, "source_count": 2},
    ]
    risk = host._handle_workflow(
        {"action": "prioritize", "planned_calls": calls, "priority_mode": "risk_first"}
    )
    assert risk["ok"] is True
    assert risk["planned_calls"][0]["arguments"]["action"] == "vulnerable"
    original = host._handle_workflow(
        {"action": "prioritize", "planned_calls": calls, "priority_mode": "original"}
    )
    assert original["planned_calls"][0]["name"] == "search"


def test_workflow_compose_audit_and_execute_plan():
    host = WorkflowHost()
    composed = host._handle_workflow(
        {"action": "compose", "workflow_actions": ["patch_review", "patch_review"], "addr": "0x401000"}
    )
    assert composed["ok"] is True
    assert composed["planned_actions"] == ["patch_review"]
    assert composed["summary"]["step_count"] == 3
    assert all(call["source_count"] == 1 for call in composed["planned_calls"])

    audit = host._handle_workflow(
        {
            "action": "audit_plan",
            "planned_calls": [
                {"name": "search", "arguments": {"action": "vulnerable"}, "output_key": "risk"},
                {"name": "search", "arguments": {"action": "vulnerable"}},
                {"name": "missing", "arguments": {"action": "nope"}},
                "bad-call",
            ],
        }
    )
    assert audit["ok"] is True
    assert audit["audit"]["invalid_call_count"] == 2
    assert audit["audit"]["duplicate_step_count"] == 1
    assert audit["audit"]["risk_hints"]
    assert audit["planned_calls"][0]["output_key"] == "risk"

    executed = host._handle_workflow(
        {
            "action": "execute_plan",
            "planned_calls": [
                {"name": "idb", "arguments": {"action": "overview"}},
                {"name": "data", "arguments": {"action": "functions"}},
            ],
            "max_steps": 1,
        }
    )
    assert executed["ok"] is True
    assert executed["summary"]["requested_steps"] == 2
    assert executed["summary"]["executed_steps"] == 1
    assert executed["summary"]["truncated"] is True

    assert host._handle_workflow({"action": "execute_plan", "planned_calls": []})["error"] is True
    assert host._handle_workflow({"action": "compose"})["error"] is True

    composed_from_single = host._handle_workflow(
        {"action": "compose", "workflow_action": "malware_deep"}
    )
    assert composed_from_single["ok"] is True
    assert composed_from_single["planned_actions"] == ["malware_deep"]

    executed_from_workflow = host._handle_workflow(
        {"action": "execute_plan", "workflow_action": "malware_deep", "max_steps": 3}
    )
    assert executed_from_workflow["ok"] is True
    assert executed_from_workflow["source"] == "plan"


def test_workflow_validation_errors_are_actionable():
    host = WorkflowHost()
    for action in ("audit_plan", "execute_plan", "prioritize", "estimate", "explain", "plan"):
        error = host._handle_workflow({"action": action})
        assert error["error"] is True
        assert error["code"] == "INVALID_ARGS"

    for action in ("audit_plan", "execute_plan", "prioritize", "estimate", "explain", "plan"):
        error = host._handle_workflow({"action": action, "workflow_action": action})
        assert error["error"] is True
        assert error["code"] == "INVALID_ARGS"


def test_tools_catalog_caches_and_supports_surfaces():
    host = WorkflowHost()
    agent = host._build_tools_list_catalog("ultra")
    assert agent
    assert host._build_tools_list_catalog("ultra") is agent
    assert all("inputSchema" in item and "category" in item for item in agent)

    host.tool_surface = "legacy"
    lean = host._build_tools_list_catalog("lean")
    assert lean
    assert host._build_tools_list_catalog("lean") is lean
    assert any(item["name"] == "idb" for item in lean)

    host.vertex_compat = True
    vertex = host._build_tools_list_catalog("ultra")
    assert vertex
    assert host._build_tools_list_catalog("ultra") is vertex
