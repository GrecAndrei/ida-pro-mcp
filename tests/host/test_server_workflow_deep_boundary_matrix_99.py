"""Deep offline boundary coverage for the host workflow coordinator."""

from __future__ import annotations

import importlib

import pytest

from ida_pro_mcp.host.server.server_workflow import ServerWorkflowMixin

workflow_module = importlib.import_module("ida_pro_mcp.host.server.server_workflow")


class _WorkflowHost(ServerWorkflowMixin):
    def __init__(self):
        self._tools_list_cache = {}
        self.tool_surface = "agent"
        self.vertex_compat = False
        self.plan_overrides = {}
        self.action_overrides = {}
        self.compose_override = None
        self.batch_result = {
            "ok": True,
            "summary": {"count": 1},
        }
        self.executed = []
        self.error_action = None
        self._workflow_depth = 0

    def _handle_workflow(self, args):
        action = str(args.get("action") or "").strip().lower()
        if self._workflow_depth:
            if action == "plan" and args.get("workflow_action") in self.plan_overrides:
                return self.plan_overrides[args["workflow_action"]]
            if action == "compose" and self.compose_override is not None:
                return self.compose_override
            if action in self.action_overrides:
                return self.action_overrides[action]
        self._workflow_depth += 1
        try:
            return super()._handle_workflow(args)
        finally:
            self._workflow_depth -= 1

    def _execute_tool(self, name, args):
        self.executed.append((name, dict(args)))
        if name == "idb" and args.get("action") == "summary":
            return {"functions": 3, "imports": 2}
        if args.get("action") == self.error_action:
            return {"error": True, "code": "INVALID_ARGS", "message": "step failed"}
        return {"ok": True, "tool": name, "action": args.get("action")}

    def _handle_batch(self, _args):
        return self.batch_result

    def _extract_response_options(self, args):
        return dict(args), {}


def _call(name="idb", action="overview", **extra):
    return {"name": name, "arguments": {"action": action, **extra}}


def test_workflow_audit_sources_warnings_and_recursive_failures():
    host = _WorkflowHost()

    from_compose = host._handle_workflow(
        {"action": "audit_plan", "workflow_actions": ["triage_fast"]}
    )
    assert from_compose["source"] == "compose"
    assert from_compose["audit"]["executable_call_count"] > 0

    from_plan = host._handle_workflow(
        {"action": "audit_plan", "workflow_action": "triage_fast"}
    )
    assert from_plan["source"] == "plan"

    large = host._handle_workflow(
        {"action": "audit_plan", "planned_calls": [_call() for _ in range(101)]}
    )
    assert any("large_plan" in warning for warning in large["audit"]["warnings"])

    empty = host._handle_workflow({"action": "audit_plan", "planned_calls": []})
    assert "no_executable_calls" in empty["audit"]["warnings"]

    host._execute_tool = lambda *_args: (_ for _ in ()).throw(RuntimeError("no summary"))
    no_summary = host._handle_workflow({"action": "triage_fast", "dry_run": True})
    assert no_summary["workflow_meta"]["has_functions"] is False

    host.compose_override = {"error": True, "code": "INNER"}
    propagated = host._handle_workflow(
        {"action": "audit_plan", "workflow_actions": ["triage_fast"]}
    )
    assert propagated["code"] == "INNER"

    host.compose_override = None
    host.plan_overrides["triage_fast"] = {"error": True, "code": "PLAN_FAILED"}
    propagated = host._handle_workflow(
        {"action": "audit_plan", "workflow_action": "triage_fast"}
    )
    assert propagated["code"] == "PLAN_FAILED"

    host._execute_tool = lambda *_args: []
    non_dict_stats = host._handle_workflow({"action": "recon_sweep", "dry_run": True})
    assert non_dict_stats["workflow_meta"]["has_functions"] is False


def test_workflow_execute_plan_sources_bindings_and_wrapped_results():
    host = _WorkflowHost()

    composed = {
        "ok": True,
        "planned_calls": [_call("idb", "overview")],
    }
    host.compose_override = composed
    result = host._handle_workflow(
        {"action": "execute_plan", "workflow_actions": ["triage_fast"]}
    )
    assert result["source"] == "compose"
    host.compose_override = {"error": True, "code": "COMPOSE_FAILED"}
    assert host._handle_workflow(
        {"action": "execute_plan", "workflow_actions": ["triage_fast"]}
    )["code"] == "COMPOSE_FAILED"
    host.compose_override = None

    from_workflow = host._handle_workflow(
        {"action": "execute_plan", "workflow_action": "triage_fast", "max_steps": 1}
    )
    assert from_workflow["source"] == "plan"

    bad_bindings = host._handle_workflow(
        {
            "action": "execute_plan",
            "planned_calls": [_call()],
            "bindings": "not-an-object",
        }
    )
    assert bad_bindings["error"] is True

    host.plan_overrides["triage_fast"] = {"error": True, "code": "PLAN_FAILED"}
    assert host._handle_workflow(
        {"action": "execute_plan", "workflow_action": "triage_fast"}
    )["code"] == "PLAN_FAILED"
    host.plan_overrides.clear()

    host.error_action = "bad"
    executed = host._handle_workflow(
        {
            "action": "execute_plan",
            "planned_calls": [_call("idb", "overview"), _call("data", "bad")],
            "continue_on_error": False,
        }
    )
    assert executed["summary"]["error_steps"] == 1
    assert executed["step_results"][1]["recovery_hint"]


def test_workflow_prioritize_composition_and_plan_edge_shapes():
    host = _WorkflowHost()
    shared = _call("idb", "overview", value=1)
    host.plan_overrides = {
        "first": {"planned_calls": [shared, shared, None]},
        "second": {"planned_calls": [shared, _call("search", "vulnerable")]},
        "empty": {"planned_calls": "not-a-list"},
    }

    composed = host._handle_workflow(
        {"action": "compose", "workflow_actions": ["first", "second", "first"]}
    )
    assert composed["planned_actions"] == ["first", "second"]
    assert len(composed["planned_calls"]) == 2
    assert composed["planned_calls"][0]["source_count"] == 2

    empty_composed = host._handle_workflow(
        {"action": "compose", "workflow_actions": ["empty"]}
    )
    assert empty_composed["planned_calls"] == []

    from_compose = host._handle_workflow(
        {"action": "prioritize", "workflow_actions": ["second"]}
    )
    assert from_compose["source"] == "compose"

    host.compose_override = {"error": True, "code": "COMPOSE_FAILED"}
    assert host._handle_workflow(
        {"action": "prioritize", "workflow_actions": ["second"]}
    )["code"] == "COMPOSE_FAILED"
    host.compose_override = None

    host.plan_overrides["second"] = {"error": True, "code": "PLAN_FAILED"}
    assert host._handle_workflow(
        {"action": "prioritize", "workflow_action": "second"}
    )["code"] == "PLAN_FAILED"
    host.plan_overrides["second"] = {"planned_calls": [shared, _call("search", "vulnerable")]}

    original = host._handle_workflow(
        {"action": "prioritize", "planned_calls": [shared], "priority_mode": "original"}
    )
    assert original["planned_calls"][0]["priority_mode"] == "original"

    from_plan = host._handle_workflow(
        {"action": "prioritize", "workflow_action": "empty"}
    )
    assert from_plan["source"] == "plan"
    assert from_plan["planned_calls"] == []

    estimate = host._handle_workflow(
        {"action": "estimate", "workflow_action": "empty"}
    )
    assert estimate["estimate"]["step_count"] == 0

    explained = host._handle_workflow(
        {"action": "explain", "workflow_action": "first"}
    )
    assert len(explained["explained_steps"]) == 2

    host.plan_overrides["broken"] = "not-a-plan"
    assert host._handle_workflow(
        {"action": "explain", "workflow_action": "broken"}
    ) == "not-a-plan"
    host.plan_overrides["not-list"] = {"planned_calls": "not-a-list"}
    not_list = host._handle_workflow(
        {"action": "explain", "workflow_action": "not-list"}
    )
    assert not_list["explained_steps"] == []


def test_workflow_embedding_fallback_and_plan_passthrough(monkeypatch):
    host = _WorkflowHost()
    core = importlib.import_module("ida_pro_mcp.host.intelligence.core")

    class _UnavailableEmbedder:
        def embed_vector(self, _text):
            return None

    monkeypatch.setattr(workflow_module, "EMBEDDING_FIRST_MODE", True)
    monkeypatch.setattr(core, "BgeCodeEmbedder", _UnavailableEmbedder)
    estimated = host._handle_workflow(
        {"action": "estimate", "workflow_action": "triage_fast"}
    )
    assert estimated["estimate"]["risk_score"] > 0

    class _PartiallyUnavailableEmbedder:
        def __init__(self):
            self.calls = 0

        def embed_vector(self, _text):
            self.calls += 1
            return [1.0] if self.calls == 1 else None

    monkeypatch.setattr(core, "BgeCodeEmbedder", _PartiallyUnavailableEmbedder)
    estimated = host._handle_workflow(
        {"action": "estimate", "workflow_action": "triage_fast"}
    )
    assert estimated["estimate"]["risk_score"] > 0

    host.action_overrides["returns-text"] = "plan result"
    assert host._handle_workflow(
        {"action": "plan", "workflow_action": "returns-text"}
    ) == "plan result"


def test_workflow_capability_gating_and_non_dict_batch_result(monkeypatch):
    host = _WorkflowHost()
    with monkeypatch.context() as patch:
        patch.setattr(
            workflow_module,
            "TOOL_ACTIONS",
            {"idb": ["overview"]},
        )
        gated = host._handle_workflow({"action": "triage_fast", "dry_run": True})
    diagnostics = gated["workflow_meta"]["plan_diagnostics"]
    assert any("action unavailable" in item for item in diagnostics)
    assert any("tool unavailable" in item for item in diagnostics)
    excluded = host._handle_workflow(
        {"action": "triage_fast", "dry_run": True, "exclude_tools": "missing"}
    )
    assert any("exclude_tools not in" in item for item in excluded["workflow_meta"]["plan_diagnostics"])

    host.batch_result = {"ok": True, "summary": "not-a-dict"}
    host.tool_surface = "agent"
    result = host._handle_workflow({"action": "malware_deep"})
    assert result["ok"] is True
    assert result["summary"] == "not-a-dict"
    host.batch_result = "non-dict result"
    assert host._handle_workflow({"action": "malware_deep"}) == "non-dict result"


def test_workflow_estimate_and_compose_propagate_inner_plan_failures():
    host = _WorkflowHost()
    host.plan_overrides["bad"] = {"error": True, "code": "PLAN_FAILED"}
    assert host._handle_workflow(
        {"action": "compose", "workflow_actions": ["bad"]}
    )["code"] == "PLAN_FAILED"
    assert host._handle_workflow(
        {"action": "estimate", "workflow_action": "bad"}
    )["code"] == "PLAN_FAILED"

    host.plan_overrides["shaped"] = {
        "planned_calls": [None, {"name": ""}, {"name": "idb"}]
    }
    estimate = host._handle_workflow(
        {"action": "estimate", "workflow_action": "shaped"}
    )
    assert estimate["estimate"]["unique_tool_count"] == 1


def test_workflow_catalog_legacy_description_and_schema_fallback(monkeypatch):
    host = _WorkflowHost()
    host.tool_surface = "legacy"
    monkeypatch.setattr(workflow_module, "TOOLS", ("visible", "hidden"))
    monkeypatch.setattr(workflow_module, "HIDDEN_TOOLS_IN_LIST", {"hidden"})
    monkeypatch.setattr(workflow_module, "build_tool_description_lean", lambda _name: "")
    monkeypatch.setattr(workflow_module, "build_input_schema_lean", lambda _name: None)
    monkeypatch.setattr(workflow_module, "classify_tool_category", lambda name: name)

    catalog = host._build_tools_list_catalog("lean")
    assert catalog == [
        {
            "name": "visible",
            "description": "Use wiki(topic='tools/visible') for usage.",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
            "category": "visible",
        }
    ]


def test_workflow_agent_vertex_catalog_sanitizes_schema():
    host = _WorkflowHost()
    host.vertex_compat = True
    catalog = host._build_tools_list_catalog("ignored")
    assert catalog
    assert all("inputSchema" in item for item in catalog)


def test_workflow_cache_lock_and_compose_key_fallback(monkeypatch):
    class _NoLock:
        pass

    host = _NoLock()
    lock = workflow_module._tools_cache_lock(host)
    assert host._tools_list_cache_lock is lock
    assert workflow_module._tools_cache_lock(host) is lock

    class _RacingInitLock:
        def __enter__(self):
            other._tools_list_cache_lock = "installed-by-racer"
            return self

        def __exit__(self, *_args):
            return False

    other = _NoLock()
    monkeypatch.setattr(workflow_module, "_TOOLS_CACHE_INIT_LOCK", _RacingInitLock())
    assert workflow_module._tools_cache_lock(other) == "installed-by-racer"

    monkeypatch.setattr(
        workflow_module.json,
        "dumps",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("json")),
    )
    key = workflow_module._compose_call_key("idb", {"action": "overview"})
    assert key[:2] == ("idb", "overview")
    assert "action" in key[2]


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("catalog", "workflow_catalog"),
        ("triage_fast", "planned_calls"),
        ("malware_deep", "planned_calls"),
        ("vuln_audit", "planned_calls"),
        ("recon_sweep", "planned_calls"),
    ],
)
def test_workflow_public_actions_have_stable_shapes(action, expected):
    host = _WorkflowHost()
    result = host._handle_workflow({"action": action, "dry_run": True})
    assert result["ok"] is True
    assert expected in result
