import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.host.server import IDAMCPServer


def test_workflow_catalog_returns_inventory():
    server = IDAMCPServer()
    result = server._handle_workflow({"action": "catalog"})
    assert result.get("ok") is True
    assert result.get("action") == "catalog"
    catalog = result.get("workflow_catalog")
    assert isinstance(catalog, dict)
    assert "triage_fast" in catalog
    assert "recon_sweep" in catalog
    assert "patch_review" in catalog
    assert catalog["patch_review"].get("requires_addr") is True


def test_workflow_plan_action_returns_dry_run_preview():
    server = IDAMCPServer()

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": False}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]
    result = server._handle_workflow({"action": "plan", "workflow_action": "recon_sweep", "limit": 4})
    assert result.get("ok") is True
    assert result.get("dry_run") is True
    assert result.get("requested_action") == "plan"
    assert result.get("planned_action") == "recon_sweep"
    assert isinstance(result.get("planned_calls"), list)
    meta = result.get("workflow_meta", {})
    assert meta.get("action") == "recon_sweep"


def test_workflow_explain_action_returns_rationales():
    server = IDAMCPServer()

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": False}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]
    result = server._handle_workflow({"action": "explain", "workflow_action": "recon_sweep", "limit": 4})
    assert result.get("ok") is True
    assert result.get("action") == "explain"
    assert result.get("dry_run") is True
    assert result.get("planned_action") == "recon_sweep"
    explained = result.get("explained_steps")
    assert isinstance(explained, list)
    assert explained
    assert isinstance(explained[0].get("rationale"), str)


def test_workflow_estimate_action_returns_projection():
    server = IDAMCPServer()

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": True}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]
    result = server._handle_workflow({"action": "estimate", "workflow_action": "recon_sweep", "limit": 4})
    assert result.get("ok") is True
    assert result.get("action") == "estimate"
    assert result.get("dry_run") is True
    estimate = result.get("estimate")
    assert isinstance(estimate, dict)
    assert isinstance(estimate.get("risk_score"), int)
    assert isinstance(estimate.get("category_counts"), dict)
    assert estimate.get("firmware_detected") is True


def test_workflow_compose_merges_plans_with_sources():
    server = IDAMCPServer()

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": False}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]
    result = server._handle_workflow(
        {
            "action": "compose",
            "workflow_actions": ["triage_fast", "vuln_audit"],
            "limit": 4,
        }
    )
    assert result.get("ok") is True
    assert result.get("action") == "compose"
    assert result.get("dry_run") is True
    calls = result.get("planned_calls")
    assert isinstance(calls, list)
    assert calls
    assert isinstance(calls[0].get("sources"), list)
    meta = result.get("workflow_meta", {})
    assert meta.get("action") == "compose"
    assert isinstance(meta.get("component_workflows"), list)


def test_workflow_prioritize_from_workflow_action():
    server = IDAMCPServer()

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": False}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]
    result = server._handle_workflow(
        {
            "action": "prioritize",
            "workflow_action": "triage_fast",
            "priority_mode": "coverage",
            "limit": 4,
        }
    )
    assert result.get("ok") is True
    assert result.get("action") == "prioritize"
    assert result.get("dry_run") is True
    calls = result.get("planned_calls")
    assert isinstance(calls, list)
    assert calls
    assert isinstance(calls[0].get("priority_index"), int)


def test_workflow_execute_plan_from_provided_calls_runs_batch():
    server = IDAMCPServer()
    captured = {}

    def _fake_batch(args):
        captured["calls"] = args.get("calls", [])
        captured["continue_on_error"] = args.get("continue_on_error")
        return {"ok": True, "calls": captured["calls"], "summary": {}}

    server._handle_batch = _fake_batch  # type: ignore[method-assign]
    result = server._handle_workflow(
        {
            "action": "execute_plan",
            "planned_calls": [
                {"name": "idb", "arguments": {"action": "overview"}},
                {"tool": "data", "action": "functions", "count": 3},
            ],
            "continue_on_error": False,
        }
    )
    assert result.get("ok") is True
    assert captured.get("continue_on_error") is False
    assert len(captured.get("calls", [])) == 2
    assert isinstance(result.get("execution_meta"), dict)
    assert result["execution_meta"].get("action") == "execute_plan"


def test_workflow_audit_plan_from_provided_calls():
    server = IDAMCPServer()
    result = server._handle_workflow(
        {
            "action": "audit_plan",
            "planned_calls": [
                {"name": "idb", "arguments": {"action": "overview"}},
                {"name": "search", "arguments": {"action": "vulnerable"}},
                {"tool": "search", "action": "vulnerable"},
                {"bad": "entry"},
            ],
        }
    )
    assert result.get("ok") is True
    assert result.get("action") == "audit_plan"
    audit = result.get("audit")
    assert isinstance(audit, dict)
    assert isinstance(audit.get("score"), int)
    assert isinstance(audit.get("warnings"), list)
    assert isinstance(audit.get("risk_hints"), list)
    assert audit.get("invalid_call_count", 0) >= 1


def test_workflow_prioritize_from_provided_calls_original_mode_keeps_order():
    server = IDAMCPServer()
    result = server._handle_workflow(
        {
            "action": "prioritize",
            "priority_mode": "original",
            "planned_calls": [
                {"name": "search", "arguments": {"action": "vulnerable"}},
                {"name": "idb", "arguments": {"action": "overview"}},
            ],
        }
    )
    assert result.get("ok") is True
    calls = result.get("planned_calls")
    assert isinstance(calls, list)
    assert calls[0].get("name") == "search"
    assert calls[1].get("name") == "idb"


def test_workflow_plan_requires_target_action():
    server = IDAMCPServer()
    result = server._handle_workflow({"action": "plan"})
    assert result.get("error") is True
    msg = result.get("message") or result.get("error") or ""
    assert "workflow_action" in str(msg)


def test_workflow_plan_rejects_recursive_target():
    server = IDAMCPServer()
    result = server._handle_workflow({"action": "plan", "workflow_action": "plan"})
    assert result.get("error") is True
    msg = result.get("message") or result.get("error") or ""
    assert "cannot target plan" in str(msg)


def test_workflow_explain_rejects_recursive_target():
    server = IDAMCPServer()
    result = server._handle_workflow({"action": "explain", "workflow_action": "explain"})
    assert result.get("error") is True
    msg = result.get("message") or result.get("error") or ""
    assert "cannot target plan/explain" in str(msg)


def test_workflow_estimate_rejects_recursive_target():
    server = IDAMCPServer()
    result = server._handle_workflow({"action": "estimate", "workflow_action": "estimate"})
    assert result.get("error") is True
    msg = result.get("message") or result.get("error") or ""
    assert "cannot target plan/explain/estimate" in str(msg)


def test_workflow_compose_requires_target_actions():
    server = IDAMCPServer()
    result = server._handle_workflow({"action": "compose"})
    assert result.get("error") is True
    msg = result.get("message") or result.get("error") or ""
    assert "workflow_actions" in str(msg)


def test_workflow_compose_rejects_non_executable_targets():
    server = IDAMCPServer()
    result = server._handle_workflow({"action": "compose", "workflow_actions": ["catalog"]})
    assert result.get("error") is True
    msg = result.get("message") or result.get("error") or ""
    assert "executable workflows only" in str(msg)


def test_workflow_prioritize_requires_input_source():
    server = IDAMCPServer()
    result = server._handle_workflow({"action": "prioritize"})
    assert result.get("error") is True
    msg = result.get("message") or result.get("error") or ""
    assert "requires planned_calls, workflow_actions, or workflow_action" in str(msg)


def test_workflow_execute_plan_requires_input_source():
    server = IDAMCPServer()
    result = server._handle_workflow({"action": "execute_plan"})
    assert result.get("error") is True
    msg = result.get("message") or result.get("error") or ""
    assert "requires planned_calls, workflow_actions, or workflow_action" in str(msg)


def test_workflow_audit_plan_requires_input_source():
    server = IDAMCPServer()
    result = server._handle_workflow({"action": "audit_plan"})
    assert result.get("error") is True
    msg = result.get("message") or result.get("error") or ""
    assert "requires planned_calls, workflow_actions, or workflow_action" in str(msg)


def test_workflow_triage_fast_includes_firmware_snapshot():
    server = IDAMCPServer()
    captured = {}

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": True}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]

    def _fake_batch(args):
        captured["calls"] = args.get("calls", [])
        return {"ok": True, "calls": captured["calls"]}

    server._handle_batch = _fake_batch  # type: ignore[method-assign]

    result = server._handle_workflow({"action": "triage_fast", "limit": 7})
    assert result.get("ok") is True
    meta = result.get("workflow_meta", {})
    assert meta.get("version") == 1
    assert meta.get("action") == "triage_fast"
    assert meta.get("firmware_mode") == "enabled"
    assert meta.get("firmware_detected") is True
    assert meta.get("trigger") == "idb_overview"
    assert meta.get("step_count", 0) >= 1
    assert isinstance(meta.get("step_tools"), list)
    assert "idb" in meta.get("step_tools", [])
    assert isinstance(meta.get("step_actions"), list)
    assert "idb.overview" in meta.get("step_actions", [])
    assert isinstance(meta.get("step_calls"), list)
    assert any(c.get("tool") == "idb" and c.get("action") == "overview" for c in meta.get("step_calls", []))

    calls = captured.get("calls", [])
    assert calls and calls[0]["name"] == "idb"
    assert calls[0]["arguments"].get("action") == "overview"
    assert any(
        c.get("name") == "firmware_view"
        and c.get("arguments", {}).get("action") == "triage_snapshot"
        for c in calls
    )
    assert any(
        c.get("name") == "llm_helpers"
        and c.get("arguments", {}).get("action") == "guided_analysis"
        for c in calls
    )


def test_workflow_triage_fast_non_firmware_skips_firmware_steps():
    server = IDAMCPServer()
    captured = {}

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": False}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]

    def _fake_batch(args):
        captured["calls"] = args.get("calls", [])
        return {"ok": True, "calls": captured["calls"]}

    server._handle_batch = _fake_batch  # type: ignore[method-assign]
    result = server._handle_workflow({"action": "triage_fast", "limit": 5})
    assert result.get("ok") is True
    meta = result.get("workflow_meta", {})
    assert meta.get("version") == 1
    assert meta.get("action") == "triage_fast"
    assert meta.get("firmware_mode") == "disabled"
    assert meta.get("firmware_detected") is False
    assert meta.get("trigger") == "idb_overview"
    assert meta.get("step_count", 0) >= 1
    assert isinstance(meta.get("step_tools"), list)
    assert "idb" in meta.get("step_tools", [])
    assert isinstance(meta.get("step_actions"), list)
    assert "idb.overview" in meta.get("step_actions", [])
    assert isinstance(meta.get("step_calls"), list)
    assert any(c.get("tool") == "idb" and c.get("action") == "overview" for c in meta.get("step_calls", []))
    calls = captured.get("calls", [])
    assert not any(c.get("name") == "firmware_view" for c in calls)
    assert not any(c.get("name") == "llm_helpers" and c.get("arguments", {}).get("action") == "guided_analysis" for c in calls)


def test_workflow_patch_review_requires_addr():
    server = IDAMCPServer()
    result = server._handle_workflow({"action": "patch_review"})
    assert result.get("error") is True
    assert "requires addr" in (result.get("message") or result.get("error") or "")


def test_workflow_triage_fast_trigger_non_dict_overview():
    server = IDAMCPServer()
    captured = {}

    def _fake_execute(tool, _args):
        if tool == "idb":
            return "unexpected"
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]

    def _fake_batch(args):
        captured["calls"] = args.get("calls", [])
        return {"ok": True, "calls": captured["calls"]}

    server._handle_batch = _fake_batch  # type: ignore[method-assign]

    result = server._handle_workflow({"action": "triage_fast", "limit": 3})
    assert result.get("ok") is True
    meta = result.get("workflow_meta", {})
    assert meta.get("firmware_detected") is False
    assert meta.get("firmware_mode") == "disabled"
    assert meta.get("trigger") == "idb_overview_non_dict"
    calls = captured.get("calls", [])
    assert not any(c.get("name") == "firmware_view" for c in calls)


def test_workflow_triage_fast_trigger_overview_error():
    server = IDAMCPServer()
    captured = {}

    def _fake_execute(tool, _args):
        if tool == "idb":
            raise RuntimeError("boom")
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]

    def _fake_batch(args):
        captured["calls"] = args.get("calls", [])
        return {"ok": True, "calls": captured["calls"]}

    server._handle_batch = _fake_batch  # type: ignore[method-assign]

    result = server._handle_workflow({"action": "triage_fast", "limit": 3})
    assert result.get("ok") is True
    meta = result.get("workflow_meta", {})
    assert meta.get("firmware_detected") is False
    assert meta.get("firmware_mode") == "disabled"
    assert meta.get("trigger") == "idb_overview_error"
    calls = captured.get("calls", [])
    assert not any(c.get("name") == "firmware_view" for c in calls)


def test_workflow_recon_sweep_includes_broad_steps():
    server = IDAMCPServer()
    captured = {}

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": False}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]

    def _fake_batch(args):
        captured["calls"] = args.get("calls", [])
        return {"ok": True, "calls": captured["calls"]}

    server._handle_batch = _fake_batch  # type: ignore[method-assign]

    result = server._handle_workflow({"action": "recon_sweep", "limit": 6, "profile": "deep"})
    assert result.get("ok") is True
    meta = result.get("workflow_meta", {})
    assert meta.get("version") == 1
    assert meta.get("action") == "recon_sweep"
    assert meta.get("profile") == "deep"
    assert meta.get("firmware_detected") is False
    assert meta.get("trigger") == "idb_overview"
    calls = captured.get("calls", [])
    assert any(c.get("name") == "search" and c.get("arguments", {}).get("action") == "structured" for c in calls)
    assert any(c.get("name") == "protocol" and c.get("arguments", {}).get("action") == "detect" for c in calls)
    assert any(c.get("name") == "summarize" and c.get("arguments", {}).get("action") == "security_posture" for c in calls)
    assert not any(c.get("name") == "firmware_view" for c in calls)


def test_workflow_recon_sweep_firmware_includes_guided_steps():
    server = IDAMCPServer()
    captured = {}

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": True}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]

    def _fake_batch(args):
        captured["calls"] = args.get("calls", [])
        return {"ok": True, "calls": captured["calls"]}

    server._handle_batch = _fake_batch  # type: ignore[method-assign]

    result = server._handle_workflow({"action": "recon_sweep", "limit": 4})
    assert result.get("ok") is True
    meta = result.get("workflow_meta", {})
    assert meta.get("action") == "recon_sweep"
    assert meta.get("firmware_mode") == "enabled"
    assert meta.get("firmware_detected") is True
    assert meta.get("trigger") == "idb_overview"
    calls = captured.get("calls", [])
    assert any(c.get("name") == "firmware_view" and c.get("arguments", {}).get("action") == "triage_snapshot" for c in calls)
    assert any(c.get("name") == "llm_helpers" and c.get("arguments", {}).get("action") == "guided_analysis" for c in calls)


def test_workflow_dry_run_returns_plan_without_batch_execution():
    server = IDAMCPServer()
    called = {"batch": 0}

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": False}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]

    def _fake_batch(_args):
        called["batch"] += 1
        return {"ok": True}

    server._handle_batch = _fake_batch  # type: ignore[method-assign]

    result = server._handle_workflow({"action": "recon_sweep", "dry_run": True, "limit": 4})
    assert result.get("ok") is True
    assert result.get("dry_run") is True
    assert isinstance(result.get("planned_calls"), list)
    assert called["batch"] == 0
    meta = result.get("workflow_meta", {})
    assert meta.get("dry_run") is True
    assert meta.get("action") == "recon_sweep"


def test_workflow_include_exclude_filters_plan_tools():
    server = IDAMCPServer()
    captured = {}

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": False}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]

    def _fake_batch(args):
        captured["calls"] = args.get("calls", [])
        return {"ok": True, "calls": captured["calls"]}

    server._handle_batch = _fake_batch  # type: ignore[method-assign]

    result = server._handle_workflow(
        {
            "action": "recon_sweep",
            "limit": 5,
            "include_tools": ["idb", "search", "threat_hunt"],
            "exclude_tools": ["search"],
        }
    )
    assert result.get("ok") is True
    meta = result.get("workflow_meta", {})
    assert meta.get("include_tools") == ["idb", "search", "threat_hunt"]
    assert meta.get("exclude_tools") == ["search"]
    calls = captured.get("calls", [])
    assert calls
    call_tools = [str(c.get("name") or "") for c in calls]
    assert set(call_tools).issubset({"idb", "threat_hunt"})
    assert "search" not in call_tools


def test_workflow_dry_run_reports_filter_diagnostics():
    server = IDAMCPServer()

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": False}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]
    result = server._handle_workflow(
        {
            "action": "recon_sweep",
            "dry_run": True,
            "include_tools": ["idb", "nonexistent_tool"],
            "exclude_tools": ["idb"],
        }
    )
    assert result.get("ok") is True
    assert result.get("dry_run") is True
    meta = result.get("workflow_meta", {})
    assert "nonexistent_tool" in meta.get("unknown_include_tools", [])
    assert "idb" in meta.get("conflicting_tools", [])
    assert isinstance(meta.get("plan_diagnostics"), list)
    assert any("include_tools not in this workflow plan" in d for d in meta.get("plan_diagnostics", []))
    assert any("both include_tools and exclude_tools" in d for d in meta.get("plan_diagnostics", []))


def test_workflow_execute_rejects_empty_filtered_plan():
    server = IDAMCPServer()

    def _fake_execute(tool, _args):
        if tool == "idb":
            return {"firmware_detected": False}
        return {}

    server._execute_tool = _fake_execute  # type: ignore[method-assign]
    result = server._handle_workflow(
        {
            "action": "recon_sweep",
            "include_tools": ["nonexistent_tool"],
        }
    )
    assert result.get("error") is True
    msg = result.get("message") or result.get("error") or ""
    assert "empty" in str(msg).lower()
