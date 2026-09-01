"""Black-box host workflow coverage for planning and execution controls."""

from __future__ import annotations

from ida_pro_mcp.host.server.server import IDAMCPServer


def _server(monkeypatch):
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    server._execute_tool = lambda tool, args: (
        {"ok": True, "functions": 4, "imports": 2}
        if tool == "idb" and args.get("action") == "summary"
        else {"ok": True, "tool": tool, "action": args.get("action")}
    )
    return server


def test_workflow_plans_cover_each_executable_action_and_filters(monkeypatch):
    server = _server(monkeypatch)
    try:
        for action in ("triage_fast", "malware_deep", "vuln_audit", "recon_sweep"):
            result = server._handle_workflow(
                {"action": action, "profile": "deep", "dry_run": True}
            )
            assert result["ok"] is True, result
            assert result["dry_run"] is True
            assert result["planned_calls"]

        patch = server._handle_workflow(
            {
                "action": "patch_review",
                "addr": "0x401000",
                "dry_run": True,
                "include_tools": ["code", "missing"],
                "exclude_tools": ["graph", "code"],
            }
        )
        assert patch["ok"] is True
        assert patch["planned_calls"] == []
        assert patch["workflow_meta"]["conflicting_tools"] == ["code"]
        assert patch["workflow_meta"]["unknown_include_tools"] == ["missing"]
        assert patch["workflow_meta"]["plan_diagnostics"]

        catalog = server._handle_workflow({"action": "catalog"})
        assert catalog["ok"] is True
        assert set(catalog["supported_profiles"]) == {"quick", "balanced", "deep"}

        invalid = server._handle_workflow({"action": "does_not_exist"})
        assert invalid["error"] is True
    finally:
        server.shutdown()


def test_workflow_composition_audit_priority_estimate_and_explain(monkeypatch):
    server = _server(monkeypatch)
    try:
        composed = server._handle_workflow(
            {"action": "compose", "workflow_actions": ["triage_fast", "vuln_audit"]}
        )
        assert composed["ok"] is True
        assert composed["dedup_enabled"] is True
        assert composed["workflow_meta"]["component_workflows"]

        planned = composed["planned_calls"]
        for mode in ("original", "coverage", "risk_first", "unknown"):
            prioritized = server._handle_workflow(
                {"action": "prioritize", "planned_calls": planned, "priority_mode": mode}
            )
            assert prioritized["ok"] is True
            assert len(prioritized["planned_calls"]) == len(planned)

        audited = server._handle_workflow(
            {
                "action": "audit_plan",
                "planned_calls": planned
                + [
                    {"name": "search", "arguments": {"action": "vulnerable"}},
                    {"name": "missing", "arguments": {"action": "x"}},
                    {"not": "a call"},
                ],
            }
        )
        assert audited["ok"] is True
        assert audited["audit"]["invalid_call_count"] >= 2
        assert audited["audit"]["risk_hints"]

        estimate = server._handle_workflow(
            {"action": "estimate", "workflow_action": "vuln_audit"}
        )
        assert estimate["ok"] is True
        assert estimate["estimate"]["step_count"] > 0

        explained = server._handle_workflow(
            {"action": "explain", "workflow_action": "patch_review", "addr": "0x401000"}
        )
        assert explained["ok"] is True
        assert explained["explained_steps"]
    finally:
        server.shutdown()


def test_workflow_execute_plan_handles_truncation_bindings_and_errors(monkeypatch):
    server = _server(monkeypatch)
    calls = []

    def execute(tool, args):
        calls.append((tool, dict(args)))
        if args.get("action") == "bad":
            return {"error": True, "code": "INVALID_ARGS", "message": "bad"}
        return {"ok": True, "value": "rich_entry", "tool": tool}

    server._execute_tool = execute
    try:
        result = server._handle_workflow(
            {
                "action": "execute_plan",
                "planned_calls": [
                    {"name": "data", "arguments": {"action": "functions"}},
                    {"name": "data", "arguments": {"action": "bad"}},
                    {"name": "data", "arguments": {"action": "functions"}},
                ],
                "max_steps": 2,
                "continue_on_error": False,
                "bindings": {"step2_query": {"step": 1, "key": "value"}},
            }
        )
        assert result["ok"] is True
        assert result["summary"]["truncated"] is True
        assert result["summary"]["executed_steps"] == 2
        assert result["summary"]["error_steps"] == 1
        assert len(calls) == 2

        missing = server._handle_workflow(
            {"action": "execute_plan", "planned_calls": [{"not": "a call"}]}
        )
        assert missing["error"] is True

        bad_audit = server._handle_workflow({"action": "audit_plan"})
        assert bad_audit["error"] is True
    finally:
        server.shutdown()
