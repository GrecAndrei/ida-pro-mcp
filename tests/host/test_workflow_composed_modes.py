"""Cross-mode coverage for workflow planning, composition, and execution."""

from __future__ import annotations

from ida_pro_mcp.host.errors import MCPError
from ida_pro_mcp.host.server.server import IDAMCPServer


def _server(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path / "runtime"))
    monkeypatch.setenv("IDA_MCP_BATCH_STATE_DIR", str(tmp_path / "batch"))
    monkeypatch.setattr(IDAMCPServer, "_detect_ida_dir", lambda self: "")
    monkeypatch.setattr(IDAMCPServer, "_find_idat", lambda self: "")
    server = IDAMCPServer()
    server._execute_tool = lambda tool, args: (
        {"ok": True, "functions": 2, "imports": 1}
        if tool == "idb" and args.get("action") == "summary"
        else {"ok": True, "tool": tool, "action": args.get("action")}
    )
    return server


def test_workflow_catalog_plan_filters_and_all_profiles(tmp_path, monkeypatch):
    server = _server(tmp_path, monkeypatch)
    try:
        assert server._handle_workflow({"action": "catalog"})["ok"] is True
        assert server._handle_workflow({"action": "patch_review"})["code"] == MCPError.INVALID_ARGS

        plan = server._handle_workflow(
            {
                "action": "plan",
                "workflow_action": "triage_fast",
                "profile": "not-a-profile",
                "include_tools": ["idb", "missing"],
                "exclude_tools": ["data", "idb"],
            }
        )
        assert plan["ok"] is True
        assert plan["workflow_meta"]["profile"] == "balanced"
        assert plan["workflow_meta"]["conflicting_tools"] == ["idb"]
        assert plan["workflow_meta"]["unknown_include_tools"] == ["missing"]
        assert any("No workflow steps" not in item for item in plan["workflow_meta"]["plan_diagnostics"])

        for action in ("malware_deep", "vuln_audit", "recon_sweep"):
            result = server._handle_workflow({"action": action, "dry_run": True})
            assert result["ok"] is True, (action, result)

        patch = server._handle_workflow({"action": "patch_review", "addr": "0x401000"})
        assert patch["ok"] is True
        assert patch["workflow_meta"]["step_count"] >= 3
    finally:
        server.shutdown()


def test_workflow_compose_estimate_explain_and_prioritize(tmp_path, monkeypatch):
    server = _server(tmp_path, monkeypatch)
    try:
        assert server._handle_workflow({"action": "compose"})["code"] == MCPError.INVALID_ARGS
        rejected = server._handle_workflow({"action": "compose", "workflow_actions": ["plan"]})
        assert rejected["code"] == MCPError.INVALID_ARGS

        composed = server._handle_workflow(
            {"action": "compose", "workflow_action": "triage_fast", "addr": "0x401000"}
        )
        assert composed["ok"] is True
        assert composed["planned_actions"] == ["triage_fast"]
        assert all("sources" in call for call in composed["planned_calls"])

        estimate = server._handle_workflow({"action": "estimate", "workflow_action": "vuln_audit"})
        assert estimate["ok"] is True
        assert estimate["estimate"]["complexity"] in {"low", "medium", "high"}
        assert server._handle_workflow({"action": "estimate"})["code"] == MCPError.INVALID_ARGS

        explained = server._handle_workflow({"action": "explain", "workflow_action": "patch_review", "addr": "0x401000"})
        assert explained["ok"] is True
        assert explained["explained_steps"]
        assert server._handle_workflow({"action": "explain", "workflow_action": "explain"})["code"] == MCPError.INVALID_ARGS

        calls = [
            {"name": "search", "arguments": {"action": "find", "query": "ordinary"}, "source_count": 1},
            {"name": "search", "arguments": {"action": "vulnerable", "query": "danger"}, "source_count": 3},
            {"name": "idb", "arguments": {"action": "overview"}, "source_count": 2},
        ]
        for mode in ("original", "coverage", "risk_first", "invalid"):
            prioritized = server._handle_workflow({"action": "prioritize", "priority_mode": mode, "planned_calls": calls})
            assert prioritized["ok"] is True
            assert prioritized["priority_mode"] == ("coverage" if mode == "invalid" else mode)
    finally:
        server.shutdown()


def test_workflow_audit_and_execute_plan_modes(tmp_path, monkeypatch):
    server = _server(tmp_path, monkeypatch)
    executed = []

    def execute(tool, args):
        executed.append((tool, dict(args)))
        if tool == "fails":
            return {"error": True, "code": MCPError.INVALID_ARGS, "category": "user", "message": "bad step"}
        return {"ok": True, "tool": tool, "result": args.get("query", "done")}

    server._execute_tool = execute
    try:
        audit = server._handle_workflow(
            {
                "action": "audit_plan",
                "planned_calls": [
                    None,
                    {"name": "search", "arguments": {"action": "vulnerable"}, "output_key": "risk"},
                    {"name": "search", "arguments": {"action": "vulnerable"}},
                    {"name": "missing_tool", "arguments": {"action": "x"}},
                ],
            }
        )
        assert audit["ok"] is True
        assert audit["audit"]["invalid_call_count"] == 2
        assert audit["audit"]["duplicate_step_count"] == 1
        assert audit["audit"]["risk_hints"]

        executed_plan = server._handle_workflow(
            {
                "action": "execute_plan",
                "planned_calls": [
                    {"name": "idb", "arguments": {"action": "overview"}, "output_key": "overview"},
                    {"name": "fails", "arguments": {"action": "x"}},
                    {"name": "data", "arguments": {"action": "functions"}},
                ],
                "continue_on_error": False,
            }
        )
        assert executed_plan["ok"] is True
        assert executed_plan["summary"]["executed_steps"] == 2
        assert executed_plan["summary"]["error_steps"] == 1
        assert len(executed) == 2

        no_calls = server._handle_workflow({"action": "execute_plan", "planned_calls": []})
        assert no_calls["code"] == MCPError.INVALID_ARGS
        unsupported = server._handle_workflow({"action": "not-real"})
        assert unsupported["code"] == MCPError.ACTION_NOT_FOUND
    finally:
        server.shutdown()
