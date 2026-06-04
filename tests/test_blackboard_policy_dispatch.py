import types

from tests._isolated_repo_loader import load_host_module

ServerBlackboardMixin = load_host_module("server_blackboard").ServerBlackboardMixin
ServerDispatchMixin = load_host_module("server_dispatch").ServerDispatchMixin


class _FakeStore:
    def __init__(self):
        self.items = []
        self._id = 0

    def write(self, title, content="", category="general", addr="", tags=None, confidence=0.5, source="", source_type="", **kwargs):
        self._id += 1
        eid = f"e{self._id}"
        self.items.append(
            {
                "id": eid,
                "title": title,
                "content": content,
                "category": category,
                "addr": addr,
                "tags": tags or [],
                "confidence": confidence,
                "source_type": source_type or source or "manual",
                "resolved": 0,
                "contradicted": 0,
            }
        )
        return eid

    def list(self, category=None, limit=100, include_resolved=True, include_contradicted=False, **kwargs):
        rows = [r for r in self.items if (not category or r.get("category") == category)]
        if not include_contradicted:
            rows = [r for r in rows if not r.get("contradicted")]
        return rows[:limit]

    def read(self, entry_id):
        for r in self.items:
            if r.get("id") == entry_id:
                return r
        return None

    def semantic_search(self, **kwargs):
        return self.list(limit=kwargs.get("top_k", 20))

    def next_target(self, limit=5):
        return [
            {
                "entry_id": "q1",
                "addr": "0x401000",
                "title": "decrypt_config",
                "confidence": 0.8,
                "priority_score": 0.55,
                "xref_count": 4,
                "entropy": 3.2,
            }
        ][:limit]

    def stats(self):
        by_category = {}
        for row in self.items:
            by_category[row["category"]] = by_category.get(row["category"], 0) + 1
        avg = 0.0
        if self.items:
            avg = sum(float(r.get("confidence") or 0.0) for r in self.items) / len(self.items)
        return {
            "total_entries": len(self.items),
            "by_category": by_category,
            "avg_confidence": avg,
            "unresolved": len(self.items),
            "contradicted": 0,
        }

    def exists_similar(self, addr, category, title):
        return any(r.get("category") == category and r.get("title") == title for r in self.items)

    def update(self, entry_id, **kwargs):
        row = self.read(entry_id)
        if not row:
            return False
        row.update(kwargs)
        return True


class _FakeAudit:
    def __init__(self):
        self.records = []

    def log(self, **kwargs):
        self.records.append(kwargs)


class _DummyDispatchServer(ServerBlackboardMixin, ServerDispatchMixin):
    def __init__(self):
        self.cache_dir = "/tmp"
        self.current_session = types.SimpleNamespace(session_id="sid-test", idb_path="/tmp/fake.i64")
        self._blackboard_module = None
        self._blackboard_store = None
        self._analysis_engines = {}
        self._send_notification = lambda _msg: None
        self._store = _FakeStore()
        self.audit = _FakeAudit()
        self._tool_calls = []
        self._usage_intel = None
        self._guardrail_strict_writes = False

    def _get_blackboard_store(self):
        return self._store

    def _normalize_tool_call_args(self, tool_name, args):
        return dict(args or {})

    def _guardrail_mode_from_args(self, call_args):
        return "assist"

    def _compute_pointer_note_signal(self, tool_name, call_args, payload):
        return 0.0

    def call_tool(self, tool_name, idb_path, **kwargs):
        self._tool_calls.append((tool_name, dict(kwargs or {})))
        return {"ok": True, "tool": tool_name, "action": kwargs.get("action"), "idb": idb_path}

    def _handle_session(self, args):
        if args.get("action") == "health" and hasattr(self, "_handle_session_health"):
            return self._handle_session_health(args)
        return {"ok": True, "tool": "session", "action": args.get("action")}


def test_dispatch_policy_allows_read_only_actions_by_default(monkeypatch):
    monkeypatch.delenv("IDA_MCP_POLICY_MODE", raising=False)
    srv = _DummyDispatchServer()

    res = srv._execute_tool_inner("code", "code", {"action": "decompile", "addr": "0x401000"})

    assert res.get("ok") is True
    assert srv._tool_calls
    assert srv.audit.records == []


def test_dispatch_policy_requires_ack_for_misc_python(monkeypatch):
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "assist")
    srv = _DummyDispatchServer()

    blocked = srv._execute_tool_inner(
        "misc",
        "misc",
        {"action": "python", "_purpose": "firmware_analysis"},
    )

    assert blocked.get("error") is True
    assert "Policy requires explicit acknowledgement" in str(blocked.get("message") or "")
    assert not srv._tool_calls
    assert any(r.get("tool") == "misc" and r.get("action") == "python" for r in srv.audit.records)


def test_dispatch_policy_ack_allows_misc_python_and_strips_internal_args(monkeypatch):
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "assist")
    srv = _DummyDispatchServer()

    res = srv._execute_tool_inner(
        "misc",
        "misc",
        {"action": "python", "_purpose": "firmware_analysis", "_risk_ack": True},
    )

    assert res.get("ok") is True
    assert srv._tool_calls
    tool_name, forwarded = srv._tool_calls[-1]
    assert tool_name == "misc"
    assert "_purpose" not in forwarded
    assert "_risk_ack" not in forwarded
    assert any(r.get("tool") == "misc" and r.get("action") == "python" for r in srv.audit.records)


def test_dispatch_policy_guardrail_ack_is_honored_even_with_false_risk_ack(monkeypatch):
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "assist")
    srv = _DummyDispatchServer()

    res = srv._execute_tool_inner(
        "misc",
        "misc",
        {"action": "python", "_risk_ack": "false", "_guardrail_ack": True},
    )

    assert res.get("ok") is True


def test_dispatch_policy_allows_session_health_without_ack(monkeypatch):
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "assist")
    srv = _DummyDispatchServer()
    srv._handle_session_health = lambda _args: {"ok": True, "tool": "session", "action": "health"}  # type: ignore[attr-defined]

    res = srv._execute_tool_inner("session", "session", {"action": "health"})

    assert res.get("ok") is True
    assert res.get("tool") == "session"
    assert res.get("action") == "health"


def test_dispatch_policy_blocks_disallowed_purpose_in_enforce_mode(monkeypatch):
    monkeypatch.setenv("IDA_MCP_POLICY_MODE", "enforce")
    srv = _DummyDispatchServer()

    blocked = srv._execute_tool_inner(
        "code",
        "code",
        {"action": "decompile", "_purpose": "cheating", "_risk_ack": True},
    )

    assert blocked.get("error") is True
    assert "Policy blocked this tool action" in str(blocked.get("message") or "")
    assert not srv._tool_calls


def test_survey_gate_allows_workflow_meta_actions(monkeypatch):
    monkeypatch.delenv("IDA_MCP_POLICY_MODE", raising=False)
    srv = _DummyDispatchServer()
    srv._get_active_survey = lambda: {"addr": "0x1000", "status": "ACTIVE"}  # type: ignore[method-assign]
    srv._handle_workflow = lambda args: {"ok": True, "action": args.get("action")}  # type: ignore[attr-defined]

    for action in ("catalog", "plan", "explain", "estimate", "compose", "prioritize", "audit_plan"):
        res = srv._execute_tool_inner("workflow", "workflow", {"action": action})
        assert res.get("ok") is True
        assert res.get("action") == action


def test_survey_gate_still_blocks_executable_workflow_actions(monkeypatch):
    monkeypatch.delenv("IDA_MCP_POLICY_MODE", raising=False)
    srv = _DummyDispatchServer()
    srv._get_active_survey = lambda: {"addr": "0x1000", "status": "ACTIVE"}  # type: ignore[method-assign]
    srv._handle_workflow = lambda args: {"ok": True, "action": args.get("action")}  # type: ignore[attr-defined]

    blocked = srv._execute_tool_inner("workflow", "workflow", {"action": "triage_fast"})

    assert blocked.get("error") is True
    assert blocked.get("code") == "SURVEY_REQUIRED"


def test_dispatch_strict_policy_blocks_non_blackboard_tool_when_stale():
    srv = _DummyDispatchServer()
    set_policy = srv._handle_blackboard(
        {
            "action": "policy_set",
            "strict_mode": True,
            "max_staleness_calls": 2,
            "require_working_set": True,
            "require_decision_or_write": True,
            "enforce_phases": ["scout", "prove", "commit", "finalize"],
        }
    )
    assert set_policy.get("ok") is True

    res = srv._execute_tool_inner("code", "code", {"action": "decompile", "addr": "0x401000"})
    assert res.get("error") is True
    assert "Strict blackboard policy gate failed" in str(res.get("message") or "")


def test_dispatch_strict_policy_allows_tool_after_fresh_cycle():
    srv = _DummyDispatchServer()
    srv._handle_blackboard(
        {
            "action": "policy_set",
            "strict_mode": True,
            "max_staleness_calls": 4,
            "require_working_set": True,
            "require_decision_or_write": True,
            "enforce_phases": ["scout", "prove", "commit", "finalize"],
        }
    )
    srv._handle_blackboard({"action": "working_set"})
    srv._handle_blackboard({"action": "write", "title": "fresh note", "category": "wm_now"})

    res = srv._execute_tool_inner("code", "code", {"action": "decompile", "addr": "0x401000"})
    assert res.get("ok") is True
    assert res.get("tool") == "code"


def test_dispatch_phase_prove_blocks_modify_until_receipts():
    srv = _DummyDispatchServer()
    srv._handle_blackboard({"action": "phase_set", "phase": "prove"})
    res = srv._execute_tool_inner(
        "modify",
        "modify",
        {"action": "set_name", "addr": "0x401000", "name": "f_cfg", "_risk_ack": True},
    )
    assert res.get("error") is True
    assert "prove phase requires evidence cards" in str(res.get("message") or "").lower()


def test_dispatch_strict_stale_not_blocked_in_scout_but_blocked_in_commit():
    srv = _DummyDispatchServer()
    srv._handle_blackboard(
        {
            "action": "policy_set",
            "strict_mode": True,
            "max_staleness_calls": 1,
            "require_working_set": True,
            "require_decision_or_write": True,
            "enforce_phases": ["commit", "finalize"],
        }
    )
    # In scout (default), stale strict policy should not block normal calls.
    ok_in_scout = srv._execute_tool_inner("code", "code", {"action": "decompile", "addr": "0x401000"})
    assert ok_in_scout.get("ok") is True

    # Move to commit and force stale state, then same call should be blocked by strict policy.
    srv._handle_blackboard({"action": "phase_set", "phase": "commit"})
    blocked = srv._execute_tool_inner("code", "code", {"action": "decompile", "addr": "0x401000"})
    assert blocked.get("error") is True
    assert "Strict blackboard policy gate failed" in str(blocked.get("message") or "")
