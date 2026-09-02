"""Composed coverage for response enrichment across compact and full modes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.server.server_response import ServerResponseMixin


class _Assembler:
    def __init__(self, pack=None):
        self.pack = pack
        self.calls = []

    def assemble(self, **kwargs):
        self.calls.append(kwargs)
        return self.pack


class _Manager:
    def __init__(self, session):
        self.session = session

    def get_session(self, sid):
        return self.session if sid == self.session.session_id else None

    def _load_skills(self, _sid):
        return {
            "activity_log": [
                {"action": "decompile", "result": {"addresses": ["0x401000"]}},
            ],
            "hypotheses": [
                {"id": "pending", "statement": "check bounds", "status": "pending"},
                {"id": "confirmed", "statement": "uses TLS", "status": "confirmed"},
            ],
            "skills": {
                "x": {"name": "xrefs", "description": "follow references", "q_value": 0.8},
            },
        }

    def _load_notebook(self, _sid):
        return "first\nlast"


class _Host(ServerResponseMixin):
    def __init__(self, *, session=None, assembler=None):
        self.current_session = session
        self.session_mgr = _Manager(session) if session is not None else None
        self.assembler = assembler
        self.enable_response_enrichment = False
        self.session_runtimes = {}
        self._pending_truncation = {}
        self._pending_session_notices = {}
        self._pointer_note_min_signal = 1.0
        self._pointer_note_pending_signal = 0.0
        self._pointer_note_last_shown_at = 0.0
        self._pointer_note_interval_seconds = 0.0
        self._session_resume_calls = {}
        import threading

        self._session_resume_calls_lock = threading.Lock()
        self._context_density_optimizer = SimpleNamespace(
            compact_response=lambda value, budget_tokens: {
                "density_compacted": True,
                "budget_tokens": budget_tokens,
                "original": value,
            }
        )

    def _json_safe_value(self, value):
        return value

    def _runtime_record(self, sid):
        return self.session_runtimes.get(sid)

    def _runtime_update(self, sid, **updates):
        self.session_runtimes.setdefault(sid, {}).update(updates)
        return True

    def _get_blackboard_store(self):
        return None

    def _blackboard_store_for(self, _session):
        return None

    def _safe_mode_active(self, _sid):
        return False

    def _truncation_owner_id(self):
        return "test-owner"


def _compact_opts(**overrides):
    opts = {
        "mode": "compact",
        "fields": [],
        "omit": [],
        "max_items": 100,
        "max_string": 100_000,
        "char_budget": 0,
        "drop_empty": True,
        "drop_false": True,
        "drop_ok": False,
        "dedupe_counts": True,
        "strip_meta": True,
        "table_mode": False,
        "batch_compact": True,
        "error_details": "basic",
    }
    opts.update(overrides)
    return opts


def _full_opts(**overrides):
    opts = _compact_opts(mode="full", char_budget=0, drop_ok=False)
    opts.update(overrides)
    return opts


def test_full_pipeline_composes_policy_phase_context_and_lockstep(monkeypatch):
    session = SimpleNamespace(session_id="SID_FULL", idb_path="/tmp/full.i64")
    assembler = _Assembler({
        "related_findings": [
            {"kind": "finding", "status": "open", "title": "bounded read", "addr": "0x402000"},
            {"kind": "question", "status": "open", "title": "ignored duplicate"},
        ],
    })
    host = _Host(session=session, assembler=assembler)
    host._phase_gates_enabled = True
    host._bb_policy_state = lambda: {"strict_mode": True}
    host._bb_policy_check = lambda _state: {
        "ok": False,
        "reasons": ["missing_working_set"],
    }
    host._phase_followup_for_response = lambda _tool: {
        "phase_gate": {"phase": "decide"},
        "must_call_before_answer": True,
        "required_followup_call": {"tool": "blackboard", "action": "decision_card"},
    }
    host._pending_session_notices = {"SID_FULL": "analysis completed"}

    result = host._prepare_response_payload(
        {
            "ok": True,
            "address": "0x402000",
            "confidence": 0.25,
            "items": [{"addr": "0x402000"}],
        },
        _full_opts(),
        tool_name="search",
        call_args={"action": "find", "addr": "0x401000"},
    )

    assert result["warning"] == "analysis completed"
    assert result["llm_address_lockstep_warnings"][0]["addr"] == "0x401000"
    assert result["blackboard_policy_gate"]["reasons"] == ["missing_working_set"]
    assert result["blackboard_phase_gate"] == {"phase": "decide"}
    assert result["required_followup_call"] == {"tool": "blackboard", "action": "decision_card"}
    assert result["llm_execution_directive"].startswith("MCP_REQUIRED_CALL")
    assert result["llm_low_confidence_gate"]["confidence"] == 0.25
    assert assembler.calls[-1]["mode"] == "full"
    assert result["context_pack"]["related_findings"]


def test_compact_pipeline_injects_related_hints_and_density_fallback(monkeypatch):
    assembler = _Assembler({
        "related_findings": [
            {"kind": "finding", "status": "confirmed", "title": "known path", "addr": "0x401000"},
            {"kind": "question", "status": "open", "title": "second path"},
        ],
    })
    host = _Host(assembler=assembler)
    monkeypatch.setattr(
        "ida_pro_mcp.host.server.server_response.CONTEXT_DENSITY_COMPACT_THRESHOLD",
        1,
    )
    result = host._prepare_response_payload(
        {"ok": True, "items": [{"addr": "0x401000"}], "text": "payload"},
        _compact_opts(char_budget=800),
        tool_name="search",
        call_args={"query": "pointer"},
    )

    assert result["density_compacted"] is True
    assert result["budget_tokens"] == 800
    assert assembler.calls[-1]["mode"] == "compact"


def test_raw_compact_response_skips_density_middleware(monkeypatch):
    host = _Host()
    called = []
    host._context_density_optimizer.compact_response = lambda *a, **k: called.append(1)
    monkeypatch.setattr(
        "ida_pro_mcp.host.server.server_response.CONTEXT_DENSITY_COMPACT_THRESHOLD",
        1,
    )
    result = host._prepare_response_payload(
        {"ok": True, "text": "large"},
        _compact_opts(char_budget=800),
        tool_name="search",
        call_args={"raw": True},
    )
    assert called == []
    assert result["text"] == "large"


def test_enriched_code_response_adds_digest_similarity_resume_and_address_math(monkeypatch):
    session = SimpleNamespace(
        session_id="SID_ENRICH",
        idb_path="/tmp/enrich.i64",
        phase="decide",
        analysis_options={},
    )
    host = _Host(session=session, assembler=_Assembler({"related_findings": []}))
    host.enable_response_enrichment = True
    host.session_runtimes[session.session_id] = {"imagebase": 0x400000}
    host._exec = lambda *args, **kwargs: {"ok": True, "results": ["0x402000"]}
    monkeypatch.setattr(
        "ida_pro_mcp.host.response_enrichment.digest_decompiled",
        lambda text, schema_attrs=None: {
            "api_calls": ["recv"],
            "patterns": ["network input"],
            "behavior_tags": ["network"],
        },
    )

    result = host._prepare_response_payload(
        {
            "ok": True,
            "pseudocode": "int f(){ return recv(s, buf, n); }",
            "address": "0x1000",
            "confidence": "0.4",
        },
        _compact_opts(drop_ok=False),
        tool_name="code",
        call_args={"action": "decompile", "addr": "0x401000"},
    )

    assert result["_digest"]["behavior_tags"] == ["network"]
    assert result["similar_functions"] == ["0x402000"]
    assert result["llm_address_calculation"]["0x1000"]["is_rva"] is True
    assert result["llm_address_calculation_imagebase"] == "0x400000"
    assert result["_session_resume"]["previously_decompiled"] == ["0x401000"]
    assert result["llm_low_confidence_gate"]["confidence"] == pytest.approx(0.4)


def test_session_imagebase_resolves_runtime_options_and_rpc_fallbacks():
    session = SimpleNamespace(
        session_id="SID_BASE",
        analysis_options={"baseaddr": "0x500000"},
    )
    host = _Host(session=session)
    assert host._get_session_imagebase("SID_BASE") == 0x500000

    session.analysis_options = {"baseaddr": "not-an-address"}
    host.session_runtimes["SID_BASE"] = {"port": 1001, "auth_token": "token"}
    host._send_rpc_raw = lambda *args, **kwargs: {"ok": True, "image_base": "0x600000"}
    assert host._get_session_imagebase("SID_BASE") == 0x600000
    assert host.session_runtimes["SID_BASE"]["imagebase"] == 0x600000


def test_session_imagebase_negative_rpc_result_and_unresolved_reference_are_safe():
    host = _Host()
    assert host._get_session_imagebase(None) is None
    host.session_runtimes["SID"] = {"port": 1001}
    host._send_rpc_raw = lambda *args, **kwargs: {"ok": True}
    assert host._get_session_imagebase("SID") is None
    assert host.session_runtimes["SID"]["imagebase"] is None

    host.current_session = SimpleNamespace(session_id="CURRENT")
    host._resolve_session_from_idb_ref = lambda _ref: None
    assert host._resolve_response_session({"idb": "missing"}).session_id == "CURRENT"


def test_blackboard_followups_ignore_invalid_and_failing_callbacks():
    host = _Host()
    payload = {"keep": True}
    host._phase_gates_enabled = True
    host._bb_policy_state = lambda: (_ for _ in ()).throw(RuntimeError("gone"))
    host._bb_policy_check = lambda _state: {"ok": False}
    host._inject_blackboard_policy_followup(payload, "code", {})
    assert payload == {"keep": True}

    host._phase_followup_for_response = lambda _tool: (_ for _ in ()).throw(RuntimeError("gone"))
    host._inject_blackboard_phase_followup(payload, "code")
    assert payload == {"keep": True}


def test_collect_addresses_and_filters_handle_nested_paths_and_non_dict_items():
    host = _Host()
    assert host._collect_hex_addresses({"rows": ["0x1000", {"target": 0x2000}]}) == ["0x1000", "0x2000"]
    assert host._collect_hex_addresses({"rows": ["0x1000", "0x1000", "nope"]}) == ["0x1000"]
    assert host._apply_output_filters(
        {"result": [{"x": 1}, "raw", {"x": 2}]},
        {"output_path": "result", "output_pluck": "x", "output_tail": 2},
    ) == ["raw", 2]
