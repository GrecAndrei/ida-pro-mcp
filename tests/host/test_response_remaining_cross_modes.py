"""Cross-mode coverage for response filtering, enrichment, and guardrails."""

from __future__ import annotations

from types import SimpleNamespace

from ida_pro_mcp.host.errors import make_error
from ida_pro_mcp.host.server.server_response import ServerResponseMixin


class _Host(ServerResponseMixin):
    def __init__(self):
        self.current_session = None
        self.session_mgr = None
        self.session_runtimes = {}
        self._pointer_note_min_signal = 1.0
        self._pointer_note_pending_signal = 0.0
        self._pointer_note_last_shown_at = 0.0
        self._pointer_note_interval_seconds = 0.0
        self._phase_gates_enabled = False
        self._pending_truncation = {}

    def _runtime_record(self, sid):
        return self.session_runtimes.get(sid)

    def _runtime_update(self, sid, **updates):
        self.session_runtimes.setdefault(sid, {}).update(updates)
        return True

    def _get_blackboard_store(self):
        return None

    def _blackboard_store_for(self, _session):
        return None


def test_pointer_signals_addresses_guardrail_modes_and_directives():
    host = _Host()
    assert host._pointer_note_signal_from_text("") == 0
    assert host._pointer_note_signal_from_text("   ") == 0
    assert host._pointer_note_signal_from_text("0x401000 + 0x20") >= 3
    assert host._pointer_note_signal_from_value(0x1000) == 0.5
    assert host._pointer_note_signal_from_value(0x10) == 0
    nested = {"target": [0x401000, {"address": "0x402000"}], "ignored": object()}
    assert host._pointer_note_signal_from_value(nested) > 0
    assert host._pointer_note_signal_from_value({"deep": {"x": {"y": {"z": "0x401000"}}}}) == 0

    host._pointer_note_min_signal = 4.0
    assert host._should_include_pointer_note("search", {"addr": "0x401000"}, {"ok": True}) is False
    assert host._should_include_pointer_note("code", {"addr": "0x401000"}, {"address": "0x402000"}) is True
    assert host._should_include_pointer_note("code", {}, make_error("INVALID_ARGS", "bad")) is False
    assert host._validate_address_lockstep({"addr": "0x401000"}, {"address": "0x402000"})[0]["addr"] == "0x401000"
    assert host._validate_address_lockstep([], {}) == []

    assert host._guardrail_mode_from_args({"_guardrail_mode": "disabled"}) == "off"
    assert host._guardrail_mode_from_args({"_guardrail_mode": "block"}) == "enforce"
    assert host._guardrail_mode_from_args({"_guardrail_mode": "unknown"}) == "assist"
    assert host._build_llm_execution_directive({}) is None
    assert "code.callers" in host._build_llm_execution_directive(
        {"must_call_before_answer": True, "required_followup_call": {}}
    )
    assert "MCP_RECOMMENDED_CALL" in host._build_llm_execution_directive(
        {"required_followup_call": {"tool": "blackboard", "action": "working_set"}}
    )
    assert "MCP_REQUIRED_CALL" in host._build_llm_execution_directive(
        {"must_call_before_answer": True, "required_followup_call": {"tool": "calc", "action": "deref"}}
    )


def test_output_filters_cover_nested_paths_and_invalid_options():
    host = _Host()
    error = make_error("INVALID_ARGS", "bad")
    assert host._apply_output_filters(error, {"output_path": "message"}) is error
    assert host._apply_output_filters({"rows": [{"value": 1}, {"value": 2}]}, {"output_path": "rows.1.value"}) == 2
    assert host._apply_output_filters({"rows": [1]}, {"output_path": "rows.9"}) == {}
    values = [{"name": "alpha"}, "beta", {"name": "gamma"}]
    assert host._apply_output_filters(
        values,
        {
            "output_skip": "not-an-int",
            "output_head": "not-an-int",
            "output_tail": "not-an-int",
            "output_grep": "[",
            "output_pluck": "name",
        },
    ) == ["alpha", "beta", "gamma"]
    assert host._apply_output_filters(
        [{"name": "alpha"}, {"name": "beta"}],
        {"output_grep": "beta", "output_pluck": "name"},
    ) == ["beta"]
    listed = {"first": ["alpha", "beta"], "second": ["beta", "gamma"], "scalar": 1}
    assert host._apply_output_filters(listed, {"output_grep": "beta"})["first"] == ["beta"]


def test_session_imagebase_calculations_and_resolution_modes(monkeypatch):
    host = _Host()
    assert host._get_session_imagebase("") is None
    host.session_runtimes["cached"] = {"imagebase": 0x400000}
    assert host._get_session_imagebase("cached") == 0x400000

    session = SimpleNamespace(session_id="opts", analysis_options={"baseaddr": "0x500000"})
    host.current_session = session
    assert host._get_session_imagebase("opts") == 0x500000
    session.analysis_options = {"baseaddr": "not-hex"}
    host.session_runtimes["opts"] = {"port": "bad"}
    assert host._get_session_imagebase("opts") is None

    host.session_runtimes["rpc"] = {"port": 1111, "auth_token": "token"}
    host._send_rpc_raw = lambda *_args, **_kwargs: {"ok": True, "image_base": "not-hex"}
    assert host._get_session_imagebase("rpc") is None
    host.session_runtimes["rpc2"] = {"port": 1111}
    host._send_rpc_raw = lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("offline"))
    assert host._get_session_imagebase("rpc2") is None

    host._get_session_imagebase = lambda _sid: 0x400000
    compacted = {"a": "0x1000", "b": "0x400000", "c": "0x0"}
    host._add_address_calculations(compacted, "opts")
    assert compacted["llm_address_calculation"]["0x1000"]["is_rva"] is True
    assert compacted["llm_address_calculation"]["0x400000"]["offset"] == 0
    assert host._add_address_calculations({"plain": "no address"}, "opts") is None

    host._resolve_session_from_idb_ref = lambda ref: session if ref == "opts" else None
    assert host._resolve_response_session({"idb": "opts"}) is session
    assert host._resolve_response_session({"idb": "missing", "session_id": ""}) is session
    host._resolve_session_from_idb_ref = lambda _ref: (_ for _ in ()).throw(RuntimeError("bad ref"))
    assert host._resolve_response_session({"idb": "bad"}) is session


def test_workspace_and_context_injection_are_bounded_and_failure_visible():
    class Store:
        def recall_lines(self, addresses, limit):
            assert addresses == ["0x401000"] and limit == 4
            return ["finding at 0x401000"]

        def examination(self, address):
            return {"verdict": "dismissed"} if address == "0x402000" else None

        def observe_code(self, addr, kind, text):
            return {"stale_marked": 1} if addr == "0x401000" and kind == "decompile" else {}

    host = _Host()
    store = Store()
    host._get_blackboard_store = lambda: store
    host._blackboard_store_for = lambda _session: store
    payload = {"address": "0x402000"}
    host._inject_workspace_recall("search", payload, {"addr": "0x401000"})
    assert payload["_recall"] == ["finding at 0x401000"]
    assert payload["_already_examined"] == {"0x402000": "dismissed"}
    host._capture_code_anchor("code", "decompile", {"addr": "0x401000"}, {"pseudocode": "int f(){}"})
    stale = {}
    host._capture_code_anchor("ida_decompile", "semantic_decompile", {"address": "0x401000"}, {"code": "int f(){}"})
    host._capture_code_anchor("blackboard", "decompile", {"addr": "0x401000"}, stale)
    assert stale == {}

    class Assembler:
        def assemble(self, **_kwargs):
            return {
                "related_findings": [
                    {"kind": "finding", "status": "open", "title": "new title", "addr": "0x403000"},
                    {"kind": "finding", "status": "open", "title": "finding at 0x401000"},
                    {"kind": "question", "status": "open", "title": ""},
                    {"kind": "finding", "status": "open", "title": "extra"},
                ]
            }

    host.assembler = Assembler()
    compact = {"_recall": ["finding at 0x401000"]}
    host._assemble_and_inject_context("search", "find", compact, "0x402000", {"mode": "compact"})
    assert compact["_context"] == ["finding/open: new title — @ 0x403000"]
    full = {}
    host._assemble_and_inject_context("search", "find", full, "0x402000", {"mode": "full"})
    assert "context_pack" in full

    class BrokenStore:
        def recall_lines(self, *_args, **_kwargs):
            raise RuntimeError("store gone")

    def get_broken_store():
        return BrokenStore()

    host._get_blackboard_store = get_broken_store
    failed = {}
    host._inject_workspace_recall("search", failed, {"addr": "0x401000"})
    assert "RuntimeError" in failed["_recall_error"]

    host.assembler = SimpleNamespace(assemble=lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("assembler down")))
    context_failed = {}
    host._assemble_and_inject_context("search", "find", context_failed, "0x401000", {"mode": "compact"})
    assert "RuntimeError" in context_failed["_context_error"]
