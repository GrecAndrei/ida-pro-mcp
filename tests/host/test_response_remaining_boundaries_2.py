"""Boundary coverage for response helpers and enrichment fail-safe paths."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

import ida_pro_mcp.host.response_enrichment as enrichment_module
import ida_pro_mcp.host.server.server_response as response_module
from ida_pro_mcp.host.server.server_response import ServerResponseMixin


class _BadDict(dict):
    def get(self, *_args, **_kwargs):
        raise RuntimeError("dict lookup failed")


class _BadList(list):
    def __iter__(self):
        raise RuntimeError("list iteration failed")


class _FakeHexPattern:
    def __init__(self, value):
        self.value = value

    def finditer(self, _text):
        return [SimpleNamespace(group=lambda _index: self.value)]

    def findall(self, _text):
        return [self.value]


class _PipelineHost(ServerResponseMixin):
    def __init__(self, session=None):
        self.current_session = session
        self.session_mgr = None
        self.session_runtimes = {}
        self._pending_truncation = {}
        self._pending_session_notices = {}
        self._phase_gates_enabled = False
        self._pointer_note_min_signal = 1.0
        self._pointer_note_pending_signal = 0.0
        self._pointer_note_last_shown_at = 0.0
        self._pointer_note_interval_seconds = 0.0
        self.enable_response_enrichment = False
        self.assembler = SimpleNamespace(assemble=lambda **_kwargs: None)
        self._context_density_optimizer = SimpleNamespace(
            compact_response=lambda value, budget_tokens: value,
        )
        self._session_resume_calls = {}
        self._session_resume_calls_lock = threading.Lock()

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
        return "boundary-test"


def _opts(**overrides):
    options = {
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
    options.update(overrides)
    return options


def test_policy_phase_and_pointer_helpers_fail_closed_at_boundaries(monkeypatch):
    host = _PipelineHost()

    host._inject_blackboard_policy_followup("not-a-dict", "search", {})
    host._inject_blackboard_phase_followup("not-a-dict", "search")
    host._phase_gates_enabled = True
    host._inject_blackboard_policy_followup({}, "search", {})
    host._inject_blackboard_phase_followup({}, "search")

    host._bb_policy_state = lambda: {"strict_mode": False}
    host._bb_policy_check = lambda _state: {"ok": False}
    policy_payload = {}
    host._inject_blackboard_policy_followup(policy_payload, "search", {})
    assert policy_payload == {}

    host._bb_policy_state = lambda: {"strict_mode": True}
    host._bb_policy_check = lambda _state: {"ok": True}
    host._inject_blackboard_policy_followup(policy_payload, "search", {})
    assert policy_payload == {}

    host._phase_followup_for_response = lambda _tool: {"phase_gate": None}
    phase_payload = {}
    host._inject_blackboard_phase_followup(phase_payload, "search")
    assert phase_payload == {}

    assert host._pointer_note_signal_from_value({str(i): i for i in range(30)}) >= 0
    host._pointer_note_min_signal = 4.0
    host._pointer_note_pending_signal = 1.0
    monkeypatch.setattr(response_module.time, "time", lambda: 100.0)
    assert host._should_include_pointer_note("unrelated", {}, {}) is False
    assert host._pointer_note_pending_signal == pytest.approx(0.75)
    assert host._should_include_pointer_note("unrelated", {}, {}) is False


def test_workspace_recall_caps_examined_addresses_and_first_address_handles_empty():
    host = _PipelineHost()

    class Store:
        def examination(self, _address):
            return {"verdict": "dismissed"}

    def get_store():
        return Store()

    host._get_blackboard_store = get_store
    addresses = [f"0x{0x401000 + i * 0x10:x}" for i in range(11)]
    payload = {"items": addresses}
    host._inject_workspace_recall("search", payload, {})
    assert len(payload["_already_examined"]) == 10
    assert host._first_addr({}) == ""


def test_hex_collection_respects_empty_invalid_and_bounded_values(monkeypatch):
    host = _PipelineHost()

    monkeypatch.setattr(response_module, "_POINTER_NOTE_HEX_RE", _FakeHexPattern(""))
    assert host._collect_hex_addresses("anything") == []
    monkeypatch.setattr(response_module, "_POINTER_NOTE_HEX_RE", _FakeHexPattern("401000"))
    assert host._collect_hex_addresses("anything") == []

    monkeypatch.setattr(response_module, "_POINTER_NOTE_HEX_RE", _FakeHexPattern("0x401000"))
    assert host._collect_hex_addresses(["anything", "anything"], max_items=1) == ["0x401000"]
    monkeypatch.setattr(response_module, "_POINTER_NOTE_HEX_RE", _FakeHexPattern(""))
    no_addresses = {str(i): "none" for i in range(25)}
    assert host._collect_hex_addresses(no_addresses) == []
    monkeypatch.setattr(response_module, "_POINTER_NOTE_HEX_RE", _FakeHexPattern("0x401000"))
    assert host._collect_hex_addresses({"a": "0x401000", "b": "0x402000"}, max_items=1) == [
        "0x401000"
    ]


def test_filter_and_imagebase_helpers_preserve_payloads_on_bad_inputs(monkeypatch):
    host = _PipelineHost()
    original = [_BadDict(name="bad")]
    assert host._apply_output_filters(original, {"output_pluck": "name"}) is original

    bad_values = {"values": _BadList(["a", "b"])}
    assert host._apply_output_filters(bad_values, {"output_grep": "a"}) is bad_values
    assert host._build_llm_execution_directive("not-a-dict") is None

    host.current_session = SimpleNamespace(session_id="S", analysis_options={})
    assert host._get_session_imagebase("S") is None

    cyclic = {}
    cyclic["self"] = cyclic
    cyclic["address"] = "0x401000"
    host._get_session_imagebase = lambda _sid: 0x400000
    host._add_address_calculations(cyclic, "S")
    assert cyclic["llm_address_calculation_imagebase"] == "0x400000"

    monkeypatch.setattr(response_module, "_POINTER_NOTE_HEX_RE", _FakeHexPattern("not-hex"))
    invalid = {"address": "anything"}
    host._add_address_calculations(invalid, "S")
    assert "llm_address_calculation" not in invalid

    monkeypatch.setattr(response_module, "_POINTER_NOTE_HEX_RE", _FakeHexPattern("0x10"))
    below_threshold = {"address": "0x10"}
    host._add_address_calculations(below_threshold, "S")
    assert "llm_address_calculation" not in below_threshold


def test_session_scoped_blackboard_store_resolution_is_safe(monkeypatch):
    class Host(ServerResponseMixin):
        pass

    host = Host.__new__(Host)
    assert host._blackboard_store_for(None) is None
    host._get_blackboard_store = lambda: None
    monkeypatch.setattr(Host, "_blackboard_module", None, raising=False)
    assert host._blackboard_store_for(SimpleNamespace()) is None

    class Module:
        class BlackboardStore:
            def __init__(self, **_kwargs):
                raise RuntimeError("database unavailable")

    monkeypatch.setattr(Host, "_blackboard_module", Module, raising=False)
    host._session_blackboard_path = lambda **_kwargs: ""
    assert host._blackboard_store_for(SimpleNamespace()) is None
    host._session_blackboard_path = lambda **_kwargs: "/tmp/session.db"
    assert host._blackboard_store_for(SimpleNamespace()) is None


def test_prepare_response_payload_skips_truncation_and_survives_middleware_failures(monkeypatch):
    host = _PipelineHost()
    host._pending_session_notices = {"S": "analysis complete"}
    host.current_session = SimpleNamespace(session_id="S")
    host._pending_truncation = {"no_truncate": True}
    host._context_density_optimizer.compact_response = lambda *_args, **_kwargs: {
        "should": "not happen"
    }
    result = host._prepare_response_payload(
        {"ok": True, "items": ["x"]},
        _opts(char_budget=10),
        tool_name="search",
        call_args={},
    )
    assert result["warning"] == "analysis complete"
    assert result["items"] == ["x"]

    host._pending_session_notices = {"S": "bad notice"}
    host._pending_truncation = {}
    class BadNotices(dict):
        def pop(self, *_args, **_kwargs):
            raise RuntimeError("notice store failed")

    host._pending_session_notices = BadNotices({"S": "bad notice"})
    host._context_density_optimizer.compact_response = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("density unavailable")
    )
    monkeypatch.setattr(response_module, "CONTEXT_DENSITY_COMPACT_THRESHOLD", 1)
    result = host._prepare_response_payload(
        {"ok": True, "large": "payload"},
        _opts(char_budget=10),
        tool_name="search",
        call_args={},
    )
    assert result["ok"] is True


def test_prepare_response_payload_handles_drop_gating_and_enrichment_errors(monkeypatch):
    host = _PipelineHost()
    host._project_top_level_fields = lambda payload, _opts: payload
    host._compact_value = lambda _payload, _opts: response_module._COMPACT_DROP
    host._compact_batch_result = lambda value, _opts: value
    result = host._prepare_response_payload(
        {"ok": True}, _opts(), tool_name="search", call_args={}
    )
    assert result == {}

    host = _PipelineHost()
    host._inject_blackboard_policy_followup = lambda *_args: (_ for _ in ()).throw(
        RuntimeError("policy callback failed")
    )
    result = host._prepare_response_payload(
        {"ok": True}, _opts(mode="full"), tool_name="search", call_args={}
    )
    assert result["ok"] is True

    host = _PipelineHost()
    host.enable_response_enrichment = True
    host._get_session_imagebase = lambda _sid: 0x400000
    monkeypatch.setattr(
        enrichment_module,
        "patch_addresses",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("patch failed")),
    )
    result = host._prepare_response_payload(
        {"ok": True, "disassembly": "lea rax, [rip+0x10]"},
        _opts(mode="full"),
        tool_name="code",
        call_args={"action": "disasm", "addr": "0x401000"},
    )
    assert result["disassembly"]


def test_prepare_response_payload_covers_digest_resume_confidence_and_context_failures(monkeypatch):
    host = _PipelineHost()
    host.enable_response_enrichment = True
    host._insight_index = SimpleNamespace(get_function=lambda address: {"address": address})
    digest_calls = []

    def fake_digest(_text, schema_attrs=None):
        digest_calls.append(schema_attrs)
        return {"api_calls": [schema_attrs["address"]]}

    monkeypatch.setattr(enrichment_module, "digest_decompiled", fake_digest)
    result = host._prepare_response_payload(
        {"ok": True, "code": "int f(){}"},
        _opts(mode="full"),
        tool_name="code",
        call_args={"action": "decompile", "addr": "0x401000"},
    )
    assert digest_calls == [{"address": "0x401000"}]
    assert result["_digest"]["api_calls"] == ["0x401000"]

    host._insight_index = SimpleNamespace(
        get_function=lambda _address: (_ for _ in ()).throw(RuntimeError("index offline"))
    )
    monkeypatch.setattr(
        enrichment_module,
        "digest_decompiled",
        lambda _text, schema_attrs=None: {"patterns": ["safe"]},
    )
    result = host._prepare_response_payload(
        {"ok": True, "output": "int g(){}"},
        _opts(mode="full"),
        tool_name="code",
        call_args={"action": "decompile", "addr": "0x402000"},
    )
    assert result["_digest"]["patterns"] == ["safe"]

    monkeypatch.setattr(
        enrichment_module,
        "digest_decompiled",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("digest failed")),
    )
    result = host._prepare_response_payload(
        {"ok": True, "pseudocode": "int h(){}"},
        _opts(mode="full"),
        tool_name="code",
        call_args={"action": "decompile", "addr": "0x403000"},
    )
    assert result["ok"] is True

    host.current_session = SimpleNamespace(session_id="S")
    host.session_mgr = SimpleNamespace()
    monkeypatch.setattr(
        enrichment_module,
        "build_session_resume",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("resume failed")),
    )
    result = host._prepare_response_payload(
        {"ok": True, "confidence": "not-a-number"},
        _opts(mode="full"),
        tool_name="search",
        call_args={},
    )
    assert result["ok"] is True


def test_prepare_response_payload_surfaces_workspace_and_late_enrichment_failures():
    host = _PipelineHost()
    host._capture_code_anchor = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("anchor failed")
    )
    host._assemble_and_inject_context = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("context failed")
    )
    result = host._prepare_response_payload(
        {"ok": True, "pseudocode": "int f(){}"},
        _opts(mode="full"),
        tool_name="code",
        call_args={"action": "decompile", "addr": "0x401000"},
    )
    assert "RuntimeError: anchor failed" in result["_anchor_error"]
    assert result["ok"] is True

    host.enable_response_enrichment = True
    host._exec = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("similar failed"))
    host._add_address_calculations = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("address math failed")
    )
    result = host._prepare_response_payload(
        {"ok": True, "value": "plain"},
        _opts(mode="full"),
        tool_name="search",
        call_args={"action": "find", "addr": "0x401000"},
    )
    assert result["ok"] is True
