"""Deep offline coverage for the workflow batch fast path and edge handling."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ida_pro_mcp.host.policy import PolicyDecision
from ida_pro_mcp.host.server import server_workflow_batch as batch_module
from ida_pro_mcp.host.server.server_workflow_batch import ServerWorkflowBatchMixin


class _RateLimiter:
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.checked = []
        self.refunded = []

    def check(self, tool):
        self.checked.append(tool)
        return self.allowed, "denied"

    def refund(self, tool):
        self.refunded.append(tool)


class _FastHost(ServerWorkflowBatchMixin):
    def __init__(self):
        self.session = SimpleNamespace(session_id="SID", idb_path="sample.i64")
        self.current_session = self.session
        self.runtime = {"port": 19000, "auth_token": "token", "alive": True}
        self.rate_limiter = _RateLimiter()
        self.default_truncate_tokens = 100
        self.sent = []
        self.recorded = []

    def _extract_response_options(self, args):
        cleaned = dict(args) if isinstance(args, dict) else args
        if not isinstance(cleaned, dict):
            return cleaned, {}
        opts = {}
        for key in ("max_tokens", "no_truncate", "trunc_offset", "trunc_limit"):
            if key in cleaned:
                opts[key] = cleaned.pop(key)
        return cleaned, opts

    def _resolve_session_from_idb_ref(self, ref):
        if ref == "raise":
            raise RuntimeError("bad session ref")
        if ref in (None, "SID"):
            return self.session
        return None

    def _agent_scope_error(self, _tool, _action):
        return getattr(self, "scope_error", None)

    def _resolve_policy_mode(self):
        return "assist"

    def _safe_mode_gate(self, _sid, _tool, _action):
        return getattr(self, "safe_error", None)

    def _runtime_record(self, _sid):
        return self.runtime

    def _runtime_alive(self, runtime):
        return bool(runtime.get("alive"))

    def _long_running_sock_timeout(self, _tool, args):
        return args.get("timeout")

    def _send_rpc_with_retry(self, request, port, **kwargs):
        self.sent.append((request, port, kwargs))
        return self.rpc_result

    def _cache_post_process_next(self, *_args):
        return _args[-1]

    def _cache_next_page(self, _name, _args, result):
        return result

    def _record_activity(self, name, _args, _result):
        self.recorded.append(name)


def _calls(**args):
    return [
        {"name": "data", "arguments": {"action": "functions", **args}},
        {"name": "data", "arguments": {"action": "strings", **args}},
    ]


@pytest.fixture
def allow_policy(monkeypatch):
    monkeypatch.setattr(
        batch_module,
        "evaluate_policy",
        lambda *_args, **_kwargs: SimpleNamespace(
            decision=PolicyDecision.ALLOW,
            risk=SimpleNamespace(value="read"),
            reasons=[],
            flags=[],
        ),
    )
    monkeypatch.setattr(batch_module, "is_rate_limit_exempt", lambda *_args: False)


def test_fast_path_success_normalizes_results_and_forwards_timeout(allow_policy):
    host = _FastHost()
    host.rpc_result = [{"value": 1}, {"ok": True, "value": 2}]

    result = host._try_batch_fast_path(
        _calls(timeout=12, _purpose="analysis", _risk_ack="ack"), False
    )

    assert result["ok"] is True
    assert result["count"] == 2
    assert result["results"][0]["result"]["ok"] is True
    assert host.sent[0][1] == 19000
    assert host.sent[0][2]["recv_timeout"] == 12
    assert host.recorded == ["data", "data"]


def test_fast_path_no_truncate_and_truncate_failure_are_safe(allow_policy, monkeypatch):
    host = _FastHost()
    host.rpc_result = [{"value": 1}, {"value": 2}]
    # Keep the response option in the cleaned arguments for this boundary
    # probe so the fast-path's own option extraction is exercised.
    host._extract_response_options = lambda args: (dict(args), {})
    result = host._try_batch_fast_path(_calls(no_truncate=True), True)
    assert result["ok"] is True

    monkeypatch.setattr(
        batch_module,
        "truncate_response",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("budget")),
    )
    result = host._try_batch_fast_path(_calls(), True)
    assert result["ok"] is True


def test_fast_path_malformed_rpc_response_returns_per_item_errors(allow_policy):
    host = _FastHost()
    host.rpc_result = {"not": "a-list"}

    result = host._try_batch_fast_path(_calls(), True)

    assert result["ok"] is False
    assert result["count"] == 2
    assert all(
        item["result"]["code"] == "RPC_CONNECTION_ERROR" for item in result["results"]
    )


def test_fast_path_stops_after_first_error_when_requested(allow_policy):
    host = _FastHost()
    host.rpc_result = [{"error": True, "code": "BAD"}, {"ok": True}]

    result = host._try_batch_fast_path(_calls(), False)

    assert result["ok"] is False
    assert result["count"] == 1
    assert result["summary"]["stopped_on_error"] is True


def test_fast_path_post_processing_failure_is_contained(allow_policy, monkeypatch):
    host = _FastHost()
    host.rpc_result = [{"ok": True}, {"ok": True}]
    monkeypatch.setattr(
        batch_module,
        "prepare_args_for_postprocess",
        lambda _name, args: (args, {"mode": "test"}),
    )
    monkeypatch.setattr(batch_module, "has_post_process", lambda _pp: True)
    monkeypatch.setattr(
        batch_module,
        "apply_post_processing",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("postprocess")),
    )

    result = host._try_batch_fast_path(_calls(), True)

    assert result["ok"] is True
    assert result["count"] == 2


def test_fast_path_post_processing_success_caches_continuation(allow_policy, monkeypatch):
    host = _FastHost()
    host.rpc_result = [{"ok": True}, {"ok": True}]
    monkeypatch.setattr(
        batch_module,
        "prepare_args_for_postprocess",
        lambda _name, args: (args, {"mode": "test"}),
    )
    monkeypatch.setattr(batch_module, "has_post_process", lambda _pp: True)
    monkeypatch.setattr(
        batch_module, "apply_post_processing", lambda result, _pp: {**result, "processed": True}
    )

    result = host._try_batch_fast_path(_calls(), True)

    assert all(item["result"]["processed"] for item in result["results"])


@pytest.mark.parametrize(
    "calls",
    [
        [""],
        [{"_precomputed_error": {"error": True}}],
        [{"name": "batch"}, {"name": "batch"}],
        [{"name": "not-a-tool"}, {"name": "not-a-tool"}],
        [
            {"name": "data", "arguments": "bad"},
            {"name": "data", "arguments": "bad"},
        ],
    ],
)
def test_fast_path_declines_malformed_or_ineligible_calls(allow_policy, calls):
    host = _FastHost()

    assert host._try_batch_fast_path(calls, False) is None


def test_fast_path_declines_precomputed_error_excluded_tool_and_single_call(allow_policy):
    host = _FastHost()
    assert host._try_batch_fast_path(
        [
            {"name": "data", "_precomputed_error": {"error": True}},
            {"name": "data"},
        ],
        False,
    ) is None
    assert host._try_batch_fast_path(
        [{"name": "session"}, {"name": "data"}], False
    ) is None
    assert host._try_batch_fast_path([{"name": "data"}], False) is None


def test_fast_path_declines_scope_policy_safe_mode_and_mixed_sessions(allow_policy):
    host = _FastHost()
    host.scope_error = {"error": True}
    assert host._try_batch_fast_path(_calls(), False) is None

    host.scope_error = None
    host.safe_error = {"error": True}
    assert host._try_batch_fast_path(_calls(), False) is None

    host.safe_error = None

    def resolve(ref):
        return SimpleNamespace(session_id="OTHER") if ref == "OTHER" else host.session

    host._resolve_session_from_idb_ref = resolve
    assert host._try_batch_fast_path(
        [
            {"name": "data", "arguments": {"action": "functions"}},
            {"name": "data", "arguments": {"action": "strings", "idb": "OTHER"}},
        ],
        False,
    ) is None


def test_fast_path_declines_session_resolution_and_policy_exceptions(monkeypatch):
    host = _FastHost()

    def fail(_ref):
        raise RuntimeError("resolve")

    host._resolve_session_from_idb_ref = fail
    assert host._try_batch_fast_path(
        [
            {"name": "data", "arguments": {"action": "functions", "idb": "raise"}},
            {"name": "data", "arguments": {"action": "strings"}},
        ],
        False,
    ) is None

    host = _FastHost()
    monkeypatch.setattr(
        batch_module,
        "evaluate_policy",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("policy")),
    )
    assert host._try_batch_fast_path(_calls(), False) is None


@pytest.mark.parametrize(
    "runtime", [None, {"port": 0, "alive": True}, {"port": 19000, "alive": False}]
)
def test_fast_path_requires_live_valid_runtime(runtime, monkeypatch):
    monkeypatch.setattr(
        batch_module,
        "evaluate_policy",
        lambda *_args, **_kwargs: SimpleNamespace(
            decision=PolicyDecision.ALLOW,
            risk=SimpleNamespace(value="read"),
            reasons=[],
            flags=[],
        ),
    )
    monkeypatch.setattr(batch_module, "is_rate_limit_exempt", lambda *_args: False)
    host = _FastHost()
    host.runtime = runtime

    assert host._try_batch_fast_path(_calls(), False) is None


def test_fast_path_refunds_rate_reservations_on_denial_and_send_error(allow_policy):
    host = _FastHost()
    host.rate_limiter.allowed = False
    host.rpc_result = [{"ok": True}, {"ok": True}]
    assert host._try_batch_fast_path(_calls(), False) is None
    assert host.rate_limiter.refunded == []

    host = _FastHost()
    host._send_rpc_with_retry = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        ConnectionError("closed")
    )
    assert host._try_batch_fast_path(_calls(), False) is None
    assert host.rate_limiter.refunded == ["data", "data"]


def test_fast_path_skips_rate_limit_exempt_calls_and_refunds_prior_reservations(
    allow_policy, monkeypatch
):
    host = _FastHost()
    host.rpc_result = [{"ok": True}, {"ok": True}]
    monkeypatch.setattr(batch_module, "is_rate_limit_exempt", lambda *_args: True)
    assert host._try_batch_fast_path(_calls(), False)["ok"] is True
    assert host.rate_limiter.checked == []
    monkeypatch.setattr(batch_module, "is_rate_limit_exempt", lambda *_args: False)

    class _SequenceLimiter(_RateLimiter):
        def __init__(self):
            super().__init__(True)
            self._answers = iter([True, False])

        def check(self, tool):
            self.checked.append(tool)
            return next(self._answers), "denied"

    host = _FastHost()
    host.rate_limiter = _SequenceLimiter()
    assert host._try_batch_fast_path(_calls(), False) is None
    assert host.rate_limiter.refunded == ["data"]


def test_fast_path_handles_timeout_and_bad_extractor_fallbacks(allow_policy):
    host = _FastHost()
    host.rpc_result = [{"ok": True}, {"ok": True}]

    def fail_timeout(*_args):
        raise RuntimeError("timeout")

    host._long_running_sock_timeout = fail_timeout
    result = host._try_batch_fast_path(_calls(), True)
    assert result["ok"] is True

    host = _FastHost()
    host._extract_response_options = lambda _args: ("bad", {})
    assert host._try_batch_fast_path(_calls(), False) is None


def test_batch_reference_helpers_cover_nested_failure_and_annotation_edges():
    host = _FastHost()
    assert host._batch_calls_use_chaining(
        [{"name": "data", "arguments": {"nested": {"x": "$base"}}}]
    ) is True
    assert host._batch_calls_use_chaining(
        [{"name": "data", "extra": "ordinary"}]
    ) is False
    assert host._batch_value_is_reference(["literal", 3], set()) is False
    assert host._batch_calls_use_chaining([None, {"name": "data", "extra": "step0_value"}]) is True
    resolved, error = host._resolve_batch_value(
        [{"x": "step0.result.missing"}], {}, {"step0": {}}, {"step0"}, 1
    )
    assert resolved is None and error["error"] is True
    resolved, ok = host._dotted_path_get({"x": 1}, "x.missing")
    assert resolved is None and ok is False
    assert host._resolve_batch_value("x", {}, {}, set(), 0) == ("x", None)
    assert host._step_output_key({"output_key": "  named  "}, 0) == "named"
    assert host._step_output_key({"output_key": 4}, 2) == "step2"


def test_batch_step_executor_covers_missing_name_and_unwrapped_failure():
    host = _FastHost()
    missing = host._run_batch_steps([{}], False)
    assert missing[0]["result"]["code"] == "INVALID_ARGS"

    host._execute_tool = lambda *_args: (_ for _ in ()).throw(RuntimeError("boom"))
    with pytest.raises(RuntimeError, match="boom"):
        host._run_batch_steps([{"name": "data", "arguments": {}}], False)


def test_handle_batch_payload_serialization_and_non_dict_step_args(monkeypatch):
    host = _FastHost()

    class _NotJson:
        pass

    too_complex = host._handle_batch({"calls": [{"name": "data"}, _NotJson()]})
    assert too_complex["code"] == "INVALID_ARGS"

    monkeypatch.setattr(host, "_try_batch_fast_path", lambda *_args: None)
    monkeypatch.setattr(host, "_batch_calls_use_chaining", lambda _calls: False)
    monkeypatch.setattr(
        host,
        "_run_batch_steps",
        lambda *_args: [
            {
                "index": 0,
                "name": "data",
                "resolved_name": "data",
                "call_args": "not-an-object",
                "result": {"ok": True},
            }
        ],
    )
    result = host._handle_batch({"calls": [{"name": "data"}]})
    assert result["ok"] is True
