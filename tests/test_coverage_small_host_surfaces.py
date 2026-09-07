"""Focused boundary tests for small host-side helpers and response paths."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

from ida_pro_mcp.host.analysis.context_density import ContextDensityOptimizer
from ida_pro_mcp.host.intelligence import rerank_profiles
from ida_pro_mcp.host.intelligence.helpers import parse_str_list
from ida_pro_mcp.host.intelligence.sources.urlhaus import UrlhausSource
from ida_pro_mcp.host.intelligence.usage import DriftDetector, UsageIntelligence
from ida_pro_mcp.host.policy import PolicyDecision, PolicyMode, RiskTier, classify_tool_action, evaluate_policy
from ida_pro_mcp.host.response_signals import build_session_resume
from ida_pro_mcp.host.server.audit import AuditLogger
from ida_pro_mcp.host.server.postprocess import apply_post_processing
from ida_pro_mcp.host.server.server_blackboard_trace import ServerBlackboardTraceMixin
from ida_pro_mcp.host.server.server_response_compact import ServerResponseCompactMixin


def test_small_helper_and_profile_fallbacks(monkeypatch):
    assert parse_str_list(123, sep="|") == ["123"]
    assert rerank_profiles.profile_from_rerank_model("unknown.gguf", requested=None).key == "custom-rerank"
    monkeypatch.setattr(rerank_profiles, "read_gguf_metadata", lambda _path: {"general.name": "BGE-Reranker"})
    assert rerank_profiles.profile_from_rerank_model("unknown.gguf").key == "bge-reranker-v2-gemma"


def test_urlhaus_non_json_plain_file_is_ignored(tmp_path):
    source = UrlhausSource()
    plain = tmp_path / "feed.bin"
    plain.write_bytes(b"not an archive")
    source._post_download(str(plain), str(tmp_path / "out"))
    assert source.parse(str(tmp_path)) == []


def test_resume_builder_handles_json_and_mapping_activity():
    class Session:
        phase = "prove"

    class Manager:
        def get_session(self, sid):
            return Session() if sid == "s1" else None

        def _load_skills(self, _sid):
            return {
                "activity_log": [
                    {"action": "decompile", "result": '{"addresses": ["0x401000"]}'},
                    {"action": "semantic_decompile", "result": {"addresses": ["0x402000"]}},
                    {"action": "decompile", "result": "{not-json"},
                ],
                "hypotheses": [
                    {"id": "p", "statement": "pending", "status": "pending"},
                    {"id": "c", "statement": "confirmed", "status": "confirmed"},
                ],
                "skills": {"s": {"name": "search", "description": "x" * 120, "q_value": 0.9}},
            }

        def _load_notebook(self, _sid):
            return "one\ntwo"

    result = build_session_resume(Manager(), "s1")
    assert result["previously_decompiled"] == ["0x401000", "0x402000"]
    assert result["analysis_progress"] == {"total_actions": 3, "phase": "prove"}
    assert result["last_notebook_entry"] == "one\ntwo"
    assert build_session_resume(Manager(), "") is None
    assert build_session_resume(Manager(), "missing") is None


def test_context_density_handles_unusual_types_and_small_paths():
    opt = ContextDensityOptimizer(
        max_xref_items=2,
        max_code_preview=1,
        max_hex_preview=1,
        max_line_length=12,
        compact_threshold=1,
    )
    assert opt.compress_code_blocks(None) is None
    assert opt.compress_hex_dumps(None) is None
    assert opt._addr_to_segment("not-an-address") == "unknown"
    assert opt._addr_to_segment("0x1000") == "0x1000-0xfffff"
    assert opt.compress_xref_lists("xrefs: 0x1000, 0x2000,") == "xrefs: 0x1000, 0x2000,"
    assert opt._compact_recursive(7, 10) == 7
    compacted = opt.compact_response(["a"] * 8, budget_tokens=100)
    assert any("items truncated" in str(item) for item in compacted)
    assert opt._compact_string("a  b\n\n\nvery-long-line") == "a b\n\nvery-long..."
    assert opt.measure_information_density("   ")["density_score"] == 0.0
    assert opt.optimize("")["note"] == "Empty input"


def test_postprocess_structured_and_invalid_inputs():
    assert apply_post_processing(
        {"items": [{"name": "one"}]}, {"grep": "[", "grep_regex": True}
    )["error"] is True
    payload = {"items": [{"name": "one"}, {"name": "two"}], "metadata": {"keep": True}}
    out = apply_post_processing(payload, {"field": "metadata", "head": 1})
    assert out == {**payload, "ok": True}
    out = apply_post_processing({"items": [1, 2], "other": 3}, {"pick": "items,missing", "limit": 1})
    assert out["items"] == [1]
    assert out["_post_processed"] is True


class _ResponseHarness(ServerResponseCompactMixin):
    default_response_mode = "compact"
    default_compact_max_items = 2
    default_compact_max_string = 64
    default_compact_char_budget = 500
    default_table_mode = False
    default_batch_compact = False
    default_error_detail_level = "basic"
    _qol_profiles = {}

    @staticmethod
    def _pop_first(values, keys, default):
        for key in keys:
            if key in values:
                return values.pop(key)
        return default


def test_response_compaction_detail_and_batch_count_paths():
    harness = _ResponseHarness()
    opts = harness._default_response_options()
    opts.update({"max_items": 1, "max_string": 64, "error_details": "basic"})
    details = harness._compact_error_details(
        {"hint": "hidden", "items": [1, 2, 3], "message": "ok"}, opts
    )
    assert details["items"] == [1]
    assert details["items_more"] == 2
    table = harness._maybe_tableify(
        [{"a": 1, "b": 2}, {"a": 3, "b": 4}, {"a": 5, "b": 6}, {"a": 7, "b": 8}],
        {"table_mode": True, "max_items": 2},
    )
    assert table["total"] == 4
    compacted = harness._compact_batch_result(
        {"results": [{"name": "search", "result": {"ok": True}}], "count": 1},
        {"batch_compact": True},
    )
    assert compacted["results"][0]["tool"] == "search"
    assert "count" not in harness._compact_value(
        {"results": [1], "count": 1}, {"dedupe_counts": True, "drop_empty": True}
    )


def test_audit_pruning_and_best_effort_write_errors(tmp_path, monkeypatch, capsys):
    logger = AuditLogger(str(tmp_path), max_mb=1)
    logger._maybe_prune_old()
    logger.log("search", "find", {"query": "x", "path": "/secret"}, {"items": [1]}, 1.234)
    logger.close()
    records = list(tmp_path.rglob("*.jsonl"))
    assert len(records) == 1
    record = json.loads(records[0].read_text(encoding="utf-8"))
    assert "args_preview" in record and "/secret" not in record["args_preview"]

    broken = AuditLogger(str(tmp_path / "broken"))
    monkeypatch.setattr(broken, "_open_for_date", lambda _dt: (_ for _ in ()).throw(OSError("disk full")))
    broken.log("search", "find", {}, {}, 0)
    assert "audit log write failed" in capsys.readouterr().err


def test_usage_thresholds_and_restart_paths(monkeypatch):
    detector = DriftDetector(window=10)
    assert detector.check("unknown") == []
    for i in range(10):
        detector.observe("code", "decompile", "s", float(i), "err" if i < 5 else None, "0x401000")
    signals = {signal["type"] for signal in detector.check("s")}
    assert {"ANALYZE_WITHOUT_RECORD", "REPEATED_ADDR", "HIGH_ERROR_RATE", "LOOP"} <= signals
    assert detector.session_report("s")["avg_latency_ms"] == 4.5
    detector.prune(10**20)
    assert detector.check("s") == []

    usage = UsageIntelligence("unused")
    assert usage.predict_next("code", "decompile") == []
    assert usage.session_report("missing")["total_calls"] == 0
    usage.observe("code", "decompile", "s", 1)
    assert usage.global_report()["active_sessions"] == 1
    usage.evict_session("s")
    assert usage.global_report()["active_sessions"] == 0
    usage._thread = types.SimpleNamespace(is_alive=lambda: True, join=lambda timeout: None)
    usage.start()
    usage._stop.set()
    usage.start()
    usage._thread = None
    usage.start()
    usage.stop()


def test_trace_mixin_boundary_and_derived_pairs():
    class Store:
        def __init__(self):
            self.writes = []
            self.updates = []

        def write(self, **kwargs):
            self.writes.append(kwargs)
            return f"e{len(self.writes)}"

        def update(self, *args, **kwargs):
            self.updates.append((args, kwargs))

        def exists_similar(self, _addr, _category, title):
            return "duplicate" in title

    class Trace(ServerBlackboardTraceMixin):
        def _validate_rename_spec(self, spec):
            return "bad" if spec["renames"][0]["name"] == "bad" else None

        def _orchestration(self):
            return types.SimpleNamespace(enqueue_trace_task=lambda *_a, **_k: "queued")

    trace = Trace()
    entities = trace._extract_trace_entities("0x401000 -> good_name 0x401000 -> good_name lane_x status_x")
    assert entities["addrs"] == ["0x401000"]
    assert entities["addr_name_pairs"] == [{"addr": "0x401000", "name": "good_name"}]
    assert trace._maybe_auto_trace_from_text(Store(), "src", "plain", auto_trace=True) is None
    assert trace._maybe_auto_trace_from_text(Store(), "src", "0x401000", auto_trace=False) is None
    store = Store()
    assert trace._auto_proposals_from_trace(
        store, "task", [{"addr": "0x401000", "name": "good_name"}, {"addr": "0x402000", "name": "bad"}]
    ) == 1
    result = trace._run_trace_task(store, {"id": "task"}, {"entities": {"addrs": [], "symbols": []}})
    assert result["ok"] is True
    assert store.writes[-1]["category"] == "proposal"


def test_policy_unknown_purpose_and_classifier_failure(monkeypatch):
    assert classify_tool_action("no-such-tool", "no-such-action") == RiskTier.UNKNOWN
    assert evaluate_policy("search", "find", purpose="made-up", mode=PolicyMode.ASSIST).decision == PolicyDecision.WARN
    assert evaluate_policy("search", "find", purpose="made-up", mode=PolicyMode.ENFORCE).decision == PolicyDecision.REQUIRE_ACK
    agent_ops = types.ModuleType("ida_pro_mcp.host.agent_operations")
    agent_ops.backend_risk_tier = lambda *_args: (_ for _ in ()).throw(RuntimeError("catalog unavailable"))
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.host.agent_operations", agent_ops)
    assert classify_tool_action("search", "find") == RiskTier.READ
