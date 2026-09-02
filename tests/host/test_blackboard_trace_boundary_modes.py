"""Composed trace-task coverage across no-runtime and runtime-backed modes."""

from __future__ import annotations

import json

from ida_pro_mcp.host.server.server_blackboard_trace import ServerBlackboardTraceMixin


class _Store:
    def __init__(self):
        self.writes = []
        self.updates = []
        self.duplicates = set()

    def write(self, **kwargs):
        self.writes.append(kwargs)
        return f"E{len(self.writes)}"

    def update(self, entry_id, **kwargs):
        self.updates.append((entry_id, kwargs))

    def exists_similar(self, addr, category, title):
        return (addr, category, title) in self.duplicates


class _TraceServer(ServerBlackboardTraceMixin):
    def __init__(self, results=None):
        self.results = results or {}

    def _execute_tool(self, tool, args):
        result = self.results.get((tool, args.get("action")))
        if isinstance(result, BaseException):
            raise result
        return result


def test_trace_entity_extraction_filters_reserved_words_and_deduplicates():
    server = _TraceServer()
    entities = server._extract_trace_entities(
        "0x401000 -> main 0x401000 -> main 0x402000: worker "
        "lane_alpha status_code normal_symbol 0x403000"
    )
    assert entities["addrs"] == ["0x401000", "0x402000", "0x403000"]
    assert "lane_alpha" not in entities["symbols"]
    assert "status_code" not in entities["symbols"]
    assert "normal_symbol" in entities["symbols"]
    assert entities["addr_name_pairs"] == [
        {"addr": "0x401000", "name": "main"},
        {"addr": "0x402000", "name": "worker"},
    ]


def test_trace_task_creation_status_and_auto_enqueue_modes(monkeypatch):
    server = _TraceServer()
    store = _Store()
    task_id = server._create_trace_task(store, "source-1", "at 0x401000", 3, 4)
    assert task_id == "E1"
    payload = json.loads(store.writes[0]["content"])
    assert payload["status"] == "pending" and payload["depth"] == 3
    assert store.writes[0]["addr"] == "0x401000"

    entry = {"id": task_id, "tags": ["trace_task", "status:old", "keep"]}
    server._set_task_status(store, entry, "running", {"progress": 1})
    assert store.updates[0][1]["tags"] == ["trace_task", "keep", "status:running"]
    assert json.loads(store.updates[0][1]["content"])["status"] == "running"

    class Orchestration:
        def enqueue_trace_task(self, _store, **kwargs):
            return kwargs["source_entry_id"] + "-queued"

    def orchestration():
        return Orchestration()

    monkeypatch.setattr(server, "_orchestration", orchestration, raising=False)
    assert server._maybe_auto_trace_from_text(store, "source-1", "0x401000", auto_trace=False) is None
    assert server._maybe_auto_trace_from_text(store, "source-1", "plain text") is None
    assert server._maybe_auto_trace_from_text(store, "source-1", "0x401000") == "source-1-queued"
    monkeypatch.setattr(server, "_orchestration", lambda: (_ for _ in ()).throw(RuntimeError("queue down")), raising=False)
    assert server._maybe_auto_trace_from_text(store, "source-1", "0x401000") is None


def test_auto_proposals_skip_invalid_and_existing_entries():
    server = _TraceServer()
    store = _Store()
    monkeypatch_pairs = [
        {"addr": "0x401000", "name": "good_name"},
        {"addr": "0x402000", "name": "duplicate"},
        {"addr": "", "name": "bad"},
    ]
    server._validate_rename_spec = lambda spec: {"error": True} if not spec["renames"][0]["addr"] else None
    store.duplicates.add(("0x402000", "proposal", "rename proposal from trace E0: 0x402000 -> duplicate"))
    assert server._auto_proposals_from_trace(store, "E0", monkeypatch_pairs) == 1
    assert store.writes[0]["category"] == "proposal"


def test_trace_execution_records_evidence_errors_and_no_runtime_completion():
    store = _Store()
    server = _TraceServer({
        ("graph", "xref_graph"): {"ok": True, "addr": "0x401000", "name": "main"},
        ("search", "find"): {"error": True, "code": "NOT_FOUND"},
    })
    server._validate_rename_spec = lambda _spec: None
    result = server._run_trace_task(
        store,
        {"id": "T1"},
        {"entities": {"addrs": ["0x401000"], "symbols": ["worker"], "addr_name_pairs": []}, "depth": 2, "limit": 2},
    )
    assert result["ok"] is True and result["evidence_count"] == 1
    assert any(row["category"] == "trace_evidence" for row in store.writes)

    failing = _TraceServer({("graph", "xref_graph"): RuntimeError("IDA unavailable"), ("search", "find"): RuntimeError("search down")})
    failing._validate_rename_spec = lambda _spec: None
    result = failing._run_trace_task(
        store,
        {"id": "T2"},
        {"entities": {"addrs": ["0x401000"], "symbols": ["worker"], "addr_name_pairs": [{"addr": "0x401000", "name": "main"}]}, "depth": 2, "limit": 2},
    )
    assert result["ok"] is False and result["evidence_count"] == 0

    class NoRuntime(ServerBlackboardTraceMixin):
        pass

    no_runtime = NoRuntime()
    no_runtime._validate_rename_spec = lambda _spec: None
    result = no_runtime._run_trace_task(store, {"id": "T3"}, {"entities": {}, "depth": 2, "limit": 2})
    assert result["ok"] is True and result["evidence_count"] == 0
