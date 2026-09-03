"""Deep offline coverage for the legacy blackboard bridge and crawler probe."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_tool_module  # noqa: E402

blackboard_module = load_tool_module("blackboard")


class _Store:
    def __init__(self):
        self.calls = []

    def semantic_search(self, **kwargs):
        self.calls.append(kwargs)
        return [
            {
                "id": "one",
                "title": "Network handler",
                "addr": "0x10",
                "category": "hypothesis",
                "confidence": 0.9,
                "similarity": 0.8,
                "tags": '["network", "socket"]',
            },
            {"id": "two", "tags": "not-json"},
            {"id": "three", "tags": ["plain"]},
        ]


def test_related_by_behavior_normalizes_numeric_inputs_and_tag_shapes():
    store = _Store()
    result = blackboard_module._related_by_behavior(
        store,
        query=" recv ",
        top_k="bad",
        threshold="bad",
        category="hypothesis",
        include_resolved=True,
        include_contradicted=True,
    )
    assert result["ok"] is True
    assert result["count"] == 3
    assert result["results"][0]["tags"] == ["network", "socket"]
    assert result["results"][1]["tags"] == []
    assert result["results"][2]["tags"] == ["plain"]
    assert store.calls == [
        {
            "query": " recv ",
            "top_k": 10,
            "threshold": 0.4,
            "category": "hypothesis",
            "include_resolved": True,
            "include_contradicted": True,
        }
    ]


def test_related_by_behavior_clamps_negative_threshold_and_top_k():
    store = _Store()
    result = blackboard_module._related_by_behavior(
        store, query="x", top_k=-2, threshold=-2
    )
    assert result["ok"] is True
    assert store.calls[0]["top_k"] == 1
    assert store.calls[0]["threshold"] == 0.0


def test_blackboard_action_admission_and_store_wiring(monkeypatch):
    store = _Store()
    monkeypatch.setattr(blackboard_module, "BlackboardStore", lambda **_kwargs: store)
    empty = blackboard_module.blackboard(action="related_by_behavior", query=" ")
    assert empty["code"] == "INVALID_ARGS"

    result = blackboard_module.blackboard(
        action="related_by_behavior",
        db_path="/tmp/blackboard-test.db",
        query="recv",
        top_k=2,
    )
    assert result["count"] == 3
    assert store.calls[0]["top_k"] == 2

    unknown = blackboard_module.blackboard(action="does_not_exist")
    assert unknown["code"] == "ACTION_NOT_FOUND"


def test_probe_address_and_rpc_helpers_are_total():
    assert blackboard_module._probe_addr(None) == ""
    assert blackboard_module._probe_addr(16) == "0x10"
    assert blackboard_module._probe_addr(" 0x000010 ") == "0x10"
    assert blackboard_module._probe_addr("  ") == ""
    assert blackboard_module._probe_addr("Function") == "function"

    assert blackboard_module._rpc_probe(lambda *_args: {"ok": True}, "tool", {}) == {
        "ok": True
    }
    assert blackboard_module._rpc_probe(lambda *_args: ["bad"], "tool", {}) is None
    assert (
        blackboard_module._rpc_probe(
            lambda *_args: (_ for _ in ()).throw(RuntimeError("closed")),
            "tool",
            {},
        )
        is None
    )


def test_rpc_probe_mode_parses_xrefs_symbols_and_function_details():
    requests = []

    def rpc(tool, payload):
        requests.append((tool, payload))
        if payload["action"] == "xrefs_to":
            return {"xrefs": "\n0x000010 code caller\n0x20 data\n0x30 code late"}
        if payload["action"] == "functions":
            return {
                "items": [
                    None,
                    {"ea": 0x40},
                    {"addr": "0x50", "name": "worker"},
                ]
            }
        return {
            "addr": "0x000060",
            "name": "entry",
            "behavior_tags": ["network"],
            "callees": [
                None,
                {"addr": "0x000070"},
                {"ea": 0x80, "name": "callee"},
                {"addr": ""},
            ],
        }

    probe = blackboard_module.CrawlerProbe(rpc)
    xrefs = probe.xrefs_to("0x10", limit=2)
    assert xrefs == [
        {"addr": "0x10", "kind": "code", "name": "caller"},
        {"addr": "0x20", "kind": "data", "name": ""},
    ]
    assert probe.symbols("work", limit=2) == [
        {"addr": "0x40", "name": "0x40"},
        {"addr": "0x50", "name": "worker"},
    ]
    function = probe.function_probe("0x60")
    assert function == {
        "addr": "0x60",
        "name": "entry",
        "behavior_tags": ["network"],
        "callees": [
            {"addr": "0x70", "name": "0x70"},
            {"addr": "0x80", "name": "callee"},
        ],
    }
    assert requests[0][1]["max_items"] == 2
    assert requests[1][1]["named_only"] is True


def test_rpc_probe_empty_and_malformed_responses_fall_back_to_empty():
    probe = blackboard_module.CrawlerProbe(lambda *_args: {"xrefs": None})
    assert probe.xrefs_to("", limit=2) == []
    assert probe.xrefs_to("0x10") == []

    probe = blackboard_module.CrawlerProbe(lambda *_args: {"items": "bad"})
    assert probe.symbols("name") == []
    assert probe.symbols("") == []

    probe = blackboard_module.CrawlerProbe(lambda *_args: None)
    empty = probe.function_probe("0x10")
    assert empty == {"addr": "0x10", "name": "", "behavior_tags": [], "callees": []}
    assert probe.function_probe(None)["addr"] == ""

    failing = blackboard_module.CrawlerProbe(
        lambda *_args: (_ for _ in ()).throw(RuntimeError("rpc"))
    )
    assert failing.xrefs_to("0x10") == []
    assert failing.symbols("name") == []
    assert failing.function_probe("0x10")["callees"] == []


def test_parser_helpers_cover_limits_invalid_items_and_empty_fields():
    probe = blackboard_module.CrawlerProbe()
    assert probe._parse_xref_lines("not-an-address", 4) == [
        {"addr": "not-an-address", "kind": "", "name": ""}
    ]
    assert probe._parse_xref_lines("\n0x10\n0x20 code", 1) == [
        {"addr": "0x10", "kind": "", "name": ""}
    ]
    assert probe._parse_function_items({"items": None}, 3) == []
    assert probe._parse_function_items({"items": [{"name": "missing"}]}, 3) == []
    assert probe._parse_function_items(
        {"items": [{"addr": "0x10"}, {"addr": "0x20"}]}, 1
    ) == [{"addr": "0x10", "name": "0x10"}]


def test_direct_ida_helpers_are_safe_when_sdk_is_unavailable():
    probe = blackboard_module.CrawlerProbe()
    assert probe.xrefs_to("0x10") == []
    assert probe.symbols("main") == []
    assert probe.function_probe("0x10")["addr"] == "0x10"


def test_direct_ida_helpers_cover_limits_deduplication_and_failures(monkeypatch):
    ida_mcp = types.ModuleType("ida_mcp")
    ida_mcp.__path__ = []
    compat = types.ModuleType("ida_mcp.compat")
    starts = {0x1000: 0x1000, 0x2000: 0x2000, 0x3000: 0x3000}
    def get_func_start(ea):
        return starts.get(ea)

    compat.get_func_start = get_func_start
    ida_mcp.compat = compat
    monkeypatch.setitem(sys.modules, "ida_mcp", ida_mcp)
    monkeypatch.setitem(sys.modules, "ida_mcp.compat", compat)

    ida_funcs = sys.modules["ida_funcs"]
    idautils = sys.modules["idautils"]
    monkeypatch.setattr(
        ida_funcs,
        "get_func_name",
        lambda ea: {0x1000: "entry", 0x2000: "callee"}.get(ea, ""),
        raising=False,
    )
    monkeypatch.setattr(
        idautils,
        "XrefsTo",
        lambda _ea, _flow: [
            types.SimpleNamespace(frm=0x1010, iscode=True),
            types.SimpleNamespace(frm=0x2020, iscode=False),
            types.SimpleNamespace(frm=0x3030, iscode=True),
        ],
        raising=False,
    )
    assert blackboard_module.CrawlerProbe().xrefs_to("0x1000", limit=2) == [
        {"addr": "0x1010", "kind": "code", "name": ""},
        {"addr": "0x2020", "kind": "data", "name": ""},
    ]

    monkeypatch.setattr(idautils, "Functions", lambda: [0x1000, 0x2000], raising=False)
    assert blackboard_module.CrawlerProbe().symbols("entry", limit=1) == [
        {"addr": "0x1000", "name": "entry"}
    ]

    monkeypatch.setattr(idautils, "FuncItems", lambda _ea: [0x1000], raising=False)
    monkeypatch.setattr(
        idautils,
        "XrefsFrom",
        lambda _ea, _flow: [
            types.SimpleNamespace(to=0x1000, iscode=True),
            types.SimpleNamespace(to=0x2000, iscode=True),
            types.SimpleNamespace(to=0x2000, iscode=True),
            types.SimpleNamespace(to=0x3000, iscode=False),
            types.SimpleNamespace(to=0x9999, iscode=True),
        ],
        raising=False,
    )
    assert blackboard_module.CrawlerProbe().function_probe("0x1000")["callees"] == [
        {"addr": "0x2000", "name": "callee"}
    ]

    monkeypatch.setattr(
        idautils,
        "XrefsTo",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("xref failure")),
        raising=False,
    )
    monkeypatch.setattr(
        idautils,
        "Functions",
        lambda: (_ for _ in ()).throw(RuntimeError("symbol failure")),
        raising=False,
    )
    assert blackboard_module.CrawlerProbe().xrefs_to("0x1000") == []
    assert blackboard_module.CrawlerProbe().symbols("entry") == []
    monkeypatch.setattr(
        compat,
        "get_func_start",
        lambda _ea: (_ for _ in ()).throw(RuntimeError("function failure")),
    )
    assert blackboard_module.CrawlerProbe().function_probe("0x1000")["callees"] == []


def test_standalone_import_supplies_host_fallback_seams(monkeypatch):
    services = types.ModuleType("ida_pro_mcp.services")

    class BaseStore:
        pass

    services.BlackboardStore = BaseStore
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)
    spec = importlib.util.spec_from_file_location(
        "_standalone_blackboard_coverage",
        Path(__file__).resolve().parents[2]
        / "src/ida_pro_mcp/ida_mcp/tools/blackboard.py",
    )
    assert spec is not None and spec.loader is not None
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)

    def marker(value):
        return value

    assert standalone.tool(marker) is marker
    assert standalone.idaread(marker) is marker
    assert standalone.idawrite(marker) is marker
    assert standalone.make_error("CODE", "message", detail=1) == {
        "ok": False,
        "code": "CODE",
        "message": "message",
        "detail": 1,
    }


def test_embedder_fallback_is_explicit_when_optional_backends_are_missing(monkeypatch):
    services = sys.modules["ida_pro_mcp.services"]
    monkeypatch.delattr(services, "BgeCodeEmbedder", raising=False)
    assert blackboard_module._get_embedder() is None


def test_embedder_fallback_can_use_host_backend(monkeypatch):
    services = sys.modules["ida_pro_mcp.services"]
    monkeypatch.delattr(services, "BgeCodeEmbedder", raising=False)
    host = types.ModuleType("host")
    host.__path__ = []
    intelligence = types.ModuleType("host.intelligence")
    core = types.ModuleType("host.intelligence.core")

    class FallbackEmbedder:
        pass

    core.BgeCodeEmbedder = FallbackEmbedder
    host.intelligence = intelligence
    intelligence.core = core
    monkeypatch.setitem(sys.modules, "host", host)
    monkeypatch.setitem(sys.modules, "host.intelligence", intelligence)
    monkeypatch.setitem(sys.modules, "host.intelligence.core", core)
    assert isinstance(blackboard_module._get_embedder(), FallbackEmbedder)


def test_standalone_import_can_use_host_store_fallback(monkeypatch):
    package = types.ModuleType("ida_pro_mcp")
    package.__path__ = []
    host = types.ModuleType("host")
    host.__path__ = []
    stores = types.ModuleType("host.blackboard_store")

    class HostStore:
        pass

    stores.BlackboardStore = HostStore
    host.blackboard_store = stores
    monkeypatch.setitem(sys.modules, "ida_pro_mcp", package)
    monkeypatch.delitem(sys.modules, "ida_pro_mcp.services", raising=False)
    monkeypatch.setitem(sys.modules, "host", host)
    monkeypatch.setitem(sys.modules, "host.blackboard_store", stores)
    spec = importlib.util.spec_from_file_location(
        "_standalone_blackboard_host_store",
        Path(__file__).resolve().parents[2]
        / "src/ida_pro_mcp/ida_mcp/tools/blackboard.py",
    )
    assert spec is not None and spec.loader is not None
    standalone = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(standalone)
    assert issubclass(standalone.BlackboardStore, HostStore)


def test_standalone_import_preserves_missing_store_error(monkeypatch):
    package = types.ModuleType("ida_pro_mcp")
    package.__path__ = []
    monkeypatch.setitem(sys.modules, "ida_pro_mcp", package)
    monkeypatch.delitem(sys.modules, "ida_pro_mcp.services", raising=False)
    monkeypatch.delitem(sys.modules, "host", raising=False)
    monkeypatch.delitem(sys.modules, "host.blackboard_store", raising=False)
    spec = importlib.util.spec_from_file_location(
        "_standalone_blackboard_missing_store",
        Path(__file__).resolve().parents[2]
        / "src/ida_pro_mcp/ida_mcp/tools/blackboard.py",
    )
    assert spec is not None and spec.loader is not None
    standalone = importlib.util.module_from_spec(spec)
    with pytest.raises(ImportError):
        spec.loader.exec_module(standalone)
