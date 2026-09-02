"""Regression tests for bb03 — IDA-side blackboard rebuilt as a thin bridge.

The legacy IDA-side ``blackboard`` module (40-action dispatcher,
``_BackgroundCrawler`` singleton, ``auto_capture_calc`` stub, KG branches,
``export_symbols``/``import_symbols``) was gutted. The module now keeps only
the three in-IDA integration seams:

  * ``BlackboardStore``  — the IDA-side subclass (embedder wiring) that
    calc/gadgets/code_helpers/search/intelligence import via
    ``from .blackboard import BlackboardStore`` (and the guarded flat form).
  * ``related_by_behavior`` — internal action called directly by
    ``intelligence(action='blackboard_search')``; pinned response shape.
  * ``CrawlerProbe`` — a thin crawler-probe adapter the host orchestrator
    imports for in-IDA xref/symbol probes.

Anything else returns ``ACTION_NOT_FOUND`` from the thin ``blackboard`` tool;
the host server is the single authority for the action enum.
"""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

# Imported at module level (rather than inside the fixture) on purpose: the
# conftest evicts-and-restores sys.modules between tests, and numpy's C
# extension cannot be loaded more than once per process — so any module that
# transitively imports numpy (ida_pro_mcp.services -> host.intelligence.core)
# must be imported before the first test's snapshot is taken.
from _isolated_repo_loader import install_common_stub, load_tool_module  # noqa: E402

import ida_pro_mcp.services  # noqa: E402

# Collection-time load pulls numpy in once; each test re-imports the module
# fresh (the conftest purges ida_mcp.tools.* submodules between tests).
load_tool_module("blackboard")
_INTELLIGENCE = load_tool_module("intelligence")


def _fresh_blackboard():
    """Re-import the blackboard module so the test sees the current source."""
    mod = sys.modules.get("ida_pro_mcp.ida_mcp.tools.blackboard")
    if mod is None:
        mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.blackboard")
    return mod


@pytest.fixture
def bb():
    return _fresh_blackboard()


@pytest.fixture
def bb_store(bb, tmp_path):
    store = bb.BlackboardStore(db_path=str(tmp_path / "bb.db"))
    yield store
    store.close()


# ---------------------------------------------------------------------------
# Module surface: the rebuilt thin bridge
# ---------------------------------------------------------------------------

def test_module_surface_keeps_only_the_integration_seams(bb):
    assert hasattr(bb, "BlackboardStore")
    assert hasattr(bb, "blackboard")
    assert hasattr(bb, "CrawlerProbe")
    assert hasattr(bb, "crawler_probe")
    # Legacy machinery is gone.
    assert not hasattr(bb, "_BackgroundCrawler")
    assert not hasattr(bb, "auto_capture_calc")


def test_blackboard_store_is_a_subclass_of_the_host_store(bb):
    from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore as Base

    assert issubclass(bb.BlackboardStore, Base)
    # The embedder wiring seam is still overridden by the IDA-side subclass.
    assert bb.BlackboardStore._get_embedder is not Base._get_embedder


def test_both_import_surfaces_resolve_blackboard_store(bb):
    # Pinned by test_swarm_t11 and settle-owned calc/gadgets/code_helpers/search:
    # `from .blackboard import BlackboardStore` and the guarded flat form both
    # resolve to the same class object.
    pkg = importlib.import_module("ida_pro_mcp.ida_mcp.tools.blackboard")
    assert pkg.BlackboardStore is bb.BlackboardStore


def test_phantom_categories_and_quick_crawler_reference_are_gone_from_docstring(bb):
    doc = (bb.__doc__ or "") + "\n" + (bb.blackboard.__doc__ or "")
    # The phantom auto-capture categories are no longer advertised. Pull every
    # parenthesized token list out of both docstrings and assert none of the
    # phantoms is enumerated as a supported category.
    import re

    enumerated = set()
    for m in re.finditer(r"\(([^)]{1,120})\)", doc):
        for token in m.group(1).split(","):
            t = token.strip().strip(".").strip()
            if t:
                enumerated.add(t)
    for phantom in (
        "cluster", "rename_suggestion", "pointer", "string", "entropy",
        "address", "pointer_chain", "deref", "session_diff",
    ):
        assert phantom not in enumerated, phantom
    # The distinctive phantom names must not appear anywhere in the docs, and
    # the legacy machinery references are gone.
    for token in (
        "cluster", "rename_suggestion", "entropy", "pointer_chain",
        "deref", "session_diff", "auto_capture_calc", "_BackgroundCrawler",
        "agent(action='quick')",
    ):
        assert token not in doc, token


def test_store_response_pipeline_seam_is_preserved(bb_store):
    # The four response-pipeline methods the auto-injected _recall /
    # _already_examined / _stale / _recall_error channel depends on remain on
    # the IDA-side subclass with unchanged contracts.
    for name in ("observe_code", "recall_lines", "examination", "current_anchor"):
        assert callable(getattr(bb_store, name, None))
    assert bb_store.examination("0x401000") is None


# ---------------------------------------------------------------------------
# Thin bridge: related_by_behavior + ACTION_NOT_FOUND
# ---------------------------------------------------------------------------

def test_related_by_behavior_pinned_shape(bb, bb_store):
    bb_store.write(
        title="Network recv handler",
        content="parses packet headers from the socket",
        category="hypothesis",
        addr="0x401000",
        status="open",
    )
    bb_store.write(
        title="CRC table builder",
        content="computes a checksum lookup table",
        category="hypothesis",
        addr="0x402000",
        status="open",
    )

    res = bb.blackboard(
        action="related_by_behavior",
        query="socket recv packet",
        top_k=10,
        threshold=0.0,
        db_path=bb_store.db_path,
    )
    # Pinned shape: {ok, behavior, results, count}, never the host `entries`
    # key, and never a joined string.
    assert res["ok"] is True
    assert res["behavior"] == "socket recv packet"
    assert isinstance(res["results"], list)
    assert res["count"] == len(res["results"])
    assert "entries" not in res
    assert any(
        item["entry_id"] and "recv" in item["title"]
        for item in res["results"]
    )
    for item in res["results"]:
        for key in ("entry_id", "title", "addr", "category", "confidence", "similarity", "tags"):
            assert key in item


def test_related_by_behavior_requires_query(bb, bb_store):
    res = bb.blackboard(action="related_by_behavior", db_path=bb_store.db_path)
    assert res["ok"] is False
    assert res["code"] == "INVALID_ARGS"


def test_removed_actions_return_action_not_found(bb, bb_store):
    # Every legacy dispatcher branch — write/read/list/search/update/delete,
    # the crawler actions, KG actions, export/import, and the dead vestigial
    # actions — is now host-routed; the in-IDA bridge must refuse them.
    for action in (
        "write", "read", "list", "search", "update", "delete", "clear",
        "stats", "merge", "prune", "contradict", "resolve", "next_target",
        "start_crawler", "stop_crawler", "crawler_status", "accept", "reject",
        "add_evidence", "calibrate", "campaign_summary", "mark_examined",
        "frontier", "coverage", "propagate_labels", "quest_board",
        "quest_complete", "semantic_index", "semantic_rebuild",
        "export_symbols", "import_symbols",
        "add_system", "add_struct", "add_gap", "fill_gap",
        "add_state_machine", "add_peripheral", "add_attack_surface",
        "kg_summary", "kg_systems", "kg_gaps", "kg_structs",
        "kg_state_machines", "kg_attack_surface", "kg_peripherals",
    ):
        res = bb.blackboard(action=action, db_path=bb_store.db_path)
        assert res["ok"] is False, action
        assert res["code"] == "ACTION_NOT_FOUND", action
        assert action in res["message"]


# ---------------------------------------------------------------------------
# Crawler-probe adapter
# ---------------------------------------------------------------------------

def test_crawler_probe_rpc_mode_parses_ida_probe_shapes(bb):
    calls = []

    def rpc_fn(tool, payload):
        calls.append((tool, payload))
        if tool == "code" and payload.get("action") == "xrefs_to":
            return {
                "ok": True,
                "addr": payload["addrs"],
                "xrefs": "0x402000  code  sub_402000\n0x403000  data  \n",
                "count": 2,
            }
        if tool == "data":
            return {
                "ok": True,
                "functions": "",
                "items": [
                    {"addr": "0x401000", "name": "main"},
                    {"addr": "0x401100", "name": "sub_401100"},
                ],
                "total": 2,
                "count": 2,
            }
        if payload.get("action") == "smart_decompile":
            return {
                "ok": True,
                "addr": "0x401000",
                "name": "main",
                "behavior_tags": ["network"],
                "callees": [{"addr": "0x402000", "name": "recv"}],
            }
        return {"ok": True}

    probe = bb.CrawlerProbe(rpc_fn=rpc_fn)

    xrefs = probe.xrefs_to("0x401000")
    assert xrefs == [
        {"addr": "0x402000", "kind": "code", "name": "sub_402000"},
        {"addr": "0x403000", "kind": "data", "name": ""},
    ]

    syms = probe.symbols("main")
    assert syms == [
        {"addr": "0x401000", "name": "main"},
        {"addr": "0x401100", "name": "sub_401100"},
    ]

    info = probe.function_probe("0x401000")
    assert info["addr"] == "0x401000"
    assert info["name"] == "main"
    assert info["behavior_tags"] == ["network"]
    assert info["callees"] == [{"addr": "0x402000", "name": "recv"}]

    # Empty/invalid inputs never hit the rpc bridge.
    assert probe.xrefs_to("") == []
    assert probe.xrefs_to(None) == []
    assert probe.symbols("") == []
    # The default module-level instance is a no-rpc CrawlerProbe.
    assert isinstance(bb.crawler_probe, bb.CrawlerProbe)


def test_crawler_probe_degrades_gracefully_without_ida(bb):
    # No rpc_fn and no IDA SDK: every probe returns an empty result set and
    # never raises, so the host crawler can treat a probe as "nothing found".
    probe = bb.CrawlerProbe()
    assert probe.xrefs_to("0x401000") == []
    assert probe.symbols("main") == []
    assert probe.function_probe("0x401000") == {
        "addr": "0x401000", "name": "", "behavior_tags": [], "callees": [],
    }
    assert probe.function_probe("") == {
        "addr": "", "name": "", "behavior_tags": [], "callees": [],
    }


def test_crawler_probe_swallows_rpc_failures(bb):
    def boom(tool, payload):
        raise RuntimeError("probe unavailable")

    probe = bb.CrawlerProbe(rpc_fn=boom)
    assert probe.xrefs_to("0x401000") == []
    assert probe.symbols("main") == []
    assert probe.function_probe("0x401000")["callees"] == []


def test_crawler_probe_parsers_and_direct_ida_mode(monkeypatch, bb):
    assert bb._probe_addr(0) == "0x0"
    assert bb._probe_addr(" 0x0000ABCD ") == "0xabcd"
    assert bb._probe_addr("symbol") == "symbol"
    assert bb._probe_addr("   ") == ""
    assert bb.CrawlerProbe._parse_xref_lines("\n0x10 code fn\n0x20 data other", 1) == [
        {"addr": "0x10", "kind": "code", "name": "fn"}
    ]
    assert bb.CrawlerProbe._parse_xref_lines(None, 4) == []
    assert bb.CrawlerProbe._parse_function_items(
        {"items": [{"addr": "0x20", "name": "fn"}, None, {"ea": 0x30}]}, 2
    ) == [
        {"addr": "0x20", "name": "fn"},
        {"addr": "0x30", "name": "0x30"},
    ]

    ida_mcp = types.ModuleType("ida_mcp")
    ida_mcp.__path__ = []
    compat = types.ModuleType("ida_mcp.compat")

    def get_func_start(ea):
        return {0x1000: 0x1000, 0x1010: 0x1000, 0x2020: 0x2000, 0x3030: 0x3000}.get(ea)

    compat.get_func_start = get_func_start
    ida_mcp.compat = compat
    monkeypatch.setitem(sys.modules, "ida_mcp", ida_mcp)
    monkeypatch.setitem(sys.modules, "ida_mcp.compat", compat)
    monkeypatch.setattr(sys.modules["ida_funcs"], "get_func_name", lambda ea: {0x1000: "main", 0x2000: "callee"}.get(ea, ""), raising=False)
    monkeypatch.setattr(
        sys.modules["idautils"],
        "XrefsTo",
        lambda _ea, _flow: [types.SimpleNamespace(frm=0x1010, iscode=True), types.SimpleNamespace(frm=0x2020, iscode=False)],
        raising=False,
    )
    monkeypatch.setattr(sys.modules["idautils"], "Functions", lambda: [0x1000, 0x2000], raising=False)
    monkeypatch.setattr(sys.modules["idautils"], "FuncItems", lambda _ea: [0x1000], raising=False)
    monkeypatch.setattr(
        sys.modules["idautils"],
        "XrefsFrom",
        lambda _ea, _flow: [types.SimpleNamespace(to=0x2020, iscode=True), types.SimpleNamespace(to=0x3030, iscode=False)],
        raising=False,
    )
    probe = bb.CrawlerProbe()
    assert probe.xrefs_to("0x1000", limit=2)[0]["name"] == "main"
    assert probe.symbols("main") == [{"addr": "0x1000", "name": "main"}]
    assert probe.function_probe("0x1000")["callees"] == [{"addr": "0x2000", "name": "callee"}]


# ---------------------------------------------------------------------------
# Integration: intelligence.blackboard_search -> related_by_behavior
# ---------------------------------------------------------------------------

class _FakeEmbedder:
    backend = "fake"

    def ensure_ready(self):
        return True


def test_intelligence_blackboard_search_routes_through_related_by_behavior(monkeypatch, tmp_path):
    import idaapi

    store = _fresh_blackboard().BlackboardStore(db_path=str(tmp_path / "bb.db"))
    store.write(
        title="Network recv handler",
        content="parses packet headers from the socket",
        category="hypothesis",
        addr="0x401000",
        status="open",
    )
    # The blackboard_search branch lazy-imports the blackboard module at call
    # time; re-resolve it fresh (conftest purges tools.* between tests) and
    # point BlackboardStore at the real store so recall is deterministic.
    # The bridge instantiates with db_path=<maybe-empty>, so the seam accepts
    # and ignores it (same pattern t11 uses for its store stub).
    blk = _fresh_blackboard()
    monkeypatch.setattr(blk, "BlackboardStore", lambda *a, **k: store)

    monkeypatch.setattr(idaapi, "PATH_TYPE_IDB", 1, raising=False)
    monkeypatch.setattr(idaapi, "get_path", lambda _t: "/tmp/fake.idb", raising=False)
    monkeypatch.setattr(ida_pro_mcp.services, "BgeCodeEmbedder", _FakeEmbedder)
    monkeypatch.setattr(ida_pro_mcp.services, "FunctionEmbeddingIndex", lambda *a, **k: None)

    resp = _INTELLIGENCE.intelligence(
        action="blackboard_search",
        query="socket recv packet",
        top_k=10,
        threshold=0.0,
    )

    assert resp["ok"] is True
    assert resp["query"] == "socket recv packet"
    assert resp["backend"] == "fake"
    blackboard = resp["blackboard"]
    # The thin bridge keeps the pinned related_by_behavior shape: a list of
    # results, never a joined string.
    assert blackboard["ok"] is True
    assert isinstance(blackboard["results"], list)
    assert any("recv" in item["title"] for item in blackboard["results"])
    store.close()


# ---------------------------------------------------------------------------
# Opaque raw-blob / RISC-V scenario
# ---------------------------------------------------------------------------

def test_opaque_raw_riscv_blob_round_trips_and_recalls(bb, bb_store):
    # A symbol-poor RISC-V region: raw instruction bytes and assembly with no
    # structured meaning a caller could grep by keyword. The store must
    # round-trip it byte-for-byte and the recall seam must surface it.
    title = "RISC-V raw region @ 0x80010000"
    content = (
        "0x00000013 nop; 0x00000513 addi a0, zero, 0; "
        "lui a5, 0x20000; auipc ra, 0x0; jalr -0x4(ra); "
        "c.li a0, 0; c.slli a5, 0x4; 0x30200073 mret; 0x100073 ecall"
    )
    eid = bb_store.write(
        title=title,
        content=content,
        category="hypothesis",
        addr="0x80010000",
        tags=["riscv", "raw", "opaque"],
        status="open",
    )

    entry = bb_store.read(eid)
    assert entry["title"] == title
    assert entry["content"] == content
    assert entry["addr"] == "0x80010000"
    assert "riscv" in entry["tags"]

    # The code-anchor staleness seam works against the raw blob text.
    anchor = bb_store.observe_code("0x80010000", "disassemble", text=content)
    assert anchor["ok"] is True
    assert anchor["digest"]
    assert bb_store.current_anchor("0x80010000", "disassemble")["digest"] == anchor["digest"]

    # Recall surfaces the finding at the address.
    lines = bb_store.recall_lines(["0x80010000"], limit=4)
    assert any("0x80010000" in line for line in lines)

    # The thin bridge's related_by_behavior finds the opaque blob lexically
    # (no embedding vectors were written, so semantic_search falls back to
    # term overlap on content).
    res = bb.blackboard(
        action="related_by_behavior",
        query="auipc jalr c.slli",
        db_path=bb_store.db_path,
    )
    assert res["ok"] is True
    assert res["count"] >= 1
    assert any(item["entry_id"] == eid for item in res["results"])


# ---------------------------------------------------------------------------
# Lifecycle: proposed -> confirmed -> rejected(contradicted) -> resolved
# ---------------------------------------------------------------------------

def test_lifecycle_proposed_through_conflict_to_resolved(bb_store):
    eid = bb_store.write(
        title="0x8041200 is a custom allocator",
        content="wraps a fixed pool",
        category="hypothesis",
        addr="0x8041200",
        kind="hypothesis",
        status="proposed",
    )
    entry = bb_store.read(eid)
    assert entry["status"] == "proposed"
    assert entry["resolved"] == 0
    assert entry["contradicted"] == 0

    # proposal_accept on the host flips proposed -> confirmed via update().
    assert bb_store.update(eid, status="confirmed")
    assert bb_store.read(eid)["status"] == "confirmed"

    # contradict stores the reason on the rejected entry and sets the derived
    # contradicted flag (reason also lands in conflict-link notes).
    assert bb_store.contradict(eid, "it calls malloc — not a custom allocator")
    after = bb_store.read(eid)
    assert after["status"] == "rejected"
    assert after["contradicted"] == 1
    assert after["rejected_reason"] == "it calls malloc — not a custom allocator"

    # resolve clears the rejection and moves to resolved.
    assert bb_store.mark_resolved(eid)
    final = bb_store.read(eid)
    assert final["status"] == "resolved"
    assert final["resolved"] == 1
    assert final["contradicted"] == 0

    # list/search accept status='proposed' as a filter (design contract: the
    # findings CRUD core accepts the proposed lifecycle state).
    pid = bb_store.write(
        title="another proposed thread",
        category="question",
        addr="0x8041300",
        kind="question",
        status="proposed",
    )
    proposed = bb_store.list(status="proposed")
    assert {e["id"] for e in proposed} == {pid}
    not_proposed = bb_store.list(status="open")
    assert not any(e["id"] == pid for e in not_proposed)
