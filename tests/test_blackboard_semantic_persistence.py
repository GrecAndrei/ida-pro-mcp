from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import types


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _load_bb():
    path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "src",
        "ida_pro_mcp",
        "ida_mcp",
        "tools",
        "blackboard.py",
    )
    spec = importlib.util.spec_from_file_location("_bb_sem", path)
    mod = importlib.util.module_from_spec(spec)
    stub_names = [
        "idaapi",
        "idc",
        "idautils",
        "ida_funcs",
        "ida_bytes",
        "ida_segment",
        "ida_name",
        "ida_typeinf",
        "ida_nalt",
        "ida_hexrays",
        "ida_frame",
        "ida_struct",
        "ida_lines",
    ]
    saved = {m: sys.modules.get(m) for m in stub_names}
    for m in stub_names:
        if m not in sys.modules:
            sys.modules[m] = types.ModuleType(m)
    try:
        spec.loader.exec_module(mod)
    finally:
        for m, orig in saved.items():
            if orig is None:
                sys.modules.pop(m, None)
            else:
                sys.modules[m] = orig
    return mod


_bb = _load_bb()
BlackboardStore = _bb.BlackboardStore


class _FakeEmbedder:
    dim = 4
    backend = "tfidf-fallback"

    def embed(self, text: str):
        n = float(max(1, len(text.strip())))
        return [1.0 / n, 2.0 / n, 3.0 / n, 4.0 / n]


def test_semantic_rebuild_indexes_missing_vectors(monkeypatch):
    monkeypatch.setattr(_bb, "_get_embedder", lambda: _FakeEmbedder())
    db = tempfile.mktemp(suffix=".bb.db")
    s = BlackboardStore(db_path=db)
    s.write("HTTP parser", "recv parse headers", embed=False)
    s.write("Crypto block", "aes round key schedule", embed=False)
    before = s.semantic_index()
    assert before["missing_vectors"] >= 2
    out = s.semantic_rebuild(force=False, limit=100)
    assert out["ok"] is True
    assert out["rebuilt"] >= 2
    after = s.semantic_index()
    assert after["embedded"] >= 2
    assert after["missing_vectors"] == 0


def test_blackboard_related_by_behavior_action(monkeypatch):
    monkeypatch.setattr(_bb, "_get_embedder", lambda: _FakeEmbedder())
    db = tempfile.mktemp(suffix=".bb.db")
    _bb.blackboard(action="write", title="HTTP parse", content="recv parse http", db_path=db)
    _bb.blackboard(action="write", title="File copy", content="open read write file", db_path=db)
    res = _bb.blackboard(action="related_by_behavior", query="http recv", db_path=db, threshold=0.0, top_k=5)
    assert res["ok"] is True
    assert res["count"] >= 1
    assert any("HTTP" in str(r.get("title") or "") for r in res["results"])


def test_blackboard_capsule_sync_on_write(monkeypatch, tmp_path):
    monkeypatch.setattr(_bb, "_get_embedder", lambda: _FakeEmbedder())
    cap = tmp_path / "project.sideband"
    monkeypatch.setenv("IDA_MCP_CAPSULE", str(cap))
    db = tempfile.mktemp(suffix=".bb.db")
    s = BlackboardStore(db_path=db)
    s.write("Network finding", "recv socket parser", category="finding", embed=True)

    from ida_pro_mcp.capsule import CapsuleStore

    with CapsuleStore.open(cap) as c:
        sem = c.semantic_summary()
        assert sem["semantic_indexes"] >= 1
        assert sem["semantic_items"] >= 1
