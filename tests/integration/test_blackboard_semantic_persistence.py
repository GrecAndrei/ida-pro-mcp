from __future__ import annotations

import tempfile

from tests._isolated_repo_loader import load_tool_module

_bb = load_tool_module("blackboard")
BlackboardStore = _bb.BlackboardStore


class _FakeEmbedder:
    dim = 4
    backend = "unavailable"

    def embed(self, text: str):
        n = float(max(1, len(text.strip())))
        return [1.0 / n, 2.0 / n, 3.0 / n, 4.0 / n]

    def embed_vector(self, text: str):
        return self.embed(text)


def test_blackboard_capsule_sync_on_write(monkeypatch, tmp_path):
    monkeypatch.setattr(_bb, "_get_embedder", _FakeEmbedder)
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
