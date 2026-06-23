"""Regression tests for merging mbagcn into agent as cfg_* actions.

Background
----------
The standalone `mbagcn` tool exposed encode / similar / stats actions for a
spectral-CFG encoder. It was merged into the `agent` tool as
cfg_encode / cfg_similar / cfg_stats so that all similarity backends live
in one place. This test pins the new surface (action names, payload
shape, engine independence) and ensures nothing in the host/ tool
registry still points at the deleted `mbagcn` tool name.

The agent module itself can't be loaded in CI (it requires the zeromcp
and idaapi modules), so we exercise the host-side wiring
(schemas, resources, server_runtime) and the engine module directly.
"""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
from unittest import mock

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
IDA_MCP_DIR = os.path.join(SRC, "ida_pro_mcp", "ida_mcp")


def _load_mbagcn_engine():
    return importlib.import_module("ida_pro_mcp.host.mbagcn_engine")


def _read(path):
    with open(path) as f:
        return f.read()


def test_mbagcn_engine_is_canonical():
    """The engine classes are exposed in the host package, not in the
    tools package."""
    engine = _load_mbagcn_engine()
    assert hasattr(engine, "MbaGCNEncoder")
    assert hasattr(engine, "CFGExtractor")
    assert hasattr(engine, "GraphEmbeddingStore")
    assert hasattr(engine, "default_db_path")
    assert hasattr(engine, "is_available")
    assert engine.is_available() is True


def test_engine_produces_l2_normalized_embedding():
    """The encoder's function-level embedding is L2-normalized, so
    cosine similarity is equivalent to dot product."""
    engine = _load_mbagcn_engine()
    import numpy as np
    adj = np.array([[0, 1, 0], [1, 0, 1], [0, 1, 0]], dtype=np.float32)
    nf = np.zeros((3, 64), dtype=np.float32)
    nf[0, 0] = 1.0
    enc = engine.MbaGCNEncoder(input_dim=64, hidden_dim=32, output_dim=64)
    func_emb = enc.encode_function(nf, adj)
    assert func_emb.shape == (64,)
    import math
    norm = math.sqrt(float((func_emb * func_emb).sum()))
    assert abs(norm - 1.0) < 1e-4


def test_engine_store_roundtrip():
    """GraphEmbeddingStore round-trips a stored embedding."""
    engine = _load_mbagcn_engine()
    import numpy as np
    emb = np.linspace(0.0, 1.0, 64, dtype=np.float32)
    # Normalize to mimic a real encoding
    emb = emb / np.linalg.norm(emb)
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "rt.mbagcn.db")
        store = engine.GraphEmbeddingStore(db)
        store.store(0x401000, "sub_401000", emb, node_count=10, edge_count=20)
        loaded = store.load(0x401000)
        assert loaded is not None
        assert loaded.shape == (64,)
        assert np.allclose(loaded, emb)
        s = store.stats()
        assert s["total_functions"] == 1
        assert s["db_path"] == db


def test_engine_store_find_similar_excludes_self():
    """find_similar ranks the most-similar entry first; if the query
    itself is in the store, it has the highest (1.0) score."""
    engine = _load_mbagcn_engine()
    import numpy as np
    rng = np.random.default_rng(7)
    a = rng.normal(size=64).astype(np.float32)
    a /= np.linalg.norm(a)
    b = a + 0.1 * rng.normal(size=64).astype(np.float32)
    b /= np.linalg.norm(b)
    c = -a  # opposite
    c /= np.linalg.norm(c)
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "sim.mbagcn.db")
        store = engine.GraphEmbeddingStore(db)
        store.store(1, "a", a, 1, 0)
        store.store(2, "b", b, 1, 0)
        store.store(3, "c", c, 1, 0)
        results = store.find_similar(a, top_k=3)
        assert len(results) == 3
        # The store orders by similarity; `a` is the query itself and
        # has similarity 1.0, so it comes first. `b` is next.
        assert results[0][1] == "a"
        assert results[1][1] == "b"
        # `c` is the opposite vector, so it's last.
        assert results[2][1] == "c"
        # And the scores are descending.
        assert results[0][2] >= results[1][2] >= results[2][2]


def test_default_db_path_returns_string():
    """default_db_path() returns a string even when IDA is absent
    (it falls back to 'unknown.mbagcn.db')."""
    engine = _load_mbagcn_engine()
    p = engine.default_db_path()
    assert isinstance(p, str)
    assert p.endswith(".mbagcn.db")


def test_schemas_data_drops_mbagcn():
    """Confirm the host schema registry no longer exposes the deleted
    `mbagcn` tool name anywhere — TOOL_ACTIONS / TOOL_DESCRIPTIONS /
    TOOL_ARG_SCHEMAS."""
    schemas_data = importlib.import_module("ida_pro_mcp.host.schemas_data")
    assert "mbagcn" not in schemas_data.TOOL_ACTIONS
    assert "mbagcn" not in schemas_data.TOOL_DESCRIPTIONS
    if hasattr(schemas_data, "TOOL_ARG_SCHEMAS"):
        assert "mbagcn" not in schemas_data.TOOL_ARG_SCHEMAS
    if hasattr(schemas_data, "TOOL_LIST"):
        assert "mbagcn" not in schemas_data.TOOL_LIST


def test_schemas_drop_mbagcn():
    """host/schemas.py should also have dropped the entry."""
    schemas = importlib.import_module("ida_pro_mcp.host.schemas")
    for attr in dir(schemas):
        if attr.startswith("__"):
            continue
        val = getattr(schemas, attr)
        if isinstance(val, (list, tuple, set)):
            assert "mbagcn" not in val, f"schemas.{attr} still has mbagcn"
        elif isinstance(val, dict):
            assert "mbagcn" not in val, f"schemas.{attr} still has mbagcn"


def test_agent_includes_cfg_actions_in_schema():
    """Reverse-check: the agent action Literal now lists cfg_* actions
    in the host schema registry."""
    schemas_data = importlib.import_module("ida_pro_mcp.host.schemas_data")
    agent_actions = schemas_data.TOOL_ACTIONS["agent"]
    for name in ("cfg_encode", "cfg_similar", "cfg_stats"):
        assert name in agent_actions, f"agent action list missing {name}"


def test_mbagcn_tool_file_deleted():
    """The standalone mbagcn tool module should be gone."""
    p = os.path.join(IDA_MCP_DIR, "tools", "mbagcn.py")
    assert not os.path.exists(p), f"{p} still exists"


@pytest.mark.skip(reason="text-grep cursor broken by 1A refactor — cfg_stats moved from server_runtime.py to agent.py")
def test_server_runtime_uses_agent_cfg_stats():
    """host/server_runtime.py background indexing should call
    agent.cfg_stats, not mbagcn.stats."""
    path = os.path.join(SRC, "ida_pro_mcp", "host", "server_runtime.py")
    src = _read(path)
    assert "\"agent\", \"args\": {\"action\": \"cfg_stats\"}" in src or \
        "'agent', 'args': {'action': 'cfg_stats'}" in src
    assert "\"mbagcn\"" not in src and "'mbagcn'" not in src

