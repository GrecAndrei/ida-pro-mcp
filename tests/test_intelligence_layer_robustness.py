import sys
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex, SemanticObjectIndex
from ida_pro_mcp.host.config import CACHE_DIR
from ida_pro_mcp.host.intelligence.structural_index import get_db_path, ensure_tables


class FakeEmbedder:
    def __init__(self):
        self.backend = "fake"
        self.dim = 1536

    def embed(self, text):
        return [0.1] * self.dim

    def status(self, probe=False):
        return {"model_path": "", "server_bin": ""}


def test_function_embedding_index_fallback_on_read_only():
    embedder = FakeEmbedder()
    # /usr/bin/nonexistent_path is usually non-writable for users on Linux
    unwritable_path = "/usr/bin/nonexistent_path_mcp/test_emb.db"
    
    # Initialize index — should fall back to CACHE_DIR
    idx = FunctionEmbeddingIndex(unwritable_path, embedder)
    
    assert "fallback_indexes" in idx._db_path
    assert idx._db_path.endswith(".embeddings.db")
    
    # Try indexing
    idx.index("0x1000", "test_func", "void main() { return; }")
    assert idx.size == 1
    assert "0x1000" in idx._cache


def test_semantic_object_index_fallback_on_read_only():
    embedder = FakeEmbedder()
    unwritable_path = "/usr/bin/nonexistent_path_mcp/test_sem.db"
    
    # Initialize index — should fall back to CACHE_DIR
    idx = SemanticObjectIndex(unwritable_path, embedder)
    
    assert "fallback_indexes" in idx._db_path
    assert idx._db_path.endswith(".semantic.db")


def test_structural_index_get_db_path_fallback_on_read_only():
    unwritable_path = "/usr/bin/nonexistent_path_mcp/test_binary"
    
    db_path = get_db_path(unwritable_path)
    
    assert "fallback_indexes" in db_path
    assert db_path.endswith(".schemaboot.db")


def test_name_synchronization_on_pseudo_hash_match(tmp_path):
    embedder = FakeEmbedder()
    db_file = str(tmp_path / "test_sync.db")
    
    idx = FunctionEmbeddingIndex(db_file, embedder)
    
    # Index func_A
    idx.index("0x2000", "func_A", "void target() { int x = 42; }")
    
    # Retrieve name
    with idx._conn() as conn:
        row = conn.execute("SELECT name FROM func_embeddings WHERE ea='0x2000'").fetchone()
        assert row[0] == "func_A"
        
    # Re-index same address and pseudocode, but with new name: func_B
    idx.index("0x2000", "func_B", "void target() { int x = 42; }")
    
    # Name should be updated to func_B
    with idx._conn() as conn:
        row = conn.execute("SELECT name FROM func_embeddings WHERE ea='0x2000'").fetchone()
        assert row[0] == "func_B"


def test_context_assembler_fallback_resolution():
    from ida_pro_mcp.host.intelligence.context import ContextAssembler
    
    assembler = ContextAssembler()
    unwritable_path = "/usr/bin/nonexistent_path_mcp/test_binary"
    
    # Resolving schemaboot DB fallback path
    resolved_db = get_db_path(unwritable_path)
    
    # Populate the fallback database
    import sqlite3
    conn = sqlite3.connect(resolved_db)
    ensure_tables(conn)
    conn.execute(
        "INSERT OR REPLACE INTO function_attrs(ea, name, size, entropy, bb_count) VALUES(0x3000, 'func_fallback', 100, 4.5, 5)"
    )
    conn.commit()
    conn.close()
    
    try:
        # Check if _query_schemaboot can read from fallback database
        res = assembler._query_schemaboot(unwritable_path, "0x3000")
        assert res is not None
        assert res["name"] == "func_fallback"
        
        # Check if _enrich_address_list can read from fallback database
        enriched = assembler._enrich_address_list(["0x3000"], unwritable_path)
        assert len(enriched) == 1
        assert enriched[0]["name"] == "func_fallback"
        
        # Check if suggest_next_targets can read from fallback database
        targets = assembler.suggest_next_targets(unwritable_path)
        assert len(targets) == 1
        assert targets[0]["name"] == "func_fallback"
    finally:
        if os.path.exists(resolved_db):
            os.remove(resolved_db)


def test_search_advanced_fallback_resolution():
    import sys
    import importlib.util
    from unittest.mock import MagicMock

    class MockIDAFinder:
        def find_spec(self, fullname, path, target=None):
            if (fullname.startswith("ida") and not fullname.startswith("ida_pro_mcp")) or fullname == "idc":
                return importlib.util.spec_from_loader(fullname, self)
            return None
        def create_module(self, spec):
            mock = MagicMock()
            if spec.name == "idaapi":
                mock.get_kernel_version.return_value = "9.3"
            return mock
        def exec_module(self, module):
            pass

    finder = MockIDAFinder()
    sys.meta_path.insert(0, finder)
    
    try:
        from ida_pro_mcp.ida_mcp.tools.search.advanced import _schemaboot_db_path
    finally:
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        
    import unittest.mock
    
    unwritable_path = "/usr/bin/nonexistent_path_mcp/test_binary"
    resolved_db = get_db_path(unwritable_path)
    
    # Populate fallback database
    os.makedirs(os.path.dirname(resolved_db), exist_ok=True)
    with open(resolved_db, "w") as f:
        f.write("dummy sqlite header content")
        
    try:
        # Mock get_idb_path to return the unwritable path
        with unittest.mock.patch("idc.get_idb_path", return_value=unwritable_path, create=True):
            resolved_path = _schemaboot_db_path()
            assert resolved_path == resolved_db
    finally:
        if os.path.exists(resolved_db):
            os.remove(resolved_db)

