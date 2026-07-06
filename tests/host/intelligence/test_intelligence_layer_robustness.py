import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_pro_mcp.host.config import CACHE_DIR
from ida_pro_mcp.services import FunctionEmbeddingIndex


class FakeEmbedder:
    def __init__(self):
        self.backend = "fake"
        self.dim = 1536

    def embed(self, text):
        return [0.1] * self.dim

    def embed_vector(self, text):
        return self.embed(text)

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


