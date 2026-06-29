"""
MbaGCN engine: spectral-graph CFG encoder for reverse-engineering similarity.

Pure NumPy. No LLM. No training. The encoder fuses spectral Laplacian
positions, basic-block features, and a deterministic Johnson-Lindenstrauss
random projection into a function-level embedding suitable for cosine
similarity. Embeddings persist to a small SQLite store keyed by function EA.

The original `mbagcn` MCP tool exposed three actions (encode / similar /
stats) and lived in `ida_mcp/tools/mbagcn.py`. It was merged into the
`agent` tool as the `cfg_encode` / `cfg_similar` / `cfg_stats` actions
to consolidate similarity backends in one place. This module is the
shared engine behind those actions.
"""

from __future__ import annotations

import math
import sqlite3
import time

try:
    import numpy as np
except Exception:
    np = None


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------


class MbaGCNEncoder:
    """
    Spectral CFG encoder for functions.

    Pipeline (training-free, deterministic):
      1. Spectral positioning via Laplacian eigenvectors
      2. Feature fusion: [spectral | block_features] per node
      3. Johnson-Lindenstrauss random projection → output_dim
      4. Degree-weighted graph pooling → function-level embedding (L2-normed)
    """

    def __init__(self, input_dim: int = 64, hidden_dim: int = 256, output_dim: int = 4096):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        self.spectral_k = min(hidden_dim, 32)

    def _normalized_laplacian(self, adj: np.ndarray) -> np.ndarray:
        degree = np.sum(adj, axis=1)
        degree = np.where(degree == 0, 1.0, degree)
        d_inv_sqrt = np.diag(1.0 / np.sqrt(degree))
        return np.eye(adj.shape[0]) - d_inv_sqrt @ adj @ d_inv_sqrt

    def _spectral_embed(self, adj: np.ndarray) -> np.ndarray:
        n = adj.shape[0]
        k = min(self.spectral_k, n)
        if n == 1:
            return np.zeros((1, k), dtype=np.float32)
        L = self._normalized_laplacian(adj)
        eigenvalues, eigenvectors = np.linalg.eigh(L)
        spec = eigenvectors[:, 1:k + 1]
        if spec.shape[1] < k:
            pad = np.zeros((n, k - spec.shape[1]), dtype=np.float32)
            spec = np.concatenate([spec, pad], axis=1)
        return spec.astype(np.float32)

    def _jl_project(self, fused: np.ndarray) -> np.ndarray:
        fused_dim = fused.shape[1]
        rng = np.random.default_rng(42 + fused_dim)
        P = rng.normal(0.0, 1.0 / math.sqrt(fused_dim),
                       size=(fused_dim, self.output_dim)).astype(np.float32)
        return fused @ P

    def encode_cfg(self, node_features: np.ndarray, adjacency: np.ndarray) -> np.ndarray:
        n = node_features.shape[0]
        if node_features.shape[1] != self.input_dim:
            pad = np.zeros((n, self.input_dim - node_features.shape[1]), dtype=np.float32)
            node_features = np.concatenate([node_features, pad], axis=1)
        spec = self._spectral_embed(adjacency)
        fused = np.concatenate([spec, node_features], axis=1)
        embeddings = self._jl_project(fused)
        embeddings = np.tanh(embeddings)
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms[norms < 1e-12] = 1.0
        return (embeddings / norms).astype(np.float32)

    def encode_function(self, node_features: np.ndarray, adjacency: np.ndarray) -> np.ndarray:
        node_embeddings = self.encode_cfg(node_features, adjacency)
        out_degrees = np.sum(adjacency, axis=1).astype(np.float32)
        total = out_degrees.sum()
        weights = (
            out_degrees / (total + 1e-12) if total > 0
            else np.ones(len(out_degrees)) / len(out_degrees)
        )
        func_embedding = np.average(node_embeddings, axis=0, weights=weights)
        norm = np.linalg.norm(func_embedding)
        if norm > 1e-12:
            func_embedding = func_embedding / norm
        return func_embedding.astype(np.float32)


# ---------------------------------------------------------------------------
# CFG extractor (IDA-aware)
# ---------------------------------------------------------------------------


class CFGExtractor:
    """Extract CFG structure and per-block features from an IDA function."""

    @staticmethod
    def extract_from_ida(func_ea: int) -> tuple[np.ndarray, np.ndarray]:
        try:
            import ida_funcs
            import idaapi
        except ImportError:
            return (
                np.zeros((1, 64), dtype=np.float32),
                np.zeros((1, 1), dtype=np.float32),
            )

        try:
            func = ida_funcs.get_func(func_ea)
        except Exception:
            func = None
        if not func:
            return (
                np.zeros((1, 64), dtype=np.float32),
                np.zeros((1, 1), dtype=np.float32),
            )

        try:
            flow = idaapi.FlowChart(func)
            blocks = list(flow)
        except Exception:
            return (
                np.zeros((1, 64), dtype=np.float32),
                np.zeros((1, 1), dtype=np.float32),
            )
        if not blocks:
            return (
                np.zeros((1, 64), dtype=np.float32),
                np.zeros((1, 1), dtype=np.float32),
            )

        n_blocks = len(blocks)
        input_dim = 64
        node_features = np.zeros((n_blocks, input_dim), dtype=np.float32)
        adjacency = np.zeros((n_blocks, n_blocks), dtype=np.float32)

        block_index = {blk.start_ea: i for i, blk in enumerate(blocks)}
        for i, blk in enumerate(blocks):
            node_features[i] = CFGExtractor._extract_block_features(blk.start_ea, blk.end_ea)
            for succ in blk.succs():
                j = block_index.get(succ.start_ea)
                if j is not None:
                    adjacency[i, j] = 1.0
        return node_features, adjacency

    @staticmethod
    def _extract_block_features(start_ea: int, end_ea: int) -> np.ndarray:
        try:
            import idautils
            import idc
        except ImportError:
            return np.zeros(64, dtype=np.float32)

        features = np.zeros(64, dtype=np.float32)
        instruction_count = 0
        call_count = 0
        jump_count = 0
        arithmetic_count = 0
        memory_count = 0

        arithmetic_mnems = {"add", "sub", "mul", "div", "imul", "idiv", "inc", "dec", "neg", "cmp"}
        memory_mnems = {"mov", "push", "pop", "lea", "movzx", "movsx", "xchg"}

        for head in idautils.Heads(start_ea, end_ea):
            if idc.is_code(idc.get_full_flags(head)):
                instruction_count += 1
                mnem = idc.print_insn_mnem(head)
                if not mnem:
                    continue
                mnem_lower = mnem.lower()
                if mnem_lower == "call":
                    call_count += 1
                elif mnem_lower.startswith("j"):
                    jump_count += 1
                elif mnem_lower in arithmetic_mnems:
                    arithmetic_count += 1
                elif mnem_lower in memory_mnems:
                    memory_count += 1

        features[0] = min(instruction_count / 50.0, 1.0)
        features[1] = min(call_count / 5.0, 1.0)
        features[2] = min(jump_count / 5.0, 1.0)
        features[3] = min(arithmetic_count / 10.0, 1.0)
        features[4] = min(memory_count / 20.0, 1.0)
        features[5] = min((end_ea - start_ea) / 200.0, 1.0)
        return features


# ---------------------------------------------------------------------------
# SQLite-backed store
# ---------------------------------------------------------------------------


class GraphEmbeddingStore:
    """Persistent function-level CFG embeddings keyed by EA."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS graph_embeddings (
                func_ea INTEGER PRIMARY KEY,
                func_name TEXT,
                embedding BLOB,
                node_count INTEGER,
                edge_count INTEGER,
                timestamp REAL
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_graph_name ON graph_embeddings(func_name)"
        )
        conn.commit()
        conn.close()

    def store(self, func_ea: int, func_name: str, embedding: np.ndarray,
              node_count: int, edge_count: int) -> None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO graph_embeddings "
            "(func_ea, func_name, embedding, node_count, edge_count, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                func_ea, func_name,
                embedding.astype(np.float32).tobytes(),
                node_count, edge_count, time.time(),
            ),
        )
        conn.commit()
        conn.close()

    def load(self, func_ea: int) -> np.ndarray | None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT embedding FROM graph_embeddings WHERE func_ea = ?", (func_ea,))
        row = cur.fetchone()
        conn.close()
        if row:
            return np.frombuffer(row[0], dtype=np.float32)
        return None

    def find_similar(self, query_embedding: np.ndarray, top_k: int = 10) \
            -> list[tuple[int, str, float]]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT func_ea, func_name, embedding FROM graph_embeddings")
        results = []
        for row in cur.fetchall():
            ea, name, emb_bytes = row
            emb = np.frombuffer(emb_bytes, dtype=np.float32)
            score = float(np.dot(emb, query_embedding))
            results.append((ea, name, score))
        conn.close()
        results.sort(key=lambda x: x[2], reverse=True)
        return results[:top_k]

    def stats(self) -> dict:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*), AVG(node_count), AVG(edge_count) FROM graph_embeddings")
        row = cur.fetchone()
        conn.close()
        return {
            "total_functions": row[0] or 0,
            "avg_nodes": round(row[1] or 0, 2),
            "avg_edges": round(row[2] or 0, 2),
            "db_path": self.db_path,
        }


# ---------------------------------------------------------------------------
# Convenience façade used by the agent tool
# ---------------------------------------------------------------------------


def default_db_path() -> str:
    """Pick the canonical .mbagcn.db path for the current IDB."""
    try:
        import ida_loader
        return ida_loader.get_path(ida_loader.PATH_TYPE_IDB) + ".mbagcn.db"
    except Exception:
        return "unknown.mbagcn.db"


def is_available() -> bool:
    """True if numpy is present and the engine can run."""
    return np is not None
