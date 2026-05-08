"""
MbaGCN: Mamba-Based Graph Convolutional Network for CFG Encoding.

Implements the three-layer architecture:
  1. Message Aggregation Layer (MAL) - normalized graph convolution
  2. Selective State Space Transition Layer (S3TL) - SSM state update
  3. Node State Prediction Layer (NSPL) - node embedding refinement

Pure NumPy. No LLM dependencies. No training required.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Tuple
try:
    import numpy as np
except Exception:
    np = None

# IDA MCP decorators
try:
    from ._common import *
except ImportError:
    try:
        from _common import *  # type: ignore[import-not-found]
    except ImportError:
        pass

if "tool" not in globals():
    tool = lambda f: f  # type: ignore
if "idaread" not in globals():
    idaread = lambda f: f  # type: ignore


class MbaGCNEncoder:
    """
    MbaGCN encoder for Control Flow Graphs.

    Uses spectral graph embedding (Laplacian eigenvectors) instead of
    untrained random SSM matrices.  The normalized graph Laplacian
    L = I - D^{-1/2} A D^{-1/2} has eigenvectors that encode structural
    position optimally (spectral graph theory) without any training.
    Node features are concatenated with spectral positions and projected
    via a fixed Johnson-Lindenstrauss random projection, giving a
    theoretically grounded, training-free CFG embedding.

    Architecture (revised):
      Step 1 — Spectral positioning: k smallest eigenvectors of L
      Step 2 — Feature fusion: [spectral | node_features] per node
      Step 3 — JL random projection → output_dim (L2-normalized)
      Step 4 — Degree-weighted graph pooling → function embedding
    """

    def __init__(self, input_dim: int = 64, hidden_dim: int = 256, output_dim: int = 4096):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        self.spectral_k = min(hidden_dim, 32)  # number of Laplacian eigenvectors

    def _normalized_laplacian(self, adj: np.ndarray) -> np.ndarray:
        """Compute symmetric normalized Laplacian L = I - D^{-1/2} A D^{-1/2}."""
        degree = np.sum(adj, axis=1)
        degree = np.where(degree == 0, 1.0, degree)
        d_inv_sqrt = np.diag(1.0 / np.sqrt(degree))
        return np.eye(adj.shape[0]) - d_inv_sqrt @ adj @ d_inv_sqrt

    def _spectral_embed(self, adj: np.ndarray) -> np.ndarray:
        """
        Compute spectral node positions from Laplacian eigenvectors.
        Returns (n_nodes, k) matrix where each row is the spectral position.
        Uses the k smallest non-trivial eigenvectors (skip the constant first).
        """
        n = adj.shape[0]
        k = min(self.spectral_k, n)
        if n == 1:
            return np.zeros((1, k), dtype=np.float32)
        L = self._normalized_laplacian(adj)
        # eigh returns eigenvalues in ascending order (smallest first)
        # for real symmetric matrices — guaranteed for graph Laplacians
        eigenvalues, eigenvectors = np.linalg.eigh(L)
        # Skip eigenvector 0 (constant), take next k
        spec = eigenvectors[:, 1:k + 1]
        if spec.shape[1] < k:
            pad = np.zeros((n, k - spec.shape[1]), dtype=np.float32)
            spec = np.concatenate([spec, pad], axis=1)
        return spec.astype(np.float32)

    def _jl_project(self, fused: np.ndarray) -> np.ndarray:
        """
        Fixed JL random projection from fused_dim → output_dim.
        Seeded deterministically so the same fused_dim always maps the
        same way, enabling cross-binary embedding comparison.
        """
        fused_dim = fused.shape[1]
        rng = np.random.default_rng(42 + fused_dim)
        P = rng.normal(0.0, 1.0 / math.sqrt(fused_dim),
                       size=(fused_dim, self.output_dim)).astype(np.float32)
        return fused @ P

    def encode_cfg(self, node_features: np.ndarray, adjacency: np.ndarray) -> np.ndarray:
        """
        Encode a CFG into per-node embeddings.

        Args:
            node_features: (n_nodes, input_dim)
            adjacency:     (n_nodes, n_nodes)

        Returns:
            embeddings: (n_nodes, output_dim) L2-normalized
        """
        n = node_features.shape[0]
        if node_features.shape[1] != self.input_dim:
            pad = np.zeros((n, self.input_dim - node_features.shape[1]), dtype=np.float32)
            node_features = np.concatenate([node_features, pad], axis=1)

        # Step 1: spectral positions (structure, no training)
        spec = self._spectral_embed(adjacency)           # (n, k)

        # Step 2: fuse spectral + node features
        fused = np.concatenate([spec, node_features], axis=1)   # (n, k+input_dim)

        # Step 3: JL random projection
        embeddings = self._jl_project(fused)             # (n, output_dim)
        embeddings = np.tanh(embeddings)

        # L2-normalize each node embedding
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms[norms < 1e-12] = 1.0
        return (embeddings / norms).astype(np.float32)

    def encode_function(self, node_features: np.ndarray, adjacency: np.ndarray) -> np.ndarray:
        """
        Pool per-node embeddings into a single function-level embedding.
        Weight by out-degree so structurally important blocks (branchy)
        contribute more.
        """
        node_embeddings = self.encode_cfg(node_features, adjacency)

        out_degrees = np.sum(adjacency, axis=1).astype(np.float32)
        total = out_degrees.sum()
        weights = out_degrees / (total + 1e-12) if total > 0 else np.ones(len(out_degrees)) / len(out_degrees)

        func_embedding = np.average(node_embeddings, axis=0, weights=weights)
        norm = np.linalg.norm(func_embedding)
        if norm > 1e-12:
            func_embedding = func_embedding / norm
        return func_embedding.astype(np.float32)


class CFGExtractor:
    """Extract CFG structure and features from IDA Pro functions."""

    @staticmethod
    def extract_from_ida(func_ea: int) -> Tuple[np.ndarray, np.ndarray]:
        """
        Extract CFG from IDA Pro function.
        
        Returns:
            node_features: (n_blocks, input_dim)
            adjacency: (n_blocks, n_blocks)
        """
        try:
            import ida_funcs
            import idautils
            import idc
            import idaapi
            
            func = ida_funcs.get_func(func_ea)
            if not func:
                return np.zeros((1, 64), dtype=np.float32), np.zeros((1, 1), dtype=np.float32)
            
            # Get basic blocks
            blocks = list(idautils.Chunks(func.start_ea))
            if not blocks:
                return np.zeros((1, 64), dtype=np.float32), np.zeros((1, 1), dtype=np.float32)
            
            n_blocks = len(blocks)
            input_dim = 64
            
            node_features = np.zeros((n_blocks, input_dim), dtype=np.float32)
            adjacency = np.zeros((n_blocks, n_blocks), dtype=np.float32)
            
            for i, (start_ea, end_ea) in enumerate(blocks):
                # Extract block features
                features = CFGExtractor._extract_block_features(start_ea, end_ea)
                node_features[i] = features
                
                # Find successors
                for head in idautils.Heads(start_ea, end_ea):
                    if idc.is_code(idc.get_full_flags(head)):
                        # Check if this is a branch instruction
                        mnem = idc.print_insn_mnem(head)
                        if mnem and mnem.lower().startswith(('jmp', 'j')):
                            # Get jump target
                            for ref in idautils.CodeRefsFrom(head, False):
                                for j, (s, e) in enumerate(blocks):
                                    if s <= ref < e:
                                        adjacency[i, j] = 1.0
                                        break
                        # Fall-through
                        next_head = idc.next_head(head, end_ea + 1)
                        if next_head < end_ea:
                            for j, (s, e) in enumerate(blocks):
                                if s <= next_head < e:
                                    adjacency[i, j] = 1.0
                                    break
            
            return node_features, adjacency
        
        except ImportError:
            # Fallback: return dummy data
            return np.zeros((1, 64), dtype=np.float32), np.zeros((1, 1), dtype=np.float32)

    @staticmethod
    def _extract_block_features(start_ea: int, end_ea: int) -> np.ndarray:
        """Extract feature vector for a basic block."""
        try:
            import idautils
            import idc
            
            features = np.zeros(64, dtype=np.float32)
            
            instruction_count = 0
            call_count = 0
            jump_count = 0
            arithmetic_count = 0
            memory_count = 0
            
            arithmetic_mnems = {'add', 'sub', 'mul', 'div', 'imul', 'idiv', 'inc', 'dec', 'neg', 'cmp'}
            memory_mnems = {'mov', 'push', 'pop', 'lea', 'movzx', 'movsx', 'xchg'}
            
            for head in idautils.Heads(start_ea, end_ea):
                if idc.is_code(idc.get_full_flags(head)):
                    instruction_count += 1
                    mnem = idc.print_insn_mnem(head)
                    if mnem:
                        mnem_lower = mnem.lower()
                        if mnem_lower == 'call':
                            call_count += 1
                        elif mnem_lower.startswith('j'):
                            jump_count += 1
                        elif mnem_lower in arithmetic_mnems:
                            arithmetic_count += 1
                        elif mnem_lower in memory_mnems:
                            memory_count += 1
            
            # Encode features
            features[0] = min(instruction_count / 50.0, 1.0)  # normalized instruction count
            features[1] = min(call_count / 5.0, 1.0)
            features[2] = min(jump_count / 5.0, 1.0)
            features[3] = min(arithmetic_count / 10.0, 1.0)
            features[4] = min(memory_count / 20.0, 1.0)
            
            # Block size
            block_size = end_ea - start_ea
            features[5] = min(block_size / 200.0, 1.0)
            
            return features
        
        except ImportError:
            return np.zeros(64, dtype=np.float32)


# ---------------------------------------------------------------------------
# Graph Embedding Store
# ---------------------------------------------------------------------------

import struct


class GraphEmbeddingStore:
    """SQLite-backed storage for function graph embeddings."""

    def __init__(self, db_path: str):
        import sqlite3
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS graph_embeddings (
                func_ea INTEGER PRIMARY KEY,
                func_name TEXT,
                embedding BLOB,
                node_count INTEGER,
                edge_count INTEGER,
                timestamp REAL
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_graph_name ON graph_embeddings(func_name)
        """)
        conn.commit()
        conn.close()

    def store(self, func_ea: int, func_name: str, embedding: np.ndarray, node_count: int, edge_count: int):
        import sqlite3
        import time
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO graph_embeddings (func_ea, func_name, embedding, node_count, edge_count, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (func_ea, func_name, embedding.astype(np.float32).tobytes(), node_count, edge_count, time.time())
        )
        conn.commit()
        conn.close()

    def load(self, func_ea: int) -> Optional[np.ndarray]:
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT embedding FROM graph_embeddings WHERE func_ea = ?", (func_ea,))
        row = cur.fetchone()
        conn.close()
        if row:
            return np.frombuffer(row[0], dtype=np.float32)
        return None

    def find_similar(self, query_embedding: np.ndarray, top_k: int = 10) -> List[Tuple[int, str, float]]:
        import sqlite3
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


# ---------------------------------------------------------------------------
# MCP Tool Interface
# ---------------------------------------------------------------------------

from typing import Annotated, Literal


@tool
@idaread
def mbagcn(
    action: Annotated[Literal["encode", "similar", "stats"], "MbaGCN action"] = "encode",
    addr: Annotated[Optional[str], "Function address to encode"] = None,
    top_k: Annotated[int, "Number of similar functions"] = 10,
    db_path: Annotated[Optional[str], "Override path to embedding DB"] = None,
    **kwargs
) -> dict:
    """
    MbaGCN: Encode function CFGs into dense embeddings for similarity search.

    Actions:
    - encode: Extract CFG from function, encode with MbaGCN, store embedding.
    - similar: Find top-k most similar functions by graph embedding.
    - stats: Show embedding database statistics.
    """
    import os
    import time

    if np is None:
        return make_error(
            MCPError.NOT_IMPLEMENTED,
            "mbagcn requires numpy in the IDA Python environment",
            hint="Install numpy into IDA's Python or run IDA with a venv that includes numpy.",
        )

    if db_path is None:
        try:
            import ida_loader
            db_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) + ".mbagcn.db"
        except Exception:
            db_path = "unknown.mbagcn.db"

    store = GraphEmbeddingStore(db_path)
    encoder = MbaGCNEncoder(input_dim=64, hidden_dim=256, output_dim=4096)

    if action == "stats":
        import sqlite3
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*), AVG(node_count), AVG(edge_count) FROM graph_embeddings")
        row = cur.fetchone()
        conn.close()
        return {
            "ok": True,
            "total_functions": row[0] or 0,
            "avg_nodes": round(row[1] or 0, 2),
            "avg_edges": round(row[2] or 0, 2),
            "db_path": db_path,
        }

    if action == "encode":
        if not addr:
            return {"ok": False, "error": "addr required for encode"}
        
        try:
            ea = int(addr, 16)
        except (ValueError, TypeError):
            return {"ok": False, "error": f"Invalid address: {addr}"}
        
        node_features, adjacency = CFGExtractor.extract_from_ida(ea)
        
        if node_features.shape[0] == 0:
            return {"ok": False, "error": "Could not extract CFG"}
        
        embedding = encoder.encode_function(node_features, adjacency)
        
        try:
            import idc
            name = idc.get_func_name(ea) or hex(ea)
        except Exception:
            name = hex(ea)
        
        store.store(ea, name, embedding, node_features.shape[0], int(np.sum(adjacency)))
        
        return {
            "ok": True,
            "func_ea": hex(ea),
            "func_name": name,
            "nodes": node_features.shape[0],
            "edges": int(np.sum(adjacency)),
            "embedding_dim": embedding.shape[0],
        }

    if action == "similar":
        if not addr:
            return {"ok": False, "error": "addr required for similar"}
        
        try:
            ea = int(addr, 16)
        except (ValueError, TypeError):
            return {"ok": False, "error": f"Invalid address: {addr}"}
        
        query_emb = store.load(ea)
        if query_emb is None:
            # Auto-encode if not found
            node_features, adjacency = CFGExtractor.extract_from_ida(ea)
            if node_features.shape[0] == 0:
                return {"ok": False, "error": "Could not extract CFG"}
            query_emb = encoder.encode_function(node_features, adjacency)
            try:
                import idc
                name = idc.get_func_name(ea) or hex(ea)
            except Exception:
                name = hex(ea)
            store.store(ea, name, query_emb, node_features.shape[0], int(np.sum(adjacency)))
        
        results = store.find_similar(query_emb, top_k=top_k)
        return {
            "ok": True,
            "query": hex(ea),
            "results": [
                {"ea": hex(ea), "name": name, "similarity": round(score, 4)}
                for ea, name, score in results
                if hex(ea) != hex(int(addr, 16))  # exclude self
            ],
        }

    return {"ok": False, "error": f"Unknown action: {action}"}
