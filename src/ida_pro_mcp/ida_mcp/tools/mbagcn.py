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
import numpy as np

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
    
    Architecture:
      MAL:  H^(l+1) = D^-1/2 * A * D^-1/2 * H^(l)
      S3TL: h_t = A_bar * h_t-1 + B_bar * x_t  (selective SSM update)
      NSPL: y = C * h_t  (node embedding)
    """

    def __init__(self, input_dim: int = 64, hidden_dim: int = 256, output_dim: int = 4096):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        
        # MAL projection
        rng = np.random.default_rng(42)
        self.W_mal = rng.normal(0, 0.01, size=(input_dim, hidden_dim)).astype(np.float32)
        
        # S3TL state space matrices (initialized for stable dynamics)
        self.A = -rng.exponential(1.0, size=(hidden_dim,)).astype(np.float32) * 0.1
        self.B = rng.normal(0, 0.1, size=(hidden_dim,)).astype(np.float32)
        self.C = rng.normal(0, 0.1, size=(hidden_dim,)).astype(np.float32)
        
        # NSPL output projection
        self.W_nspl = rng.normal(0, 0.01, size=(hidden_dim, output_dim)).astype(np.float32)

    def _normalize_adjacency(self, adj: np.ndarray) -> np.ndarray:
        """Symmetric normalization: D^-1/2 * A * D^-1/2."""
        n = adj.shape[0]
        degree = np.sum(adj, axis=1)
        degree[degree == 0] = 1.0  # avoid division by zero
        d_inv_sqrt = np.diag(1.0 / np.sqrt(degree))
        return d_inv_sqrt @ adj @ d_inv_sqrt

    def _mal(self, node_features: np.ndarray, adj_norm: np.ndarray) -> np.ndarray:
        """Message Aggregation Layer."""
        # Aggregate neighbor features
        aggregated = adj_norm @ node_features  # (n_nodes, input_dim)
        # Project to hidden dim
        return aggregated @ self.W_mal  # (n_nodes, hidden_dim)

    def _s3tl(self, mal_output: np.ndarray) -> np.ndarray:
        """
        Selective State Space Transition Layer.
        
        For each node, apply discretized SSM:
          h_t = exp(delta * A) * h_{t-1} + delta * B * x_t
        
        where delta is input-dependent (selective).
        """
        n_nodes = mal_output.shape[0]
        hidden_states = np.zeros((n_nodes, self.hidden_dim), dtype=np.float32)
        
        for t in range(n_nodes):
            x_t = mal_output[t]
            # Selective step size based on input magnitude
            delta_t = np.log(1 + np.exp(np.dot(x_t, x_t) / self.hidden_dim))
            
            # Discretize: A_bar = exp(delta * A)
            A_bar = np.exp(delta_t * self.A)
            
            # State update
            if t > 0:
                hidden_states[t] = A_bar * hidden_states[t - 1] + delta_t * self.B * x_t
            else:
                hidden_states[t] = delta_t * self.B * x_t
        
        return hidden_states

    def _nspl(self, hidden_states: np.ndarray) -> np.ndarray:
        """Node State Prediction Layer."""
        # y = C * h (element-wise, broadcasted)
        node_embeddings = hidden_states * self.C  # (n_nodes, hidden_dim)
        # Project to output dimension
        return node_embeddings @ self.W_nspl  # (n_nodes, output_dim)

    def encode_cfg(self, node_features: np.ndarray, adjacency: np.ndarray) -> np.ndarray:
        """
        Encode a Control Flow Graph.
        
        Args:
            node_features: (n_nodes, input_dim) - feature vectors for each basic block
            adjacency: (n_nodes, n_nodes) - adjacency matrix (0/1)
        
        Returns:
            node_embeddings: (n_nodes, output_dim) - embedding for each node
        """
        if node_features.shape[1] != self.input_dim:
            raise ValueError(f"Expected input_dim={self.input_dim}, got {node_features.shape[1]}")
        
        adj_norm = self._normalize_adjacency(adjacency)
        
        # Layer 1: MAL
        mal_out = self._mal(node_features, adj_norm)
        mal_out = np.tanh(mal_out)  # activation
        
        # Layer 2: S3TL
        hidden = self._s3tl(mal_out)
        
        # Layer 3: NSPL
        embeddings = self._nspl(hidden)
        
        # L2 normalize each embedding
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms[norms < 1e-12] = 1.0
        embeddings = embeddings / norms
        
        return embeddings

    def encode_function(self, node_features: np.ndarray, adjacency: np.ndarray) -> np.ndarray:
        """
        Encode a function's CFG to a single function-level embedding.
        
        Returns the mean of all node embeddings, weighted by out-degree.
        """
        node_embeddings = self.encode_cfg(node_features, adjacency)
        
        # Weight by out-degree (entry points have higher influence)
        out_degrees = np.sum(adjacency, axis=1)
        weights = out_degrees / (np.sum(out_degrees) + 1e-12)
        
        func_embedding = np.average(node_embeddings, axis=0, weights=weights)
        
        # Renormalize
        norm = np.linalg.norm(func_embedding)
        if norm > 1e-12:
            func_embedding = func_embedding / norm
        
        return func_embedding


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
