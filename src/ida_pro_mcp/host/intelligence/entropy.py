"""Entropy and novelty calculators for active learning triage."""

from __future__ import annotations

import math
import sqlite3
from typing import Any

from .core import BgeCodeEmbedder
from .embeddings import FunctionEmbeddingIndex
from .structural_index import get_db_path


class FunctionEntropyCalculator:
    """
    Computes structural entropy for functions and ranks them
    by novelty/dissimilarity to the semantic index or intent context.
    """

    @staticmethod
    def compute_instruction_entropy(row: dict[str, Any]) -> float:
        """
        Computes Shannon entropy over instruction counts.
        """
        counts = [
            row.get("xor_count") or 0,
            row.get("mov_count") or 0,
            row.get("cmp_count") or 0,
            row.get("jmp_count") or 0,
            row.get("ret_count") or 0,
            row.get("push_count") or 0,
            row.get("pop_count") or 0,
            row.get("lea_count") or 0,
            row.get("test_count") or 0,
        ]
        total = sum(counts)
        if total == 0:
            return 0.0
        entropy = 0.0
        for c in counts:
            if c > 0:
                p = c / total
                entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def compute_structural_entropy(cls, row: dict[str, Any]) -> float:
        """
        Computes a normalized structural entropy score in [0.0, 1.0]
        based on byte entropy, instruction counts/ratios, and CFG attributes.
        """
        instr_entropy = cls.compute_instruction_entropy(row)
        p_instr_entropy = min(1.0, instr_entropy / 3.17)

        # Byte entropy (shannon entropy of bytes) normalized [0.0, 8.0] -> [0.0, 1.0]
        raw_byte_entropy = float(row.get("entropy") or 0.0)
        p_byte_entropy = min(1.0, max(0.0, raw_byte_entropy / 8.0))

        # CFG complexity and basic block count (log-scaled)
        cc = max(0, int(row.get("cyclomatic_complexity") or 0))
        p_cc = min(1.0, math.log2(1.0 + cc) / 10.0)

        bb = max(0, int(row.get("bb_count") or 0))
        p_bb = min(1.0, math.log2(1.0 + bb) / 10.0)

        # XOR ratio and API count
        p_xor = min(1.0, max(0.0, float(row.get("xor_ratio") or 0.0)))

        api_cnt = max(0, int(row.get("api_count") or 0))
        p_api = min(1.0, math.log2(1.0 + api_cnt) / 5.0)

        # Blend structural parameters
        score = (
            0.25 * p_instr_entropy
            + 0.25 * p_byte_entropy
            + 0.20 * p_cc
            + 0.10 * p_bb
            + 0.10 * p_xor
            + 0.10 * p_api
        )
        return round(score, 4)

    def compute_triage_suggestions(
        self,
        idb_path: str,
        context: str | None = None,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Query functions from the structural index, calculate their structural entropy,
        determine their semantic novelty against the existing index (or custom context),
        and return the top ranked triage suggestions.
        """
        db_path = get_db_path(idb_path)
        if not db_path:
            return []

        # 1. Fetch structural function features
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            rows = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM function_attrs WHERE is_thunk=0 AND is_library=0"
                ).fetchall()
            ]
            conn.close()
        except Exception:
            return []

        if not rows:
            return []

        # 2. Open semantic index to check explored status and compute novelty
        embedder = BgeCodeEmbedder()
        emb_index = FunctionEmbeddingIndex(idb_path + ".embeddings.db", embedder)

        explored_eas = set(emb_index._cache.keys())

        # If a context text is provided, embed it
        ctx_vec: list[float] | None = None
        if context and context.strip():
            try:
                ctx_vec = embedder.embed(context)
            except Exception:
                ctx_vec = None

        suggestions = []
        for row in rows:
            ea_int = int(row["ea"])
            ea_hex = hex(ea_int)
            name = row["name"]

            # Compute structural entropy
            struct_entropy = self.compute_structural_entropy(row)

            # Determine explored status
            is_explored = ea_hex in explored_eas or str(ea_int) in explored_eas

            # Compute semantic novelty
            semantic_novelty = 1.0
            similarity = 0.0

            if is_explored:
                # Find matching embedding
                key = ea_hex if ea_hex in explored_eas else str(ea_int)
                vec = emb_index._cache.get(key)

                if vec is not None:
                    if ctx_vec:
                        # Dissimilarity to target context
                        similarity = BgeCodeEmbedder.cosine(vec, ctx_vec)
                        semantic_novelty = 1.0 - max(0.0, similarity)
                    else:
                        # Dissimilarity to the rest of the binary functions
                        other_similarities = []
                        for other_ea, other_vec in list(emb_index._cache.items()):
                            if other_ea != key and other_vec is not None:
                                other_similarities.append(
                                    BgeCodeEmbedder.cosine(vec, other_vec)
                                )
                        if other_similarities:
                            # Novelty is 1.0 - max similarity to other functions
                            semantic_novelty = 1.0 - max(0.0, *other_similarities)
                        else:
                            semantic_novelty = 1.0

            # Compute final blended triage score
            # Prioritize unexplored functions by adding a curiosity bonus
            curiosity_bonus = 0.2 if not is_explored else 0.0

            triage_score = (
                0.5 * struct_entropy
                + 0.3 * semantic_novelty
                + 0.2 * curiosity_bonus
            )

            suggestions.append(
                {
                    "ea": ea_hex,
                    "name": name,
                    "structural_entropy": struct_entropy,
                    "semantic_novelty": round(semantic_novelty, 4),
                    "similarity": round(similarity, 4) if ctx_vec else None,
                    "explored": is_explored,
                    "triage_score": round(triage_score, 4),
                    "cyclomatic_complexity": row["cyclomatic_complexity"],
                    "bb_count": row["bb_count"],
                    "api_count": row["api_count"],
                }
            )

        # Rank suggestions by triage_score descending
        suggestions.sort(key=lambda x: x["triage_score"], reverse=True)
        return suggestions[:limit]
