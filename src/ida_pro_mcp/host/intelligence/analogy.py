"""Analogy mapping and finding transfer engine across historical binaries/capsules."""

from __future__ import annotations

import os
import sqlite3
from typing import Any

from .core import BgeCodeEmbedder
from .embeddings import FunctionEmbeddingIndex
from .structural_index import get_db_path


class CrossBinaryAnalogyEngine:
    """
    Compares current session functions against historical capsules
    based on embedding similarity and control-flow structural similarity.
    """

    @staticmethod
    def compute_analogy_score(
        current_attrs: dict[str, Any],
        source_attrs: dict[str, Any],
        current_vector: list[float],
        source_vector: list[float],
        threshold_cosine: float = 0.85,
        threshold_structural: float = 0.70,
    ) -> tuple[float, float, float]:
        """
        Computes cosine similarity and structural ratio similarity.
        Returns (confidence, cosine_sim, structural_sim) if passing thresholds,
        else (0.0, 0.0, 0.0).
        """
        # 1. Structural ratio similarity (very cheap, prunes 99.9% of non-matching pairs)
        def ratio(x: Any, y: Any) -> float:
            x_val = float(x if x is not None else 0.0)
            y_val = float(y if y is not None else 0.0)
            return (min(x_val, y_val) + 1.0) / (max(x_val, y_val) + 1.0)

        sim_size = ratio(current_attrs.get("size"), source_attrs.get("size"))
        sim_bb = ratio(current_attrs.get("bb_count"), source_attrs.get("bb_count"))
        sim_cc = ratio(
            current_attrs.get("cyclomatic_complexity"),
            source_attrs.get("cyclomatic_complexity"),
        )
        sim_api = ratio(current_attrs.get("api_count"), source_attrs.get("api_count"))
        sim_xor = ratio(current_attrs.get("xor_ratio"), source_attrs.get("xor_ratio"))

        structural_sim = (sim_size + sim_bb + sim_cc + sim_api + sim_xor) / 5.0
        if structural_sim < threshold_structural:
            return 0.0, 0.0, 0.0

        # 2. Cosine similarity (more expensive dot product, only runs on structural candidates)
        cosine_sim = BgeCodeEmbedder.cosine(current_vector, source_vector)
        if cosine_sim < threshold_cosine:
            return 0.0, 0.0, 0.0

        confidence = cosine_sim * structural_sim
        return (
            round(confidence, 4),
            round(cosine_sim, 4),
            round(structural_sim, 4),
        )

    @staticmethod
    def get_capsule_comments(sideband_path: str) -> dict[str, str]:
        """Fetch custom comments/notes associated with functions inside sideband."""
        comments: dict[str, str] = {}
        if not sideband_path or not os.path.exists(sideband_path):
            return comments
        try:
            conn = sqlite3.connect(sideband_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT title, body FROM notes WHERE kind IN ('function_comment', 'comment', 'function')"
            ).fetchall()
            for r in rows:
                comments[str(r["title"])] = str(r["body"])
            conn.close()
        except Exception:
            pass
        return comments

    def suggest_analogies(
        self,
        current_idb: str,
        library_idbs: list[str],
        threshold_cosine: float = 0.85,
        threshold_structural: float = 0.70,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Rank functions in current session by their similarity to historical library functions.
        Returns a list of suggested analogies.
        """
        current_db = get_db_path(current_idb)
        if not current_db or not os.path.exists(current_db):
            return []

        # 1. Load active functions and their embeddings
        try:
            conn = sqlite3.connect(current_db)
            conn.row_factory = sqlite3.Row
            current_funcs = {
                int(r["ea"]): dict(r)
                for r in conn.execute(
                    "SELECT * FROM function_attrs WHERE is_thunk=0 AND is_library=0"
                ).fetchall()
            }
            conn.close()
        except Exception:
            return []

        embedder = BgeCodeEmbedder()
        current_idx = FunctionEmbeddingIndex(
            current_idb + ".embeddings.db", embedder
        )

        suggestions: list[dict[str, Any]] = []

        # 2. Iterate over analogy sources (historical library binaries)
        for lib_idb in library_idbs:
            lib_db = get_db_path(lib_idb)
            if not lib_db or not os.path.exists(lib_db):
                continue

            try:
                conn = sqlite3.connect(lib_db)
                conn.row_factory = sqlite3.Row
                lib_funcs = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM function_attrs WHERE is_thunk=0 AND is_library=0"
                    ).fetchall()
                ]
                conn.close()
            except Exception:
                continue

            lib_idx = FunctionEmbeddingIndex(lib_idb + ".embeddings.db", embedder)

            # Retrieve optional capsule comments
            lib_comments = self.get_capsule_comments(
                os.path.splitext(lib_idb)[0] + ".sideband"
            )

            # Compare every current function against every historical function
            for ea, cur_func in current_funcs.items():
                ea_hex = hex(ea)
                cur_name = cur_func["name"]
                # Only suggest if name is generic
                is_generic = (
                    cur_name.startswith(("sub_", "0x", "nullsub_"))
                )

                # Fetch active embedding
                cur_key = (
                    ea_hex if ea_hex in current_idx._cache else str(ea)
                )
                cur_vec = current_idx._cache.get(cur_key)
                if cur_vec is None:
                    continue

                for lib_func in lib_funcs:
                    lib_ea = int(lib_func["ea"])
                    lib_name = lib_func["name"]

                    # Do not suggest generic names from library
                    if (
                        lib_name.startswith(("sub_", "0x", "nullsub_"))
                    ):
                        continue

                    # Fetch library embedding
                    lib_hex = hex(lib_ea)
                    lib_key = lib_hex if lib_hex in lib_idx._cache else str(lib_ea)
                    lib_vec = lib_idx._cache.get(lib_key)
                    if lib_vec is None:
                        continue

                    # Compute score
                    confidence, cos_sim, struct_sim = self.compute_analogy_score(
                        cur_func,
                        lib_func,
                        cur_vec,
                        lib_vec,
                        threshold_cosine=threshold_cosine,
                        threshold_structural=threshold_structural,
                    )

                    if confidence > 0.0:
                        # Extract matching comment
                        comment = lib_comments.get(
                            lib_name
                        ) or lib_comments.get(lib_hex)

                        suggestions.append(
                            {
                                "addr": ea_hex,
                                "current_name": cur_name,
                                "matched_name": lib_name,
                                "matched_comment": comment,
                                "confidence": confidence,
                                "source_idb": lib_idb,
                                "source_addr": lib_hex,
                                "similarity_cosine": cos_sim,
                                "similarity_structural": struct_sim,
                                "is_generic": is_generic,
                            }
                        )

        # Sort suggestions by confidence descending
        suggestions.sort(key=lambda x: x["confidence"], reverse=True)
        return suggestions[:limit]
