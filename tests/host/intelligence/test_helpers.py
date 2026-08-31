"""Tests for the shared embedding helpers.

Covers the vectorized batch cosine similarity (both the NumPy fast path and
the pure-Python fallback must agree), and the shared full-decomp document
budget used by the local and cloud embedders.
"""

from __future__ import annotations

import math
import sys
from unittest import mock

import pytest

from ida_pro_mcp.host.intelligence.helpers import (
    _EmbedResult,
    batch_cosine_similarity,
    cosine_similarity,
    decomp_document_char_budget,
    pack_floats,
    unpack_floats,
)


class TestBatchCosineSimilarity:
    def _rows(self):
        # Two unit vectors (a ≈ b), one orthogonal, one anti-parallel.
        return [
            [1.0, 0.0],
            [0.0, 1.0],
            [-1.0, 0.0],
        ]

    def test_numpy_path_matches_per_row_cosine(self):
        query = [0.8, 0.6]
        rows = self._rows()
        sims = batch_cosine_similarity(query, rows)
        assert len(sims) == len(rows)
        for sim, row in zip(sims, rows, strict=True):
            assert sim == pytest.approx(cosine_similarity(query, row), abs=1e-12)
        # Sanity: closest match is the (1, 0) row.
        assert sims.index(max(sims)) == 0

    def test_fallback_path_matches_numpy_path(self):
        query = [0.8, 0.6]
        rows = self._rows()
        expected = batch_cosine_similarity(query, rows)
        with mock.patch.dict(sys.modules, {"numpy": None}):
            fallback = batch_cosine_similarity(query, rows)
        assert fallback == pytest.approx(expected, abs=1e-12)

    def test_empty_vectors(self):
        assert batch_cosine_similarity([1.0, 0.0], []) == []
        assert batch_cosine_similarity([], []) == []

    def test_zero_norm_query_scores_zero_everywhere(self):
        sims = batch_cosine_similarity([0.0, 0.0], self._rows())
        assert sims == [0.0, 0.0, 0.0]

    def test_zero_norm_row_scores_zero(self):
        rows = [[1.0, 0.0], [0.0, 0.0], [0.0, 1.0]]
        sims = batch_cosine_similarity([1.0, 0.0], rows)
        assert sims == pytest.approx([1.0, 0.0, 0.0], abs=1e-12)

    def test_non_normalized_rows_are_handled(self):
        # Same direction, different magnitude -> cosine 1.0.
        sims = batch_cosine_similarity([2.0, 0.0], [[4.0, 0.0], [0.0, 5.0]])
        assert sims[0] == pytest.approx(1.0, abs=1e-12)
        assert sims[1] == pytest.approx(0.0, abs=1e-12)

    def test_dimension_mismatch_falls_back_without_crashing(self):
        # numpy path would raise on the matmul; the helper must fall back
        # and return the per-row loop result (truncated zip, matching the
        # historical dot_product behavior) rather than propagate.
        with mock.patch.dict(sys.modules, {"numpy": None}):
            sims = batch_cosine_similarity([1.0, 0.0, 0.0], [[1.0, 0.0]])
        assert sims == pytest.approx([cosine_similarity([1.0, 0.0, 0.0], [1.0, 0.0])])

    def test_dimension_mismatch_with_numpy_importable_still_falls_back(self):
        # Same fallback must hold when numpy is importable: the matmul shape
        # error is swallowed and the per-row loop answers.
        sims = batch_cosine_similarity([1.0, 0.0, 0.0], [[1.0, 0.0]])
        assert sims == pytest.approx([cosine_similarity([1.0, 0.0, 0.0], [1.0, 0.0])])

    def test_accepts_tuples_and_iterators(self):
        sims = batch_cosine_similarity((0.6, 0.8), [(1.0, 0.0), [0.0, 1.0]])
        assert sims[0] == pytest.approx(0.6, abs=1e-12)
        assert sims[1] == pytest.approx(0.8, abs=1e-12)


class TestFloatPacking:
    def test_round_trip_preserves_float32_values(self):
        values = [1.25, -2.5, 0.0]
        assert unpack_floats(pack_floats(values)) == values

    def test_rejects_corrupt_trailing_bytes(self):
        with pytest.raises(ValueError, match="multiple of 4"):
            unpack_floats(pack_floats([1.0]) + bytes([0]))


class TestDecompDocumentCharBudget:
    def test_explicit_budget_wins_and_is_clamped(self):
        assert decomp_document_char_budget(100000, explicit_chars=5000) == 5000
        # Below the 1024 floor.
        assert decomp_document_char_budget(100000, explicit_chars=100) == 1024
        # Above the input window.
        assert decomp_document_char_budget(4096, explicit_chars=99999) == 4096

    def test_fraction_of_window(self):
        assert decomp_document_char_budget(10000, fraction=0.2) == 2000
        # Fraction is clamped to [0.1, 1.0] — and the 1024 floor still wins
        # over a clamped-to-0.1 fraction of a modest window.
        assert decomp_document_char_budget(10000, fraction=5.0) == 10000
        assert decomp_document_char_budget(10000, fraction=0.001) == 1024

    def test_small_window_respects_floor(self):
        assert decomp_document_char_budget(100, fraction=0.5) == 1024


class TestEmbedResultContract:
    def test_ok_false_vector_is_none(self):
        result = _EmbedResult(vector=None, backend="unavailable", ok=False)
        assert result.ok is False
        assert result.vector is None
        assert "ok=False" in repr(result)
