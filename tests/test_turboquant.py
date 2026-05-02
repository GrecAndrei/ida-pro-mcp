"""Unit tests for TurboQuant and FunctionEmbeddingEngine."""

import os
import sys
import importlib.util

# Bypass ida_pro_mcp package (which pulls in zeromcp via __init__.py)
_tq_path = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "src", "ida_pro_mcp", "ida_mcp", "tools", "turboquant.py"
)
_spec = importlib.util.spec_from_file_location("turboquant", _tq_path)
_tq_mod = importlib.util.module_from_spec(_spec)
sys.modules["turboquant"] = _tq_mod
_spec.loader.exec_module(_tq_mod)

import numpy as np
import pytest
from turboquant import TurboQuantMemoryBank, FunctionEmbeddingEngine


class TestTurboQuantMemoryBank:
    def test_ingest_reconstruct_roundtrip(self):
        bank = TurboQuantMemoryBank(dim=512, chunk_size=64)
        vec = np.random.randn(512).astype(np.float32)
        bank.ingest("test", vec)
        recon = bank.reconstruct("test")
        assert recon.shape == (512,)
        assert recon.dtype == np.float32
        # Reconstruction should be close (cosine similarity > 0.85 for 3-bit)
        cos_sim = np.dot(vec, recon) / (np.linalg.norm(vec) * np.linalg.norm(recon))
        assert cos_sim > 0.85, f"Cosine similarity too low: {cos_sim}"

    def test_similarity_ranking(self):
        bank = TurboQuantMemoryBank(dim=256, chunk_size=32)
        # Store 3 vectors
        v1 = np.random.randn(256).astype(np.float32)
        v2 = np.random.randn(256).astype(np.float32)
        v3 = np.random.randn(256).astype(np.float32)
        bank.ingest("a", v1)
        bank.ingest("b", v2)
        bank.ingest("c", v3)

        # Query with v1 should return "a" first
        results = bank.similarity(v1, top_k=3)
        assert results[0][0] == "a"
        assert len(results) == 3

    def test_compression_ratio(self):
        bank = TurboQuantMemoryBank(dim=1024, chunk_size=128)
        for i in range(10):
            bank.ingest(str(i), np.random.randn(1024).astype(np.float32))
        ratio = bank.compression_ratio()
        # 3-bit indices (stored in uint8) + 1-bit signs (int8) + 4-byte norm
        # = 2 bytes per dim + 4 bytes vs 4 bytes per dim
        expected = (2 * 1024 + 4) / (4 * 1024)
        assert abs(ratio - expected) < 0.01

    def test_save_load_roundtrip(self, tmp_path):
        bank = TurboQuantMemoryBank(dim=256, chunk_size=32)
        vec = np.random.randn(256).astype(np.float32)
        bank.ingest("x", vec)

        path = tmp_path / "tq.bin"
        bank.save(str(path))

        bank2 = TurboQuantMemoryBank(dim=256, chunk_size=32)
        bank2.load(str(path))
        assert "x" in bank2._store
        recon = bank2.reconstruct("x")
        cos_sim = np.dot(vec, recon) / (np.linalg.norm(vec) * np.linalg.norm(recon))
        assert cos_sim > 0.85

    def test_empty_bank_similarity(self):
        bank = TurboQuantMemoryBank(dim=128, chunk_size=32)
        q = np.random.randn(128).astype(np.float32)
        assert bank.similarity(q) == []

    def test_dimension_mismatch(self):
        bank = TurboQuantMemoryBank(dim=128, chunk_size=32)
        with pytest.raises(ValueError):
            bank.ingest("bad", np.random.randn(64).astype(np.float32))


class TestFunctionEmbeddingEngine:
    def test_vectorize_basic(self):
        engine = FunctionEmbeddingEngine(dim=512)
        vec = engine.vectorize(
            instruction_mix={"mov": 10, "call": 5},
            apis=["VirtualAlloc", "CreateThread"],
            strings=["error", "config"],
            numeric_attrs={"size": 200, "entropy": 5.5},
        )
        assert vec.shape == (512,)
        assert vec.dtype == np.float32
        assert abs(np.linalg.norm(vec) - 1.0) < 1e-5  # normalized

    def test_vectorize_from_schemaboot_row(self):
        engine = FunctionEmbeddingEngine(dim=512)
        row = {
            "instruction_mix": {"mov": 20, "xor": 3},
            "apis": ["malloc", "free"],
            "strings": ["hello", "world"],
            "size": 150,
            "entropy": 6.2,
            "bb_count": 10,
            "call_count": 5,
            "cyclomatic_complexity": 3,
            "string_count": 2,
            "api_count": 2,
            "xref_count": 8,
            "loop_count": 1,
            "xor_count": 3,
        }
        vec = engine.vectorize_from_schemaboot_row(row)
        assert vec.shape == (512,)
        assert abs(np.linalg.norm(vec) - 1.0) < 1e-5

    def test_determinism(self):
        engine = FunctionEmbeddingEngine(dim=256)
        args = {
            "instruction_mix": {"call": 5},
            "apis": ["api"],
            "strings": ["str"],
            "numeric_attrs": {"size": 100},
        }
        v1 = engine.vectorize(**args)
        v2 = engine.vectorize(**args)
        assert np.allclose(v1, v2)

    def test_different_inputs_produce_different_vectors(self):
        engine = FunctionEmbeddingEngine(dim=256)
        v1 = engine.vectorize(instruction_mix={"mov": 10})
        v2 = engine.vectorize(instruction_mix={"call": 10})
        assert not np.allclose(v1, v2)
