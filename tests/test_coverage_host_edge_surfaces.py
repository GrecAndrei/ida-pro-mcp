"""Behavior tests for small production surfaces missed by the broad suite."""

from __future__ import annotations

import sqlite3
from datetime import datetime

import pytest

from ida_pro_mcp.host import config
from ida_pro_mcp.host.analysis import context_density, patterns
from ida_pro_mcp.host.response_enrichment import digest_decompiled, patch_addresses
from ida_pro_mcp.host.stores.symbol_db import SymbolDB, _confine_db_path


def test_config_runtime_and_r2_fallbacks_are_deterministic(monkeypatch, tmp_path):
    monkeypatch.delenv("IDA_MCP_CACHE_DIR", raising=False)
    monkeypatch.delenv("IDA_MCP_DATA_DIR", raising=False)
    fallback = tmp_path / "fallback"
    monkeypatch.setattr(config, "_default_runtime_dir", lambda: str(fallback))
    assert config._resolve_runtime_dir() == str(fallback)

    monkeypatch.setenv("IDA_MCP_R2_BIN", "   ")
    assert config._resolve_r2_bin() == "r2"
    monkeypatch.delenv("IDA_MCP_R2_BIN")
    monkeypatch.setattr(config.shutil, "which", lambda name: "/bin/rz" if name == "rz" else None)
    assert config._resolve_r2_bin() == "/bin/rz"
    monkeypatch.setattr(config.shutil, "which", lambda name: "/bin/r2" if name == "r2" else None)
    assert config._resolve_r2_bin() == "/bin/r2"
    monkeypatch.setattr(config.shutil, "which", lambda _name: None)
    assert config._resolve_r2_bin() == "r2"

    monkeypatch.setenv("IDA_MCP_R2_BININFO_BIN", "   ")
    assert config._resolve_r2_bininfo_bin() == "rabin2"
    monkeypatch.delenv("IDA_MCP_R2_BININFO_BIN")
    monkeypatch.setattr(config.shutil, "which", lambda name: "/bin/rz-bin" if name == "rz-bin" else None)
    assert config._resolve_r2_bininfo_bin() == "/bin/rz-bin"
    monkeypatch.setattr(config.shutil, "which", lambda name: "/bin/rabin2" if name == "rabin2" else None)
    assert config._resolve_r2_bininfo_bin() == "/bin/rabin2"
    monkeypatch.setattr(config.shutil, "which", lambda _name: None)
    assert config._resolve_r2_bininfo_bin() == "rabin2"

    assert config._parse_int(None) is None
    assert config._parse_int(True) is None
    assert config._parse_int(7) == 7
    assert config._parse_int(" 9 ") == 9
    assert config._parse_int("not-an-int") is None
    assert config._parse_iso_datetime(datetime(2025, 1, 1)) == datetime(2025, 1, 1)


def test_config_migration_and_rotation_failure_paths_are_safe(monkeypatch, tmp_path):
    script_dir = tmp_path / "script"
    script_dir.mkdir()
    monkeypatch.setattr(config, "__file__", str(script_dir / "config.py"))
    target = tmp_path / "target"

    # No legacy directory and an already-equal target are both no-ops.
    config._migrate_legacy_runtime_dir(str(target))
    legacy = script_dir / "ida_mcp_cache"
    legacy.mkdir()
    config._migrate_legacy_runtime_dir(str(legacy))

    # A target that cannot be created is ignored without leaking the error.
    with monkeypatch.context() as patch:
        patch.setattr(config.os, "makedirs", lambda *_a, **_k: (_ for _ in ()).throw(OSError("read-only")))
        config._migrate_legacy_runtime_dir(str(target))

    (legacy / "broken.txt").write_text("x", encoding="utf-8")
    with monkeypatch.context() as patch:
        patch.setattr(config.shutil, "copy2", lambda *_a, **_k: (_ for _ in ()).throw(OSError("copy failed")))
        config._migrate_legacy_runtime_dir(str(target))

    monkeypatch.setattr(config, "_BRIDGE_LOG_MAX_BYTES", 0)
    config._rotate_bridge_log_if_needed()
    monkeypatch.setattr(config, "_BRIDGE_LOG_MAX_BYTES", 1)
    monkeypatch.setattr(config, "BRIDGE_LOG", str(tmp_path / "missing" / "bridge.log"))
    config._rotate_bridge_log_if_needed()


def test_symbol_db_repairs_legacy_duplicate_rows_and_handles_empty_queries(tmp_path):
    assert _confine_db_path("").endswith("symbol_kb.db")
    db_path = tmp_path / "legacy.db"
    SymbolDB(str(db_path))
    SymbolDB._initialized_paths.discard(str(db_path))

    conn = sqlite3.connect(db_path)
    conn.execute("DROP INDEX idx_symbols_uniq")
    row = ("handler", "", "", "0x1000", "arm", "same-fp", "", "[]", "[]", 0.5, 1.0, 1.0)
    conn.execute(
        "INSERT INTO symbols(symbol_name, source_session, source_binary, source_addr, chip_family, "
        "fingerprint, callgraph_hash, strings_json, embedding_json, confidence, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        row,
    )
    conn.execute(
        "INSERT INTO symbols(symbol_name, source_session, source_binary, source_addr, chip_family, "
        "fingerprint, callgraph_hash, strings_json, embedding_json, confidence, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        row,
    )
    conn.commit()
    conn.close()

    repaired = SymbolDB(str(db_path))
    assert repaired.query_symbols("handler")
    assert repaired.query_hypotheses() == []


def test_response_enrichment_schema_and_conversion_boundaries(monkeypatch):
    import ida_pro_mcp.host.response_enrichment as enrichment

    monkeypatch.setattr(
        enrichment,
        "coerce_int",
        lambda _value: (_ for _ in ()).throw(ValueError("bad offset")),
    )
    assert patch_addresses("mov rax, [rsp+0x10]", {"rsp": 0x1000}) == "mov rax, [rsp+0x10]"
    assert patch_addresses("lea rax, [unknown+0x10]", {}) == "lea rax, [unknown+0x10]"
    assert digest_decompiled(None) == {}
    duplicate = digest_decompiled("malloc(); malloc();")
    assert duplicate["api_calls"] == ["malloc"]

    result = digest_decompiled(
        "if (IsDebuggerPresent()) { VirtualAlloc(); CryptEncrypt(); }",
        {
            "apis": ["connect"],
            "has_loops": True,
            "cyclomatic_complexity": 4,
            "entropy": 7.12345,
            "xref_count": 3,
            "has_crypto_constants": True,
        },
    )
    assert result["complexity"]["has_loops"] is True
    assert result["complexity"]["cyclomatic_complexity"] == 4
    assert result["complexity"]["entropy"] == 7.123
    assert result["complexity"]["xref_count"] == 3
    assert {"network", "crypto", "allocator"}.issubset(result["behavior_tags"])
    assert "Crypto constants (verified by structural analysis)" in result["patterns"]


def test_matching_modes_cover_flags_and_successful_fuzzy_hits(monkeypatch, tmp_path):
    assert patterns._compile_smart_pattern_uncached("/foo/ms")("foo\nbar") is True
    matcher = patterns._compile_semantic_matcher("decrypt buffer", fuzzy_cutoff=0.5)
    assert matcher is not None
    assert matcher("decrpyt buffer") is True
    assert patterns.looks_like_code(b"\x00" + bytes(range(1, 65)), max_zero_ratio=0.01) is False

    monkeypatch.setenv("HOME", str(tmp_path))
    facts = patterns.GlobalFactsDatabase()
    assert facts.count() > 0
    facts.close()
    facts.close()


def test_context_density_short_blocks_and_module_wrappers():
    optimizer = context_density.ContextDensityOptimizer(max_code_preview=3)
    short = "```python\nreturn 1\n```"
    assert optimizer.compress_code_blocks(short) == short
    assert optimizer.compress_xref_lists([1, 2]) == [1, 2]
    assert optimizer._compact_recursive([1, 2], 10) == [1, 2]
    assert optimizer.compress_xref_lists(42) == 42
    assert context_density.compact_response({"address": "0x401000"}) == {"address": "0x401000"}
    assert context_density.measure_information_density("0x401000")["estimated_tokens"] > 0


@pytest.mark.parametrize("value", ["", " ", "\n"])
def test_context_density_empty_text_wrappers(value):
    assert context_density.measure_information_density(value)["density_score"] == 0.0
