from __future__ import annotations

import os
from pathlib import Path

import pytest

from ida_pro_mcp.host.stores.symbol_db import (
    SymbolDB,
    _confine_db_path,
    _default_db_path,
)


def test_confine_db_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path))

    # Default path
    def_path = _default_db_path()
    assert str(tmp_path) in def_path

    # In-root path
    valid_sub = tmp_path / "sub" / "symbols.db"
    confined = _confine_db_path(str(valid_sub))
    assert confined == str(valid_sub.resolve())

    # Path traversal with .. is rejected
    with pytest.raises(ValueError, match="must not contain '..'"):
        _confine_db_path(str(tmp_path / ".." / "escaped.db"))

    # Out of root path whose parent does not exist is rejected
    with pytest.raises(ValueError, match="outside the data root and its parent does not exist"):
        _confine_db_path("/nonexistent_dir_12345/db.sqlite")


def test_symbol_db_crud_and_lookups(tmp_path: Path) -> None:
    db_file = tmp_path / "symbol_test.db"
    db = SymbolDB(str(db_file))

    # Empty symbol or fingerprint returns 0
    assert db.upsert_symbol({"symbol_name": "", "fingerprint": "abc"}) == 0
    assert db.upsert_symbol({"symbol_name": "crypto_aes", "fingerprint": ""}) == 0

    # Insert new symbol
    sym_id = db.upsert_symbol(
        {
            "symbol_name": "crypto_aes_init",
            "source_session": "sess-1",
            "source_binary": "firmware.bin",
            "source_addr": "0x401000",
            "chip_family": "cortex-m4",
            "fingerprint": "fp_aes_1234",
            "callgraph_hash": "cg_hash_1",
            "strings": ["AES Key Schedule", "Rijndael"],
            "confidence": 0.95,
        }
    )
    assert sym_id > 0

    # Query symbols by name
    results = db.query_symbols("aes", limit=10)
    assert len(results) >= 1
    assert results[0]["symbol_name"] == "crypto_aes_init"
    assert "AES Key Schedule" in results[0]["strings"]
    assert results[0]["chip_family"] == "cortex-m4"

    # Query symbols by string content
    str_results = db.query_symbols("Rijndael", limit=10)
    assert len(str_results) >= 1
    assert str_results[0]["symbol_name"] == "crypto_aes_init"

    # Lookup by fingerprint
    fp_results = db.lookup_by_fingerprint("fp_aes_1234")
    assert len(fp_results) == 1
    assert fp_results[0]["symbol_name"] == "crypto_aes_init"

    # Update existing symbol (same name & fingerprint)
    updated_id = db.upsert_symbol(
        {
            "symbol_name": "crypto_aes_init",
            "fingerprint": "fp_aes_1234",
            "chip_family": "cortex-m4",
            "confidence": 0.99,
        }
    )
    assert updated_id == sym_id
    fp_results2 = db.lookup_by_fingerprint("fp_aes_1234")
    assert fp_results2[0]["confidence"] == 0.99

    # Stats by chip
    stats = db.stats_by_chip()
    assert len(stats) >= 1
    assert stats[0]["chip_family"] == "cortex-m4"
    assert stats[0]["symbol_count"] >= 1


def test_symbol_db_hypotheses(tmp_path: Path) -> None:
    db_file = tmp_path / "hypotheses_test.db"
    db = SymbolDB(str(db_file))

    # Empty inputs return 0
    assert db.upsert_hypothesis(binary_hash="", addr_offset=0, hypothesis_text="text") == 0
    assert db.upsert_hypothesis(binary_hash="hash1", addr_offset=0, hypothesis_text="") == 0

    # Insert hypothesis
    h_id = db.upsert_hypothesis(
        binary_hash="bin_sha256_abc",
        addr_offset=0x2000,
        hypothesis_text="Likely FreeRTOS task scheduler",
        confidence=0.85,
        chip_family="stm32",
        source_session="sess-2",
        source_binary="sample.elf",
    )
    assert h_id > 0

    # Query hypotheses by binary_hash
    res = db.query_hypotheses(binary_hash="bin_sha256_abc")
    assert len(res) == 1
    assert res[0]["hypothesis_text"] == "Likely FreeRTOS task scheduler"
    assert res[0]["addr_offset"] == 0x2000

    # Query hypotheses by chip_family
    res_chip = db.query_hypotheses(chip_family="stm32")
    assert len(res_chip) == 1

    # Query with empty filters returns []
    assert db.query_hypotheses() == []

    # Update hypothesis (same binary_hash, offset, hypothesis_text)
    h_id2 = db.upsert_hypothesis(
        binary_hash="bin_sha256_abc",
        addr_offset=0x2000,
        hypothesis_text="Likely FreeRTOS task scheduler",
        confidence=0.95,
        chip_family="stm32",
    )
    assert h_id2 == h_id
    res_updated = db.query_hypotheses(binary_hash="bin_sha256_abc")
    assert res_updated[0]["confidence"] == 0.95
