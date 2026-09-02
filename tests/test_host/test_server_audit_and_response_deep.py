from __future__ import annotations

import json
from pathlib import Path

import pytest

from ida_pro_mcp.host.server.audit import (
    AuditLogger,
    _bounded_result_size,
    _canonical_args_hash,
    _sample_value,
    _shallow,
)


def test_bounded_result_size_and_sample() -> None:
    assert _bounded_result_size(None) == 0
    assert _bounded_result_size("text") == 4
    assert _bounded_result_size(b"bytes") == 5

    data = {"k1": "v1", "k2": [1, 2, 3]}
    size = _bounded_result_size(data)
    assert size > 0

    sampled = _sample_value(data)
    assert sampled["k1"] == "v1"


def test_shallow_and_canonical_args_hash() -> None:
    assert _shallow(None) is None
    assert _shallow(True) is True
    assert _shallow(123) == 123
    assert _shallow("abc") == "abc"
    assert _shallow(b"\xde\xad\xbe\xef") == "deadbeef"

    nested = {"a": {"b": {"c": {"d": "too_deep"}}}}
    res = _shallow(nested)
    assert res["a"]["b"]["c"] == "<truncated>"

    # Large list truncation
    big_list = list(range(50))
    res_list = _shallow(big_list, max_items=5)
    assert len(res_list) == 6
    assert res_list[-1] == "<+45>"

    # Canonical hash
    h1 = _canonical_args_hash({"a": 1, "b": 2})
    h2 = _canonical_args_hash({"b": 2, "a": 1})
    assert h1 == h2
    assert len(h1) == 16


def test_audit_logger_write(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    logger = AuditLogger(str(log_dir))

    logger.log(
        tool="search",
        action="find",
        args={"query": "main"},
        result={"address": "0x401000"},
        latency_ms=12.5,
        session_id="sess_test",
    )

    # Check that a .jsonl file was created
    jsonl_files = list(log_dir.rglob("*.jsonl"))
    assert len(jsonl_files) == 1

    lines = jsonl_files[0].read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["tool"] == "search"
    assert record["action"] == "find"
    assert record["session_id"] == "sess_test"
