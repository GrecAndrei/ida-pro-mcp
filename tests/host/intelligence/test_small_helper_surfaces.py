"""High-value boundary tests for small host helpers and source adapters."""

from __future__ import annotations

import json
import zipfile

import pytest

from ida_pro_mcp.host.analysis import patterns
from ida_pro_mcp.host.intelligence import helpers
from ida_pro_mcp.host.intelligence.rerank_profiles import (
    BGE_RERANKER_V2_GEMMA,
    QWEN3_RERANKER_4B,
    get_rerank_model_profile,
    profile_from_rerank_model,
)
from ida_pro_mcp.host.intelligence.sources.lolbas import LolbasSource
from ida_pro_mcp.host.intelligence.sources.yara_source import YaraSource


def test_numeric_vector_and_text_helpers_cover_fallbacks():
    assert helpers.quantile([], 0.5, default=3) == 3.0
    assert helpers.quantile([2], 0.5) == 2.0
    assert helpers.quantile([3, 1, 2], -1) == 1.0
    assert helpers.quantile([3, 1, 2], 2) == 3.0
    assert helpers.dot_product([1, 2], [3, 4]) == 11.0
    assert helpers.cosine_similarity([0, 0], [1, 0]) == 0.0
    assert helpers.similarity_ratio("abc", "abd") > 0.5
    assert helpers.best_match("helo", ["hello"], n=1, cutoff=0.5) == ["hello"]
    assert helpers.estimate_tokens("") == 0 and helpers.estimate_tokens("12345678") == 2
    assert helpers.coerce_int(None, 9) == 9
    assert helpers.coerce_int(True) == 1
    assert helpers.coerce_int(12) == 12
    assert helpers.coerce_int("  ", 9) == 9
    assert helpers.coerce_int("0x10") == 16
    assert helpers.coerce_int("10") == 10
    assert helpers.coerce_int("ff") == 255
    assert helpers.coerce_int("bad-value", 7) == 7
    assert helpers.coerce_int(object(), 8) == 8
    assert helpers.parse_str_list(None) == []
    assert helpers.parse_str_list([" a ", None, ""]) == ["a"]
    assert helpers.parse_str_list(("a", " b ")) == ["a", "b"]
    assert helpers.parse_str_list("a, ,b") == ["a", "b"]
    assert helpers.parse_str_list(12, sep="|") == ["12"]
    assert helpers.parse_str_list("   ") == []
    assert helpers.decomp_document_char_budget(10000, explicit_chars=0, fraction=0) == 1024

    with pytest.raises(ValueError, match="dimension mismatch"):
        helpers._batch_cosine_numpy(__import__("numpy"), [1, 2], [[1]])
    with pytest.raises(ValueError, match="unexpected array shape"):
        helpers._batch_cosine_numpy(__import__("numpy"), [[1, 2]], [[1, 2]])


def test_rerank_profiles_alias_filename_metadata_and_custom_modes(monkeypatch, tmp_path):
    assert get_rerank_model_profile(None) is None
    assert get_rerank_model_profile("qwen3") .key == "qwen3-reranker-0.6b"
    assert get_rerank_model_profile("bge-m3").opt_in is True
    assert profile_from_rerank_model("/tmp/Qwen3-Reranker-4B-Q4.gguf") is QWEN3_RERANKER_4B
    assert profile_from_rerank_model("/tmp/unknown.gguf", requested="bge") is BGE_RERANKER_V2_GEMMA

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.rerank_profiles.read_gguf_metadata",
        lambda _path: {"general.name": "BGE-Reranker gemma", "general.license": "custom"},
    )
    assert profile_from_rerank_model(str(tmp_path / "model.bin")).family == "bge"
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.rerank_profiles.read_gguf_metadata",
        lambda _path: {"general.name": "BGE-Reranker M3"},
    )
    assert profile_from_rerank_model(str(tmp_path / "model.bin")).key == "bge-reranker-v2-m3"
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.rerank_profiles.read_gguf_metadata",
        lambda _path: {"general.name": "Qwen3-Reranker 4B"},
    )
    assert profile_from_rerank_model(str(tmp_path / "model.bin")) is QWEN3_RERANKER_4B
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.rerank_profiles.read_gguf_metadata",
        lambda _path: {"general.name": "Qwen3-Reranker 0.6B"},
    )
    assert profile_from_rerank_model(str(tmp_path / "model.bin")).key == "qwen3-reranker-0.6b"
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.rerank_profiles.read_gguf_metadata",
        lambda _path: {"general.name": "private-model", "general.license": "MIT"},
    )
    custom = profile_from_rerank_model(str(tmp_path / "model.bin"))
    assert custom.key == "custom-rerank" and custom.license == "MIT" and custom.opt_in is True


def test_lolbas_parser_handles_fallback_files_and_malformed_commands(tmp_path):
    source = LolbasSource()
    assert source.parse(str(tmp_path)) == []
    data = [
        {"Name": "certutil.exe", "Description": "desc", "Full_Path": "C:\\Windows", "Commands": [
            {"MitreID": "T1105, T1140", "Category": "Download", "Command": "-url", "Privilege": "User", "Description": "fetch"},
            {"MitreID": "T1105", "Usecase": "Download", "Command": "-decode"},
            "bad-command",
        ]},
        {"Description": "missing name", "Commands": []},
        "not-a-dict",
    ]
    (tmp_path / "other.json").write_text(json.dumps(data), encoding="utf-8")
    rows = source.parse(str(tmp_path))
    assert len(rows) == 1
    assert rows[0]["id"] == "LOLBAS-certutil.exe"
    assert rows[0]["techniques"] == ["T1105", "T1140"]
    assert rows[0]["tactics"] == ["Download"]
    assert rows[0]["commands"][0]["privilege"] == "User"
    (tmp_path / "other.json").write_text("{broken", encoding="utf-8")
    assert source.parse(str(tmp_path)) == []


def test_yara_source_discovers_rules_and_extracts_archives(monkeypatch, tmp_path):
    root = tmp_path / "rules"
    root.mkdir()
    (root / "one.yar").write_text("rule one {}", encoding="utf-8")
    yara = YaraSource()
    calls = []

    monkeypatch.setattr("ida_pro_mcp.host.intelligence.threat_corpus.parse_yara_dir", lambda path: calls.append(path) or [{"name": "one"}])
    rows = yara.parse(str(tmp_path))
    assert rows == [{"name": "one"}] and calls == [str(root)]

    archive = tmp_path / "rules.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("safe/rule.yar", "rule safe {}")
    extracted = []
    monkeypatch.setattr(yara, "_safe_extract", lambda zf, dest: extracted.append((zf.namelist(), dest)))
    yara._post_download(str(archive), str(tmp_path / "out"))
    assert extracted and extracted[0][0] == ["safe/rule.yar"]
    yara._post_download(str(tmp_path / "rules.txt"), str(tmp_path / "out"))
