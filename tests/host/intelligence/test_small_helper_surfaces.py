"""High-value boundary tests for small host helpers and source adapters."""

from __future__ import annotations

import json
import struct
import zipfile

import pytest

from ida_pro_mcp.host.analysis import patterns
from ida_pro_mcp.host.intelligence import helpers
from ida_pro_mcp.host.intelligence.model_profiles import (
    BGE_CODE_V1,
    QWEN3_EMBEDDING_0_6B,
    ZEMBED_1,
    get_model_profile,
    model_dimension,
    profile_from_model,
    read_gguf_metadata,
)
from ida_pro_mcp.host.intelligence.rerank_profiles import (
    BGE_RERANKER_V2_GEMMA,
    QWEN3_RERANKER_4B,
    get_rerank_model_profile,
    profile_from_rerank_model,
)
from ida_pro_mcp.host.intelligence.sources.lolbas import LolbasSource
from ida_pro_mcp.host.intelligence.sources.sigma_rules import SigmaRulesSource
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


def test_embedding_profiles_and_gguf_metadata_cover_scalar_array_and_fallback_modes(
    monkeypatch, tmp_path
):
    assert get_model_profile(None) is None
    assert get_model_profile(" BGE ") is BGE_CODE_V1
    assert get_model_profile("qwen3-embedding") is QWEN3_EMBEDDING_0_6B
    assert ZEMBED_1.format_text("query", "query").startswith("<|im_start|>system")
    assert QWEN3_EMBEDDING_0_6B.format_text("doc", "document") == "doc"
    assert profile_from_model("/models/zembed-1-q4.gguf") is ZEMBED_1
    assert profile_from_model("/models/bge-code-v1.gguf") is BGE_CODE_V1
    assert profile_from_model("/models/Qwen3-Embedding-0.6B.gguf") is QWEN3_EMBEDDING_0_6B

    scalar_values = [
        (0, "u8", struct.pack("<B", 1)),
        (1, "i8", struct.pack("<b", -1)),
        (2, "u16", struct.pack("<H", 2)),
        (3, "i16", struct.pack("<h", -2)),
        (4, "u32", struct.pack("<I", 4)),
        (5, "i32", struct.pack("<i", -4)),
        (6, "float", struct.pack("<f", 1.5)),
        (7, "bool", struct.pack("<?", True)),
        (10, "u64", struct.pack("<Q", 10)),
        (11, "i64", struct.pack("<q", -11)),
        (12, "double", struct.pack("<d", 12.5)),
    ]

    def string_value(value):
        raw = value.encode()
        return struct.pack("<Q", len(raw)) + raw

    rows = scalar_values + [
        (8, "text", string_value("hello")),
        (9, "array", struct.pack("<IQ", 0, 2) + struct.pack("<BB", 7, 8)),
    ]
    payload = bytearray(b"GGUF" + struct.pack("<IQQ", 3, 0, len(rows)))
    for value_type, key, value in rows:
        payload += string_value(key)
        payload += struct.pack("<I", value_type)
        payload += value
    model = tmp_path / "metadata.gguf"
    model.write_bytes(payload)
    metadata = read_gguf_metadata(str(model))
    assert metadata["gguf.version"] == 3
    assert metadata["u8"] == 1 and metadata["i8"] == -1
    assert metadata["float"] == pytest.approx(1.5)
    assert metadata["bool"] is True and metadata["text"] == "hello"
    assert metadata["array"] == [7, 8]

    assert read_gguf_metadata("") == {}
    assert read_gguf_metadata(str(tmp_path / "missing.gguf")) == {}
    bad = tmp_path / "bad.gguf"
    bad.write_bytes(b"NOPE")
    assert read_gguf_metadata(str(bad)) == {}
    bad.write_bytes(b"GGUF" + b"\x03\x00")
    assert read_gguf_metadata(str(bad)) == {}
    bad.write_bytes(b"GGUF" + struct.pack("<IQQ", 1, 0, 0))
    assert read_gguf_metadata(str(bad)) == {}

    # Exercise the three model-name metadata aliases, independent of the
    # filename heuristics above.
    for model_name, expected in (
        ("Zembed 1", ZEMBED_1),
        ("BGE Code v1", BGE_CODE_V1),
        ("Qwen3 Embedding 0.6B", QWEN3_EMBEDDING_0_6B),
    ):
        monkeypatch.setattr(
            "ida_pro_mcp.host.intelligence.model_profiles.read_gguf_metadata",
            lambda _path, model_name=model_name: {"general.name": model_name},
        )
        assert profile_from_model(str(tmp_path / "metadata-without-name.gguf")) is expected

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.model_profiles.read_gguf_metadata",
        lambda _path: {"general.name": "Custom", "general.architecture": "x", "x.embedding_length": 128},
    )
    custom = profile_from_model(str(tmp_path / "custom.gguf"))
    assert custom.key == "custom" and custom.dimension == 128 and custom.license == "unknown"
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.model_profiles.read_gguf_metadata",
        lambda _path: {"general.architecture": "x", "x.embedding_length": "bad"},
    )
    assert model_dimension(str(tmp_path / "custom.gguf"), BGE_CODE_V1) == BGE_CODE_V1.dimension


def test_gguf_reader_rejects_truncation_and_unsafe_sizes(tmp_path):
    model = tmp_path / "bad.gguf"

    def header(count=1, version=3):
        return b"GGUF" + struct.pack("<IQQ", version, 0, count)

    # A metadata key with no complete type/value must fail closed.
    model.write_bytes(header() + struct.pack("<Q", 3) + b"key" + b"\x00")
    assert read_gguf_metadata(str(model)) == {}
    for value in (
        string_value_for_test("scalar") + struct.pack("<I", 2) + b"\x01",
        string_value_for_test("string") + struct.pack("<I", 8) + b"\x01",
        string_value_for_test("array") + struct.pack("<I", 9) + b"\x00\x00\x00\x00",
    ):
        model.write_bytes(header() + value)
        assert read_gguf_metadata(str(model)) == {}
    # Unsupported value types and unreasonable string/array sizes are also
    # rejected by the same public parser boundary.
    for value in (
        string_value_for_test("x") + struct.pack("<I", 99),
        string_value_for_test("x") + struct.pack("<I", 8) + struct.pack("<Q", 17 * 1024 * 1024),
        string_value_for_test("x") + struct.pack("<I", 9) + struct.pack("<IQ", 0, 10_000_001),
    ):
        model.write_bytes(header() + value)
        assert read_gguf_metadata(str(model)) == {}


def string_value_for_test(value: str) -> bytes:
    raw = value.encode()
    return struct.pack("<Q", len(raw)) + raw


def test_sigma_source_selects_roots_deduplicates_tags_and_extracts_archives(tmp_path):
    root = tmp_path / "sigma-main" / "rules"
    root.mkdir(parents=True)
    tags = "  - sigma.tag0\n" + "\n".join(f"  - sigma.tag{i}" for i in range(18))
    (root / "a.yml").write_text(
        "title: \"Suspicious shell\"\n"
        "description: \"desc\"\n"
        "status: stable\nlevel: high\nid: rule-1\ntags:\n"
        f"{tags}\n",
        encoding="utf-8",
    )
    (root / "z.yaml").write_text("title: Suspicious shell\n", encoding="utf-8")
    (root / "ignored.txt").write_text("title: ignored\n", encoding="utf-8")
    source = SigmaRulesSource()
    entries = source.parse(str(tmp_path))
    assert len(entries) == 1
    assert entries[0]["id"] == "rule-1"
    assert entries[0]["name"] == "Suspicious shell"
    assert len(entries[0]["tags"]) == 16
    assert source._extract_yaml_field("title: \"x\"", "description") == ""

    archive = tmp_path / "sigma.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("sigma-main/rules/a.yml", "title: a\n")
    extracted = []
    source._safe_extract = lambda zf, dest: extracted.append((zf.namelist(), dest))
    source._post_download(str(archive), str(tmp_path / "out"))
    source._post_download(str(tmp_path / "sigma.tar"), str(tmp_path / "out"))
    assert extracted and extracted[0][0] == ["sigma-main/rules/a.yml"]


def test_sigma_source_skips_unreadable_and_oversized_rules(tmp_path, monkeypatch):
    root = tmp_path / "rules"
    root.mkdir()
    unreadable = root / "unreadable.yml"
    oversized = root / "oversized.yml"
    unreadable.write_text("title: unreadable\n", encoding="utf-8")
    oversized.write_text("title: oversized\n", encoding="utf-8")
    real_getsize = __import__("os").path.getsize

    def getsize(path):
        if path == str(unreadable):
            raise OSError("gone")
        if path == str(oversized):
            return 500_001
        return real_getsize(path)

    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.sources.sigma_rules.os.path.getsize",
        getsize,
    )
    assert SigmaRulesSource().parse(str(tmp_path)) == []
