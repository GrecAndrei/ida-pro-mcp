"""ThreatCorpus holder, modular cache, and singleton loader tests.

Covers the corpus object (indexes, lookups, serialization), the per-source
cache files + manifest round-trip, V1 migration, and the lazy singleton
(no network — downloads are monkeypatched or avoided entirely).
"""

from __future__ import annotations

import json
import os

import pytest

from ida_pro_mcp.host.intelligence import threat_corpus as tc_mod
from ida_pro_mcp.host.intelligence.threat_corpus import ThreatCorpus

CWE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns:cwe="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <cwe:Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation" Status="Incomplete" Abstraction="Class">
      <cwe:Description>Cross-Site Scripting.</cwe:Description>
    </cwe:Weakness>
    <cwe:Weakness ID="999" Name="Deprecated" Status="Deprecated"/>
  </Weaknesses>
</Weakness_Catalog>
"""

STIX_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1",
            "name": "Spearphishing Attachment",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566.001"},
            ],
            "kill_chain_phases": [{"phase_name": "initial-access"}],
        },
        {
            "type": "malware",
            "id": "malware--2",
            "name": "TrickBot",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0266"},
            ],
            "x_mitre_aliases": ["TrickBot", "TrickBot Loader"],
        },
    ],
}

YARA_RULE = """rule suspicious_usage
{
    strings:
        $a = "CreateRemoteThread"
        $b = "VirtualAllocEx"
    condition:
        $a or $b
}
"""


def _write(path, text):
    path.write_text(text, encoding="utf-8")


def _sample_corpus() -> ThreatCorpus:
    return ThreatCorpus(
        entries={
            "cwe": [{"id": "CWE-79", "name": "XSS", "description": "injection"}],
            "attack_patterns": [{"id": "T1566.001", "name": "Spearphish", "aliases": ["Phish"]}],
            "malware": [{"id": "S0266", "name": "TrickBot", "aliases": ["trickbot", "TrickBot Loader"]}],
            "yara_rules": [
                {"id": "rule-1", "name": "suspicious_usage", "strings": ["CreateRemoteThread", "VirtualAllocEx"]},
            ],
            "lolbas": [{"id": "LOLBAS-cmd", "name": "cmd.exe", "description": "shell"}],
        },
        source_fingerprints={
            src: f"fp-{src}"
            for src in ("cwe", "attack_patterns", "malware", "yara_rules", "lolbas")
        },
        built_at="2026-01-01T00:00:00Z",
    )


@pytest.fixture
def isolated_cache(monkeypatch, tmp_path):
    cache_dir = tmp_path / "corpus"
    monkeypatch.setattr(tc_mod, "CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(tc_mod, "CORPUS_CACHE_DIR", str(cache_dir))
    monkeypatch.setattr(tc_mod, "MANIFEST_PATH", str(cache_dir / "manifest.json"))
    monkeypatch.setattr(tc_mod, "CORPUS_CACHE_FILENAME", "threat_corpus_v2.json")
    monkeypatch.setattr(tc_mod, "_corpus_singleton", None)
    return cache_dir


class TestCorpusObject:
    def test_properties_counts_and_sources(self):
        c = _sample_corpus()
        assert c.cwe[0]["id"] == "CWE-79"
        assert c.attack_patterns[0]["name"] == "Spearphish"
        assert c.malware[0]["name"] == "TrickBot"
        assert c.yara_rules[0]["name"] == "suspicious_usage"
        assert c.count_by_type() == {
            "cwe": 1, "attack_patterns": 1, "malware": 1, "yara_rules": 1, "lolbas": 1,
        }
        assert c.available_sources() == ["attack_patterns", "cwe", "lolbas", "malware", "yara_rules"]
        assert c.is_empty() is False
        assert ThreatCorpus().is_empty() is True
        assert ThreatCorpus().count_by_type() == {}

    def test_find_cwe_normalizes_prefix(self):
        c = _sample_corpus()
        assert c.find_cwe("79")["id"] == "CWE-79"
        assert c.find_cwe("CWE-79")["id"] == "CWE-79"
        assert c.find_cwe("") is None
        assert c.find_cwe("CWE-1") is None

    def test_find_technique_and_malware(self):
        c = _sample_corpus()
        assert c.find_technique("t1566.001")["id"] == "T1566.001"
        assert c.find_technique("T1566.001")["id"] == "T1566.001"
        assert c.find_technique("") is None
        assert c.find_malware("trickbot")["id"] == "S0266"
        assert c.find_malware("TrickBot Loader")["id"] == "S0266"
        assert c.find_malware("") is None
        assert c.find_malware("nope") is None

    def test_search_yara_strings_exact_and_substring(self):
        c = _sample_corpus()
        exact = c.search_yara_strings("createremotethread")
        assert [r["name"] for r in exact] == ["suspicious_usage"]
        sub = c.search_yara_strings("remotethread")
        assert [r["name"] for r in sub] == ["suspicious_usage"]
        assert c.search_yara_strings("") == []
        assert c.search_yara_strings("zzz") == []

    def test_all_yara_strings_min_len_and_dedup(self):
        c = ThreatCorpus(entries={
            "yara_rules": [
                {"name": "r1", "strings": ["ab", "HELLO", "hello", "world"]},
            ],
            "yara_rules_extra": [
                {"name": "r2", "strings": ["world", "longstring"]},
            ],
        })
        out = c.all_yara_strings(min_len=4)
        assert out == ["HELLO", "world", "longstring"]  # dedup, case-insensitive
        assert c.all_yara_strings(min_len=10) == ["longstring"]
        limited = c.all_yara_strings(min_len=4, max_count=2)
        assert len(limited) == 2

    def test_search_fulltext_and_get_by_id(self):
        c = _sample_corpus()
        hits = c.search("lolbas", "shell", limit=1)
        assert [h["id"] for h in hits] == ["LOLBAS-cmd"]
        assert c.search("lolbas", "") == []
        assert c.get_by_id("cwe", "CWE-79")["name"] == "XSS"
        assert c.get_by_id("cwe", "missing") is None
        assert c.get_source_entries("nope") == []

    def test_serialization_roundtrip(self):
        c = _sample_corpus()
        restored = ThreatCorpus.from_dict(c.to_dict())
        assert restored.built_at == c.built_at
        assert restored.source_fingerprints == c.source_fingerprints
        assert restored.cwe == c.cwe
        assert restored.find_malware("trickbot") is not None

    def test_from_dict_v1_migration(self):
        v1 = {
            "version": 1,
            "built_at": "2025-01-01",
            "source_fingerprint": "abc",
            "cwe": [{"id": "CWE-89", "name": "SQLi"}],
            "attack_patterns": [{"id": "T1059", "name": "Cmd"}],
            "malware": [],
        }
        migrated = ThreatCorpus.from_dict(v1)
        assert migrated.cwe[0]["id"] == "CWE-89"
        assert migrated.attack_patterns[0]["id"] == "T1059"
        assert migrated.source_fingerprints == {"combined": "abc"}
        assert migrated.built_at == "2025-01-01"
        assert ThreatCorpus.from_dict(None).is_empty() is True

    def test_helpers(self):
        assert tc_mod._clip(None) == ""
        assert tc_mod._clip("  x  ") == "x"
        long = tc_mod._clip("a" * 500, max_len=16)
        assert len(long) == 16 and long.endswith("...")
        assert tc_mod._coerce_str_list(None) == []
        assert tc_mod._coerce_str_list("x") == ["x"]
        assert tc_mod._coerce_str_list(["a", "a", "", None, "b"]) == ["a", "b"]
        assert tc_mod._coerce_str_list({"not": "list"}) == []
        assert tc_mod._coerce_str_list(["a" * 300], item_max=10) == ["a" * 10]
        assert tc_mod._coerce_str_list(list(range(40)), max_items=5) == ["0", "1", "2", "3", "4"]
        assert tc_mod._local_name("{ns}tag") == "tag"
        assert tc_mod._local_name("plain") == "plain"


class TestCorpusCache:
    def test_save_and_load_roundtrip(self, isolated_cache):
        c = _sample_corpus()
        manifest = tc_mod.save_corpus(c)
        assert os.path.isfile(manifest)
        assert os.path.isfile(tc_mod._source_cache_path("cwe"))
        loaded = tc_mod.load_corpus()
        assert loaded is not None
        assert loaded.cwe == c.cwe
        assert loaded.malware == c.malware
        assert loaded.source_fingerprints == c.source_fingerprints
        assert loaded.built_at == c.built_at

    def test_save_backs_up_legacy_file(self, isolated_cache, tmp_path):
        legacy = tc_mod.corpus_cache_path()
        os.makedirs(os.path.dirname(legacy), exist_ok=True)
        with open(legacy, "w", encoding="utf-8") as f:
            f.write("{}")
        tc_mod.save_corpus(_sample_corpus())
        assert os.path.isfile(legacy + ".v1_backup")
        assert not os.path.isfile(legacy)

    def test_load_manifest_missing_or_corrupt(self, isolated_cache):
        assert tc_mod._load_manifest() is None
        os.makedirs(isolated_cache, exist_ok=True)
        (isolated_cache / "manifest.json").write_text("{bad json")
        assert tc_mod._load_manifest() is None

    def test_load_modular_skips_missing_and_corrupt_sources(self, isolated_cache, tmp_path):
        os.makedirs(isolated_cache, exist_ok=True)
        (isolated_cache / "a.json").write_text(json.dumps({"entries": [{"id": "a1"}], "fingerprint": "f1", "built_at": "t"}))
        (isolated_cache / "b.json").write_text("{bad")
        manifest = {
            "version": 2,
            "sources": {"a": {"count": 1}, "b": {"count": 1}, "missing": {"count": 1}},
        }
        corpus = tc_mod._load_modular_corpus(manifest)
        assert corpus is not None
        assert corpus.entries == {"a": [{"id": "a1"}]}
        assert corpus.source_fingerprints == {"a": "f1"}

    def test_load_v1_corpus(self, isolated_cache):
        legacy = tc_mod.corpus_cache_path()
        os.makedirs(os.path.dirname(legacy), exist_ok=True)
        with open(legacy, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "cwe": [{"id": "CWE-1"}], "source_fingerprint": "old"}, f)
        loaded = tc_mod.load_corpus()
        assert loaded is not None
        assert loaded.cwe[0]["id"] == "CWE-1"
        assert loaded.source_fingerprints == {"combined": "old"}

    def test_load_corpus_none_when_empty(self, isolated_cache):
        assert tc_mod.load_corpus() is None

    def test_delete_corpus_cache(self, isolated_cache, tmp_path):
        assert tc_mod.delete_corpus_cache() is False
        tc_mod.save_corpus(_sample_corpus())
        legacy = tc_mod.corpus_cache_path()
        os.makedirs(os.path.dirname(legacy), exist_ok=True)
        with open(legacy, "w", encoding="utf-8") as f:
            f.write("{}")
        assert tc_mod.delete_corpus_cache() is True
        assert os.listdir(isolated_cache) == []
        assert not os.path.isfile(legacy)


class TestCorpusSingleton:
    def test_ensure_loaded_from_cache_then_singleton(self, isolated_cache):
        tc_mod.save_corpus(_sample_corpus())
        corpus, info = tc_mod.ensure_corpus_loaded()
        assert corpus is not None
        assert info["from_cache"] is True
        assert info["singleton"] is True
        assert info["counts"]["cwe"] == 1
        again, info2 = tc_mod.ensure_corpus_loaded()
        assert again is corpus
        assert info2["loaded"] is True

    def test_ensure_loaded_builds_from_explicit_sources(self, isolated_cache, tmp_path):
        cwe = tmp_path / "cwec.xml"
        _write(cwe, CWE_XML)
        attack = tmp_path / "attack.json"
        _write(attack, json.dumps(STIX_BUNDLE))
        yara_dir = tmp_path / "yara"
        yara_dir.mkdir()
        _write(yara_dir / "apt.yar", YARA_RULE)

        corpus, info = tc_mod.ensure_corpus_loaded(
            cwe_path=str(cwe), attack_paths=[str(attack)], yara_dir=str(yara_dir)
        )
        assert corpus is not None
        assert info["rebuilt"] is True
        assert info["from_cache"] is False
        assert corpus.cwe[0]["id"] == "CWE-79"
        assert corpus.attack_patterns[0]["id"] == "T1566.001"
        assert corpus.malware[0]["id"] == "S0266"
        assert corpus.yara_rules[0]["name"] == "suspicious_usage"
        # Deprecated CWE-999 excluded.
        assert len(corpus.cwe) == 1
        # Persisted to the cache for the next process.
        assert tc_mod.load_corpus() is not None

    def test_ensure_loaded_auto_download(self, isolated_cache, tmp_path):
        data_dir = tmp_path / "dl"
        data_dir.mkdir()
        _write(data_dir / "lolbas.json", json.dumps([
            {"Name": "certutil.exe", "Description": "download", "Full_Path": "", "Commands": [
                {"Command": "certutil -urlcache", "Category": "Download", "MitreID": "T1105"},
            ]},
        ]))

        def _fake_download(dest_dir=None, force=False, progress_cb=None, sources=None):
            return {"source_dirs": {"lolbas": str(data_dir)}, "downloaded": [], "errors": []}

        tc_mod.download_corpus_sources = _fake_download
        corpus, info = tc_mod.ensure_corpus_loaded(auto_download=True)
        assert corpus is not None
        assert info["rebuilt"] is True
        assert corpus.get_source_entries("lolbas")[0]["id"] == "LOLBAS-certutil.exe"

    def test_ensure_loaded_none_without_sources(self, isolated_cache):
        corpus, info = tc_mod.ensure_corpus_loaded()
        assert corpus is None
        assert info["loaded"] is False
        assert "no sources" in info["reason"]

    def test_ensure_loaded_rebuild_bypasses_singleton(self, isolated_cache):
        tc_mod.save_corpus(_sample_corpus())
        tc_mod.ensure_corpus_loaded()
        # rebuild=True with no sources -> falls through to None.
        corpus, info = tc_mod.ensure_corpus_loaded(rebuild=True)
        assert corpus is None

    def test_invalidate_corpus_cache(self, isolated_cache):
        tc_mod.save_corpus(_sample_corpus())
        corpus, _ = tc_mod.ensure_corpus_loaded()
        assert corpus is not None
        tc_mod.invalidate_corpus_cache()
        assert tc_mod._corpus_singleton is None
        assert tc_mod.load_corpus() is None
