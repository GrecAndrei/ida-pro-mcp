"""ThreatCorpus holder, modular cache, and singleton loader tests.

Covers the corpus object (indexes, lookups, serialization), the per-source
cache files + manifest round-trip, V1 migration, and the lazy singleton
(no network — downloads are monkeypatched or avoided entirely).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

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


def test_threat_corpus_download_timeout_env_is_safe():
    """A malformed corpus-download timeout must not break host import."""
    code = (
        "from ida_pro_mcp.host.intelligence.threat_corpus "
        "import _DOWNLOAD_TIMEOUT; print(_DOWNLOAD_TIMEOUT)"
    )
    for raw, expected in (("oops", 120), ("-1", 1), ("0", 1)):
        env = dict(os.environ, IDA_MCP_DOWNLOAD_TIMEOUT=raw)
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, env=env
        )
        assert proc.returncode == 0, proc.stderr
        assert int(proc.stdout) == expected


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

    def test_ensure_loaded_auto_download(self, isolated_cache, tmp_path, monkeypatch):
        data_dir = tmp_path / "dl"
        data_dir.mkdir()
        _write(data_dir / "lolbas.json", json.dumps([
            {"Name": "certutil.exe", "Description": "download", "Full_Path": "", "Commands": [
                {"Command": "certutil -urlcache", "Category": "Download", "MitreID": "T1105"},
            ]},
        ]))

        def _fake_download(dest_dir=None, force=False, progress_cb=None, sources=None):
            return {"source_dirs": {"lolbas": str(data_dir)}, "downloaded": [], "errors": []}

        monkeypatch.setattr(tc_mod, "download_corpus_sources", _fake_download)
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


class TestThreatCorpusParserBoundaries:
    def test_cwe_parser_rejects_bad_files_and_normalizes_fields(self, tmp_path):
        assert tc_mod.parse_cwe_xml("") == []
        assert tc_mod.parse_cwe_xml(str(tmp_path / "missing.xml")) == []
        malformed = tmp_path / "malformed.xml"
        _write(malformed, "<Weakness_Catalog>")
        assert tc_mod.parse_cwe_xml(str(malformed)) == []

        languages = "".join(
            f"<cwe:Language>Language-{i}</cwe:Language>" for i in range(15)
        )
        technologies = "".join(
            f"<cwe:Technology>Technology-{i}</cwe:Technology>" for i in range(15)
        )
        xml = f"""<?xml version="1.0"?>
        <cwe:Weakness_Catalog xmlns:cwe="http://cwe.mitre.org/cwe-7">
          <cwe:Weaknesses>
            <cwe:Weakness Name="no id" />
            <cwe:Weakness ID="1" Status="Deprecated" />
            <cwe:Weakness ID="2" Status="Withdrawn" />
            <cwe:Weakness ID="777" Abstraction="Class" Structure="Simple">
              <cwe:Name>Child supplied name</cwe:Name>
              <cwe:Description>  A description  </cwe:Description>
              <cwe:Background_Details>
                <cwe:Background_Detail>First background.</cwe:Background_Detail>
                <cwe:Background_Detail>Second background.</cwe:Background_Detail>
              </cwe:Background_Details>
              <cwe:Applicable_Platforms>
                <cwe:Language>Python</cwe:Language>
                <cwe:Language Class="Language-C">C</cwe:Language>
                <cwe:Language Name="C++" Class="Language-CPP">ignored text</cwe:Language>
                <cwe:Language Name="Not language-specific" />
                {languages}
                <cwe:Technology>Desktop</cwe:Technology>
                <cwe:Technology Class="Browser">ignored text</cwe:Technology>
                <cwe:Technology Name="Not technology-specific" />
                {technologies}
              </cwe:Applicable_Platforms>
              <cwe:Common_Consequences>
                <cwe:Consequence>
                  <cwe:Scope>Integrity</cwe:Scope>
                  <cwe:Technical_Impact>Modify memory</cwe:Technical_Impact>
                  <cwe:Consequence_Scope>Availability</cwe:Consequence_Scope>
                  <cwe:Technical_Impact_Scope>Modify memory</cwe:Technical_Impact_Scope>
                  <cwe:Other>ignored</cwe:Other>
                </cwe:Consequence>
              </cwe:Common_Consequences>
            </cwe:Weakness>
          </cwe:Weaknesses>
        </cwe:Weakness_Catalog>"""
        path = tmp_path / "cwe.xml"
        _write(path, xml)

        entries = tc_mod.parse_cwe_xml(str(path))
        assert len(entries) == 1
        entry = entries[0]
        assert entry["id"] == "CWE-777"
        assert entry["name"] == "Child supplied name"
        assert entry["description"] == "A description"
        assert entry["background"] == "First background. Second background."
        assert entry["languages"][:3] == ["Python", "Language-C", "C++"]
        assert "Not language-specific" not in entry["languages"]
        assert len(entry["languages"]) == tc_mod._CWE_LANGUAGES_MAX
        assert entry["technologies"][:2] == ["Desktop", "Browser"]
        assert "Not technology-specific" not in entry["technologies"]
        assert len(entry["technologies"]) == tc_mod._CWE_TECHNOLOGIES_MAX
        assert entry["scopes"] == ["Integrity", "Modify memory", "Availability"]

    def test_attack_parser_handles_invalid_objects_and_all_supported_types(self, tmp_path):
        assert tc_mod.parse_attack_stix("")["attack_pattern"] == []
        missing = tmp_path / "missing.json"
        assert not any(tc_mod.parse_attack_stix(str(missing)).values())
        path = tmp_path / "attack.json"
        for payload in ("not json", [], {"objects": {}}):
            _write(path, json.dumps(payload))
            result = tc_mod.parse_attack_stix(str(path))
            assert not any(result.values())

        valid_ref = [{"source_name": "other", "external_id": "wrong"}, None,
                     {"source_name": "MITRE-ATTACK", "external_id": "T1001"}]
        objects = [
            "not an object",
            {"id": "missing-type"},
            {"type": "x-mitre-data-component", "id": "ignored"},
            {"type": "attack-pattern", "id": "revoked", "revoked": True,
             "external_references": valid_ref},
            {"type": "attack-pattern", "id": "deprecated", "x_mitre_deprecated": True,
             "external_references": valid_ref},
            {"type": "attack-pattern", "id": "no-external", "external_references": [{"source_name": "other"}]},
            {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Technique",
             "description": "description", "x_mitre_detection": "detect",
             "x_mitre_platforms": "Windows", "x_mitre_aliases": ["Alias"],
             "x_mitre_domains": ["enterprise-attack"], "x_mitre_is_subtechnique": True,
             "kill_chain_phases": [None, {}, {"phase_name": "execution"}],
             "external_references": valid_ref},
            {"type": "malware", "id": "malware--1", "name": "Malware", "is_family": True,
             "external_references": [{"source_name": "mitre-attack", "external_id": "S1001"}]},
            {"type": "intrusion-set", "id": "intrusion--1",
             "external_references": [{"source_name": "mitre-attack", "external_id": "G1001"}]},
            {"type": "tool", "id": "tool--1",
             "external_references": [{"source_name": "mitre-attack", "external_id": "S1002"}]},
            {"type": "course-of-action", "id": "coa--1",
             "external_references": [{"source_name": "mitre-attack", "external_id": "M1001"}]},
        ]
        _write(path, json.dumps({"type": "bundle", "objects": objects}))

        result = tc_mod.parse_attack_stix(str(path))
        assert result["attack_pattern"][0]["id"] == "T1001"
        assert result["attack_pattern"][0]["platforms"] == ["Windows"]
        assert result["attack_pattern"][0]["tactics"] == ["execution"]
        assert result["malware"][0]["family"] is True
        assert result["intrusion_set"][0]["id"] == "G1001"
        assert result["tool"][0]["id"] == "S1002"
        assert result["course_of_action"][0]["id"] == "M1001"

    def test_yara_parser_filters_rules_and_handles_caps(self, tmp_path):
        assert tc_mod._parse_yara_rule_text("", "x.yar") is None
        metadata_only = """global rule metadata_only {
            meta:
                description = "metadata"
                author = "author"
                reference = "reference"
            condition:
                true
        }"""
        parsed = tc_mod._parse_yara_rule_text(metadata_only, "/tmp/x.yar")
        assert parsed["description"] == "metadata"
        assert parsed["author"] == "author"
        assert parsed["reference"] == "reference"
        assert parsed["strings"] == []

        filtered = """private rule filtered {
            strings:
                $empty = ""
                $long = "LONG_PLACEHOLDER"
                $one = "needle"
                $two = "needle"
                $hex = { 01 02 03 }
            condition:
                true
        }""".replace("LONG_PLACEHOLDER", "x" * (tc_mod._YARA_STRING_MAX + 1))
        parsed = tc_mod._parse_yara_rule_text(filtered, "x.yar")
        assert parsed["strings"] == ["needle"]

        capped_strings = "\n".join(f'        $s{i} = "value-{i}"' for i in range(100))
        capped = tc_mod._parse_yara_rule_text(
            f"rule capped {{ strings:\n{capped_strings}\n condition: true }}", "x.yar"
        )
        assert len(capped["strings"]) == 96

    def test_yara_directory_skips_bad_files_and_duplicate_rules(self, tmp_path, monkeypatch):
        assert tc_mod.parse_yara_dir("") == []
        assert tc_mod.parse_yara_dir(str(tmp_path / "missing")) == []
        rules = tmp_path / "rules"
        rules.mkdir()
        good = """rule useful {
            meta:
                description = "useful rule"
            strings:
                $a = "needle"
            condition:
                $a
        }"""
        _write(rules / "good.yar", good)
        _write(rules / "duplicate.yara", good)
        _write(rules / "empty.yar", "rule empty { condition: true }")
        _write(rules / "unclosed.yar", "rule unclosed { strings: $a = \"x\" condition: true")
        _write(rules / "ignored.txt", good)
        size_error = rules / "size_error.yar"
        read_error = rules / "read_error.yar"
        _write(size_error, good)
        _write(read_error, good)

        real_getsize = tc_mod.os.path.getsize

        def getsize(path):
            if os.fspath(path) == os.fspath(size_error):
                raise OSError("stat failed")
            return real_getsize(path)

        real_open = __import__("builtins").open

        def open_for_test(path, *args, **kwargs):
            if os.fspath(path) == os.fspath(read_error):
                raise OSError("read failed")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(tc_mod.os.path, "getsize", getsize)
        monkeypatch.setattr(__import__("builtins"), "open", open_for_test)

        parsed = tc_mod.parse_yara_dir(str(rules))
        assert [rule["name"] for rule in parsed] == ["useful"]

    def test_source_fingerprint_handles_missing_and_unstatable_files(self, tmp_path, monkeypatch):
        cwe = tmp_path / "cwe.xml"
        attack = tmp_path / "attack.json"
        yara = tmp_path / "yara"
        yara.mkdir()
        broken = yara / "broken.yar"
        _write(cwe, "cwe")
        _write(attack, "attack")
        _write(yara / "good.yar", "good")
        _write(broken, "broken")

        real_stat = tc_mod.os.stat

        def stat(path, *args, **kwargs):
            if os.fspath(path) == os.fspath(broken):
                raise OSError("gone")
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(tc_mod.os, "stat", stat)
        fingerprint = tc_mod.compute_source_fingerprint(
            str(cwe), [str(attack), "", str(tmp_path / "missing.json")], str(yara)
        )
        assert len(fingerprint) == 32
        missing = tc_mod.compute_source_fingerprint(None, [None, str(tmp_path / "missing.json")], str(tmp_path / "no-yara"))
        assert len(missing) == 32
        assert missing != fingerprint


class TestThreatCorpusPipelineBoundaries:
    def test_download_url_enforces_size_and_preserves_request(self, monkeypatch):
        seen = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, size):
                seen["size"] = size
                return b"payload"

        def urlopen(request, timeout):
            seen["url"] = request.full_url
            seen["agent"] = request.get_header("User-agent")
            seen["timeout"] = timeout
            return Response()

        monkeypatch.setattr(tc_mod.urllib.request, "urlopen", urlopen)
        assert tc_mod._download_url("https://example.test/feed") == b"payload"
        assert seen["url"] == "https://example.test/feed"
        assert seen["agent"] == "ida-pro-mcp/1.0"
        assert seen["size"] == tc_mod._MAX_DOWNLOAD_BYTES + 1

        monkeypatch.setattr(tc_mod, "_MAX_DOWNLOAD_BYTES", 3)
        with pytest.raises(ValueError, match="exceeds"):
            tc_mod._download_url("https://example.test/large")

    def test_download_and_build_pipelines_report_source_modes(self, monkeypatch, tmp_path):
        calls = []

        class Source:
            def __init__(self, name, urls, *, multi=False, fail=False):
                self.name = name
                self.urls = urls
                self.is_multi_type = multi
                self.fail = fail

            def download(self, dest_dir, **kwargs):
                calls.append((self.name, dest_dir, kwargs))
                if self.fail:
                    raise RuntimeError("download failed")
                return {"data_dir": str(tmp_path / self.name), "downloaded": [self.name], "errors": []}

            def parse(self, _data_dir):
                if self.fail:
                    raise RuntimeError("parse failed")
                if self.is_multi_type:
                    return [
                        {"id": "a", "_attack_type": "attack_patterns"},
                        {"id": "same", "_attack_type": "multi"},
                    ]
                return [{"id": self.name}]

            def fingerprint(self, _data_dir):
                return f"fp-{self.name}"

        good = Source("good", ["https://example/good"])
        multi = Source("multi", ["https://example/multi"], multi=True)
        no_urls = Source("no-urls", [])
        failing = Source("failing", ["https://example/failing"], fail=True)
        sources_mod = __import__("ida_pro_mcp.host.intelligence.sources", fromlist=["SOURCES"])
        monkeypatch.setattr(sources_mod, "SOURCES", [good, multi, no_urls, failing])

        downloaded = tc_mod.download_corpus_sources(
            str(tmp_path / "downloads"), force=True, progress_cb=lambda _message: None,
            sources=["good", "multi", "failing", "unknown"],
        )
        assert set(downloaded["source_dirs"]) == {"good", "multi"}
        assert downloaded["downloaded"] == ["good", "multi"]
        assert any("failing" in error for error in downloaded["errors"])
        assert [call[0] for call in calls] == ["good", "multi", "failing"]
        assert calls[0][2] == {"force": True, "progress_cb": calls[0][2]["progress_cb"]}

        source_dirs = {"good": str(tmp_path / "good"), "multi": str(tmp_path / "multi"), "failing": str(tmp_path / "failing")}
        (tmp_path / "good").mkdir()
        (tmp_path / "multi").mkdir()
        built = tc_mod._build_from_sources({"source_dirs": source_dirs})
        assert built is not None
        assert built.get_source_entries("good") == [{"id": "good"}]
        assert built.get_source_entries("attack_patterns") == [{"id": "a"}]
        assert built.get_source_entries("multi") == [{"id": "same"}]
        assert all("_attack_type" not in entry for entries in built.entries.values() for entry in entries)

        empty = tc_mod._build_from_sources({"source_dirs": {}})
        assert empty is None

    def test_singleton_rechecks_cache_created_during_download(self, isolated_cache, monkeypatch):
        cached = ThreatCorpus(entries={"cwe": [{"id": "CWE-race"}]})
        calls = {"load": 0}

        def load_during_race():
            calls["load"] += 1
            return None if calls["load"] == 1 else cached

        monkeypatch.setattr(tc_mod, "load_corpus", load_during_race)
        monkeypatch.setattr(tc_mod, "download_corpus_sources", lambda **_kwargs: {"source_dirs": {}})
        corpus, info = tc_mod.ensure_corpus_loaded(auto_download=True)
        assert corpus is cached
        assert info["from_cache"] is True
        assert calls["load"] == 2

    def test_auto_download_empty_result_returns_actionable_status(self, isolated_cache, monkeypatch):
        monkeypatch.setattr(tc_mod, "download_corpus_sources", lambda **_kwargs: {"source_dirs": {}})
        corpus, info = tc_mod.ensure_corpus_loaded(auto_download=True, rebuild=True)
        assert corpus is None
        assert info == {
            "loaded": False,
            "from_cache": False,
            "rebuilt": False,
            "reason": "no sources provided and no cache available",
        }

    def test_v1_loader_rejects_invalid_versions_and_shapes(self, isolated_cache):
        legacy = tc_mod.corpus_cache_path()
        os.makedirs(os.path.dirname(legacy), exist_ok=True)
        for payload in ([], {"version": 0}, {"version": "bad"}):
            _write(__import__("pathlib").Path(legacy), json.dumps(payload))
            if payload.get("version") == "bad" if isinstance(payload, dict) else False:
                with pytest.raises(ValueError):
                    tc_mod.load_corpus()
            else:
                assert tc_mod.load_corpus() is None
