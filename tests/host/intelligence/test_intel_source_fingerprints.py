"""Regression tests for the g04_intel_sources fixer wave.

Covers findings in host/intelligence/sources/* and threat_corpus.py:

  * an attempted-but-empty multi-type (ATT&CK) source survives a save/load
    round-trip with its fingerprint/bucket intact, instead of vanishing from
    the manifest and becoming indistinguishable from "never attempted".
  * the transient ``_attack_type`` split marker never reaches the saved corpus
    (multi-type entries are persisted as clean copies).
  * FindCrypt entries are indexable: each entry carries an id (rule name) and
    its quoted strings, so get_by_id / all_yara_strings / search_yara_strings
    reach them.
  * the FindCrypt description parser is escaped-quote-aware and bounded to the
    rule's meta section, so a comment line is never captured.
  * ATT&CK technique ids shared across the enterprise/ics/mobile bundles dedup
    to one entry.
  * the dead get_source()/source_names() registry helpers are gone.

All tests are standalone (no IDA, no network).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[3] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_pro_mcp.host.intelligence import threat_corpus as tc_mod  # noqa: E402
from ida_pro_mcp.host.intelligence.sources import (  # noqa: E402
    AttackSource,
    FindCryptSource,
)
from ida_pro_mcp.host.intelligence.threat_corpus import ThreatCorpus  # noqa: E402

CWE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns:cwe="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <cwe:Weakness ID="119" Name="Improper Restriction of Operations within the Bounds of a Memory Buffer" Status="Incomplete" Abstraction="Class">
      <cwe:Description>Write past the end of a buffer.</cwe:Description>
    </cwe:Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""


def _write(tmp_path, relpath: str, content: str) -> str:
    target = tmp_path / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return str(target)


def _attack_bundle(external_id: str, obj_id: str, name: str = "Spearphishing") -> dict:
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": obj_id,
                "name": name,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": external_id},
                ],
            }
        ],
    }


@pytest.fixture
def isolated_cache(monkeypatch, tmp_path):
    cache_dir = tmp_path / "corpus"
    monkeypatch.setattr(tc_mod, "CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(tc_mod, "CORPUS_CACHE_DIR", str(cache_dir))
    monkeypatch.setattr(tc_mod, "MANIFEST_PATH", str(cache_dir / "manifest.json"))
    monkeypatch.setattr(tc_mod, "CORPUS_CACHE_FILENAME", "threat_corpus_v2.json")
    monkeypatch.setattr(tc_mod, "_corpus_singleton", None)
    return cache_dir


# ── multi-type source: empty parse survives save/load ───────────────────────

class TestEmptyMultiTypeSource:
    def test_attempted_but_empty_attack_survives_roundtrip(self, isolated_cache, tmp_path):
        # The attack data dir exists (so the source was downloaded) but contains
        # no *.json bundles -> AttackSource.parse returns [].
        attack_dir = tmp_path / "attack"
        attack_dir.mkdir()
        cwe_dir = tmp_path / "cwe"
        _write(cwe_dir, "cwec.xml", CWE_XML)

        dl = {"source_dirs": {"attack": str(attack_dir), "cwe": str(cwe_dir)}, "downloaded": [], "errors": []}
        corpus = tc_mod._build_from_sources(dl)

        assert corpus is not None
        assert corpus.get_source_entries("cwe"), "cwe must parse"
        assert corpus.get_source_entries("attack") == []
        assert corpus.source_fingerprints.get("attack"), "attempted-but-empty attack must keep a fingerprint"

        tc_mod.save_corpus(corpus)
        loaded = tc_mod.load_corpus()

        assert loaded is not None
        assert "attack" in loaded.available_sources()
        assert loaded.get_source_entries("attack") == []
        assert "attack" in loaded.source_fingerprints
        assert loaded.source_fingerprints["attack"] == corpus.source_fingerprints["attack"]

    def test_transient_marker_never_persists(self, isolated_cache, tmp_path):
        attack_dir = tmp_path / "attack"
        attack_dir.mkdir()
        _write(attack_dir, "enterprise.json", json.dumps(_attack_bundle("T1566.001", "attack-pattern--1")))

        dl = {"source_dirs": {"attack": str(attack_dir)}, "downloaded": [], "errors": []}
        corpus = tc_mod._build_from_sources(dl)

        assert corpus is not None
        assert corpus.get_source_entries("attack_patterns"), "bundle must land in its bucket"
        for bucket in ("attack", "attack_patterns", "malware", "intrusion_sets", "tools", "mitigations"):
            for e in corpus.get_source_entries(bucket):
                assert "_attack_type" not in e, f"_attack_type leaked into {bucket}"

        tc_mod.save_corpus(corpus)
        loaded = tc_mod.load_corpus()
        assert loaded is not None
        for bucket in ("attack", "attack_patterns", "malware", "intrusion_sets", "tools", "mitigations"):
            for e in loaded.get_source_entries(bucket):
                assert "_attack_type" not in e, f"_attack_type leaked into {bucket} after reload"


# ── FindCrypt: entries reachable via indexed lookups ────────────────────────

class TestFindCryptIndexable:
    def test_findcrypt_entry_reachable_by_id_and_strings(self, tmp_path):
        rule = (
            "rule aes_sbox\n"
            "{\n"
            "    meta:\n"
            '        description = "AES S-box"\n'
            "    strings:\n"
            '        $s1 = "7c77f26b6fc53001672bfed7ab76"\n'
            "    condition:\n"
            "        $s1\n"
            "}\n"
        )
        _write(tmp_path, "rules/crypto.yar", rule)

        entries = FindCryptSource().parse(str(tmp_path))
        assert len(entries) == 1
        assert entries[0]["id"] == "aes_sbox"
        assert entries[0]["strings"] == ["7c77f26b6fc53001672bfed7ab76"]

        corpus = ThreatCorpus(entries={"findcrypt": entries})

        assert corpus.get_by_id("findcrypt", "aes_sbox")["name"] == "aes_sbox"
        assert "7c77f26b6fc53001672bfed7ab76" in corpus.all_yara_strings(min_len=1)
        hits = corpus.search_yara_strings("7c77f26b6fc53001672bfed7ab76")
        assert [h["name"] for h in hits] == ["aes_sbox"]

    def test_findcrypt_dedups_same_rule_across_files(self, tmp_path):
        rule = (
            "rule dup_rule\n"
            "{\n"
            "    meta:\n"
            '        description = "dup"\n'
            "    strings:\n"
            '        $a = "s"\n'
            "    condition:\n"
            "        $a\n"
            "}\n"
        )
        _write(tmp_path, "a/crypto.yar", rule)
        _write(tmp_path, "b/crypto.yar", rule)

        entries = FindCryptSource().parse(str(tmp_path))
        assert len(entries) == 1
        assert entries[0]["id"] == "dup_rule"


# ── FindCrypt: hardened description parser ──────────────────────────────────

class TestFindCryptDescription:
    def test_escaped_quotes_parse_fully(self, tmp_path):
        rule = (
            "rule quoted_rule\n"
            "{\n"
            "    meta:\n"
            '        // description = "commented out"\n'
            '        description = "A rule with a \\"quoted\\" part"\n'
            "    strings:\n"
            '        $a = "needle"\n'
            "    condition:\n"
            "        $a\n"
            "}\n"
        )
        _write(tmp_path, "rules/q.yar", rule)

        entries = FindCryptSource().parse(str(tmp_path))
        assert len(entries) == 1
        # The whole description is captured — the inner \" sequence is kept
        # verbatim (mirroring threat_corpus._YARA_META_KV_RE), not truncated
        # at the first inner quote as the old regex did.
        assert entries[0]["display_name"] == 'A rule with a \\"quoted\\" part'

    def test_comment_line_before_meta_is_not_captured(self, tmp_path):
        rule = (
            "rule commented_rule\n"
            "{\n"
            '    // description = "not captured"\n'
            "    meta:\n"
            '        description = "captured"\n'
            "    strings:\n"
            '        $a = "needle"\n'
            "    condition:\n"
            "        $a\n"
            "}\n"
        )
        _write(tmp_path, "rules/c.yar", rule)

        entries = FindCryptSource().parse(str(tmp_path))
        assert len(entries) == 1
        assert entries[0]["display_name"] == "captured"


# ── ATT&CK: merge hygiene across bundles ────────────────────────────────────

class TestAttackMergeHygiene:
    def test_shared_technique_id_dedups_to_one_entry(self, tmp_path):
        _write(tmp_path, "enterprise.json", json.dumps(_attack_bundle("T1566.001", "attack-pattern--1")))
        _write(tmp_path, "mobile.json", json.dumps(_attack_bundle("T1566.001", "attack-pattern--9")))

        entries = AttackSource().parse(str(tmp_path))
        patterns = [e for e in entries if e.get("_attack_type") == "attack_patterns"]
        assert len(patterns) == 1
        assert patterns[0]["id"] == "T1566.001"

        # A distinct id from a third bundle still survives the merge.
        _write(tmp_path, "ics.json", json.dumps(_attack_bundle("T1566.002", "attack-pattern--5")))
        entries = AttackSource().parse(str(tmp_path))
        patterns = [e for e in entries if e.get("_attack_type") == "attack_patterns"]
        assert {e["id"] for e in patterns} == {"T1566.001", "T1566.002"}


# ── dead code removal ───────────────────────────────────────────────────────

def test_source_registry_convenience_helpers_removed():
    import ida_pro_mcp.host.intelligence.sources as sources_mod

    assert not hasattr(sources_mod, "get_source")
    assert not hasattr(sources_mod, "source_names")
    assert "get_source" not in sources_mod.__all__
    assert "source_names" not in sources_mod.__all__
    # The registry itself is still the public surface.
    assert "SOURCES" in sources_mod.__all__
    assert sources_mod.SOURCES
