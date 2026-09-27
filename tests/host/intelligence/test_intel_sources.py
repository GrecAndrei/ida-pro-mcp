"""f13_intel_sources regression tests.

Covers intelligence-source fixes:
  - yara_scanner: duplicate rule-namespace disambiguation (no silent drop)
  - sources/base: corrupt download self-heals instead of poisoning the cache
  - families: EA sort key survives non-0x EA forms
  - threat_corpus: multi-type source fingerprints survive save/load,
    invalidate clears the legacy backup, auto-download runs outside the
    global lock, and yara string matches resolve to their real source
  - sigma_rules: rule id below the old 4096-byte prefix fold is still found
  - cwe_source: multi-XML data dirs parse deterministically
"""
from __future__ import annotations

import json
import os
import zipfile

import pytest

from ida_pro_mcp.host.intelligence import threat_corpus as tc_mod, yara_scanner as ys
from ida_pro_mcp.host.intelligence.families import _ea_sort_key, compute_function_families
from ida_pro_mcp.host.intelligence.sources import CweSource, SigmaRulesSource
from ida_pro_mcp.host.intelligence.sources.base import SourceParser
from ida_pro_mcp.host.intelligence.threat_corpus import ThreatCorpus

STIX_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1",
            "name": "Spearphishing Attachment",
            "description": "Send a malicious attachment.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1566.001"},
            ],
            "kill_chain_phases": [{"phase_name": "initial-access"}],
        },
        {
            "type": "malware",
            "id": "malware--2",
            "name": "TrickBot",
            "description": "Banking trojan.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0266"},
            ],
            "x_mitre_aliases": ["TrickBot"],
        },
    ],
}

CWE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns:cwe="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <cwe:Weakness ID="119" Name="Improper Restriction of Operations within the Bounds of a Memory Buffer" Status="Incomplete" Abstraction="Class">
      <cwe:Description>Write past the end of a buffer.</cwe:Description>
    </cwe:Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""


def _write(tmp_path, relpath: str, content: str):
    target = tmp_path / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


@pytest.fixture
def isolated_cache(monkeypatch, tmp_path):
    cache_dir = tmp_path / "corpus"
    monkeypatch.setattr(tc_mod, "CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(tc_mod, "CORPUS_CACHE_DIR", str(cache_dir))
    monkeypatch.setattr(tc_mod, "MANIFEST_PATH", str(cache_dir / "manifest.json"))
    monkeypatch.setattr(tc_mod, "CORPUS_CACHE_FILENAME", "threat_corpus_v2.json")
    monkeypatch.setattr(tc_mod, "_corpus_singleton", None)
    return cache_dir


# ── yara_scanner: duplicate rule-namespace collision ────────────────────────

class TestYaraNamespaceCollision:
    def test_same_basename_in_merged_dirs_is_disambiguated(self, tmp_path, monkeypatch):
        pytest.importorskip("yara")
        monkeypatch.setattr(ys, "findcrypt_rules_dir", lambda: "")
        rules_dir = tmp_path / "rules"
        _write(rules_dir, "a/apt.yar", 'rule apt_one { strings: $a = "ALPHA" condition: $a }')
        _write(rules_dir, "b/apt.yar", 'rule apt_two { strings: $a = "BETA" condition: $a }')

        namespaces = [ns for ns, _ in ys._iter_rule_files(str(rules_dir))]
        assert len(namespaces) == 2
        assert namespaces[0] == "apt"
        assert namespaces[1] != namespaces[0]  # disambiguated, not silently dropped

        rules, file_errors, compile_errors = ys.compile_rules(str(rules_dir))
        assert rules is not None
        assert file_errors == []
        assert compile_errors == []
        # Both rule sets are actually compiled and matchable.
        assert [m.rule for m in ys.scan_bytes(rules, b"ALPHA")] == ["apt_one"]
        assert [m.rule for m in ys.scan_bytes(rules, b"BETA")] == ["apt_two"]


# ── sources/base: corrupt download self-heals ───────────────────────────────

class TestDownloadSelfHeals:
    def test_failed_post_download_cleans_up_and_retries(self, monkeypatch, tmp_path):
        import ida_pro_mcp.host.intelligence.threat_corpus as tc

        calls = {"n": 0}

        def _fake_download(url):
            calls["n"] += 1
            return b"zipbytes"

        monkeypatch.setattr(tc, "_download_url", _fake_download)

        class FlakySource(SourceParser):
            name = "flaky"
            description = "flaky"
            cache_key = "flaky"

            def __init__(self):
                self.urls = ["https://example.com/flaky.zip"]
                self._fail = True

            def _post_download(self, fpath, dest_dir):
                if self._fail:
                    raise zipfile.BadZipFile("truncated archive")

            def parse(self, data_dir):
                return []

        src = FlakySource()
        dest = str(tmp_path / "corpus")

        # First attempt: the archive is corrupt -> error, and the bad file must
        # be removed so a later non-forced run re-downloads instead of skipping
        # a poisoned cache entry forever.
        first = src.download(dest)
        assert first["errors"]
        assert calls["n"] == 1
        assert not (tmp_path / "corpus" / "flaky" / "flaky.zip").exists()

        # Second attempt with force=False re-downloads (the corrupt file is gone).
        src._fail = False
        second = src.download(dest)
        assert second["downloaded"] == ["flaky.zip"]
        assert second["errors"] == []
        assert calls["n"] == 2
        assert (tmp_path / "corpus" / "flaky" / "flaky.zip").read_bytes() == b"zipbytes"

    def test_network_failure_does_not_remove_preexisting_file(self, monkeypatch, tmp_path):
        import ida_pro_mcp.host.intelligence.threat_corpus as tc

        def boom(url):
            raise OSError("network down")

        monkeypatch.setattr(tc, "_download_url", boom)

        class StubSource(SourceParser):
            name = "stub"
            description = "stub"
            cache_key = "stub"

            def __init__(self):
                self.urls = ["https://example.com/stub.json"]

            def parse(self, data_dir):
                return []

        dest = tmp_path / "corpus"
        fpath = dest / "stub" / "stub.json"
        fpath.parent.mkdir(parents=True)
        fpath.write_bytes(b"precious cached bytes")

        result = StubSource().download(str(dest), force=True)
        assert result["errors"]
        # The failure happened before any write this attempt; the previously
        # good cached file must survive.
        assert fpath.read_bytes() == b"precious cached bytes"


# ── families: lenient EA parsing ────────────────────────────────────────────

class TestFamiliesEaParsing:
    def test_ea_sort_key_lenient_and_deterministic(self):
        assert _ea_sort_key("0x401000") == 0x401000
        assert _ea_sort_key("") == 0
        k1 = _ea_sort_key("sub_401000")
        k2 = _ea_sort_key("sub_401000")
        assert k1 == k2  # deterministic fallback, no ValueError

    def test_symbolic_ea_does_not_abort_clustering(self):
        class _FakeIndex:
            def __init__(self, cache, meta):
                self._cache = cache
                self._meta = meta

            def _similarity_candidates(self, exclude_ea, address_ranges):
                return list(self._cache.items())

            def _row_meta_for_eas(self, eas):
                return {ea: self._meta.get(ea, {"name": ea}) for ea in eas}

            def _row_docs_for_eas(self, eas):
                return dict.fromkeys(eas, "")

        cache = {
            "0x401000": [1.0, 0.0, 0.0],
            "0x402000": [0.99, 0.14, 0.0],
            "sub_403000": [0.98, 0.20, 0.0],  # int("sub_403000", 0) would raise
        }
        meta = {
            "0x401000": {"name": "parse_packet"},
            "0x402000": {"name": "sub_402000"},
            "sub_403000": {"name": "parse_frame"},
        }
        result = compute_function_families(_FakeIndex(cache, meta), min_size=2, min_similarity=0.9)
        assert result["families_found"] == 1
        family = result["families"][0]
        assert family["size"] == 3
        assert family["id"].startswith("0x")


# ── threat_corpus: multi-type source fingerprints ───────────────────────────

class TestMultiTypeFingerprints:
    def test_attack_fingerprint_stored_under_bucket_keys(self, isolated_cache, tmp_path):
        data_dir = tmp_path / "attack"
        data_dir.mkdir()
        _write(data_dir, "enterprise-attack.json", json.dumps(STIX_BUNDLE))

        dl = {"source_dirs": {"attack": str(data_dir)}, "downloaded": [], "errors": []}
        corpus = tc_mod._build_from_sources(dl)
        assert corpus is not None
        assert corpus.get_source_entries("attack_patterns")
        assert corpus.get_source_entries("malware")
        # The single-source fingerprint must be recorded under every bucket key
        # it populates — otherwise save_corpus drops it from the manifest.
        populated = [b for b in ("attack_patterns", "malware", "intrusion_sets", "tools", "mitigations")
                     if corpus.get_source_entries(b)]
        assert populated
        for bucket in populated:
            assert corpus.source_fingerprints.get(bucket), f"fingerprint missing for {bucket}"
        assert len({corpus.source_fingerprints[b] for b in populated}) == 1

        # Round-trip through the modular cache preserves the bucket fingerprints.
        tc_mod.save_corpus(corpus)
        loaded = tc_mod.load_corpus()
        assert loaded is not None
        assert loaded.source_fingerprints == corpus.source_fingerprints


# ── threat_corpus: invalidate + backup cleanup ──────────────────────────────

class TestInvalidateCorpusCache:
    def test_invalidate_clears_legacy_backup_too(self, isolated_cache, tmp_path):
        legacy = tc_mod.corpus_cache_path()
        os.makedirs(os.path.dirname(legacy), exist_ok=True)
        for path in (legacy, legacy + ".v1_backup"):
            with open(path, "w", encoding="utf-8") as f:
                f.write("{}")
        tc_mod.save_corpus(ThreatCorpus(entries={"cwe": [{"id": "CWE-1"}]}))
        assert os.path.isfile(legacy + ".v1_backup")

        tc_mod.invalidate_corpus_cache()
        assert tc_mod._corpus_singleton is None
        assert not os.path.isfile(legacy)
        assert not os.path.isfile(legacy + ".v1_backup")
        assert os.listdir(isolated_cache) == []
        assert tc_mod.load_corpus() is None


# ── threat_corpus: download outside the global lock ─────────────────────────

class TestAutoDownloadOutsideLock:
    def test_download_runs_without_holding_corpus_lock(self, isolated_cache, monkeypatch, tmp_path):
        data_dir = tmp_path / "dl"
        data_dir.mkdir()
        _write(data_dir, "lolbas.json", json.dumps([
            {"Name": "certutil.exe", "Description": "download", "Full_Path": "", "Commands": [
                {"Command": "certutil -urlcache", "Category": "Download", "MitreID": "T1105"},
            ]},
        ]))

        def _fake_download(dest_dir=None, force=False, progress_cb=None, sources=None):
            # The point of the fix: slow network I/O must never run while the
            # process-global corpus lock is held (it would stall every session).
            assert not tc_mod._corpus_lock.locked(), "download ran while holding the corpus lock"
            return {"source_dirs": {"lolbas": str(data_dir)}, "downloaded": [], "errors": []}

        monkeypatch.setattr(tc_mod, "download_corpus_sources", _fake_download)
        corpus, info = tc_mod.ensure_corpus_loaded(auto_download=True)
        assert corpus is not None
        assert info["rebuilt"] is True
        assert corpus.get_source_entries("lolbas")[0]["id"] == "LOLBAS-certutil.exe"

    def test_warm_cache_avoids_download(self, isolated_cache, monkeypatch):
        tc_mod.save_corpus(ThreatCorpus(entries={"cwe": [{"id": "CWE-1"}]}))
        called = {"n": 0}

        def _fake_download(dest_dir=None, force=False, progress_cb=None, sources=None):
            called["n"] += 1
            return {"source_dirs": {}, "downloaded": [], "errors": []}

        monkeypatch.setattr(tc_mod, "download_corpus_sources", _fake_download)
        corpus, info = tc_mod.ensure_corpus_loaded(auto_download=True)
        assert corpus is not None
        assert info["from_cache"] is True
        assert called["n"] == 0  # a warm cache must not trigger a download


# ── threat_corpus: yara string source attribution ───────────────────────────

class TestYaraStringAttribution:
    def test_rule_name_in_both_corpora_resolves_to_real_source(self):
        c = ThreatCorpus(entries={
            "yara_rules": [
                {"id": "sig-1", "name": "apt_sig", "description": "signature-base version",
                 "source": "signature_base", "strings": ["CreateRemoteThread", "shared_marker"]},
            ],
            "yara_rules_extra": [
                {"id": "extra-1", "name": "apt_sig", "description": "yara-rules-extra version",
                 "source": "yara_rules_extra", "strings": ["VirtualAllocEx", "shared_marker"]},
            ],
        })
        # A string present in only one corpus must return that corpus's rule.
        assert [h["description"] for h in c.search_yara_strings("createremotethread")] == \
            ["signature-base version"]
        assert [h["description"] for h in c.search_yara_strings("virtualallocex")] == \
            ["yara-rules-extra version"]
        # A shared string resolves to both sources, each attributed correctly.
        both = c.search_yara_strings("shared_marker")
        assert {h["description"] for h in both} == {"signature-base version", "yara-rules-extra version"}
        assert [h["source"] for h in both].count("signature_base") == 1
        assert [h["source"] for h in both].count("yara_rules_extra") == 1


# ── sigma_rules: id below the 4096-byte fold ────────────────────────────────

class TestSigmaDeepId:
    def test_id_past_4096_bytes_is_found(self, tmp_path):
        preamble = "# " + "a" * 5000 + "\n"
        rule = (
            "title: Deep Rule\n"
            + preamble
            + "id: 11111111-2222-3333-4444-555555555555\n"
            + "status: experimental\n"
            + "description: deep\n"
        )
        _write(tmp_path, "rules/deep.yaml", rule)
        entries = SigmaRulesSource().parse(str(tmp_path))
        assert len(entries) == 1
        assert entries[0]["id"] == "11111111-2222-3333-4444-555555555555"
        assert not entries[0]["id"].startswith("SIGMA-")


# ── cwe_source: deterministic XML selection ─────────────────────────────────

class TestCweDeterministicXml:
    def test_multi_xml_data_dir_picks_sorted_first(self, tmp_path):
        xml_a = CWE_XML  # ID 119
        xml_b = CWE_XML.replace('ID="119"', 'ID="120"')
        # Write out of sorted order to prove order does not come from glob luck.
        _write(tmp_path, "b_catalog.xml", xml_b)
        _write(tmp_path, "a_catalog.xml", xml_a)
        entries = CweSource().parse(str(tmp_path))
        assert entries and entries[0]["id"] == "CWE-119"
