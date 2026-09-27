"""p09_intelligence: threat_corpus regression tests.

Covers private-rule regex, list-valued search, empty-source manifest
round-trip, and fingerprint cap consistency.
"""

from __future__ import annotations

import json
import os
import zipfile

import pytest

from ida_pro_mcp.host.intelligence import threat_corpus as tc_mod
from ida_pro_mcp.host.intelligence.sources.base import SourceParser
from ida_pro_mcp.host.intelligence.sources.lolbas import LolbasSource
from ida_pro_mcp.host.intelligence.sources.urlhaus import UrlhausSource


@pytest.fixture
def isolated_cache(monkeypatch, tmp_path):
    cache_dir = tmp_path / "corpus"
    monkeypatch.setattr(tc_mod, "CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(tc_mod, "CORPUS_CACHE_DIR", str(cache_dir))
    monkeypatch.setattr(tc_mod, "MANIFEST_PATH", str(cache_dir / "manifest.json"))
    monkeypatch.setattr(tc_mod, "_corpus_singleton", None)
    return cache_dir


class TestYaraRuleRegex:
    def test_private_rule_matches(self):
        m = tc_mod._YARA_RULE_RE.search("private rule Evil {")
        assert m is not None
        assert m.group(1) == "Evil"

    def test_global_and_plain_rules_match(self):
        assert tc_mod._YARA_RULE_RE.search("global rule Bad {").group(1) == "Bad"
        assert tc_mod._YARA_RULE_RE.search("rule Normal {").group(1) == "Normal"


class TestSearchFlattensLists:
    def test_list_valued_fields_searchable(self):
        c = tc_mod.ThreatCorpus(entries={
            "malware": [{"id": "M1", "name": "trickbot",
                         "aliases": ["tbot"], "tags": ["banking", "Trojan"]}],
        })
        assert len(c.search("malware", "banking")) == 1
        assert len(c.search("malware", "tbot")) == 1
        assert len(c.search("malware", "zzz")) == 0


class TestEmptySourceManifest:
    def test_empty_source_survives_save_load(self, isolated_cache):
        corpus = tc_mod.ThreatCorpus(
            entries={"cwe": [], "yara_rules": [{"name": "r1", "id": "r1"}]},
            source_fingerprints={"cwe": "fp_empty", "yara_rules": "fp_yara"},
        )
        manifest = tc_mod.save_corpus(corpus)
        with open(manifest, encoding="utf-8") as f:
            data = json.load(f)
        assert data["sources"]["cwe"]["count"] == 0
        assert "cwe" in data["sources"]
        loaded = tc_mod.load_corpus()
        assert loaded is not None
        assert loaded.entries["cwe"] == []
        assert loaded.source_fingerprints.get("cwe") == "fp_empty"


class TestFingerprintCap:
    def test_cap_tracks_rule_dir_max(self, tmp_path):
        # The fingerprint file cap must not be lower than the parse cap.
        assert tc_mod._YARA_RULE_DIR_MAX_RULES >= 1000
        # And the code path references the constant (no stray hardcoded 1000).
        src = __import__("inspect").getsource(tc_mod.compute_source_fingerprint)
        assert "_YARA_RULE_DIR_MAX_RULES" in src
        assert "count >= 1000" not in src


class TestZipSlipGuard:
    def test_traversal_member_rejected(self, tmp_path):
        bad = tmp_path / "bad.zip"
        with zipfile.ZipFile(bad, "w") as zf:
            zf.writestr("../evil.txt", "pwned")
        with zipfile.ZipFile(bad) as zf, pytest.raises(zipfile.BadZipFile):
            SourceParser._safe_extract(zf, str(tmp_path / "out"))

    def test_absolute_member_rejected(self, tmp_path):
        bad = tmp_path / "abs.zip"
        with zipfile.ZipFile(bad, "w") as zf:
            zf.writestr("/abs/evil.txt", "pwned")
        with zipfile.ZipFile(bad) as zf, pytest.raises(zipfile.BadZipFile):
            SourceParser._safe_extract(zf, str(tmp_path / "out2"))

    def test_benign_nested_archive_extracts(self, tmp_path):
        good = tmp_path / "good.zip"
        with zipfile.ZipFile(good, "w") as zf:
            zf.writestr("repo/dir/file.yar", "rule x {}")
        dest = tmp_path / "good_out"
        with zipfile.ZipFile(good) as zf:
            SourceParser._safe_extract(zf, str(dest))
        assert (dest / "repo" / "dir" / "file.yar").exists()


class TestUrlhaus:
    def test_find_json_walks_recursively(self, tmp_path):
        nested = tmp_path / "nested" / "json"
        nested.mkdir(parents=True)
        (nested / "data.json").write_text("{}")
        found = UrlhausSource._find_json(str(tmp_path))
        assert found is not None
        assert found.endswith(os.path.join("nested", "json", "data.json"))

    def test_corrupt_archive_is_swallowed(self, tmp_path):
        src = UrlhausSource()
        fake = tmp_path / "blob"
        fake.write_bytes(b"not a zip")
        # Must not raise — corrupt archives degrade to non-zip handling.
        src._post_download(str(fake), str(tmp_path / "dest"))


class TestLolbasGuards:
    def test_non_dict_items_and_bad_commands_skipped(self, tmp_path):
        src = LolbasSource()
        bad = [
            {"Name": "ok", "Commands": [{"MitreID": "T1"}]},
            "junk",
            {"Name": "x", "Commands": "notalist"},
        ]
        data_dir = tmp_path / "lolbas"
        data_dir.mkdir()
        (data_dir / "lolbas.json").write_text(json.dumps(bad), encoding="utf-8")
        entries = src.parse(str(data_dir))
        names = [e["name"] for e in entries]
        assert "ok" in names
        assert "x" in names
        assert "junk" not in names
