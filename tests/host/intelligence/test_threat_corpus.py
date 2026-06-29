from __future__ import annotations

import json
import os

import pytest

from ida_pro_mcp.host.intelligence.threat_corpus import (
    CORPUS_CACHE_FILENAME,
    CORPUS_VERSION,
    ThreatCorpus,
    build_corpus_from_sources,
    compute_source_fingerprint,
    corpus_cache_path,
    delete_corpus_cache,
    ensure_corpus_loaded,
    load_corpus,
    parse_attack_stix,
    parse_cwe_xml,
    parse_yara_dir,
    save_corpus,
)

_CWE_REAL = "/tmp/cwe_inspect/cwec_v4.20.xml"
_ATT_REAL = "/home/alex/Downloads/datasets-temp/enterprise-attack.json"
_YARA_REAL = "/home/alex/Downloads/datasets-temp/signature-base/yara"
_HAVE_REAL = os.path.isfile(_CWE_REAL) and os.path.isfile(_ATT_REAL) and os.path.isdir(_YARA_REAL)


_CWE_TINY_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <Weakness ID="120" Name="Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')" Abstraction="Base" Structure="Simple" Status="Stable">
      <Description>The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.</Description>
      <Applicable_Platforms>
        <Language Class="C" Prevalence="Often"/>
        <Language Name="C++" Prevalence="Often"/>
        <Technology Class="Web Server" Prevalence="Sometimes"/>
      </Applicable_Platforms>
      <Common_Consequences>
        <Consequence_Scope>Confidentiality</Consequence_Scope>
        <Consequence_Scope>Integrity</Consequence_Scope>
      </Common_Consequences>
    </Weakness>
    <Weakness ID="787" Name="Out-of-bounds Write" Abstraction="Base" Structure="Simple" Status="Incomplete">
      <Description>The product writes data past the end, or before the beginning, of the intended buffer.</Description>
    </Weakness>
    <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Structure="Simple" Status="Deprecated">
      <Description>Deprecated entry.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""


_ATT_TINY = {
    "type": "bundle",
    "id": "bundle--test",
    "objects": [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--a",
            "revoked": False,
            "x_mitre_deprecated": False,
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries may abuse command and script interpreters to execute commands.",
            "x_mitre_detection": "Monitor command-line activity.",
            "x_mitre_platforms": ["Windows", "Linux", "macOS"],
            "x_mitre_is_subtechnique": False,
            "x_mitre_domains": ["enterprise-attack"],
            "kill_chain_phases": [{"phase_name": "execution"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--b",
            "revoked": True,
            "name": "Deprecated Technique",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
        },
        {
            "type": "malware",
            "id": "malware--c",
            "revoked": False,
            "x_mitre_deprecated": False,
            "name": "Mimikatz",
            "description": "Mimikatz is a credential extraction tool.",
            "x_mitre_aliases": ["mimikatz", "mimilib"],
            "x_mitre_platforms": ["Windows"],
            "is_family": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "S0001"}],
        },
        {
            "type": "intrusion-set",
            "id": "intrusion-set--d",
            "revoked": False,
            "x_mitre_deprecated": False,
            "name": "APT28",
            "x_mitre_aliases": ["Fancy Bear", "Sofacy"],
            "external_references": [{"source_name": "mitre-attack", "external_id": "G0008"}],
        },
        {
            "type": "course-of-action",
            "id": "course-of-action--e",
            "revoked": False,
            "x_mitre_deprecated": False,
            "name": "Audit",
            "description": "Perform audits.",
            "external_references": [{"source_name": "mitre-attack", "external_id": "M1047"}],
        },
        {
            "type": "identity",
            "id": "identity--f",
            "name": "Identity Object (should be skipped)",
        },
    ],
}


_YARA_TINY_DIR = {
    "rule1.yar": (
        'rule FirstRule {\n'
        '   meta:\n'
        '      description = "First test rule"\n'
        '      author = "Test Author"\n'
        '      reference = "https://example.com"\n'
        '   strings:\n'
        '      $s1 = "hello world" ascii\n'
        '      $s2 = /md5sum/ nocase\n'
        '   condition:\n'
        '      any of them\n'
        '}\n'
    ),
    "rule2.yar": (
        'rule SecondRule {\n'
        '   meta:\n'
        '      description = "Second test rule"\n'
        '   strings:\n'
        '      $a = "second"\n'
        '   condition:\n'
        '      $a\n'
        '}\n'
    ),
    "rule3_nometa.yar": (
        'rule NoMetaRule {\n'
        '   strings:\n'
        '      $x = "xyz"\n'
        '   condition:\n'
        '      $x\n'
        '}\n'
    ),
    "rule_skip.yar": (
        'rule EmptyRule {\n'
        '   condition:\n'
        '      false\n'
        '}\n'
    ),
}


def test_parse_cwe_xml_tiny(tmp_path):
    p = tmp_path / "tiny.xml"
    p.write_text(_CWE_TINY_XML)
    entries = parse_cwe_xml(str(p))
    assert len(entries) == 2
    e0 = entries[0]
    assert e0["id"] == "CWE-120"
    assert "Buffer Copy" in e0["name"]
    assert "verifying" in e0["description"]
    assert "C" in e0["languages"]
    assert "C++" in e0["languages"]
    assert "Web Server" in e0["technologies"]
    assert "Confidentiality" in e0["scopes"]
    e1 = entries[1]
    assert e1["id"] == "CWE-787"
    assert e1["languages"] == []


def test_parse_cwe_xml_handles_missing_and_malformed(tmp_path):
    assert parse_cwe_xml(str(tmp_path / "missing.xml")) == []
    bad = tmp_path / "bad.xml"
    bad.write_text("not xml at all")
    assert parse_cwe_xml(str(bad)) == []


def test_parse_cwe_xml_skips_deprecated(tmp_path):
    p = tmp_path / "tiny.xml"
    p.write_text(_CWE_TINY_XML)
    entries = parse_cwe_xml(str(p))
    ids = [e["id"] for e in entries]
    assert "CWE-89" not in ids
    assert "CWE-120" in ids
    assert "CWE-787" in ids


@pytest.mark.skipif(not _HAVE_REAL, reason="real CWE/ATT&CK/YARA datasets not present")
def test_parse_cwe_xml_real():
    entries = parse_cwe_xml(_CWE_REAL)
    assert len(entries) > 900
    sample = next(e for e in entries if e["id"] == "CWE-120")
    assert "Memory-Unsafe" in sample["languages"]
    assert "C" in sample["languages"]


def test_parse_attack_stix_tiny(tmp_path):
    p = tmp_path / "tiny.json"
    p.write_text(json.dumps(_ATT_TINY))
    parsed = parse_attack_stix(str(p))
    assert len(parsed["attack_pattern"]) == 1
    assert parsed["attack_pattern"][0]["id"] == "T1059"
    assert "Windows" in parsed["attack_pattern"][0]["platforms"]
    assert "execution" in parsed["attack_pattern"][0]["tactics"]
    assert len(parsed["malware"]) == 1
    assert parsed["malware"][0]["id"] == "S0001"
    assert "mimikatz" in parsed["malware"][0]["aliases"]
    assert len(parsed["intrusion_set"]) == 1
    assert parsed["intrusion_set"][0]["id"] == "G0008"
    assert len(parsed["course_of_action"]) == 1
    assert all(o["id"] != "identity--f" for o in parsed["attack_pattern"])


def test_parse_attack_stix_handles_missing(tmp_path):
    assert parse_attack_stix(str(tmp_path / "missing.json")) == {
        "attack_pattern": [], "malware": [], "intrusion_set": [],
        "tool": [], "course_of_action": [],
    }


@pytest.mark.skipif(not os.path.isfile(_ATT_REAL), reason="real ATT&CK dataset not present")
def test_parse_attack_stix_real():
    parsed = parse_attack_stix(_ATT_REAL)
    assert len(parsed["attack_pattern"]) > 600
    assert len(parsed["malware"]) > 500
    assert len(parsed["intrusion_set"]) > 100
    assert len(parsed["tool"]) > 50
    ap = parsed["attack_pattern"][0]
    assert ap["id"].startswith("T")
    assert ap["source"] == "mitre_attack"
    assert "name" in ap and ap["name"]


def test_parse_yara_dir_tiny(tmp_path):
    yd = tmp_path / "yara"
    yd.mkdir()
    for name, body in _YARA_TINY_DIR.items():
        (yd / name).write_text(body)
    rules = parse_yara_dir(str(yd))
    names = {r["name"] for r in rules}
    assert "FirstRule" in names
    assert "SecondRule" in names
    assert "NoMetaRule" in names
    first = next(r for r in rules if r["name"] == "FirstRule")
    assert first["description"] == "First test rule"
    assert first["author"] == "Test Author"
    assert "hello world" in first["strings"]
    assert "hello" in first["strings"][0] or first["strings"][0] == "hello world"


def test_parse_yara_dir_handles_missing(tmp_path):
    assert parse_yara_dir(str(tmp_path / "missing")) == []


@pytest.mark.skipif(not os.path.isdir(_YARA_REAL), reason="real signature-base not present")
def test_parse_yara_dir_real():
    rules = parse_yara_dir(_YARA_REAL)
    assert len(rules) > 500
    apt = next((r for r in rules if "DNS_Hijacking" in r["name"]), None)
    assert apt is not None
    assert "/Client/Login?id=" in apt["strings"]


def test_threat_corpus_indexes_and_lookup():
    corpus = build_corpus_from_sources()
    corpus.cwe = [
        {"id": "CWE-120", "name": "Buffer Overflow", "description": "buffer overflow",
         "abstraction": "Base", "structure": "Simple", "background": "",
         "languages": ["C"], "technologies": [], "scopes": [], "source": "cwe"}
    ]
    corpus.attack_patterns = [
        {"id": "T1059", "name": "Command Interpreter", "description": "",
         "detection": "", "platforms": ["Linux"], "aliases": [],
         "tactics": [], "is_subtechnique": False, "domains": [], "source": "mitre_attack"}
    ]
    corpus.malware = [
        {"id": "S0001", "name": "Mimikatz", "description": "", "aliases": ["mimikatz"],
         "platforms": ["Windows"], "family": True, "source": "mitre_attack"}
    ]
    corpus.yara_rules = [
        {"name": "RuleA", "description": "desc", "author": "a", "reference": "",
         "strings": ["/login.php?id=", "Mozilla"], "source": "signature_base", "file": "r.yar"}
    ]
    corpus2 = ThreatCorpus(
        corpus.cwe, corpus.attack_patterns, corpus.malware, [], [], [], corpus.yara_rules,
        source_fingerprint="abc",
    )
    counts = corpus2.count_by_type()
    assert counts["cwe"] == 1
    assert counts["yara_rules"] == 1
    assert corpus2.find_cwe("120")["name"] == "Buffer Overflow"
    assert corpus2.find_cwe("CWE-120")["name"] == "Buffer Overflow"
    assert corpus2.find_technique("T1059")["name"] == "Command Interpreter"
    assert corpus2.find_malware("Mimikatz") is not None
    assert corpus2.find_malware("mimikatz") is not None
    assert corpus2.search_yara_strings("/login.php?id=")[0]["name"] == "RuleA"
    assert len(corpus2.all_yara_strings()) >= 2
    assert corpus2.is_empty() is False


def test_threat_corpus_to_from_dict_roundtrip():
    corpus = ThreatCorpus(
        cwe=[{"id": "CWE-1", "name": "X", "description": "d", "abstraction": "Base",
              "structure": "Simple", "background": "", "languages": [],
              "technologies": [], "scopes": [], "source": "cwe"}],
        attack_patterns=[], malware=[], intrusion_sets=[], tools=[],
        mitigations=[], yara_rules=[], source_fingerprint="fp",
    )
    data = corpus.to_dict()
    assert data["version"] == CORPUS_VERSION
    assert data["source_fingerprint"] == "fp"
    restored = ThreatCorpus.from_dict(data)
    assert restored.find_cwe("CWE-1")["name"] == "X"
    assert restored.source_fingerprint == "fp"


def test_corpus_cache_save_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.threat_corpus.CACHE_DIR", str(tmp_path)
    )
    corpus = ThreatCorpus(
        cwe=[{"id": "CWE-2", "name": "Y", "description": "d", "abstraction": "Base",
              "structure": "Simple", "background": "", "languages": [],
              "technologies": [], "scopes": [], "source": "cwe"}],
        attack_patterns=[], malware=[], intrusion_sets=[], tools=[],
        mitigations=[], yara_rules=[], source_fingerprint="x",
    )
    path = save_corpus(corpus)
    assert path == corpus_cache_path()
    assert os.path.isfile(path)
    loaded = load_corpus()
    assert loaded is not None
    assert loaded.find_cwe("CWE-2")["name"] == "Y"
    assert loaded.source_fingerprint == "x"


def test_corpus_cache_wrong_version_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.threat_corpus.CACHE_DIR", str(tmp_path)
    )
    p = corpus_cache_path()
    with open(p, "w") as f:
        json.dump({"version": 999, "cwe": []}, f)
    assert load_corpus() is None


def test_corpus_delete_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.threat_corpus.CACHE_DIR", str(tmp_path)
    )
    corpus = ThreatCorpus([], [], [], [], [], [], [], "fp")
    save_corpus(corpus)
    assert delete_corpus_cache() is True
    assert not os.path.isfile(corpus_cache_path())
    assert delete_corpus_cache() is False


def test_ensure_corpus_loaded_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.threat_corpus.CACHE_DIR", str(tmp_path)
    )
    corpus = ThreatCorpus(
        cwe=[{"id": "CWE-3", "name": "Z", "description": "d", "abstraction": "Base",
              "structure": "Simple", "background": "", "languages": [],
              "technologies": [], "scopes": [], "source": "cwe"}],
        attack_patterns=[], malware=[], intrusion_sets=[], tools=[],
        mitigations=[], yara_rules=[], source_fingerprint="abc",
    )
    save_corpus(corpus)
    loaded, status = ensure_corpus_loaded()
    assert loaded is not None
    assert status["loaded"] is True
    assert status["from_cache"] is True
    assert status["rebuilt"] is False
    assert status["counts"]["cwe"] == 1


def test_ensure_corpus_loaded_no_sources_no_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.threat_corpus.CACHE_DIR", str(tmp_path)
    )
    assert not os.path.isfile(corpus_cache_path())
    loaded, status = ensure_corpus_loaded()
    assert loaded is None
    assert status["loaded"] is False
    assert "no sources" in status["reason"]


def test_ensure_corpus_loaded_rebuild_from_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.threat_corpus.CACHE_DIR", str(tmp_path)
    )
    cwe = tmp_path / "cwe.xml"
    cwe.write_text(_CWE_TINY_XML)
    loaded, status = ensure_corpus_loaded(
        rebuild=True, cwe_path=str(cwe), attack_paths=None, yara_dir=None
    )
    assert loaded is not None
    assert status["rebuilt"] is True
    assert status["counts"]["cwe"] == 2
    assert status["from_cache"] is False
    assert os.path.isfile(corpus_cache_path())


def test_compute_source_fingerprint_stable(tmp_path):
    fp1 = compute_source_fingerprint("", [], "")
    fp2 = compute_source_fingerprint("", [], "")
    assert fp1 == fp2
    assert len(fp1) == 32
    cwe = tmp_path / "c.xml"
    cwe.write_text("<root/>")
    fp3 = compute_source_fingerprint(str(cwe), [], "")
    assert fp3 != fp1


def test_corpus_cache_filename_constant():
    assert f"threat_corpus_v{CORPUS_VERSION}.json" == CORPUS_CACHE_FILENAME
