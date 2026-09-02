from __future__ import annotations

import json
from pathlib import Path

import pytest

from ida_pro_mcp.host.intelligence.threat_corpus import (
    ThreatCorpus,
    load_corpus,
    parse_attack_stix,
    parse_cwe_xml,
    parse_yara_dir,
    save_corpus,
)


def test_threat_corpus_model() -> None:
    empty_corpus = ThreatCorpus()
    assert empty_corpus.is_empty() is True

    corpus = ThreatCorpus(
        entries={
            "cwe": [
                {
                    "id": "CWE-120",
                    "name": "Buffer Copy without Checking Size of Input",
                    "description": "The software copies an input buffer without checking size.",
                }
            ]
        }
    )
    assert corpus.is_empty() is False
    assert corpus.count_by_type()["cwe"] == 1
    assert corpus.find_cwe("CWE-120") is not None


def test_parse_cwe_xml(tmp_path: Path) -> None:
    cwe_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">
        <Weaknesses>
            <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation">
                <Description>Cross-site scripting (XSS)</Description>
            </Weakness>
        </Weaknesses>
    </Weakness_Catalog>
    """
    xml_file = tmp_path / "cwe.xml"
    xml_file.write_text(cwe_xml, encoding="utf-8")

    cwes = parse_cwe_xml(str(xml_file))
    assert len(cwes) == 1
    assert cwes[0]["id"] == "CWE-79"
    assert cwes[0]["name"] == "Improper Neutralization of Input During Web Page Generation"


def test_parse_attack_stix(tmp_path: Path) -> None:
    stix_payload = {
        "type": "bundle",
        "id": "bundle--123",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--456",
                "name": "Process Injection",
                "description": "Adversaries may inject code into processes.",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1055"}],
            }
        ],
    }
    stix_file = tmp_path / "attack.json"
    stix_file.write_text(json.dumps(stix_payload), encoding="utf-8")

    attack_data = parse_attack_stix(str(stix_file))
    assert len(attack_data["attack_pattern"]) == 1
    assert attack_data["attack_pattern"][0]["id"] == "T1055"
    assert attack_data["attack_pattern"][0]["name"] == "Process Injection"


def test_parse_yara_dir(tmp_path: Path) -> None:
    yara_dir = tmp_path / "yara_rules"
    yara_dir.mkdir()
    rule_file = yara_dir / "sample.yar"
    rule_file.write_text(
        """
        rule Detect_Malware {
            meta:
                description = "Detects malicious sample"
                author = "Analyst"
            strings:
                $s1 = "malicious_payload"
            condition:
                $s1
        }
        """,
        encoding="utf-8",
    )

    rules = parse_yara_dir(str(yara_dir))
    assert len(rules) == 1
    assert rules[0]["name"] == "Detect_Malware"
    assert rules[0]["description"] == "Detects malicious sample"


def test_corpus_save_and_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IDA_MCP_CACHE_DIR", str(tmp_path))
    corpus = ThreatCorpus(entries={"cwe": [{"id": "CWE-89", "name": "SQL Injection"}]})

    cache_path = save_corpus(corpus)
    assert Path(cache_path).is_file()

    loaded = load_corpus()
    assert loaded is not None
    assert any(item.get("id") == "CWE-89" for item in loaded.cwe)
