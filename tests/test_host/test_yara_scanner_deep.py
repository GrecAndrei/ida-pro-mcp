from __future__ import annotations

from pathlib import Path

import pytest

from ida_pro_mcp.host.intelligence.yara_scanner import (
    YaraRuleMatch,
    YaraStringHit,
    compile_text,
    is_yara_available,
    scan_bytes,
    yara_version,
)


def test_yara_string_hit_and_match_dataclasses() -> None:
    hit = YaraStringHit(identifier="$s1", offset=0x100, data="test_indicator")
    assert hit.to_dict() == {
        "identifier": "$s1",
        "offset": 0x100,
        "data": "test_indicator",
    }

    match = YaraRuleMatch(
        rule="Rule_A",
        namespace="default",
        tags=["apt", "malware"],
        meta={"severity": "high"},
        strings=[hit],
    )
    d = match.to_dict()
    assert d["rule"] == "Rule_A"
    assert d["string_count"] == 1
    assert d["tags"] == ["apt", "malware"]


def test_yara_availability_and_compilation() -> None:
    available = is_yara_available()
    assert isinstance(available, bool)
    if not available:
        pytest.skip("yara-python not installed")

    ver = yara_version()
    assert isinstance(ver, str)

    rule_source = """
    rule Unit_Test_Rule {
        strings:
            $str1 = "AUTHENTIC_YARA_TEST"
        condition:
            $str1
    }
    """
    compiled = compile_text(rule_source)
    assert compiled is not None

    matches = scan_bytes(compiled, b"Header... AUTHENTIC_YARA_TEST ...Tail")
    assert len(matches) == 1
    assert matches[0].rule == "Unit_Test_Rule"
    assert matches[0].strings[0].data == "AUTHENTIC_YARA_TEST"
