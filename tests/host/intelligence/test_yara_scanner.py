from __future__ import annotations

import os
import time

import pytest

from ida_pro_mcp.host.intelligence.yara_scanner import (
    YaraRuleMatch,
    YaraScanner,
    YaraStringHit,
    compile_rules,
    compile_text,
    default_compiled_path,
    default_rules_dir,
    is_yara_available,
    load_compiled_rules,
    scan_address_range,
    scan_bytes,
    scan_file,
    yara_version,
)

_YARA_REAL = "/home/alex/Downloads/datasets-temp/signature-base/yara"
_HAVE_REAL = os.path.isdir(_YARA_REAL)


_TINY_RULE = (
    'rule TestRule {\n'
    '   meta:\n'
    '      description = "test rule for scanner tests"\n'
    '      author = "Test Author"\n'
    '      reference = "https://example.com"\n'
    '   strings:\n'
    '      $hello = "hello world" ascii\n'
    '      $login = "/login.php?id="\n'
    '   condition:\n'
    '      any of them\n'
    '}\n'
)

_TINY_RULE2 = (
    'rule TestRuleTwo {\n'
    '   meta:\n'
    '      description = "second test rule"\n'
    '   strings:\n'
    '      $world = "world"\n'
    '   condition:\n'
    '      $world\n'
    '}\n'
)

_TINY_DIR = {
    "rule1.yar": _TINY_RULE,
    "rule2.yar": _TINY_RULE2,
}


def test_yara_available_and_version():
    assert is_yara_available() is True
    v = yara_version()
    assert v != "unavailable"
    assert v.count(".") >= 1


def test_default_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.yara_scanner.CACHE_DIR", str(tmp_path)
    )
    assert default_rules_dir() == str(tmp_path / "signature-base" / "yara")
    assert default_compiled_path() == str(tmp_path / "signature_base_compiled.bin")


def test_compile_rules_tiny(tmp_path):
    yd = tmp_path / "yara"
    yd.mkdir()
    for name, body in _TINY_DIR.items():
        (yd / name).write_text(body)
    rules, fe, ce = compile_rules(str(yd))
    assert rules is not None
    assert fe == []
    assert ce == []


def test_compile_rules_no_files(tmp_path):
    rules, fe, ce = compile_rules(str(tmp_path / "missing"))
    assert rules is None
    assert ce
    assert "no rule files" in ce[0]["message"]
    assert ce[0].get("code") == "NO_RESULTS"
    assert ce[0].get("error") is True
    assert ce[0].get("hint")


def test_compile_rules_missing_dir_returns_error():
    rules, fe, ce = compile_rules("/nonexistent/path")
    assert rules is None
    assert ce
    assert ce[0].get("error") is True


def test_compile_rules_writes_to_output(tmp_path):
    yd = tmp_path / "yara"
    yd.mkdir()
    (yd / "r.yar").write_text(_TINY_RULE)
    out = tmp_path / "compiled.bin"
    rules, fe, ce = compile_rules(str(yd), str(out))
    assert rules is not None
    assert os.path.isfile(str(out))


def test_load_compiled_rules_missing(tmp_path):
    assert load_compiled_rules(str(tmp_path / "missing.bin")) is None


def test_load_compiled_rules_roundtrip(tmp_path):
    yd = tmp_path / "yara"
    yd.mkdir()
    (yd / "r.yar").write_text(_TINY_RULE)
    out = tmp_path / "compiled.bin"
    rules, _, _ = compile_rules(str(yd), str(out))
    assert rules is not None
    loaded = load_compiled_rules(str(out))
    assert loaded is not None


def test_scan_bytes_finds_match(tmp_path):
    yd = tmp_path / "yara"
    yd.mkdir()
    (yd / "r.yar").write_text(_TINY_RULE)
    rules, _, _ = compile_rules(str(yd))
    matches = scan_bytes(rules, b"this contains hello world and /login.php?id=42")
    assert len(matches) == 1
    m = matches[0]
    assert m.rule == "TestRule"
    assert "test rule" in m.meta.get("description", "")
    identifiers = {h.identifier for h in m.strings}
    assert "$hello" in identifiers
    assert "$login" in identifiers
    assert all(isinstance(h.offset, int) for h in m.strings)


def test_scan_bytes_no_match(tmp_path):
    yd = tmp_path / "yara"
    yd.mkdir()
    (yd / "r.yar").write_text(_TINY_RULE)
    rules, _, _ = compile_rules(str(yd))
    assert scan_bytes(rules, b"unrelated data") == []


def test_scan_bytes_handles_none_rules():
    assert scan_bytes(None, b"hello world") == []


def test_scan_file_missing():
    assert scan_file(None, "/nonexistent") == []


def test_scan_address_range_chunks_correctly(tmp_path):
    yd = tmp_path / "yara"
    yd.mkdir()
    (yd / "r.yar").write_text(_TINY_RULE)
    rules, _, _ = compile_rules(str(yd))
    buf = b"\x00" * 100 + b"hello world" + b"\x00" * 100
    chunks_seen: list[tuple[int, int]] = []

    def reader(addr: int, size: int) -> bytes:
        chunks_seen.append((addr, size))
        return buf[addr: addr + size]

    matches = scan_address_range(rules, reader, 0, len(buf), chunk_size=64)
    assert matches
    assert matches[0].rule == "TestRule"
    assert any(h.offset == 100 for h in matches[0].strings)
    assert len(chunks_seen) >= 2
    assert all(size <= 64 for _a, size in chunks_seen)


def test_scan_address_range_handles_none_rules():
    assert scan_address_range(None, lambda a, s: b"", 0, 10) == []


def test_scan_address_range_handles_empty_range(tmp_path):
    yd = tmp_path / "yara"
    yd.mkdir()
    (yd / "r.yar").write_text(_TINY_RULE)
    rules, _, _ = compile_rules(str(yd))
    assert scan_address_range(rules, lambda a, s: b"", 10, 10) == []


def test_scan_address_range_continues_on_none_read(tmp_path):
    yd = tmp_path / "yara"
    yd.mkdir()
    (yd / "r.yar").write_text(_TINY_RULE)
    rules, _, _ = compile_rules(str(yd))

    def flaky_reader(addr: int, size: int):
        if addr == 0:
            return None
        return b"hello world" + b"\x00" * (size - len(b"hello world"))

    matches = scan_address_range(rules, flaky_reader, 0, 200, chunk_size=100)
    assert matches
    assert matches[0].rule == "TestRule"


def test_yara_scanner_load_and_stats(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.yara_scanner.CACHE_DIR", str(tmp_path)
    )
    yd = tmp_path / "yara"
    yd.mkdir()
    (yd / "r.yar").write_text(_TINY_RULE)
    s = YaraScanner(rules_dir=str(yd), compiled_path=str(tmp_path / "c.bin"))
    assert s.is_loaded() is False
    status = s.load()
    assert status["loaded"] is True
    assert status["from_cache"] is False
    assert s.is_loaded() is True
    st = s.stats()
    assert st["loaded"] is True
    assert st["rules_dir_exists"] is True
    assert s.scan_bytes(b"hello world")
    s.unload()
    assert s.is_loaded() is False


def test_yara_scanner_load_from_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.yara_scanner.CACHE_DIR", str(tmp_path)
    )
    yd = tmp_path / "yara"
    yd.mkdir()
    (yd / "r.yar").write_text(_TINY_RULE)
    out = tmp_path / "c.bin"
    compile_rules(str(yd), str(out))
    s = YaraScanner(rules_dir=str(yd), compiled_path=str(out))
    status = s.load()
    assert status["loaded"] is True
    assert status["from_cache"] is True
    assert s.scan_bytes(b"hello world")


def test_yara_scanner_load_missing_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.yara_scanner.CACHE_DIR", str(tmp_path)
    )
    s = YaraScanner(
        rules_dir=str(tmp_path / "nonexistent"),
        compiled_path=str(tmp_path / "c.bin"),
    )
    status = s.load()
    assert status["loaded"] is False
    assert "rules dir" in status["reason"]


@pytest.mark.skipif(not _HAVE_REAL, reason="real signature-base not present")
def test_yara_scanner_real_dataset_full_flow(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.yara_scanner.CACHE_DIR", str(tmp_path)
    )
    s = YaraScanner(rules_dir=_YARA_REAL, compiled_path=str(tmp_path / "sb.bin"))
    t = time.time()
    status = s.load()
    assert status["loaded"] is True, f"compile failed: {status}"
    elapsed = time.time() - t
    assert elapsed < 5.0
    buf = (
        b"MZ" + b"\x00" * 100
        + b"/Client/Login?id=42 Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko"
    )
    matches = s.scan_bytes(buf)
    assert any("DNS" in m.rule or "Hijack" in m.rule for m in matches), f"no DNS matches: {[m.rule for m in matches]}"


@pytest.mark.skipif(not _HAVE_REAL, reason="real signature-base not present")
def test_yara_scanner_real_dataset_cached_reload(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.yara_scanner.CACHE_DIR", str(tmp_path)
    )
    s1 = YaraScanner(rules_dir=_YARA_REAL, compiled_path=str(tmp_path / "sb.bin"))
    s1.load(force_recompile=True)
    s2 = YaraScanner(rules_dir=_YARA_REAL, compiled_path=str(tmp_path / "sb.bin"))
    t = time.time()
    status = s2.load()
    elapsed = time.time() - t
    assert status["loaded"] is True
    assert status["from_cache"] is True
    assert elapsed < 0.5


def test_compile_text_valid_rule():
    rules = compile_text(_TINY_RULE)
    assert rules is not None
    buf = b"the quick brown fox /login.php?id=42 hello world"
    matches = scan_bytes(rules, buf, base_offset=0x1000)
    assert matches, "expected at least one match for hello world string"
    m = matches[0]
    assert isinstance(m, YaraRuleMatch)
    assert m.rule == "TestRule"
    assert m.namespace == "default"
    assert m.meta.get("description") == "test rule for scanner tests"
    assert isinstance(m.strings, list) and m.strings
    hit = m.strings[0]
    assert isinstance(hit, YaraStringHit)
    assert hit.identifier in ("$hello", "$login")
    # base_offset shifts the absolute offset by region_base
    assert hit.offset >= 0x1000


def test_compile_text_invalid_rule_returns_none():
    """compile_text must swallow yara-python errors and return None —
    callers (yara_hunt) fall back to the regex scanner when this returns None."""
    rules = compile_text("not a real yara rule -- syntax error {")
    assert rules is None


def test_compile_text_empty_source_returns_none():
    assert compile_text("") is None


def test_scan_bytes_empty_data_returns_empty():
    rules = compile_text(_TINY_RULE)
    assert rules is not None
    assert scan_bytes(rules, b"") == []
    assert scan_bytes(rules, b"no match here") == []


def test_scan_bytes_none_rules_returns_empty():
    """scan_bytes(None, data) is the documented graceful-degradation path
    used when yara-python is unavailable or the rule failed to compile."""
    assert scan_bytes(None, b"hello world") == []


def test_yara_string_hit_to_dict_shape():
    """yara_hunt builds its entry dict from these fields:
    match.rule, hit.identifier, hit.offset, hit.data.
    Lock the data-class contract so the integration doesn't drift."""
    hit = YaraStringHit(identifier="$a", offset=42, data="abc")
    assert hit.identifier == "$a"
    assert hit.offset == 42
    assert hit.data == "abc"
    assert hit.to_dict() == {"identifier": "$a", "offset": 42, "data": "abc"}


def test_yara_rule_match_to_dict_shape():
    m = YaraRuleMatch(
        rule="R",
        namespace="ns",
        tags=["tlp_red"],
        meta={"author": "test"},
        strings=[YaraStringHit(identifier="$x", offset=10, data="x")],
    )
    d = m.to_dict()
    assert d["rule"] == "R"
    assert d["namespace"] == "ns"
    assert d["tags"] == ["tlp_red"]
    assert d["meta"] == {"author": "test"}
    assert d["string_count"] == 1
    assert d["strings"] == [{"identifier": "$x", "offset": 10, "data": "x"}]


@pytest.mark.skipif(not is_yara_available(), reason="yara-python not installed")
def test_compile_text_matches_substring_at_offset():
    rules = compile_text(
        'rule Needle {\n'
        '   strings: $needle = "needle"\n'
        '   condition: $needle\n'
        '}\n'
    )
    data = b"AAAAA needle BBBBB"
    matches = scan_bytes(rules, data, base_offset=0)
    assert matches
    assert matches[0].rule == "Needle"
    assert any(h.offset == 6 and h.identifier == "$needle" for h in matches[0].strings)
