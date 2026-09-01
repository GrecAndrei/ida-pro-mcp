"""Behavioral tests for the host-side YARA scanner (yara-python backend).

The scanner compiles rule trees, scans bytes/files/address ranges, and
wraps everything in a small load/cache layer.  All tests use local fixture
rules — no network, no IDA.  Skipped wholesale when yara-python is not
installed.
"""
from __future__ import annotations

import pytest

yara = pytest.importorskip("yara")

from ida_pro_mcp.host.intelligence import yara_scanner as ys  # noqa: E402

SIMPLE_RULE = """
rule find_marker
{
    meta:
        description = "detects marker bytes"
        severity = 7
    strings:
        $a = "MAGIC"
        $b = { de ad be ef }
    condition:
        any of them
}
"""


def _rules(source: str = SIMPLE_RULE):
    return ys.compile_text(source)


class TestCompile:
    def test_compile_text_valid(self):
        rules = _rules()
        assert rules is not None

    def test_compile_text_invalid_source_returns_none(self):
        assert ys.compile_text("rule broken {{") is None

    def test_compile_text_empty_returns_none(self):
        assert ys.compile_text("") is None

    def test_compile_rules_empty_dir_reports_error(self, tmp_path):
        rules, file_errors, compile_errors = ys.compile_rules(str(tmp_path / "empty"))
        assert rules is None
        assert compile_errors  # "no rule files found"

    def test_compile_rules_directory(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.yar").write_text(SIMPLE_RULE, encoding="utf-8")
        (rules_dir / "b.yara").write_text("rule other { strings: $x = \"x\" condition: $x }", encoding="utf-8")
        rules, file_errors, compile_errors = ys.compile_rules(str(rules_dir))
        assert rules is not None
        assert file_errors == []
        assert compile_errors == []

    def test_compile_rules_saves_compiled_output(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.yar").write_text(SIMPLE_RULE, encoding="utf-8")
        out = tmp_path / "compiled" / "rules.bin"
        rules, _, _ = ys.compile_rules(str(rules_dir), str(out))
        assert rules is not None
        assert out.is_file()
        assert out.stat().st_size > 0
        # Saved rules reload and still match.
        loaded = ys.load_compiled_rules(str(out))
        assert loaded is not None
        assert ys.scan_bytes(loaded, b"xx MAGIC yy")


class TestScan:
    def test_scan_bytes_meta_tags_offsets(self):
        rules = _rules()
        matches = ys.scan_bytes(rules, b"prefix MAGIC\xde\xad\xbe\xef suffix", base_offset=0x1000)
        assert len(matches) == 1
        m = matches[0]
        assert m.rule == "find_marker"
        assert m.meta["description"] == "detects marker bytes"
        assert m.meta["severity"] == 7
        # MAGIC starts at index 7 -> 0x1007; hex string at index 12 -> 0x100c.
        offsets = [s.offset for s in m.strings]
        assert 0x1007 in offsets
        assert 0x100C in offsets

    def test_scan_bytes_no_match(self):
        assert ys.scan_bytes(_rules(), b"nothing here") == []

    def test_scan_bytes_none_rules(self):
        assert ys.scan_bytes(None, b"data") == []

    def test_scan_file(self, tmp_path):
        target = tmp_path / "sample.bin"
        target.write_bytes(b"AA MAGIC BB")
        matches = ys.scan_file(_rules(), str(target))
        assert len(matches) == 1
        assert matches[0].rule == "find_marker"

    def test_scan_file_missing_path(self):
        assert ys.scan_file(_rules(), "/nonexistent") == []

    def test_string_hit_data_is_clipped_text(self):
        matches = ys.scan_bytes(_rules(), b"x" * 20 + b"MAGIC" + b"y" * 300)
        assert matches
        for s in matches[0].strings:
            assert len(s.data) <= 256


class TestScanAddressRange:
    def test_chunked_range_with_base_offset(self):
        rules = _rules()
        blob = bytearray(b"\x00" * 1000)
        blob[800:805] = b"MAGIC"
        calls = []

        def read_bytes(addr, size):
            calls.append((addr, size))
            rel = addr - 0x5000
            return bytes(blob[rel : rel + size])

        matches = ys.scan_address_range(rules, read_bytes, 0x5000, 0x5000 + 1000, chunk_size=256)
        assert len(matches) == 1
        assert matches[0].strings[0].offset == 0x5000 + 800
        # Data is fetched in bounded chunks (256), not one big read.
        assert all(size <= 256 for _addr, size in calls)

    def test_range_with_read_failures_still_finds_matches(self):
        rules = _rules()
        blob = bytearray(b"\x00" * 512)
        blob[400:405] = b"MAGIC"

        def read_bytes(addr, size):
            if 100 <= addr < 200:  # hole in the middle, away from the match
                return None
            return bytes(blob[addr : addr + size])

        matches = ys.scan_address_range(rules, read_bytes, 0, 512, chunk_size=128)
        assert any(400 in [s.offset for s in m.strings] for m in matches)

    def test_range_respects_max_bytes(self):
        rules = _rules()
        reads = []

        def read_bytes(addr, size):
            reads.append(addr)
            return b"\x00" * size

        ys.scan_address_range(rules, read_bytes, 0, 10_000, chunk_size=32, max_bytes=64)
        assert reads == [0, 32]  # exactly the byte budget, no more chunks

    def test_empty_range_returns_empty(self):
        assert ys.scan_address_range(_rules(), lambda a, s: b"", 10, 10) == []


class TestYaraScanner:
    def test_load_fresh_then_cache(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.yar").write_text(SIMPLE_RULE, encoding="utf-8")
        compiled = tmp_path / "compiled.bin"
        scanner = ys.YaraScanner(str(rules_dir), str(compiled))
        assert not scanner.is_loaded()

        first = scanner.load()
        assert first["loaded"] is True
        assert first["from_cache"] is False
        assert scanner.is_loaded()
        assert scanner.stats()["loaded_from"] == "fresh_compile"
        assert ys.scan_bytes(scanner._rules, b"MAGIC")

        scanner.unload()
        assert not scanner.is_loaded()

        second = scanner.load()
        assert second["loaded"] is True
        assert second["from_cache"] is True
        assert scanner.stats()["loaded_from"] == "compiled_cache"

    def test_load_force_recompile(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.yar").write_text(SIMPLE_RULE, encoding="utf-8")
        compiled = tmp_path / "compiled.bin"
        scanner = ys.YaraScanner(str(rules_dir), str(compiled))
        assert scanner.load()["from_cache"] is False
        assert scanner.load(force_recompile=True)["from_cache"] is False

    def test_load_missing_rules_dir(self, tmp_path):
        scanner = ys.YaraScanner(str(tmp_path / "nope"), str(tmp_path / "c.bin"))
        result = scanner.load()
        assert result["loaded"] is False
        assert "not found" in result["reason"]

    def test_stats_shape(self, tmp_path):
        scanner = ys.YaraScanner(str(tmp_path / "rules"), str(tmp_path / "c.bin"))
        stats = scanner.stats()
        assert stats["loaded"] is False
        assert stats["yara_version"]
        assert stats["rules_dir_exists"] is False

    def test_available_and_version(self):
        assert ys.is_yara_available() is True
        assert ys.yara_version() != "unavailable"


class TestRuleFileIteration:
    def test_iter_skips_oversize_and_other_extensions(self, tmp_path, monkeypatch):
        # Isolate from any real findcrypt corpus downloaded on this machine.
        monkeypatch.setattr(ys, "findcrypt_rules_dir", lambda: "")
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "small.yar").write_text(SIMPLE_RULE, encoding="utf-8")
        (rules_dir / "notes.txt").write_text("not a rule", encoding="utf-8")
        big = rules_dir / "big.yar"
        big.write_bytes(b"x" * (2_000_000 + 1))
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "outside.yar").write_text(SIMPLE_RULE, encoding="utf-8")
        (rules_dir / "linked.yar").symlink_to(outside / "outside.yar")
        (rules_dir / "linked-dir").symlink_to(outside, target_is_directory=True)
        files = ys._iter_rule_files(str(rules_dir))
        assert [fname for _ns, fname in files] == [str(rules_dir / "small.yar")]

    def test_iter_missing_dir(self):
        assert ys._iter_rule_files("/nonexistent") == []
