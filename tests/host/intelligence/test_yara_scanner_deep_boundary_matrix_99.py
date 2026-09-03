"""Offline boundary coverage for the optional YARA scanner backend."""

from __future__ import annotations

import sys
import types

from ida_pro_mcp.host.intelligence import yara_scanner as ys


class _FakeRules:
    def __init__(self, matches=()):
        self.matches = list(matches)
        self.saved = []

    def match(self, **_kwargs):
        return iter(self.matches)

    def save(self, path):
        self.saved.append(path)


def _fake_yara(monkeypatch, *, rules=None, compile_error=None, load_error=None):
    class _Yara:
        class SyntaxError(Exception):
            pass

        @staticmethod
        def compile(**_kwargs):
            if compile_error:
                raise compile_error
            return rules or _FakeRules()

        @staticmethod
        def load(_path):
            if load_error:
                raise load_error
            return rules or _FakeRules()

    monkeypatch.setitem(sys.modules, "yara", _Yara)
    return _Yara


def test_yara_availability_version_and_safe_meta_failure(monkeypatch):
    monkeypatch.setitem(sys.modules, "yara", None)
    assert ys.is_yara_available() is False
    assert ys.yara_version() == "unavailable"

    class _BadString:
        def __str__(self):
            raise RuntimeError("cannot stringify")

    assert ys._safe_meta_value(_BadString()) is None
    assert ys.default_rules_dir().endswith("signature-base/yara")
    assert ys.default_compiled_path().endswith(ys._COMPILED_FILENAME)


def test_rule_file_iteration_handles_extra_dirs_size_errors_and_cap(tmp_path, monkeypatch):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    first = rules_dir / "first.yar"
    second = rules_dir / "second.yar"
    first.write_text("rule first { condition: true }")
    second.write_text("rule second { condition: true }")
    extra_missing = tmp_path / "missing-extra"
    monkeypatch.setattr(ys, "findcrypt_rules_dir", lambda: str(extra_missing))
    real_getsize = ys.os.path.getsize

    def getsize_with_error(path):
        if str(path) == str(second):
            raise OSError("stat failed")
        return real_getsize(path)

    monkeypatch.setattr(ys.os.path, "getsize", getsize_with_error)
    assert ys._iter_rule_files(str(rules_dir)) == [("first", str(first))]

    monkeypatch.setattr(ys.os.path, "getsize", real_getsize)
    monkeypatch.setattr(ys, "_MAX_RULE_FILES", 1)
    assert len(ys._iter_rule_files(str(rules_dir))) == 1

    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "first.yar").write_text("rule extra { condition: true }")
    monkeypatch.setattr(ys, "_MAX_RULE_FILES", 5000)
    monkeypatch.setattr(ys, "findcrypt_rules_dir", lambda: str(extra))
    namespaces = [namespace for namespace, _path in ys._iter_rule_files(str(rules_dir))]
    assert namespaces == ["first", "second", "first__1"]


def test_compile_rules_reports_read_compile_and_save_failures(monkeypatch, tmp_path):
    rule_path = tmp_path / "broken.yar"
    rule_path.write_text("rule broken { condition: true }")
    monkeypatch.setattr(ys, "_iter_rule_files", lambda _path: [("broken", str(rule_path))])
    monkeypatch.setattr(ys, "is_yara_available", lambda: True)
    _fake_yara(monkeypatch, compile_error=RuntimeError("compiler unavailable"))
    rules, file_errors, compile_errors = ys.compile_rules(str(tmp_path))
    assert rules is None and not file_errors
    assert compile_errors[0]["code"] == "YARA_SCAN_ERROR"

    monkeypatch.setattr(ys, "_iter_rule_files", lambda _path: [("missing", str(tmp_path / "missing.yar"))])
    rules, file_errors, compile_errors = ys.compile_rules(str(tmp_path))
    assert rules is None and file_errors and compile_errors[0]["code"] == "NO_RESULTS"

    monkeypatch.setattr(ys, "_iter_rule_files", lambda _path: [("broken", str(rule_path))])
    compiled = _FakeRules()
    _fake_yara(monkeypatch, rules=compiled)
    out = tmp_path / "out.bin"
    assert ys.compile_rules(str(tmp_path), str(out))[0] is compiled
    assert ys.compile_rules(str(tmp_path), externals={})[0] is compiled
    assert compiled.saved == [str(out)]

    class _BrokenSave(_FakeRules):
        def save(self, _path):
            raise OSError("disk full")

    _fake_yara(monkeypatch, rules=_BrokenSave())
    _, _, save_errors = ys.compile_rules(str(tmp_path), str(out))
    assert save_errors[0]["code"] == "IO_ERROR"


def test_compiled_loader_and_conversion_catch_optional_and_malformed_backends(monkeypatch, tmp_path):
    compiled = tmp_path / "compiled.bin"
    compiled.write_bytes(b"compiled")
    monkeypatch.setattr(ys, "is_yara_available", lambda: False)
    assert ys.load_compiled_rules(str(compiled)) is None

    _fake_yara(monkeypatch, load_error=RuntimeError("bad compiled rules"))
    monkeypatch.setattr(ys, "is_yara_available", lambda: True)
    assert ys.load_compiled_rules(str(compiled)) is None

    class _BadTagsMeta:
        rule = "bad"

        @property
        def tags(self):
            raise RuntimeError("tags")

        @property
        def meta(self):
            raise RuntimeError("meta")

        @property
        def strings(self):
            raise RuntimeError("strings")

    converted = ys._match_to_rule_match(_BadTagsMeta())
    assert converted.tags == [] and converted.meta == {} and converted.strings == []

    class _BadSlice(bytes):
        def __getitem__(self, _key):
            return self

        def decode(self, **_kwargs):
            raise RuntimeError("decode")

    class _BadMatched:
        identifier = "bad"

        class _BadInstance:
            @property
            def matched_data(self):
                raise RuntimeError("data unavailable")

        instances = [
            _BadInstance(),
            types.SimpleNamespace(matched_data=_BadSlice(b"raw"), offset=3),
            types.SimpleNamespace(matched_data=b"ok", offset=4),
        ]

    match = types.SimpleNamespace(
        rule="demo", namespace="n", tags=None, meta=None, strings=[_BadMatched()]
    )
    result = ys._match_to_rule_match(match, base_offset=10)
    assert len(result.strings) == 3
    assert result.strings[0].data == ""
    assert result.strings[1].data.startswith("b'")
    assert result.strings[2].offset == 14


def test_scan_limits_and_address_range_match_limits(monkeypatch):
    match = types.SimpleNamespace(rule="r", namespace="", tags=[], meta={}, strings=[])
    rules = _FakeRules([match, match])
    monkeypatch.setattr(ys, "_MAX_MATCHES_PER_SCAN", 1)
    assert len(ys.scan_bytes(rules, b"data")) == 1
    assert len(ys.scan_file(rules, __file__)) == 1

    monkeypatch.setattr(ys, "scan_bytes", lambda *_args, **_kwargs: [ys.YaraRuleMatch("r", "", [], {})])
    assert len(ys.scan_address_range(rules, lambda _addr, _size: b"data", 0, 4, chunk_size=4)) == 1


def test_scanner_delegates_properties_availability_and_cache_compile_failure(monkeypatch, tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    compiled = tmp_path / "compiled.bin"
    compiled.write_bytes(b"cache")
    scanner = ys.YaraScanner(str(rules_dir), str(compiled))
    assert scanner.rules_dir == str(rules_dir)
    assert scanner.compiled_path == str(compiled)
    monkeypatch.setattr(ys, "is_yara_available", lambda: True)
    monkeypatch.setattr(ys, "load_compiled_rules", lambda _path: None)
    monkeypatch.setattr(ys, "compile_rules", lambda *_args: (None, [{"file": 1}], [{"compile": 1}]))
    failed = scanner.load()
    assert failed["loaded"] is False and failed["file_errors"] == [{"file": 1}]
    assert scanner.available() is True
    scanner._rules = _FakeRules()
    assert scanner.scan_bytes(b"x") == []
    assert scanner.scan_file(__file__) == []
    assert scanner.scan_address_range(lambda _addr, _size: b"", 0, 1) == []
    scanner.unload()
    assert scanner.is_loaded() is False
