"""Boundary coverage for downloaded threat-feed source parsers."""

from __future__ import annotations

import json
import zipfile

from ida_pro_mcp.host.intelligence.sources.urlhaus import UrlhausSource
from ida_pro_mcp.host.intelligence.sources.yara_rules_extra import YaraRulesExtraSource


def test_urlhaus_parser_supports_feed_shapes_and_bad_files(tmp_path):
    source = UrlhausSource()
    assert source.parse(str(tmp_path / "missing")) == []
    path = tmp_path / "feed.json"
    path.write_text(
        json.dumps({"one": {"url": "http://one", "tags": ["a", "b"]}, "two": [{"url": "http://two", "date": "today"}, 3]}),
        encoding="utf-8",
    )
    entries = source.parse(str(tmp_path))
    assert [entry["url"] for entry in entries] == ["http://one", "http://two"]
    assert entries[0]["threat"] == "a, b"
    assert entries[1]["date_added"] == "today"
    path.write_text("not json", encoding="utf-8")
    assert source.parse(str(tmp_path)) == []
    path.write_text(json.dumps({"data": [{"url": "http://data", "threat": "x"}]}), encoding="utf-8")
    assert source.parse(str(tmp_path))[0]["url"] == "http://data"


def test_urlhaus_archive_and_zip_detection_modes(tmp_path):
    source = UrlhausSource()
    assert UrlhausSource._find_json(str(tmp_path / "none")) is None
    assert not UrlhausSource._is_zip(str(tmp_path / "none"))
    archive = tmp_path / "download.bin"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("nested/feed.json", "[]")
    assert source._is_zip(str(archive)) is True
    dest = tmp_path / "out"
    dest.mkdir()
    source._post_download(str(archive), str(dest))
    assert (dest / "nested" / "feed.json").exists()
    plain = tmp_path / "plain.data"
    plain.write_text("plain", encoding="utf-8")
    source._post_download(str(plain), str(dest))
    source._post_download(str(tmp_path / "missing.data"), str(dest))


def test_yara_rules_extra_parser_and_archive_modes(tmp_path, monkeypatch):
    import ida_pro_mcp.host.intelligence.threat_corpus as corpus

    source = YaraRulesExtraSource()
    calls = []
    monkeypatch.setattr(corpus, "parse_yara_dir", lambda path: calls.append(path) or [{"name": "rule"}])
    flat = tmp_path / "flat"
    flat.mkdir()
    assert source.parse(str(flat))[0]["source"] == "yara_rules_extra"
    nested = tmp_path / "nested"
    (nested / "rules-master").mkdir(parents=True)
    assert source.parse(str(nested))[0]["source"] == "yara_rules_extra"
    assert len(calls) == 2

    archive = tmp_path / "rules.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("rules-master/test.yar", "rule test { condition: true }")
    dest = tmp_path / "extract"
    dest.mkdir()
    source._post_download(str(archive), str(dest))
    assert (dest / "rules-master" / "test.yar").exists()
    source._post_download(str(tmp_path / "not-archive.txt"), str(dest))
