"""Behavior coverage for the wiki and miscellaneous IDA tools.

These tests exercise the public tool contracts and the filesystem/IDA seams
that are easy to miss in a happy-path fake-IDB test.
"""

from __future__ import annotations

import builtins
import importlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace

wiki_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.wiki")
misc_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.misc")


def test_wiki_read_pagination_sections_and_missing_topic():
    wiki_mod._WIKI_CACHE.clear()

    first = wiki_mod.wiki(action="read", topic="QuickStart", limit=2)
    assert first["ok"] is True
    assert first["content"].startswith("# QuickStart")
    assert first["_truncated"] is True
    assert first["next_offset"] == 2
    assert first["breadcrumbs"] == ["QuickStart"]

    section = wiki_mod.wiki(
        action="read",
        topic="QuickStart",
        section="Open a binary",
    )
    assert section["ok"] is True
    assert section["section_filter"] == "Open a binary"
    assert "ida_open_binary" in section["content"]
    assert section["line_range"].split("-")[0].isdigit()

    missing_section = wiki_mod.wiki(
        action="read", topic="QuickStart", section="does not exist"
    )
    assert missing_section["error"] is True
    assert missing_section["code"] == wiki_mod.MCPError.INVALID_ARGS

    missing = wiki_mod.wiki(action="read", topic="QuickStrat")
    assert missing["error"] is True
    assert missing["code"] == wiki_mod.MCPError.FILE_NOT_FOUND
    assert "suggestion" in missing

    assert wiki_mod.wiki(action="read").get("error") is True
    assert wiki_mod.wiki(action="read", topic="../QuickStart").get("error") is True


def test_wiki_search_semantic_sections_and_suggestions():
    wiki_mod._WIKI_CACHE.clear()

    search = wiki_mod.wiki(
        action="search", query="binary", include_snippets=True, context_lines=1
    )
    assert search["ok"] is True
    assert search["count"] > 0
    assert all(item["matched_on"] == ["content_contains"] for item in search["matches"])
    assert any(item.get("matches") for item in search["matches"])

    semantic = wiki_mod.wiki(
        action="semantic_search", query="flow", include_snippets=True
    )
    assert semantic["ok"] is True
    assert semantic["count"] > 0
    assert all(item["matched_on"] == ["semantic_overlap"] for item in semantic["matches"])

    sections = wiki_mod.wiki(action="sections", topic="tools/code")
    assert sections["ok"] is True
    assert sections["headers"]
    assert {"level", "text", "line"} <= sections["headers"][0].keys()

    suggested = wiki_mod.wiki(action="suggest", query="calculaton")
    assert suggested["ok"] is True
    assert suggested["suggestion"]
    assert 0.0 < suggested["score"] <= 1.0

    no_suggestion = wiki_mod.wiki(action="suggest", query="zzzz-not-a-topic")
    assert no_suggestion == {
        "ok": True,
        "query": "zzzz-not-a-topic",
        "suggestion": None,
        "score": 0.0,
    }
    assert wiki_mod.wiki(action="search").get("error") is True
    assert wiki_mod.wiki(action="suggest").get("error") is True
    assert wiki_mod.wiki(action="unknown").get("error") is True


def test_wiki_file_cache_and_fuzzy_matching(tmp_path: Path):
    first_path = tmp_path / "one.md"
    second_path = tmp_path / "two.md"
    first_path.write_text("one", encoding="utf-8")
    second_path.write_text("two", encoding="utf-8")

    old_limit = wiki_mod._MAX_WIKI_CACHE
    try:
        wiki_mod._WIKI_CACHE.clear()
        wiki_mod._MAX_WIKI_CACHE = 1
        assert wiki_mod._read_wiki_file(str(first_path)) == "one"
        assert wiki_mod._read_wiki_file(str(first_path)) == "one"
        assert wiki_mod._read_wiki_file(str(second_path)) == "two"
        assert os.path.realpath(first_path) not in wiki_mod._WIKI_CACHE
        assert os.path.realpath(second_path) in wiki_mod._WIKI_CACHE
    finally:
        wiki_mod._MAX_WIKI_CACHE = old_limit
        wiki_mod._WIKI_CACHE.clear()

    topics = {"tools": ["calculation", "code"], "root": ["QuickStart"]}
    assert wiki_mod._fuzzy_find_topic("tools/code", topics) == ("tools/code", 1.0)
    fuzzy, score = wiki_mod._fuzzy_find_topic("calculaton", topics)
    assert fuzzy == "tools/calculation"
    assert score >= 0.6
    assert wiki_mod._fuzzy_find_topic("zzzz", topics) == (None, 0.0)


def test_misc_file_formats_and_write_errors(tmp_path: Path):
    binary_path = tmp_path / "nested" / "data.bin"
    written = misc_mod.write_file_impl(str(binary_path), "00ff10", encoding="binary")
    assert written == {
        "ok": True,
        "path": str(binary_path),
        "size": 3,
        "encoding": "binary",
    }
    read_binary = misc_mod.read_file_impl(str(binary_path), encoding="binary")
    assert read_binary["content"] == "00ff10"
    assert read_binary["size"] == 3

    empty = misc_mod.write_file_impl(str(tmp_path / "empty.txt"), "")
    assert empty["ok"] is True and empty["size"] == 0
    assert misc_mod.read_file_impl(str(tmp_path / "empty.txt"))["content"] == ""

    invalid_hex = misc_mod.write_file_impl(str(tmp_path / "bad.bin"), "not-hex", "binary")
    assert invalid_hex["error"] is True
    assert invalid_hex["code"] == misc_mod.MCPError.FILE_ENCODING_ERROR

    missing = misc_mod.read_file_impl(str(tmp_path / "missing"))
    assert missing["code"] == misc_mod.MCPError.FILE_NOT_FOUND
    not_file = misc_mod.read_file_impl(str(tmp_path))
    assert not_file["code"] == misc_mod.MCPError.INVALID_FILE_FORMAT


def test_misc_python_idc_and_unknown_action(monkeypatch):
    multiline = misc_mod.misc(action="python", code="print('hello')\nanswer = 42")
    assert multiline["ok"] is True
    assert multiline["output"] == "hello\n"
    assert multiline["result"] is None

    syntax = misc_mod.execute_python("(")
    assert syntax["error"] is True
    assert syntax["code"] == misc_mod.MCPError.SCRIPT_ERROR

    runtime = misc_mod.execute_python("raise RuntimeError('boom')")
    assert runtime["error"] is True
    assert "boom" in runtime["message"]

    too_large = misc_mod.execute_python("x" * (misc_mod._MAX_SCRIPT_LENGTH + 1))
    assert too_large["code"] == misc_mod.MCPError.SIZE_LIMIT_EXCEEDED

    idc = sys.modules["idc"]
    monkeypatch.setattr(idc, "eval_idc", lambda code: 7)
    assert misc_mod.misc(action="idc", code="return 7")["result"] == 7
    monkeypatch.setattr(idc, "eval_idc", lambda code: (_ for _ in ()).throw(ValueError("bad idc")))
    assert misc_mod.misc(action="idc", code="bad")["error"] is True

    unknown = misc_mod.misc(action="not-an-action")
    assert unknown["error"] is True
    assert unknown["code"] == misc_mod.MCPError.ACTION_NOT_FOUND


def test_misc_signatures_and_plugin_actions(monkeypatch, tmp_path: Path):
    sig_dir = tmp_path / "sig"
    sig_dir.mkdir()
    (sig_dir / "compiler.sig").write_text("sig", encoding="ascii")
    (sig_dir / "other.sig").write_text("sig", encoding="ascii")
    monkeypatch.setattr(misc_mod.idaapi, "idadir", lambda _arg: str(tmp_path), raising=False)
    monkeypatch.setattr(misc_mod, "_SIG_PATH_CACHE", None)
    monkeypatch.setattr(misc_mod.idaapi, "get_idasgn_qty", lambda: 1, raising=False)
    monkeypatch.setattr(misc_mod.idaapi, "get_idasgn_desc", lambda index: "applied.sig", raising=False)

    listed = misc_mod.misc(action="list_sigs", name="compiler")
    assert listed["ok"] is True
    assert [item["name"] for item in listed["available"]] == ["compiler"]
    assert listed["applied"] == ["applied.sig"]

    assert misc_mod.misc(action="load_sig", name="missing.sig")["code"] == misc_mod.MCPError.NOT_FOUND

    calls = []
    libfuncs = SimpleNamespace(
        plan_to_apply_ldes=lambda name: calls.append(("plan", name)),
        apply_ldes=lambda name: calls.append(("apply", name)),
    )
    monkeypatch.setitem(sys.modules, "ida_libfuncs", libfuncs)
    loaded = misc_mod.misc(action="load_sig", name="compiler.sig")
    assert loaded == {"ok": True, "name": "compiler", "applied": True, "note": "Signature applied immediately"}
    assert calls == [("plan", "compiler"), ("apply", "compiler")]

    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "demo.py").write_text("", encoding="ascii")
    (plugin_dir / "ignore.txt").write_text("", encoding="ascii")
    monkeypatch.setenv("IDADIR", str(tmp_path))
    loader = sys.modules["ida_loader"]
    monkeypatch.setattr(loader, "find_plugin", lambda name, _load: 123, raising=False)
    monkeypatch.setattr(loader, "run_plugin", lambda plugin, arg: plugin == 123 and arg == 9, raising=False)
    plugins = misc_mod.misc(action="plugin_list")
    assert plugins["count"] == 1
    assert plugins["plugins"][0]["name"] == "demo.py"
    assert misc_mod.misc(action="plugin_run", name="demo", arg=9)["ok"] is True

    monkeypatch.setattr(loader, "find_plugin", lambda name, _load: -1, raising=False)
    assert misc_mod.misc(action="plugin_run", name="missing")["code"] == misc_mod.MCPError.PLUGIN_NOT_FOUND
    monkeypatch.setattr(loader, "find_plugin", lambda name, _load: 123, raising=False)
    monkeypatch.setattr(loader, "run_plugin", lambda plugin, arg: False, raising=False)
    assert misc_mod.misc(action="plugin_run", name="demo")["code"] == misc_mod.MCPError.PLUGIN_ERROR


def test_misc_health_reload_and_signature_api_fallback(monkeypatch):
    monkeypatch.setattr(misc_mod.idaapi, "get_kernel_version", lambda: "fake-9.2", raising=False)
    monkeypatch.setattr(misc_mod.idaapi, "get_ida_subdir", lambda _name: "/fake/ida", raising=False)
    health = misc_mod.misc(action="health", verbose=True)
    assert health.get("ok") is True
    assert {"ida_path", "cwd", "python_version", "platform"} <= health.keys()

    assert misc_mod.misc(action="reload").get("error") is True
    reload_result = misc_mod.misc(action="reload", modules="misc,does_not_exist")
    assert reload_result["ok"] is True
    assert reload_result["reloaded"][0]["status"] == "skipped"
    assert reload_result["reloaded"][1]["status"] == "error"

    # Exercise the modern planner fallback and the queued-application path.
    fake_idc = sys.modules["idc"]
    planner_calls = []
    def record_plan(name):
        planner_calls.append(name)

    monkeypatch.setattr(fake_idc, "plan_to_apply_idasgn", record_plan, raising=False)
    fake_libfuncs = SimpleNamespace()
    monkeypatch.setitem(sys.modules, "ida_libfuncs", fake_libfuncs)
    # A synthetic signature directory keeps this independent of the local IDA installation.
    monkeypatch.setattr(misc_mod, "_sig_paths", lambda: ("/tmp/modern.sig",))
    queued = misc_mod.misc(action="load_sig", name="modern")
    assert queued["ok"] is True and queued["applied"] is False
    assert planner_calls == ["modern"]

    monkeypatch.delattr(fake_idc, "plan_to_apply_idasgn", raising=False)
    unavailable = misc_mod.misc(action="load_sig", name="modern")
    assert unavailable["error"] is True
    assert unavailable["code"] == misc_mod.MCPError.UNKNOWN


def test_misc_file_and_signature_helpers_report_boundary_failures(monkeypatch, tmp_path: Path):
    """Exercise the filesystem and signature seams without touching a real IDA install."""
    target = tmp_path / "target"
    target.write_text("payload", encoding="utf-8")

    def fail_open(*_args, **_kwargs):
        raise OSError(13, "permission denied")

    monkeypatch.setattr(builtins, "open", fail_open)
    read_error = misc_mod.read_file_impl(str(target))
    assert read_error["code"] == misc_mod.MCPError.FILE_READ_ERROR
    assert read_error["details"]["errno"] == 13

    write_error = misc_mod.write_file_impl(str(tmp_path / "write-target"), "x")
    assert write_error["code"] == misc_mod.MCPError.FILE_WRITE_ERROR
    assert write_error["details"]["errno"] == 13

    monkeypatch.setattr(misc_mod, "validate_path_safe", lambda _path: (_ for _ in ()).throw(RuntimeError("path seam")))
    assert misc_mod.read_file_impl("ignored")["error"] is True
    assert misc_mod.write_file_impl("ignored", "x")["error"] is True

    monkeypatch.setattr(misc_mod.idaapi, "idadir", lambda _arg: str(tmp_path), raising=False)
    monkeypatch.setattr(misc_mod, "_SIG_PATH_CACHE", None)
    glob = importlib.import_module("glob")
    monkeypatch.setattr(glob, "glob", lambda *_args, **_kwargs: [str(tmp_path / "nested.sig")])
    monkeypatch.setattr(misc_mod.os.path, "getmtime", lambda _path: (_ for _ in ()).throw(OSError("gone")))
    assert misc_mod._sig_paths() == (str(tmp_path / "nested.sig"),)


def test_misc_dispatch_and_cache_modes(monkeypatch):
    assert misc_mod.misc(action="python")["code"] == misc_mod.MCPError.MISSING_REQUIRED_ARG
    assert misc_mod.misc(action="idc")["code"] == misc_mod.MCPError.MISSING_REQUIRED_ARG

    monkeypatch.setattr(misc_mod, "execute_python", lambda _script: {})
    no_result = misc_mod.misc(action="python", code="pass")
    assert no_result["note"].startswith("Script executed")

    monkeypatch.setattr(misc_mod, "execute_python", lambda _script: "unexpected")
    assert misc_mod.misc(action="python", expr="1") == {"ok": True, "output": "", "result": None}

    sync_mod = importlib.import_module("ida_pro_mcp.ida_mcp.sync")
    monkeypatch.setattr(sync_mod, "_tool_cache", lambda: None)
    assert misc_mod.misc(action="cache_stats") == {"ok": True, "message": "Cache not available"}

    monkeypatch.setattr(misc_mod, "_sig_paths", lambda: ("/tmp/one.sig",))
    monkeypatch.setattr(misc_mod.idaapi, "get_idasgn_qty", lambda: 0, raising=False)
    monkeypatch.setattr(misc_mod, "_sig_paths", lambda: (_ for _ in ()).throw(RuntimeError("sig listing")))
    assert misc_mod.misc(action="list_sigs")["error"] is True


def test_misc_signature_plugin_and_health_exception_modes(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(misc_mod, "_sig_paths", lambda: ("/tmp/one.sig",))
    fake_idc = SimpleNamespace()
    fake_libfuncs = SimpleNamespace(
        plan_to_apply_ldes=lambda _name: None,
        apply_ldes=lambda _name: (_ for _ in ()).throw(RuntimeError("apply failed")),
    )
    monkeypatch.setitem(sys.modules, "idc", fake_idc)
    monkeypatch.setitem(sys.modules, "ida_libfuncs", fake_libfuncs)
    queued = misc_mod.misc(action="load_sig", name="one.sig")
    assert queued["ok"] is True and queued["applied"] is False
    assert misc_mod.misc(action="load_sig")["code"] == misc_mod.MCPError.MISSING_REQUIRED_ARG

    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    monkeypatch.setenv("IDADIR", str(tmp_path))
    loader = sys.modules["ida_loader"]
    monkeypatch.setattr(loader, "find_plugin", lambda *_args: (_ for _ in ()).throw(RuntimeError("loader")), raising=False)
    assert misc_mod.misc(action="plugin_run", name="broken")["error"] is True
    assert misc_mod.misc(action="plugin_run")["code"] == misc_mod.MCPError.MISSING_REQUIRED_ARG

    monkeypatch.setattr(misc_mod.os, "listdir", lambda _path: (_ for _ in ()).throw(OSError("unreadable")))
    listed = misc_mod.misc(action="plugin_list")
    assert listed["ok"] is True and listed["plugins"] == []

    monkeypatch.setattr(misc_mod.idaapi, "get_kernel_version", lambda: (_ for _ in ()).throw(RuntimeError("health")), raising=False)
    assert misc_mod.misc(action="health")["error"] is True


def test_misc_reload_all_and_python_exec_fallback(monkeypatch):
    assert misc_mod.misc(action="reload", modules="all")["ok"] is True

    # A valid expression prints its value; a statement-only expression takes
    # the eval SyntaxError fallback and still restores the caller's streams.
    expression = misc_mod.execute_python("41 + 1")
    assert expression == {"output": "42\n", "result": 42}
    statement = misc_mod.execute_python("answer = 42")
    assert statement == {"output": "", "result": None}
