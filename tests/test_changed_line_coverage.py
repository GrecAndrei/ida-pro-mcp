"""Tests for the diff-scoped changed-line coverage guard."""

from __future__ import annotations

import subprocess
import sys
import types

import pytest

from scripts import check_changed_line_coverage as guard

DIFF = """diff --git a/src/example.py b/src/example.py
--- a/src/example.py
+++ b/src/example.py
@@ -2,0 +3,4 @@
+def added():
+    return 1
+
+# explanation
diff --git a/tests/test_example.py b/tests/test_example.py
--- /dev/null
+++ b/tests/test_example.py
@@ -0,0 +1,2 @@
+def test_added():
+    assert True
"""


def test_parse_added_lines_filters_paths_and_tracks_hunks():
    assert guard.parse_added_lines(DIFF, roots=("src",)) == {"src/example.py": {3, 4, 5, 6}}
    assert guard.parse_added_lines(DIFF, roots=("tests",)) == {"tests/test_example.py": {1, 2}}
    malformed = "+++ b/src/bad.py\n@@ malformed\n+line\n"
    assert guard.parse_added_lines(malformed, roots=("src",)) == {}
    deleted = "+++ /dev/null\n@@ -1 +0,0 @@\n"
    assert guard.parse_added_lines(deleted, roots=("src",)) == {}


def test_evaluate_changed_lines_requires_tests_and_applies_threshold():
    source = {"src/example.py": {3, 4, 5, 6}}
    tests = {"tests/test_example.py": {1, 2}}
    executable = {"src/example.py": {3, 4}}
    executed = {"src/example.py": {3}}
    result = guard.evaluate_changed_line_coverage(source, tests, executable, executed)
    assert result.ok is False
    assert result.source_lines == 2
    assert result.covered_lines == 1
    assert "50.0%" in result.message

    passed = guard.evaluate_changed_line_coverage(
        source,
        tests,
        executable,
        {"src/example.py": {3, 4}},
    )
    assert passed.ok is True and passed.percentage == 100.0
    no_tests = guard.evaluate_changed_line_coverage(source, {}, {}, {})
    assert no_tests.ok is False and "added tests" in no_tests.message
    comments_only = guard.evaluate_changed_line_coverage({"src/example.py": {5, 6}}, tests, executable, executed)
    assert comments_only.ok is True and comments_only.source_lines == 0


def test_git_and_base_resolution_paths(monkeypatch):
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        return types.SimpleNamespace(returncode=0, stdout="base-sha\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert guard._git_diff("base") == "base-sha\n"
    assert guard._resolve_base("explicit") == "explicit"
    monkeypatch.delenv("GITHUB_BASE_SHA", raising=False)
    assert guard._resolve_base(None) == "base-sha"
    assert calls[0][:3] == ["git", "diff", "--unified=0"]

    monkeypatch.setenv("GITHUB_BASE_SHA", "from-env")
    assert guard._resolve_base(None) == "from-env"

    def failed_run(_command, **_kwargs):
        return types.SimpleNamespace(returncode=1, stdout="", stderr="git failed")

    monkeypatch.setattr(subprocess, "run", failed_run)
    with pytest.raises(RuntimeError, match="git failed"):
        guard._git_diff("base")
    monkeypatch.delenv("GITHUB_BASE_SHA", raising=False)
    with pytest.raises(RuntimeError, match="no parent"):
        guard._resolve_base(None)


def test_coverage_lines_maps_measured_files_and_keeps_unmeasured_source_strict(tmp_path, monkeypatch):
    source = tmp_path / "src" / "example.py"
    source.parent.mkdir()
    source.write_text("def added():\n    return 1\n", encoding="utf-8")
    unmeasured = tmp_path / "src" / "unmeasured.py"
    unmeasured.write_text("# comment\ndef untouched():\n    return 2\n", encoding="utf-8")
    external = tmp_path / "external.py"
    data = types.SimpleNamespace(
        measured_files=lambda: [str(source), str(external)],
        lines=lambda filename: (
            [2]
            if filename == str(source)
            else []
            if filename == str(unmeasured)
            else [1]
        ),
    )

    class FakeCoverage:
        def __init__(self, data_file):
            assert data_file == str(tmp_path / ".coverage")

        def load(self):
            return None

        def get_data(self):
            return data

        def analysis2(self, filename):
            if filename == str(source):
                return filename, [1, 2], [], [1], []
            assert filename == str(unmeasured)
            return filename, [2, 3], [], [2, 3], []

    monkeypatch.setitem(sys.modules, "coverage", types.SimpleNamespace(Coverage=FakeCoverage))
    executable, executed = guard._coverage_lines(
        tmp_path / ".coverage", tmp_path, {"src/example.py", "src/unmeasured.py", "missing.py"}
    )
    assert executable == {"src/example.py": {1, 2}, "src/unmeasured.py": {2, 3}}
    assert executed == {"src/example.py": {2}, "src/unmeasured.py": set()}


def test_main_pass_fail_and_no_source_paths(monkeypatch):
    monkeypatch.setattr(guard, "_resolve_base", lambda _explicit: "base")
    monkeypatch.setattr(guard, "_git_diff", lambda _base: "")
    assert guard.main(["--base", "base"]) == 0

    monkeypatch.setattr(guard, "_git_diff", lambda _base: DIFF)
    monkeypatch.setattr(
        guard,
        "_coverage_lines",
        lambda *_args: ({"src/example.py": {3, 4}}, {"src/example.py": {3, 4}}),
    )
    assert guard.main(["--base", "base"]) == 0

    monkeypatch.setattr(
        guard,
        "_coverage_lines",
        lambda *_args: ({"src/example.py": {3, 4}}, {"src/example.py": {3}}),
    )
    assert guard.main(["--base", "base"]) == 1

    monkeypatch.setattr(guard, "_git_diff", lambda _base: DIFF.split("diff --git a/tests", 1)[0])
    assert guard.main(["--base", "base"]) == 1

    monkeypatch.setattr(guard, "_resolve_base", lambda _explicit: (_ for _ in ()).throw(RuntimeError("bad base")))
    assert guard.main([]) == 1
