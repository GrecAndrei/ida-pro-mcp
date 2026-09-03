#!/usr/bin/env python3
"""Require tests and coverage for executable lines added to a change.

The check is deliberately diff-scoped.  It does not replace the project's
overall coverage report: it makes a new source line expensive to leave
untested while allowing older, separately tracked debt to be handled on its
own schedule.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SOURCE_ROOTS = ("src", "scripts", "install.py")


def _diff_path(raw: str) -> str | None:
    """Normalize a unified-diff path, returning ``None`` for deleted files."""
    value = raw.strip()
    if value == "/dev/null":
        return None
    if value.startswith("b/"):
        value = value[2:]
    return value


def _is_python_path(path: str) -> bool:
    return path.endswith(".py")


def _under_root(path: str, roots: tuple[str, ...]) -> bool:
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots)


def parse_added_lines(
    diff_text: str,
    *,
    roots: tuple[str, ...],
) -> dict[str, set[int]]:
    """Return added Python line numbers grouped by repository-relative path."""
    added: dict[str, set[int]] = {}
    path: str | None = None
    new_line: int | None = None
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            path = _diff_path(line[4:])
            if path is None or not _is_python_path(path) or not _under_root(path, roots):
                path = None
            continue
        if line.startswith("@@ "):
            try:
                new_part = line.split("+", 1)[1].split(" ", 1)[0]
                start, _, count = new_part.partition(",")
                new_line = int(start)
                if count == "0":
                    new_line = None
            except (IndexError, ValueError):
                new_line = None
            continue
        if new_line is None:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            if path is not None:
                added.setdefault(path, set()).add(new_line)
            new_line += 1
        elif line.startswith("-"):
            continue
        else:
            new_line += 1
    return added


@dataclass(frozen=True)
class CoverageResult:
    ok: bool
    source_lines: int
    covered_lines: int
    percentage: float
    message: str


def evaluate_changed_line_coverage(
    added_source: dict[str, set[int]],
    added_tests: dict[str, set[int]],
    executable_lines: dict[str, set[int]],
    executed_lines: dict[str, set[int]],
    *,
    minimum: float = 0.95,
) -> CoverageResult:
    """Evaluate test presence and executable-line coverage for a diff."""
    source = {
        path: set(lines) & executable_lines.get(path, set(lines))
        for path, lines in added_source.items()
    }
    total = sum(len(lines) for lines in source.values())
    if total == 0:
        return CoverageResult(True, 0, 0, 100.0, "no executable Python source lines added")
    test_count = sum(len(lines) for lines in added_tests.values())
    if test_count == 0:
        return CoverageResult(False, total, 0, 0.0, "source additions require added tests")
    covered = sum(
        len(lines & executed_lines.get(path, set()))
        for path, lines in source.items()
    )
    percentage = covered / total
    ok = percentage >= minimum
    message = (
        f"changed-line coverage {percentage:.1%} ({covered}/{total}); "
        f"minimum is {minimum:.1%}"
    )
    return CoverageResult(ok, total, covered, percentage * 100.0, message)


def _git_diff(base: str) -> str:
    result = subprocess.run(
        ["git", "diff", "--unified=0", "--no-color", f"{base}..HEAD", "--"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git diff failed with status {result.returncode}")
    return result.stdout


def _resolve_base(explicit: str | None) -> str:
    if explicit:
        return explicit
    env_base = os.environ.get("GITHUB_BASE_SHA")
    if env_base:
        return env_base
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD^"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RuntimeError("provide --base when the repository has no parent commit")
    return result.stdout.strip()


def _coverage_lines(
    coverage_file: Path,
    repo_root: Path,
    source_paths: set[str],
) -> tuple[dict[str, set[int]], dict[str, set[int]]]:
    try:
        import coverage
    except ImportError as exc:  # pragma: no cover - packaging failure, not logic
        raise RuntimeError("coverage.py is required; install the dev dependency") from exc
    runner = coverage.Coverage(data_file=str(coverage_file))
    runner.load()
    data = runner.get_data()
    measured: dict[str, str] = {}
    for filename in data.measured_files():
        candidate = Path(filename)
        try:
            relative = candidate.resolve().relative_to(repo_root.resolve()).as_posix()
        except ValueError:
            continue
        measured[relative] = filename
    executable: dict[str, set[int]] = {}
    executed: dict[str, set[int]] = {}
    for path in source_paths:
        filename = measured.get(path, str(repo_root / path))
        if not Path(filename).is_file():
            # An unavailable changed file is source, not an exemption.
            continue
        analysis = runner.analysis2(filename)
        executable[path] = set(analysis[1])
        executed[path] = set(data.lines(filename) or ())
    return executable, executed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="base commit; defaults to GITHUB_BASE_SHA or HEAD^")
    parser.add_argument("--coverage-file", default=".coverage")
    parser.add_argument("--minimum", type=float, default=0.95)
    parser.add_argument("--source-root", action="append", dest="source_roots")
    parser.add_argument("--test-root", default="tests")
    args = parser.parse_args(argv)
    try:
        base = _resolve_base(args.base)
        diff = _git_diff(base)
        roots = tuple(args.source_roots or DEFAULT_SOURCE_ROOTS)
        added_source = parse_added_lines(diff, roots=roots)
        added_tests = parse_added_lines(diff, roots=(args.test_root,))
        if not added_source:
            print("changed-line coverage: no Python source additions")
            return 0
        repo_root = Path.cwd()
        executable, executed = _coverage_lines(
            repo_root / args.coverage_file,
            repo_root,
            set(added_source),
        )
        result = evaluate_changed_line_coverage(
            added_source,
            added_tests,
            executable,
            executed,
            minimum=args.minimum,
        )
        print(f"changed-line coverage: {result.message}")
        if not result.ok:
            print("changed-line coverage: FAIL", file=sys.stderr)
            return 1
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"changed-line coverage error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
