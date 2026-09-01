#!/usr/bin/env python3
"""Validate the commit classes used by this repository.

The check is intentionally small and independent of GitHub APIs so it can run
both locally and in pull-request CI.  Merge commits are ignored because the
hosting service owns their messages; every authored commit must have exactly
one approved class prefix.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterable

COMMIT_CLASSES = ("minor", "relevant", "major", "PR-work")
_CLASS_RE = re.compile(r"\[(minor|relevant|major|PR-work)\]")
_PREFIX_RE = re.compile(r"^\[(minor|relevant|major|PR-work)\]\s+\S")
_SEVERITY = {name: index for index, name in enumerate(("minor", "PR-work", "relevant", "major"))}


def classify_subject(subject: str) -> str:
    """Return the class for *subject* or raise ``ValueError`` if invalid."""
    matches = _CLASS_RE.findall(subject)
    if len(matches) != 1 or not _PREFIX_RE.match(subject):
        allowed = ", ".join(f"[{name}]" for name in COMMIT_CLASSES)
        raise ValueError(f"commit subject must start with exactly one of: {allowed}")
    return matches[0]


def highest_class(classes: Iterable[str]) -> str:
    """Return the strongest safeguard class in an iterable of classes."""
    values = list(classes)
    if not values:
        raise ValueError("no authored commits found in the requested range")
    return max(values, key=_SEVERITY.__getitem__)


def validate_commit(sha: str, subject: str, changed_paths: Iterable[str]) -> str:
    """Validate one authored commit and return its change class."""
    commit_class = classify_subject(subject)
    if "CHANGELOG.md" not in set(changed_paths):
        raise ValueError("every commit class must update CHANGELOG.md")
    return commit_class


def _subjects(revision_range: str) -> list[tuple[str, str]]:
    result = subprocess.run(
        ["git", "log", "--no-merges", "--format=%H%x00%s", revision_range],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git log failed with status {result.returncode}")
    commits: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        sha, separator, subject = line.partition("\0")
        if separator:
            commits.append((sha, subject))
    return commits


def _changed_paths(commit_sha: str) -> set[str]:
    result = subprocess.run(
        ["git", "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit_sha],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git diff-tree failed with status {result.returncode}")
    return {path for path in result.stdout.splitlines() if path}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--range", dest="revision_range", required=True, help="git revision range to inspect")
    args = parser.parse_args(argv)

    try:
        commits = _subjects(args.revision_range)
        classes: list[str] = []
        for sha, subject in commits:
            try:
                commit_class = validate_commit(sha, subject, _changed_paths(sha))
            except ValueError as exc:
                raise ValueError(f"{sha[:12]} ({subject!r}): {exc}") from exc
            classes.append(commit_class)
            print(f"{sha[:12]} {commit_class}: {subject}")
        print(f"highest_class={highest_class(classes)}")
    except (RuntimeError, ValueError) as exc:
        print(f"commit policy error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
