"""Tests for the repository's commit and workflow guard scripts."""

from __future__ import annotations

import pytest

from scripts.check_commit_policy import classify_subject, highest_class, validate_commit
from scripts.check_workflow_pins import find_violations


@pytest.mark.parametrize("subject, expected", [
    ("[minor] clarify a sentence", "minor"),
    ("[relevant] add a client check", "relevant"),
    ("[major] publish alpha bundles", "major"),
    ("[PR-work] address review feedback", "PR-work"),
])
def test_commit_subject_classes_are_explicit(subject: str, expected: str):
    assert classify_subject(subject) == expected


@pytest.mark.parametrize("subject", [
    "clarify a sentence",
    "fix [minor] a sentence",
    "[minor] [relevant] mixed scope",
    "[MAJOR] wrong case",
    "[major]",
])
def test_commit_subject_requires_exactly_one_prefix(subject: str):
    with pytest.raises(ValueError):
        classify_subject(subject)


def test_highest_class_uses_strongest_required_safeguard():
    assert highest_class(["minor", "PR-work"]) == "PR-work"
    assert highest_class(["PR-work", "relevant"]) == "relevant"
    assert highest_class(["relevant", "major"]) == "major"
    with pytest.raises(ValueError):
        highest_class([])


@pytest.mark.parametrize("commit_class", ["minor", "relevant", "major", "PR-work"])
def test_every_commit_class_requires_a_changelog_entry(commit_class: str):
    subject = f"[{commit_class}] make a coherent change"
    assert validate_commit("abcdef123456", subject, {"CHANGELOG.md"}) == commit_class
    with pytest.raises(ValueError, match="CHANGELOG.md"):
        validate_commit("abcdef123456", subject, {"README.md"})


def test_workflow_actions_are_pinned():
    assert find_violations(__import__("pathlib").Path(".github/workflows")) == []
