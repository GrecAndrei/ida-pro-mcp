"""The commit, pull request, and merge rules must stay stated in both places.

`CONTRIBUTING.md` is the human-facing authority and `AGENTS.md` restates the same
policy for coding agents. The two are written separately, so they can drift. A
drift means either a contributor follows a rule that CI does not enforce, or an
agent follows a rule a human was never told about. Both are silent failures that
only surface during review, so they are asserted here instead.

These tests check agreement on the *rules*, not on prose: the approved classes,
the changelog requirement, the enforcers, and the merge method. They deliberately
avoid pinning exact sentences, because rewording guidance should not require a
code change.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

COMMIT_CLASSES = ("minor", "relevant", "major", "PR-work")


def _read(name: str) -> str:
    path = REPO_ROOT / name
    assert path.is_file(), f"{name} is missing"
    return path.read_text(encoding="utf-8")


def test_both_rule_documents_exist():
    # Asserted via _read; a missing file fails with a clear message.
    assert _read("CONTRIBUTING.md").strip()
    assert _read("AGENTS.md").strip()


def test_both_documents_name_every_commit_class():
    contributing = _read("CONTRIBUTING.md")
    agents = _read("AGENTS.md")
    for name in COMMIT_CLASSES:
        assert f"[{name}]" in contributing, f"CONTRIBUTING.md omits [{name}]"
        assert f"[{name}]" in agents, f"AGENTS.md omits [{name}]"


def test_both_documents_state_the_changelog_rule_for_every_commit():
    for name in ("CONTRIBUTING.md", "AGENTS.md"):
        text = _read(name)
        assert "CHANGELOG.md" in text, f"{name} does not mention CHANGELOG.md"
        lowered = text.lower()
        assert "every" in lowered, f"{name} does not scope the changelog rule to every commit"


def test_both_documents_name_the_policy_enforcer():
    enforcer = "scripts/check_commit_policy.py"
    for name in ("CONTRIBUTING.md", "AGENTS.md"):
        assert enforcer in _read(name), f"{name} does not name {enforcer}"


def test_contributing_states_the_merge_method():
    # The repository merges feature branches with a merge commit so the per-commit
    # class prefixes and changelog entries stay reviewable. If the method changes,
    # this test should fail and force the documentation to change with it.
    contributing = _read("CONTRIBUTING.md")
    assert "merge commit" in contributing.lower(), (
        "CONTRIBUTING.md must state how branches are merged"
    )
    assert "squash" in contributing.lower(), (
        "CONTRIBUTING.md must say why squash/rebase merges are not used"
    )


def test_contributing_forbids_pr_work_as_a_behavior_change_hider():
    text = _read("CONTRIBUTING.md")
    lowered = text.lower()
    assert "not a safe default" in lowered or "never use `[pr-work]`" in lowered, (
        "CONTRIBUTING.md must warn against filing behavior changes as [PR-work]"
    )


def test_contributing_documents_the_draft_to_ready_workflow():
    text = _read("CONTRIBUTING.md").lower()
    assert "draft" in text and "ready for review" in text, (
        "CONTRIBUTING.md must describe when a PR becomes ready for review"
    )


def test_contributing_documents_the_strict_deprecation_check():
    # The repo runs green with DeprecationWarning escalated; a contributor who
    # edits imports or the test loader needs to know the strict gate exists.
    text = _read("CONTRIBUTING.md")
    assert "-W error::DeprecationWarning" in text, (
        "CONTRIBUTING.md must document the strict deprecation gate"
    )
    assert "load_standalone_package_module" in text, (
        "CONTRIBUTING.md must point at the supported standalone module loader"
    )


def test_contributing_links_the_authoritative_agent_policy():
    # The two documents are meant to agree; CONTRIBUTING.md must say so, and name
    # AGENTS.md, or contributors will not know the pair is intentionally paired.
    assert "AGENTS.md" in _read("CONTRIBUTING.md")
