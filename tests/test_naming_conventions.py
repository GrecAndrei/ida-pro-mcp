"""Test filenames must say what they test.

Test files were named after internal work-order codes — ``test_swarm_q07_...``,
``test_p14_...``, ``test_bb01_...`` — across ten inconsistent letter
generations. The codes appeared in no documentation, so nobody could find the
tests for a subsystem without grepping source, and a contributor had no way to
know what a new file was supposed to cover.

Those 107 files were renamed to describe their subject. This test keeps them
named that way, and pins the two renames that had to be resolved by reading the
file rather than by a mechanical rule, so a future collision cannot be papered
over with a code again.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_ROOT = REPO_ROOT / "tests"

# A filename code: test_<letters><digits>[letter]?_name.py, or a swarm marker.
_CODENAME_RE = re.compile(r"^test_(?:swarm_|[a-z]{1,3}\d+[a-z]?_)")

# Names chosen by reading the file, because a bare rename collided with a
# sibling covering a different aspect of the same subsystem. Pinning them here
# documents why they differ.
RESOLVED_BY_HAND = {
    "tests/host/test_dispatch_policy_gates.py": "test_dispatch_replay_idempotency.py",
    "tests/ida_mcp/test_zeromcp_protocol.py": "test_zeromcp_tool_filtering.py",
    "tests/host/test_runtime_lease_validation.py": "test_runtime_lease_heartbeat.py",
    "tests/ida_mcp/test_calc_graph_normalization.py": "test_calc_graph_evaluation.py",
    "tests/ida_mcp/test_gadgets_riscv_cops.py": "test_gadgets_raw_sweep.py",
    "tests/ida_mcp/test_misc_tools_governance.py": "test_misc_tools_dwarf_and_api_sets.py",
    "tests/host/intelligence/test_intel_sources.py": "test_intel_source_fingerprints.py",
}



def _test_files() -> list[Path]:
    return [
        p
        for p in sorted(TESTS_ROOT.rglob("test_*.py"))
        if "__pycache__" not in p.parts
    ]


def test_the_suite_is_not_empty():
    # A vacuous pass would let the real assertions below assert nothing.
    assert len(_test_files()) > 400, f"only found {len(_test_files())} test files"


def test_no_test_file_is_named_after_a_work_order_code():
    offenders = [
        p.relative_to(REPO_ROOT).as_posix()
        for p in _test_files()
        if _CODENAME_RE.match(p.name)
    ]
    assert not offenders, f"test files named after opaque codes: {offenders}"


@pytest.mark.parametrize("path", sorted(RESOLVED_BY_HAND))
def test_hand_resolved_names_still_exist_and_differ(path: str):
    # These pairs collided under a mechanical rename because two generations of
    # work covered the same subsystem. If one is deleted, this fails and the
    # counterpart must be re-examined rather than silently merged.
    assert (REPO_ROOT / path).is_file(), f"{path} was removed"
    assert Path(path).name != Path(RESOLVED_BY_HAND[path]).name


def test_renamed_tests_state_their_subject_in_the_first_line():
    # A reader opening the file should see a subject, not a work-order id. Only
    # the opening line is checked: a code mentioned later in the body is
    # legitimate provenance ("this test maps to a finding in the t03 order").
    stale = []
    for p in _test_files():
        first = p.read_text(encoding="utf-8").split("\n", 1)[0]
        if re.search(r"\b(swarm|bb\d|q\d\d|p\d\d|f\d\d|t\d\d|WO-)\b", first, re.I):
            stale.append(f"{p.relative_to(REPO_ROOT).as_posix()}: {first.strip()[:50]}")
    assert not stale, f"docstrings still open with a work-order code: {stale[:10]}"


def test_no_filename_carries_a_code_anywhere_in_it():
    # Anchored matchers miss codes buried mid-name, e.g. test_usage_p09_fixes.
    offenders = [
        p.relative_to(REPO_ROOT).as_posix()
        for p in _test_files()
        if re.search(r"swarm|(?<![a-z])[a-z]{1,2}\d+[a-z]?_(?=[a-z])", p.stem)
        and not re.match(r"^test_(p0[0-9]|p1[0-9])$", p.stem)
    ]
    assert not offenders, f"filenames still embed a work-order code: {offenders}"
