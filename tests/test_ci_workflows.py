"""Guard rails for the GitHub Actions workflows.

CI is part of the repo's contract: a workflow regression (for example live
IDA tests running in a runner without a license) fails at the worst possible
time — after push. These tests keep those invariants cheap and local.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_workflow_pins import find_violations

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

yaml = pytest.importorskip("yaml")


def _load_workflow(name: str) -> dict:
    with open(WORKFLOWS / name, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    assert isinstance(data, dict), f"{name} is not a mapping"
    return data


def test_standalone_ci_never_runs_live_ida_suite():
    """The standalone workflow must exclude tests/integration.

    Without the ignore, a runner with a C compiler (ubuntu-latest has gcc)
    passes the live suite's availability check and every test class waits
    out its server-startup timeout against a machine with no licensed IDA.
    """
    wf = _load_workflow("standalone-tests.yml")
    commands = []
    for job in wf.get("jobs", {}).values():
        for step in job.get("steps", []):
            run = step.get("run")
            if run:
                commands.append(run)
    assert any("pytest" in c and "tests/integration" in c for c in commands), (
        "standalone-tests.yml must run pytest with --ignore=tests/integration"
    )


def test_standalone_ci_enforces_changed_line_coverage():
    wf = _load_workflow("standalone-tests.yml")
    test_job = wf["jobs"]["test"]
    assert test_job["timeout-minutes"] >= 15, (
        "standalone test matrix needs enough time for Python 3.12 coverage"
    )
    checkouts = [
        step
        for step in test_job["steps"]
        if step.get("uses", "").startswith("actions/checkout@")
    ]
    assert checkouts and checkouts[0]["with"]["fetch-depth"] == 0

    commands = [step.get("run", "") for step in test_job["steps"]]
    coverage_commands = [command for command in commands if "coverage run" in command]
    assert coverage_commands and "pytest" in coverage_commands[0]
    assert "check_changed_line_coverage.py" in coverage_commands[0]


def test_ida_runtime_matrix_never_runs_on_hosted_runners():
    """The live-IDA matrix needs a licensed install, so it must be
    self-hosted-only and dispatch-triggered. A push/PR trigger would queue
    on GitHub-hosted runners (no IDA) or bill the repo without consent."""
    wf = _load_workflow("ida-runtime-matrix.yml")

    # PyYAML is YAML 1.1, where the bare key `on` parses as boolean True;
    # GitHub reads YAML 1.2 semantics. Accept either spelling.
    triggers_raw = wf.get("on")
    if not isinstance(triggers_raw, dict):
        triggers_raw = wf.get(True)
    triggers = set(triggers_raw or {})
    assert triggers == {"workflow_dispatch"}, (
        "ida-runtime-matrix.yml must be workflow_dispatch-only; "
        f"found triggers: {triggers}"
    )

    for job in wf.get("jobs", {}).values():
        labels = job.get("runs-on")
        assert isinstance(labels, list) and "self-hosted" in labels, (
            "ida-runtime-matrix.yml jobs must run on a self-hosted runner "
            f"(licensed IDA cannot be provisioned on hosted runners); got {labels}"
        )
        for step in job.get("steps", []):
            run = step.get("run")
            if run and "run_ida_matrix" in run:
                assert "tests/integration" not in run, (
                    "the matrix runner must stay the single source of truth; "
                    "do not inline pytest test paths into the workflow"
                )


def test_all_workflow_actions_use_immutable_refs():
    assert find_violations(WORKFLOWS) == []


def test_dependency_review_blocks_high_severity_changes():
    wf = _load_workflow("dependency-review.yml")
    action_steps = [
        step
        for step in wf["jobs"]["review"]["steps"]
        if "dependency-review-action" in str(step.get("uses", ""))
    ]
    assert len(action_steps) == 1
    assert action_steps[0]["with"]["fail-on-severity"] == "high"
    assert wf["permissions"]["contents"] == "read"


def test_alpha_release_requires_existing_alpha_tag_and_protected_publish():
    wf = _load_workflow("alpha-release.yml")
    triggers = wf.get("on")
    if not isinstance(triggers, dict):
        triggers = wf.get(True)
    assert set(triggers) == {"workflow_dispatch"}
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert inputs["tag"]["required"] is True
    assert inputs["publish"]["type"] == "boolean"

    publish = wf["jobs"]["publish"]
    assert publish["if"] == "inputs.publish == true"
    assert publish["environment"]["name"] == "release"
    assert publish["permissions"] == {
        "contents": "write",
        "id-token": "write",
        "attestations": "write",
    }
