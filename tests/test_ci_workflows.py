"""Guard rails for the GitHub Actions workflows.

CI is part of the repo's contract: a workflow regression (e.g. live-IDA
tests running in a runner without a license, or the llama.cpp pin drifting
from the build script) fails at the worst possible time — after push.  These
tests keep those invariants cheap and local.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
BUILD_SCRIPT = ROOT / "scripts" / "build_native_llama.sh"

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


def test_llama_cpp_pin_matches_build_script():
    """CI's llama.cpp pin must equal the build script's canonical default.

    The driver targets one exact llama.cpp commit; a silent drift between
    the workflow env and the script default rebuilds against a version the
    driver was never validated on.
    """
    wf = _load_workflow("native-build.yml")
    ci_pin = wf.get("env", {}).get("LLAMA_CPP_COMMIT")
    assert ci_pin, "native-build.yml must define env.LLAMA_CPP_COMMIT"

    script_text = BUILD_SCRIPT.read_text(encoding="utf-8")
    match = re.search(r'LLAMA_CPP_COMMIT="\$\{LLAMA_CPP_COMMIT:-([0-9a-f]{40})\}"', script_text)
    assert match, "build_native_llama.sh must define LLAMA_CPP_COMMIT default"

    assert match.group(1) == ci_pin, (
        f"llama.cpp pin drifted: workflow={ci_pin} script={match.group(1)}"
    )
    # The workflow's verify grep must actually match the script line, or the
    # pin check silently no-ops on CI.  Reconstruct the grepped pattern.
    expected = f'LLAMA_CPP_COMMIT="${{LLAMA_CPP_COMMIT:-{ci_pin}}}"'
    assert expected in script_text, (
        "native-build.yml verify grep would not match build_native_llama.sh"
    )
