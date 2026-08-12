#!/usr/bin/env python3
"""Run the live-IDA suites against every IDA install detected on this machine.

The host-side suite (2834 tests) is IDA-independent and runs on
GitHub-hosted runners; the suites under tests/integration spawn real idat
processes and need a licensed install. This runner is the 9.3/9.4 runtime
matrix: it discovers every local install (same discovery the installer
uses) and runs the integration suites once per install with IDA_DIR pinned,
so a migration that works on 9.3 but breaks on 9.4 is caught locally and on
self-hosted CI (see .github/workflows/ida-runtime-matrix.yml).

With ``--idalib`` each install also runs the suite under the idalib
in-process backend (IDA_MCP_RUNTIME=idalib). idalib requires the idapro
whl + activation for that install (``py-activate-idalib.py -d <dir>``),
which this runner performs per install; installs without an idalib/python
directory are skipped with a note.

Usage:
    python scripts/run_ida_matrix.py [--install PATH ...] [--idalib] [-- pytest args]

Exit code is nonzero when any install's run fails. With no installs
detected the script prints a note and exits 0 (the GitHub-hosted CI job is
expected to be a no-op; licensed IDA only exists on self-hosted runners).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _detect_installs(explicit: list[str]) -> list[tuple[str, str]]:
    """Return [(display_name, install_dir)] using installer discovery."""
    if explicit:
        return [("explicit", p) for p in explicit]
    try:
        sys.path.insert(0, str(ROOT))
        from ida_pro_mcp.installer.discovery import detect_ida_installs

        installs = detect_ida_installs()
    except Exception as exc:  # pragma: no cover - discovery is best-effort
        print(f"note: IDA discovery unavailable ({exc}); nothing to run")
        return []
    if not installs:
        return []
    return [(inst.full_version_str, str(inst.path)) for inst in installs]


def _activate_idalib(install_dir: str) -> bool:
    """Point the idapro activation at *install_dir*; True on success."""
    activate = os.path.join(install_dir, "idalib", "python", "py-activate-idalib.py")
    if not os.path.isfile(activate):
        return False
    proc = subprocess.run(
        [sys.executable, activate, "-d", install_dir],
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def _has_idalib(install_dir: str) -> bool:
    idalib_python = os.path.join(install_dir, "idalib", "python")
    return os.path.isdir(os.path.join(idalib_python, "idapro")) or bool(
        glob_whl(idalib_python)
    )


def glob_whl(idalib_python: str) -> list[str]:
    import glob

    return glob.glob(os.path.join(idalib_python, "idapro-*.whl"))


def _run_suite(env: dict, install_dir: str, label: str, pytest_args: list[str]) -> int:
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        str(ROOT / "tests" / "integration"),
        "-q",
        *pytest_args,
    ]
    print(f"\n=== runtime matrix: {label} ({install_dir}) ===")
    return subprocess.run(cmd, env=env, cwd=ROOT).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--install",
        action="append",
        default=[],
        help="Explicit IDA install directory (repeatable); overrides discovery",
    )
    parser.add_argument(
        "--idalib",
        action="store_true",
        help="Also run the suite under the idalib in-process backend "
        "(activates idalib per install)",
    )
    args, pytest_args = parser.parse_known_args(argv)

    installs = _detect_installs(args.install)
    if not installs:
        print(
            "no IDA installs detected — matrix is a no-op. "
            "Run with --install <dir> or install IDA Pro/IDA Home."
        )
        return 0

    env = os.environ.copy()
    env["IDA_MCP_DISABLE_RATE_LIMIT"] = "1"
    env["IDA_MCP_POLICY_MODE"] = "permissive"

    failures: list[tuple[str, int]] = []
    summary: list[str] = []
    for name, install_dir in installs:
        env["IDA_DIR"] = install_dir
        env.pop("IDA_MCP_RUNTIME", None)
        rc = _run_suite(env, install_dir, f"{name} (idat)", pytest_args)
        mark = "PASS" if rc == 0 else "FAIL"
        summary.append(f"{mark}  {name} (idat)")
        if rc != 0:
            failures.append((f"{name} (idat)", rc))

        if args.idalib:
            if not _has_idalib(install_dir):
                print(f"note: {install_dir} has no idalib/python — skipping idalib leg")
                summary.append(f"SKIP {name} (idalib: no idalib/python)")
                continue
            if not _activate_idalib(install_dir):
                print(f"note: idalib activation failed for {install_dir} — skipping leg")
                summary.append(f"SKIP {name} (idalib: activation failed)")
                continue
            env["IDA_MCP_RUNTIME"] = "idalib"
            rc = _run_suite(env, install_dir, f"{name} (idalib)", pytest_args)
            mark = "PASS" if rc == 0 else "FAIL"
            summary.append(f"{mark}  {name} (idalib)")
            if rc != 0:
                failures.append((f"{name} (idalib)", rc))

    print("\n=== runtime matrix summary ===")
    for line in summary:
        print(line)
    if failures:
        print(f"\n{len(failures)} leg(s) FAILED")
        return 1
    print(f"\nall {len(installs)} install(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

