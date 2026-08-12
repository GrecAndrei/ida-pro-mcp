#!/usr/bin/env python3
"""Run the live-IDA suites against every IDA install detected on this machine.

The host-side suite (2834 tests) is IDA-independent and runs on
GitHub-hosted runners; the suites under tests/integration spawn real idat
processes and need a licensed install. This runner is the 9.3/9.4 runtime
matrix: it discovers every local install (same discovery the installer
uses) and runs the integration suites once per install with IDA_DIR pinned,
so a migration that works on 9.3 but breaks on 9.4 is caught locally and on
self-hosted CI (see .github/workflows/ida-runtime-matrix.yml).

Usage:
    python scripts/run_ida_matrix.py [--install PATH ...] [-- pytest args]

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--install",
        action="append",
        default=[],
        help="Explicit IDA install directory (repeatable); overrides discovery",
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
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            str(ROOT / "tests" / "integration"),
            "-q",
            *pytest_args,
        ]
        print(f"\n=== runtime matrix: {name} ({install_dir}) ===")
        proc = subprocess.run(cmd, env=env, cwd=ROOT)
        mark = "PASS" if proc.returncode == 0 else "FAIL"
        summary.append(f"{mark}  {name}")
        if proc.returncode != 0:
            failures.append((name, proc.returncode))

    print("\n=== runtime matrix summary ===")
    for line in summary:
        print(line)
    if failures:
        print(f"\n{len(failures)} install(s) FAILED")
        return 1
    print(f"\nall {len(installs)} install(s) passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
