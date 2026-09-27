#!/usr/bin/env python3
"""Run the opt-in end-to-end suite for every public ``ida_*`` operation.

Examples:
  python scripts/run_live_agent_surface.py --ida-dir /opt/ida
  python scripts/run_live_agent_surface.py --ida-dir /opt/ida --binary /path/to/fixture
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida-dir", help="Directory containing idat or idat64")
    parser.add_argument("--idat", help="Explicit idat/idat64 executable")
    parser.add_argument("--binary", help="Optional binary; otherwise compile the deterministic fixture")
    parser.add_argument(
        "--intelligence-mode", choices=["jev", "custom", "disabled"], default="disabled",
        help="Explicit intelligence provider mode for advisory checks",
    )
    parser.add_argument(
        "--intelligence-enabled", dest="intelligence_enabled", action="store_true", default=False,
        help="allow the selected provider to run; without this every advisory call stays deterministic",
    )
    parser.add_argument(
        "--intelligence-disabled", dest="intelligence_enabled", action="store_false",
        help="force the intelligence layer off even when a provider is selected (default)",
    )
    parser.add_argument("--jev-model", default="jev-latest")
    parser.add_argument(
        "--jev-input-usd-per-mtok", default="",
        help="opt in to metered Jev input; unset keeps the spend gate closed and "
        "Jev advisory calls are blocked before transport",
    )
    parser.add_argument(
        "--jev-output-usd-per-mtok", default="",
        help="opt in to metered Jev output; unset keeps the spend gate closed",
    )
    parser.add_argument("--call-timeout", type=int, default=180, help="Maximum seconds for one MCP call or IDA startup")
    parser.add_argument("--pytest-timeout", type=int, default=600, help="Maximum seconds for each pytest case")
    args = parser.parse_args()

    env = os.environ.copy()
    env["IDA_MCP_LIVE_TEST"] = "1"
    env["IDA_MCP_LIVE_CALL_TIMEOUT"] = str(max(30, args.call_timeout))
    if args.ida_dir:
        env["IDA_MCP_LIVE_IDADIR"] = str(Path(args.ida_dir).expanduser().resolve())
    if args.idat:
        env["IDA_MCP_LIVE_IDAT"] = str(Path(args.idat).expanduser().resolve())
    if args.binary:
        env["IDA_MCP_LIVE_BINARY"] = str(Path(args.binary).expanduser().resolve())
    env["IDA_MCP_INTELLIGENCE_MODE"] = args.intelligence_mode
    env["IDA_MCP_INTELLIGENCE_ENABLED"] = "1" if args.intelligence_enabled else "0"
    if args.intelligence_mode in {"jev", "custom"} and not args.intelligence_enabled:
        print(
            f"warning: the intelligence layer is off (mode {args.intelligence_mode} "
            "selected but not enabled); advisory calls stay deterministic. Pass "
            "--intelligence-enabled to arm it."
        )
    if args.jev_model:
        env["IDA_MCP_JEV_MODEL"] = args.jev_model
    if args.jev_input_usd_per_mtok:
        env["IDA_MCP_JEV_INPUT_USD_PER_MTOK"] = str(args.jev_input_usd_per_mtok)
    if args.jev_output_usd_per_mtok:
        env["IDA_MCP_JEV_OUTPUT_USD_PER_MTOK"] = str(args.jev_output_usd_per_mtok)
    if args.intelligence_mode == "jev" and not (
        args.jev_input_usd_per_mtok and args.jev_output_usd_per_mtok
    ):
        print(
            "warning: Jev spend is disabled because no input/output price was "
            "given; Jev advisory calls will be blocked before transport. Pass "
            "--jev-input-usd-per-mtok and --jev-output-usd-per-mtok to opt in."
        )

    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-m",
            "live_ida",
            "-q",
            f"--timeout={max(60, args.pytest_timeout)}",
            "tests/integration",
            "-m",
            "live_ida",
        ],
        cwd=REPO_ROOT,
        env=env,
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
