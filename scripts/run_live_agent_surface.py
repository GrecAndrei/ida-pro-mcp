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
        "--embed-profile", choices=["qwen3-embedding-0.6b", "bge-code-v1", "zembed-1"],
        help="Optional local embedding profile for semantic coverage (default: qwen3-embedding-0.6b)",
    )
    parser.add_argument("--embed-model", help="Optional GGUF model path for semantic coverage")
    parser.add_argument("--embed-server-bin", help="Optional llama-server path for semantic coverage")
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
    if args.embed_profile:
        env["IDA_MCP_EMBED_PROFILE"] = args.embed_profile
    if args.embed_model:
        env["IDA_MCP_EMBED_MODEL"] = str(Path(args.embed_model).expanduser().resolve())
    if args.embed_server_bin:
        env["IDA_MCP_EMBED_SERVER_BIN"] = str(Path(args.embed_server_bin).expanduser().resolve())

    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
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
