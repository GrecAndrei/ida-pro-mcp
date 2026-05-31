#!/usr/bin/env python3
"""Thin wrapper for the organized installer package."""

from __future__ import annotations

import os
import sys


def _bootstrap_import_path() -> None:
    root = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(root, "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def main() -> int:
    _bootstrap_import_path()
    from ida_pro_mcp.installer.main import main as installer_main

    return installer_main()


if __name__ == "__main__":
    raise SystemExit(main())
