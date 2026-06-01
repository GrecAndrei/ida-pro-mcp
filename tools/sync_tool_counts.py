#!/usr/bin/env python3
"""Master sync: keep docs and test fixtures consistent with the live tool surface.

Single source of truth: ``ida_pro_mcp.host.schemas.{TOOLS, ADVERTISED_TOOLS,
HIDDEN_TOOLS_IN_LIST}``.

Run this after adding or removing tools, and tests in
``tests/test_tool_count_sync.py`` will tell you the docs are out of sync
if you forget.

Usage::

    python -m tools.sync_tool_counts          # update docs in place
    python -m tools.sync_tool_counts --check  # exit 1 if out of sync
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable, Tuple

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"


def _live_counts() -> Tuple[int, int, int]:
    """Return (TOOLS, ADVERTISED, HIDDEN) from the live schema."""
    from ida_pro_mcp.host.schemas import (  # noqa: WPS433 — local import
        ADVERTISED_TOOLS,
        HIDDEN_TOOLS_IN_LIST,
        TOOLS,
    )

    return len(TOOLS), len(ADVERTISED_TOOLS), len(HIDDEN_TOOLS_IN_LIST)


def _patch(path: Path, patterns: Iterable[Tuple[str, str]]) -> bool:
    """Replace ``(pattern, repl)`` pairs in ``path``. Returns True if changed."""
    text = path.read_text(encoding="utf-8")
    new = text
    for pat, repl in patterns:
        new = re.sub(pat, repl, new)
    if new == text:
        return False
    path.write_text(new, encoding="utf-8")
    return True


def sync(check_only: bool = False) -> int:
    """Sync the two docs. Returns 0 on success, 1 if --check and out of sync."""
    total, advertised, hidden = _live_counts()

    techref = DOCS / "TECHNICAL_REFERENCE.md"
    toolsref = DOCS / "TOOLS_REFERENCE.md"

    techref_patterns = [
        (r"`TOOLS` — ordered list of all \d+ tool names",
         f"`TOOLS` — ordered list of all {total} tool names"),
        (r"`ADVERTISED_TOOLS` — \d+ tools shown in `tools/list`",
         f"`ADVERTISED_TOOLS` — {advertised} tools shown in `tools/list`"),
        (r"`HIDDEN_TOOLS_IN_LIST` — \d+ tools callable via alias/name but hidden from listings",
         f"`HIDDEN_TOOLS_IN_LIST` — {hidden} tools callable via alias/name but hidden from listings"),
    ]
    toolsref_patterns = [
        (r"Current canonical tool surface: \*\*\d+ tools\*\*",
         f"Current canonical tool surface: **{total} tools**"),
    ]

    dirty: list[Path] = []
    if _patch(techref, techref_patterns):
        dirty.append(techref)
    if _patch(toolsref, toolsref_patterns):
        dirty.append(toolsref)

    msg = (
        f"tool counts: TOOLS={total} ADVERTISED={advertised} HIDDEN={hidden}"
    )
    if dirty:
        for p in dirty:
            print(f"updated: {p.relative_to(ROOT)}")
        print(msg)
        return 1 if check_only else 0
    if check_only:
        print(f"in sync: {msg}")
    else:
        print(f"no change: {msg}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="exit 1 if docs are out of sync with live schema")
    args = parser.parse_args(argv)
    return sync(check_only=args.check)


if __name__ == "__main__":
    sys.exit(main())
