#!/usr/bin/env python3
"""Check that GitHub Actions dependencies are immutable and reviewable."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_USES_RE = re.compile(r"^\s*uses:\s*([^\s#]+)")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def find_violations(workflows_dir: Path) -> list[str]:
    violations: list[str] = []
    for path in sorted(workflows_dir.glob("*.y*ml")):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            match = _USES_RE.match(line)
            if not match:
                continue
            action = match.group(1)
            if action.startswith("./"):
                continue
            if "@" not in action:
                violations.append(f"{path}:{line_number}: action has no immutable ref: {action}")
                continue
            name, ref = action.rsplit("@", 1)
            if not name or not _SHA_RE.fullmatch(ref):
                violations.append(f"{path}:{line_number}: action ref is not a 40-hex SHA: {action}")
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workflow_dir", nargs="?", type=Path, default=Path(".github/workflows"))
    args = parser.parse_args(argv)
    violations = find_violations(args.workflow_dir)
    if violations:
        print("\n".join(violations), file=sys.stderr)
        return 1
    print(f"All workflow actions under {args.workflow_dir} use immutable refs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
