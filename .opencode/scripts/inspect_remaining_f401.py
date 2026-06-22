#!/usr/bin/env python3
"""For each remaining F401, decide: remove if truly unused, else add noqa.

The remaining 31 F401s are mostly in try/except import blocks where the
import is for testing availability. If the name is not actually used in the
file body, we can drop it from the import list.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path("src").resolve()
RUFF = ".venv/bin/ruff"

res = subprocess.run(
    [RUFF, "check", "src", "--select", "F401", "--no-fix", "--output-format", "json"],
    capture_output=True, text=True
)
try:
    data = json.loads(res.stdout)
except json.JSONDecodeError:
    print("Ruff returned no JSON; aborting")
    sys.exit(1)

# Read all source text once
all_text = {}
for f in ROOT.rglob("*.py"):
    if "__pycache__" in f.parts:
        continue
    all_text[str(f)] = f.read_text(errors="ignore")

# For each F401, find the imported alias name (last component)
# and check if the alias appears anywhere else in the file.
def find_uses(file_text: str, alias: str) -> int:
    """Count bareword occurrences of `alias` in file_text (not inside imports)."""
    count = 0
    in_from_paren = False
    for line in file_text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("import "):
            continue
        if stripped.startswith("from "):
            # Continue on next line if paren is open
            in_from_paren = "(" in stripped and ")" not in stripped
            continue
        if in_from_paren:
            if ")" in stripped:
                in_from_paren = False
            continue
        count += len(re.findall(rf"\b{re.escape(alias)}\b", line))
    return count

# Strategy:
# - In a try/except import block, the import is multi-line `from X import (a, b as c)`.
# - For each unused name, we can either drop it from the multi-import, or
#   add `# noqa: F401` to the import line.
# Simplest: if alias is never used → drop name from import statement.
# If alias is used → add `# noqa: F401` to the import line.

# Group by file
per_file: dict[str, list[dict]] = {}
for d in data:
    per_file.setdefault(d["filename"], []).append(d)

for file, entries in per_file.items():
    text = all_text[file]
    lines = text.split("\n")
    for e in entries:
        # e["message"] like: `idaapi` imported but unused
        m = re.search(r"`([^`]+)` imported but unused", e["message"])
        if not m:
            continue
        full_name = m.group(1)  # e.g. "..rpc.unsafe" or "idaapi"
        alias = full_name.rsplit(".", 1)[-1]
        uses = find_uses(text, alias)
        loc = e["location"]
        line_no = loc["row"] - 1  # 0-indexed
        print(f"{file}:{line_no+1}  alias={alias!r} uses={uses}  -> {'drop' if uses == 0 else 'noqa'}")
