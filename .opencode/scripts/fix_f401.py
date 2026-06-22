#!/usr/bin/env python3
"""Add noqa: F401 to imports that are re-exports used elsewhere."""
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

per_file: dict[str, list[dict]] = {}
for d in data:
    f = d["filename"]
    per_file.setdefault(f, []).append(d)

def module_path(file: str) -> str:
    p = Path(file).resolve()
    rel = p.relative_to(ROOT)
    return ".".join(rel.with_suffix("").parts)

all_text = {}
for f in ROOT.rglob("*.py"):
    if "__pycache__" in f.parts:
        continue
    all_text[str(f)] = f.read_text(errors="ignore")

def is_reexport(file: str, name: str) -> bool:
    mod = module_path(file)
    # Strict: other files do `from <exact_module> import <exact_name>`
    pat1 = re.compile(rf"\bfrom\s+{re.escape(mod)}\s+import\s+[^()#]*\b{re.escape(name)}\b")
    for other_file, text in all_text.items():
        if other_file == file:
            continue
        if pat1.search(text):
            return True
    # Also: star-import from this module (`from <mod> import *`)
    # In that case ruff doesn't flag the names, so we don't need to handle it.
    return False

remove_names: dict[str, set[str]] = {}
noqa_names: dict[str, set[str]] = {}
for file, entries in per_file.items():
    for e in entries:
        name = e["message"].split("`")[1]
        short = name.split(".")[-1]
        if is_reexport(file, short):
            noqa_names.setdefault(file, set()).add(name)
        else:
            remove_names.setdefault(file, set()).add(name)

def add_noqa(file: str, names: set[str]) -> None:
    path = Path(file)
    text = path.read_text()
    lines = text.split("\n")
    for i, line in enumerate(lines):
        for name in names:
            short = name.split(".")[-1]
            patterns = [
                rf"^(\s*)import\s+{re.escape(short)}\s*(#.*)?$",
                rf"^(\s*)from\s+\S+\s+import\s+.*\b{re.escape(short)}\b.*$",
            ]
            for pat in patterns:
                m = re.match(pat, line)
                if m:
                    if "noqa" in line:
                        continue
                    if line.rstrip().endswith("\\"):
                        continue
                    lines[i] = f"{line.rstrip()}  # noqa: F401"
                    break
    path.write_text("\n".join(lines))

for file, names in noqa_names.items():
    add_noqa(file, names)
    print(f"noqa: {file}: {sorted(names)}")

with open("/tmp/remove_names.txt", "w") as f:
    for file, names in remove_names.items():
        for n in sorted(names):
            f.write(f"{file}\t{n}\n")
print(f"\nWill remove {sum(len(v) for v in remove_names.values())} unused names")
