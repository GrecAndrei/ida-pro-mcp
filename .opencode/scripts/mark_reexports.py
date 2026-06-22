#!/usr/bin/env python3
"""Add `noqa: F401` to imports in modules where the name is referenced
by other modules in the project (re-exports). Uses AST for accuracy.

Then run `ruff check src --select F401 --fix` to remove the actual
dead imports.
"""
import ast
import re
import subprocess
from pathlib import Path

ROOT = Path("src").resolve()
RUFF = ".venv/bin/ruff"


def module_path(file: Path) -> str:
    rel = file.relative_to(ROOT)
    return ".".join(rel.with_suffix("").parts)


# 1. Build map: for each module, what names are defined at module level.
defined_names: dict[str, set[str]] = {}

# 2. Build map: for each (module, name) tuple, who references it?
# Reference = `from <module> import <name>` OR `from .x import <name>` (where
# the importing module is the relative parent).

all_files = []
for f in ROOT.rglob("*.py"):
    if "__pycache__" in f.parts:
        continue
    all_files.append(f)

print(f"Indexing {len(all_files)} files...")

# Parse all files with AST
for f in all_files:
    try:
        tree = ast.parse(f.read_text(errors="ignore"), filename=str(f))
    except SyntaxError:
        continue
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    defined_names[module_path(f)] = names

print("Collecting re-exports...")

# For each (module, name), find which other modules import it.
# Using both absolute and relative imports.
def find_reexported_names() -> set[tuple[str, str]]:
    """Return set of (module, name) that are re-exported by being imported elsewhere."""
    reexported = set()
    for f in all_files:
        text = f.read_text(errors="ignore")
        try:
            tree = ast.parse(text, filename=str(f))
        except SyntaxError:
            continue
        importer_mod = module_path(f)
        importer_parts = importer_mod.split(".")
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                module = node.module
                level = node.level or 0
                # Resolve relative module
                if level > 0:
                    base = importer_parts[: len(importer_parts) - level]
                    if module:
                        resolved = ".".join(base + [module])
                    else:
                        resolved = ".".join(base)
                else:
                    resolved = module
                # If this is a star import, all defined names in `resolved` are
                # implicitly re-exported.
                for alias in node.names:
                    if alias.name == "*":
                        if resolved in defined_names:
                            for n in defined_names[resolved]:
                                reexported.add((resolved, n))
                    else:
                        local = alias.asname or alias.name
                        reexported.add((resolved, local))
    return reexported


reexported = find_reexported_names()
print(f"Found {len(reexported)} re-exported (module, name) pairs")

# 3. Run ruff to find F401s, and for each one, check if the (module, name)
# is in the reexported set.
res = subprocess.run(
    [RUFF, "check", "src", "--select", "F401", "--no-fix", "--output-format", "json"],
    capture_output=True, text=True
)
import json
data = json.loads(res.stdout)

# Group by file
per_file: dict[str, list[dict]] = {}
for d in data:
    per_file.setdefault(d["filename"], []).append(d)

# For each F401, check if (module, alias) is reexported
def is_reexport(file: str, name: str) -> bool:
    mod = module_path(Path(file))
    if (mod, name) in reexported:
        return True
    # Also check if a star import from this module is used (in which case
    # all names are implicitly re-exported). We capture that via the * handling.
    return False


# Apply noqa to re-exports; let ruff auto-fix the rest.
noqa_count = 0
for file, entries in per_file.items():
    p = Path(file)
    text = p.read_text()
    lines = text.split("\n")
    changed = False
    # Group by line
    by_line: dict[int, list[str]] = {}
    for e in entries:
        m = re.search(r"`([^`]+)` imported but unused", e["message"])
        if not m:
            continue
        full_name = m.group(1)
        alias = full_name.rsplit(".", 1)[-1]
        line_no = e["location"]["row"] - 1
        by_line.setdefault(line_no, []).append(alias)
    for line_no, aliases in by_line.items():
        # Check each alias; if ANY of them is reexported, mark the line noqa
        # (because we can't partially-noqa a line). Actually, we should be
        # precise: re-export or not.
        # But for safety, if the line has noqa-eligible aliases, mark it.
        line = lines[line_no]
        if "noqa" in line:
            continue
        # Only add noqa if any alias is a re-export
        any_reexport = any(is_reexport(file, a) for a in aliases)
        if any_reexport:
            lines[line_no] = f"{line.rstrip()}  # noqa: F401"
            changed = True
            noqa_count += 1
    if changed:
        p.write_text("\n".join(lines))

print(f"Added noqa: F401 to {noqa_count} import lines")
