#!/usr/bin/env python3
"""Carefully fix the 31 remaining F401 errors.

Strategy:
- For multi-line parenthesized `from X import (a, b, c)`, drop the specific
  unused name from the import.
- For single-line imports, drop the whole line if it becomes empty.
- For top-level `import x` (e.g. `import idaapi` in try blocks), add noqa
  if the name is used elsewhere, else drop the name.

This script is conservative: it does NOT remove the `try:` line itself.
"""
import json
import re
import subprocess
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
    raise SystemExit("Ruff returned no JSON")

all_text = {}
for f in ROOT.rglob("*.py"):
    if "__pycache__" in f.parts:
        continue
    all_text[str(f)] = f.read_text(errors="ignore")


def find_uses(file_text: str, alias: str) -> int:
    """Count bareword occurrences of `alias` in file_text, skipping import statements."""
    count = 0
    in_from_paren = False
    for line in file_text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("import "):
            # Standalone `import x, y, z` — only skip the actual import line
            # (the symbols here shouldn't be counted)
            continue
        if stripped.startswith("from "):
            in_from_paren = "(" in stripped and ")" not in stripped
            continue
        if in_from_paren:
            if ")" in stripped:
                in_from_paren = False
            continue
        count += len(re.findall(rf"\b{re.escape(alias)}\b", line))
    return count


# Per-file plans: list of (line_no_0indexed, alias, action)
# action: "drop" or "noqa"
per_file: dict[str, list[tuple[int, str, str]]] = {}
for d in data:
    m = re.search(r"`([^`]+)` imported but unused", d["message"])
    if not m:
        continue
    full_name = m.group(1)
    alias = full_name.rsplit(".", 1)[-1]
    line_no = d["location"]["row"] - 1
    text = all_text[d["filename"]]
    uses = find_uses(text, alias)
    action = "drop" if uses == 0 else "noqa"
    per_file.setdefault(d["filename"], []).append((line_no, alias, action))


def process_file(file: str, items: list[tuple[int, str, str]]) -> bool:
    """Process items for one file. Returns True if file was changed."""
    text = all_text[file]
    lines = text.split("\n")

    # Sort bottom-up so we can mutate safely
    items_sorted = sorted(items, key=lambda x: x[0], reverse=True)

    for line_no, alias, action in items_sorted:
        if line_no >= len(lines):
            continue
        line = lines[line_no]

        if action == "noqa":
            if "noqa" in line:
                continue
            # Add noqa to this line
            lines[line_no] = f"{line.rstrip()}  # noqa: F401"
            continue

        # action == "drop"
        # Find the import statement. It might be multi-line, so we need
        # to find the enclosing `from` or `import` statement and the closing paren.
        # The alias is on line_no. We need to know:
        #   - is this inside a parenthesized import?
        #   - is the line the standalone `import` itself?
        # We walk back to find the start of the statement.
        stmt_start = line_no
        # Walk back through continuation lines (if any)
        while stmt_start > 0 and not lines[stmt_start].lstrip().startswith(("from ", "import ")):
            # If we find a line starting with `from` or `import` first, stop
            stmt_start -= 1
        if stmt_start == line_no and not line.lstrip().startswith(("from ", "import ")):
            # The line itself doesn't start with from/import. But the alias IS on an import line.
            # Actually, line_no IS the import line (it contains the alias name in the F401 report).
            # If we're in a multi-line case, the `from` is on a previous line.
            pass

        # Check if the start is a parenthesized import
        stmt_line = lines[stmt_start]
        is_parenthesized = "(" in stmt_line
        if is_parenthesized:
            # Find the closing paren
            depth = 0
            end = stmt_start
            for i in range(stmt_start, len(lines)):
                for ch in lines[i]:
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            end = i
                            break
                if depth == 0 and i >= stmt_start and "(" in lines[stmt_start]:
                    end = i
                    break
            # Now edit lines[stmt_start:end+1] to drop the alias.
            # Patterns to handle:
            #  - `    alias,\n`  (alias + comma, possibly with `as` clause)
            #  - `    alias\n`   (last item, no trailing comma)
            #  - `    alias as something,\n`
            #  - `    ,alias` (unlikely but possible)
            for i in range(stmt_start, end + 1):
                cur = lines[i]
                # Pattern 1: leading `alias as X,` or `alias,` or `alias`
                new = re.sub(
                    rf"^\s*{re.escape(alias)}\s*(as\s+\w+)?\s*,?\s*$",
                    "",
                    cur,
                )
                if new != cur:
                    lines[i] = new
                    continue
                # Pattern 2: trailing `, alias` or `, alias as X`
                new = re.sub(
                    rf",(\s*){re.escape(alias)}\s*(as\s+\w+)?\s*$",
                    "",
                    cur,
                )
                if new != cur:
                    lines[i] = new
                    continue
                # Pattern 3: middle `, alias,`
                new = re.sub(
                    rf",\s*{re.escape(alias)}\s*(as\s+\w+)?\s*,",
                    ",",
                    cur,
                )
                if new != cur:
                    lines[i] = new
            # After dropping, collapse blank lines within the paren block,
            # and if the whole block has no symbols left, drop the `from` line too.
            block_lines = lines[stmt_start:end + 1]
            [ln for ln in block_lines if ln.strip() and ln.strip() not in "()"]
            # If only the `from X import (` and `)` lines remain, drop the whole statement.
            has_content = any(re.search(r"\w", ln) and "import" not in ln for ln in block_lines[1:-1])
            if not has_content:
                # Drop from stmt_start to end
                for _ in range(end - stmt_start + 1):
                    del lines[stmt_start]
            else:
                # Collapse blank lines inside the parens
                i = stmt_start + 1
                while i < end - 1:
                    if lines[i].strip() == "":
                        del lines[i]
                        end -= 1
                    else:
                        i += 1
        else:
            # Single-line: `from X import a, b, c` or `import x, y, z`
            # Drop the alias from this line.
            # Patterns:
            #  - `from X import alias, ...` -> `from X import ...`
            #  - `from X import ..., alias` -> `from X import ...`
            #  - `from X import alias` -> delete line
            #  - `import alias, ...` -> `import ...`
            #  - `import alias` -> delete line
            new = lines[line_no]
            new = re.sub(
                rf"^(\s*from\s+\S+\s+import\s+){re.escape(alias)}\s*(as\s+\w+)?\s*,\s*",
                r"\1",
                new,
            )
            new = re.sub(
                rf",\s*{re.escape(alias)}\s*(as\s+\w+)?\s*$",
                "",
                new,
            )
            new = re.sub(
                rf"^(\s*import\s+){re.escape(alias)}\s*(as\s+\w+)?\s*,\s*",
                r"\1",
                new,
            )
            # If the line is now empty (just whitespace), delete it.
            if not new.strip():
                del lines[line_no]
            else:
                lines[line_no] = new

    new_text = "\n".join(lines)
    if new_text != text:
        Path(file).write_text(new_text)
        return True
    return False


for file, items in per_file.items():
    changed = process_file(file, items)
    if changed:
        print(f"updated: {file}")
print("done")
