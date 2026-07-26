#!/usr/bin/env python3
"""
sync_schemas.py — auto-sync ADVERTISED_TOOLS and TOOL_DESCRIPTIONS in schemas.py
against what the actual tool files declare.

Run from the project root:
    python scripts/sync_schemas.py [--dry-run]
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "src/ida_pro_mcp/ida_mcp/tools"
SCHEMAS_PY = PROJECT_ROOT / "src/ida_pro_mcp/host/schemas.py"

# Tools that should NEVER be advertised (ML infra, UI-only, or internal helpers)
ALWAYS_HIDDEN = {
    "plugins",       # IDA plugin management, not RE analysis
    "cybercane",     # exports as "governance" — already listed under that name
    "_common",       # Not a tool
    "_api_categories",
    "arch_utils",
    "firmware_heuristics",
    "hybrid_search",
    "query_lang",
    "semantic_matching",
}

# Host-side tools registered in server.py — not in tools/ dir, always keep advertised
HOST_SIDE_TOOLS = {
    "session", "truncation", "bookmarks", "batch", "wiki",
    "search", "predictor", "workflow",
}

# cybercane.py exports the function as "governance" — handle separately
# (governance is already in ADVERTISED_TOOLS as the right name)


def get_tool_files() -> list[Path]:
    return sorted(
        p for p in TOOLS_DIR.glob("*.py")
        if p.stem not in ("__init__",) and not p.stem.startswith("_")
    )


def extract_tool_info(path: Path) -> dict | None:
    """Extract @tool function name, docstring, and action Literals from a tool file."""
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
    except Exception as e:
        print(f"  WARN: failed to parse {path.name}: {e}")
        return None

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        has_tool_dec = any(
            ("tool" in ast.unparse(d)) for d in node.decorator_list
        )
        if not has_tool_dec:
            continue

        func_name = node.name
        docstring = ast.get_docstring(node) or ""

        # Extract action Literal values from the signature
        actions: list[str] = []
        for arg in node.args.args:
            if arg.arg != "action":
                continue
            ann = arg.annotation
            if ann is None:
                break
            # Unwrap Optional[Literal[...]] or Annotated[..., Literal[...]] etc.
            actions = _extract_literals(ann)
            break

        return {
            "func_name": func_name,
            "module_name": path.stem,
            "docstring": docstring,
            "actions": actions,
        }
    return None


def _extract_literals(node) -> list[str]:
    """Recursively extract str values from Literal[] in an AST annotation."""
    if node is None:
        return []
    s = ast.unparse(node)
    # Find all Literal[...] occurrences in the unparsed string
    result: list[str] = []
    for match in re.finditer(r"Literal\[([^\]]+)\]", s):
        inner = match.group(1)
        for part in inner.split(","):
            part = part.strip().strip("'\"")
            if part:
                result.append(part)
    return result


def build_short_description(info: dict) -> str:
    """Build a concise single-line description from docstring + actions."""
    doc = info["docstring"].strip()
    actions = info["actions"]
    func = info["func_name"]

    if not doc:
        desc = func.replace("_", " ").capitalize() + " tool."
    else:
        # Take first paragraph (up to first blank line)
        first_para = doc.split("\n\n")[0].strip()
        # Collapse whitespace
        first_para = " ".join(first_para.split())
        # Trim very long first paragraphs
        if len(first_para) > 400:
            first_para = first_para[:397] + "..."
        desc = first_para

    if actions:
        actions_str = ", ".join(actions)
        # Only append if not already in description
        if "Actions:" not in desc and "actions:" not in desc:
            desc = desc.rstrip(".") + f". Actions: {actions_str}."
        else:
            # Replace the Actions: portion if actions list changed
            desc = re.sub(r"\s*Actions:.*$", f" Actions: {actions_str}.", desc)

    return desc


def parse_advertised_tools(src: str) -> tuple[int, int, list[str]]:
    """Parse ADVERTISED_TOOLS list from schemas.py source. Returns (start_line, end_line, tools)."""
    lines = src.splitlines()
    in_block = False
    start = end = -1
    tools = []
    for i, line in enumerate(lines):
        if re.match(r"^ADVERTISED_TOOLS\s*=\s*\[", line):
            in_block = True
            start = i
            continue
        if in_block:
            m = re.match(r'\s*"(\w+)"', line)
            if m:
                tools.append(m.group(1))
            if "]" in line and not line.strip().startswith("#"):
                end = i
                break
    return start, end, tools


def parse_tool_descriptions_keys(src: str) -> set[str]:
    """Parse the keys present in TOOL_DESCRIPTIONS dict."""
    keys = set()
    in_block = False
    for line in src.splitlines():
        if re.match(r"^TOOL_DESCRIPTIONS\s*=\s*\{", line):
            in_block = True
            continue
        if in_block:
            m = re.match(r'\s*"(\w+)":', line)
            if m:
                keys.add(m.group(1))
            if re.match(r"^}", line):
                break
    return keys


def run(dry_run: bool = False):
    src = SCHEMAS_PY.read_text(encoding="utf-8")
    lines = src.splitlines(keepends=True)

    # ── 1. Collect tool info from all tool files ──────────────────────────────
    all_tool_info: dict[str, dict] = {}
    for path in get_tool_files():
        info = extract_tool_info(path)
        if info is None:
            continue
        # The exported tool name is the function name (may differ from module name)
        tool_name = info["func_name"]
        all_tool_info[tool_name] = info
        # Also index by module name if different
        if info["module_name"] != tool_name and info["module_name"] not in ALWAYS_HIDDEN:
            all_tool_info[info["module_name"]] = info

    print(f"Found {len(all_tool_info)} tool names from {len(get_tool_files())} files")

    # ── 2. Decide ADVERTISED_TOOLS ────────────────────────────────────────────
    # Start with everything that has a tool function, minus always-hidden,
    # plus host-side tools that live in server.py not in tools/
    should_advertise = sorted(
        {name for name in all_tool_info if name not in ALWAYS_HIDDEN}
        | HOST_SIDE_TOOLS
    )
    print(f"Should advertise: {len(should_advertise)} tools")

    # ── 3. Update ADVERTISED_TOOLS block in schemas.py ────────────────────────
    start_line, end_line, current_advertised = parse_advertised_tools(src)
    if start_line == -1:
        print("ERROR: could not find ADVERTISED_TOOLS in schemas.py")
        sys.exit(1)

    new_advertised_set = set(should_advertise)
    old_advertised_set = set(current_advertised)
    added = sorted(new_advertised_set - old_advertised_set)
    removed = sorted(old_advertised_set - new_advertised_set)

    print("\nADVERTISED_TOOLS changes:")
    print(f"  Adding {len(added)}: {added}")
    print(f"  Removing {len(removed)}: {removed}")

    new_advertised_block = "ADVERTISED_TOOLS = [\n"
    for name in sorted(should_advertise):
        new_advertised_block += f'    "{name}",\n'
    new_advertised_block += "]\n"

    # Build replacement by reconstructing the file around the block
    before = "".join(lines[:start_line])
    after = "".join(lines[end_line + 1:])
    new_src = before + new_advertised_block + after

    # ── 4. Audit and update TOOL_DESCRIPTIONS ─────────────────────────────────
    existing_keys = parse_tool_descriptions_keys(new_src)
    desc_added = []
    desc_updated = []

    for tool_name, info in sorted(all_tool_info.items()):
        if tool_name in ALWAYS_HIDDEN:
            continue
        if tool_name not in should_advertise:
            continue

        new_desc = build_short_description(info)

        if tool_name not in existing_keys:
            # Insert before closing "}" of TOOL_DESCRIPTIONS
            # Find the closing brace
            insert_line = f'    "{tool_name}": {repr(new_desc)},\n'
            # Find TOOL_DESCRIPTIONS closing brace
            td_close = re.search(r'^TOOL_DESCRIPTIONS\s*=\s*\{', new_src, re.M)
            if td_close:
                # Find matching close brace
                pos = td_close.end()
                depth = 1
                while pos < len(new_src) and depth > 0:
                    if new_src[pos] == '{':
                        depth += 1
                    elif new_src[pos] == '}':
                        depth -= 1
                    pos += 1
                close_pos = pos - 1
                # Insert before closing brace
                new_src = new_src[:close_pos] + insert_line + new_src[close_pos:]
                desc_added.append(tool_name)
        else:
            # Check if actions list is stale
            info_actions = info["actions"]
            if not info_actions:
                continue  # Can't validate without extracted actions

            # Find existing description line
            pattern = rf'("{tool_name}":\s*")([^"]*)"'
            m = re.search(pattern, new_src)
            if not m:
                # Multi-line description — skip auto-update, too risky
                continue

            existing_desc = m.group(2)
            # Extract existing actions from description
            actions_match = re.search(r"Actions:\s*([^.]+)\.", existing_desc)
            if not actions_match:
                continue

            existing_actions_str = actions_match.group(1)
            existing_actions = {a.strip() for a in existing_actions_str.split(",")}
            new_actions = set(info_actions)

            # Only update if actions have meaningfully changed (new ones added or old ones removed)
            missing = new_actions - existing_actions
            extra = existing_actions - new_actions
            if missing or extra:
                # Rebuild actions in description with correct list
                new_actions_str = ", ".join(sorted(info_actions))
                new_desc_text = re.sub(
                    r"Actions:\s*[^.]+\.",
                    f"Actions: {new_actions_str}.",
                    existing_desc
                )
                new_src = new_src[:m.start()] + f'"{tool_name}": "{new_desc_text}"' + new_src[m.end():]
                desc_updated.append(f"{tool_name} (+{sorted(missing)} -{sorted(extra)})")

    print("\nTOOL_DESCRIPTIONS changes:")
    print(f"  Added {len(desc_added)}: {desc_added}")
    print(f"  Updated actions {len(desc_updated)}: {desc_updated}")

    # ── 5. Write output ───────────────────────────────────────────────────────
    if dry_run:
        print("\n[DRY RUN] No files written.")
        # Show diff summary
        print(f"\nFinal ADVERTISED_TOOLS count: {len(should_advertise)}")
    else:
        SCHEMAS_PY.write_text(new_src, encoding="utf-8")
        print(f"\nWrote {SCHEMAS_PY}")
        print(f"Final ADVERTISED_TOOLS count: {len(should_advertise)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Sync schemas.py with actual tool files")
    ap.add_argument("--dry-run", action="store_true", help="Report changes without writing")
    args = ap.parse_args()
    run(dry_run=args.dry_run)
