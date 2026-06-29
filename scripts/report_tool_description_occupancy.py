#!/usr/bin/env python3
"""Report character and token occupancy for MCP tool descriptions.

This script reads TOOL_DESCRIPTIONS from src/ida_pro_mcp/host/schemas.py,
tokenizes each description with tiktoken's cl100k_base encoding, and prints a
compact per-tool and aggregate size report.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import tiktoken

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS_PATH = ROOT / "src" / "ida_pro_mcp" / "host" / "schemas.py"


def load_tool_descriptions() -> dict[str, str]:
    source = SCHEMAS_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(SCHEMAS_PATH))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "TOOL_DESCRIPTIONS":
                    return ast.literal_eval(node.value)
    raise RuntimeError("TOOL_DESCRIPTIONS not found in schemas.py")


def main() -> int:
    descriptions = load_tool_descriptions()
    encoding = tiktoken.get_encoding("cl100k_base")

    rows = []
    total_chars = 0
    total_tokens = 0

    for tool_name in sorted(descriptions):
        desc = str(descriptions[tool_name] or "")
        chars = len(desc)
        tokens = len(encoding.encode(desc))
        total_chars += chars
        total_tokens += tokens
        rows.append(
            {
                "tool": tool_name,
                "chars": chars,
                "tokens": tokens,
                "chars_per_token": round(chars / tokens, 2) if tokens else None,
            }
        )

    rows.sort(key=lambda row: (-row["tokens"], row["tool"]))

    print(f"Tool descriptions: {len(rows)}")
    print(f"Total characters: {total_chars}")
    print(f"Total tokens (cl100k_base): {total_tokens}")
    print(f"Average chars/token: {round(total_chars / total_tokens, 2) if total_tokens else 0}")
    print()
    print("Top 15 by token count:")
    for row in rows[:15]:
        print(f"{row['tool']:<20} {row['tokens']:>5} tokens  {row['chars']:>5} chars")

    out_path = ROOT / "scripts" / "tool_description_occupancy.json"
    out_path.write_text(
        json.dumps(
            {
                "encoding": "cl100k_base",
                "tool_count": len(rows),
                "total_chars": total_chars,
                "total_tokens": total_tokens,
                "average_chars_per_token": round(total_chars / total_tokens, 4)
                if total_tokens
                else 0,
                "tools": rows,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print()
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
