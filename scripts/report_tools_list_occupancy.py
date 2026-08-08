#!/usr/bin/env python3
"""Report token occupancy for `tools/list` payloads.

Measures the JSON payload returned by IDAMCPServer.handle_request({"method": "tools/list"})
for the supported catalog modes and writes a machine-readable summary.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import tiktoken
except ImportError:  # not declared in pyproject.toml
    raise SystemExit("tiktoken is required for this report; install it with: pip install tiktoken") from None

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ida_mcp_stdio swaps sys.stdout -> sys.stderr at import time so the MCP
# protocol stream stays isolated. The report's own output must remain on
# stdout, so capture and restore the original stream around the import.
_ORIG_STDOUT = sys.stdout
from ida_mcp_stdio import IDAMCPServer  # noqa: E402

sys.stdout = _ORIG_STDOUT


def measure_payload(server: IDAMCPServer, mode: str) -> dict:
    server.default_tools_list_mode = mode
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    result = response["result"]
    encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    tools = result.get("tools", [])
    tool_desc_blob = json.dumps(
        [{"name": t.get("name"), "description": t.get("description")} for t in tools],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    input_schema_blob = json.dumps(
        [t.get("inputSchema") for t in tools],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "mode": mode,
        "tool_count": len(tools),
        "response_chars": len(encoded),
        "response_tokens": len(ENC.encode(encoded)),
        "tool_desc_chars": len(tool_desc_blob),
        "tool_desc_tokens": len(ENC.encode(tool_desc_blob)),
        "schema_chars": len(input_schema_blob),
        "schema_tokens": len(ENC.encode(input_schema_blob)),
        "response": result,
    }


ENC = tiktoken.get_encoding("cl100k_base")


def main() -> int:
    server = IDAMCPServer()
    modes = ["full", "lean", "ultra"]

    rows = []
    for mode in modes:
        rows.append(measure_payload(server, mode))

    print("tools/list payload occupancy")
    print()
    for row in rows:
        print(
            f"{row['mode']:<5} tools={row['tool_count']:>3} "
            f"response={row['response_tokens']:>5} tokens / {row['response_chars']:>6} chars "
            f"description-only={row['tool_desc_tokens']:>5} tokens "
            f"schema-only={row['schema_tokens']:>5} tokens"
        )

    out_path = ROOT / "scripts" / "tools_list_occupancy.json"
    out_path.write_text(
        json.dumps(
            {
                "encoding": "cl100k_base",
                "modes": [
                    {k: v for k, v in row.items() if k != "response"}
                    for row in rows
                ],
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
