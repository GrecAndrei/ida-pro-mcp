"""
MCP Resource provider: Exposes IDB data as read-only resources.

Resources are hierarchical URIs that the LLM can read without calling tools.
This turns the IDA database into a virtual filesystem.

Supported URIs:
  ida://meta                        - IDB metadata
  ida://segments                    - All segments
  ida://segments/{name}             - Specific segment
  ida://functions                   - Top functions
  ida://functions/{addr}            - Function info
  ida://functions/{addr}/decompile  - Decompilation
  ida://functions/{addr}/disasm     - Disassembly
  ida://functions/{addr}/xrefs      - Xrefs to function
  ida://strings                     - Strings
  ida://imports                     - Imports
  ida://exports                     - Exports
  ida://structs                     - Structures
  ida://bookmarks                   - Bookmarks
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

# We avoid importing IDA modules here; resource resolution is delegated
# to the server's tool execution pipeline.


RESOURCE_TEMPLATES = [
    "ida://meta",
    "ida://segments",
    "ida://segments/{name}",
    "ida://functions",
    "ida://functions/{addr}",
    "ida://functions/{addr}/decompile",
    "ida://functions/{addr}/disasm",
    "ida://functions/{addr}/xrefs",
    "ida://strings",
    "ida://imports",
    "ida://exports",
    "ida://structs",
    "ida://bookmarks",
    "ida://skills",
    "ida://facts",
    "ida://archive",
]


def list_resources() -> List[Dict]:
    """Return static resource catalog."""
    return [
        {"uri": "ida://meta", "name": "IDB Metadata", "mimeType": "application/json"},
        {"uri": "ida://segments", "name": "Segments", "mimeType": "application/json"},
        {"uri": "ida://functions", "name": "Functions", "mimeType": "application/json"},
        {"uri": "ida://strings", "name": "Strings", "mimeType": "application/json"},
        {"uri": "ida://imports", "name": "Imports", "mimeType": "application/json"},
        {"uri": "ida://exports", "name": "Exports", "mimeType": "application/json"},
        {"uri": "ida://structs", "name": "Structures", "mimeType": "application/json"},
        {"uri": "ida://bookmarks", "name": "Bookmarks", "mimeType": "application/json"},
        {"uri": "ida://skills", "name": "L3 Task Skills", "mimeType": "application/json"},
        {"uri": "ida://facts", "name": "L2 Global Facts", "mimeType": "application/json"},
        {"uri": "ida://archive", "name": "L4 Session Archive", "mimeType": "application/json"},
    ]


def _make_text_content(text: str) -> Dict:
    return {"uri": "", "mimeType": "text/plain", "text": text}


def _make_json_content(data: Any) -> Dict:
    return {
        "uri": "",
        "mimeType": "application/json",
        "text": json.dumps(data, indent=2, ensure_ascii=False),
    }


class ResourceResolver:
    """Resolves ida:// URIs by delegating to tool calls or memory tiers."""

    def __init__(self, tool_executor, insight_index=None, global_facts=None, session_mgr=None):
        self.tool_executor = tool_executor
        self.insight_index = insight_index
        self.global_facts = global_facts
        self.session_mgr = session_mgr

    def read(self, uri: str) -> Optional[Dict]:
        if not uri.startswith("ida://"):
            return None
        rest = uri[6:].strip("/")
        if not rest:
            return self._read_root()

        parts = rest.split("/")
        domain = parts[0]

        if domain == "meta":
            return self._read_meta()
        elif domain == "segments":
            if len(parts) == 1:
                return self._read_segments()
            return self._read_segment(parts[1])
        elif domain == "functions":
            if len(parts) == 1:
                return self._read_functions()
            addr = parts[1]
            if len(parts) == 2:
                return self._read_function(addr)
            sub = parts[2]
            if sub == "decompile":
                return self._read_function_decompile(addr)
            elif sub == "disasm":
                return self._read_function_disasm(addr)
            elif sub == "xrefs":
                return self._read_function_xrefs(addr)
            return None
        elif domain == "strings":
            return self._read_strings()
        elif domain == "imports":
            return self._read_imports()
        elif domain == "exports":
            return self._read_exports()
        elif domain == "structs":
            return self._read_structs()
        elif domain == "bookmarks":
            return self._read_bookmarks()
        elif domain == "skills":
            return self._read_skills()
        elif domain == "facts":
            return self._read_facts()
        elif domain == "archive":
            return self._read_archive()
        return None

    def _exec(self, tool_name: str, **kwargs) -> Any:
        return self.tool_executor(tool_name, kwargs)

    def _read_root(self) -> Dict:
        return _make_json_content({
            "domains": ["meta", "segments", "functions", "strings", "imports", "exports", "structs", "bookmarks"],
            "note": "Append domain name to ida:// to read resources",
        })

    def _read_meta(self) -> Dict:
        result = self._exec("idb", action="meta")
        return _make_json_content(result)

    def _read_segments(self) -> Dict:
        result = self._exec("idb", action="segments")
        return _make_json_content(result)

    def _read_segment(self, name: str) -> Optional[Dict]:
        result = self._exec("idb", action="segments")
        if isinstance(result, dict) and "segments" in result:
            for seg in result["segments"]:
                if seg.get("name") == name or seg.get("segment_name") == name:
                    return _make_json_content(seg)
        return _make_json_content({"error": f"Segment '{name}' not found"})

    def _read_functions(self) -> Dict:
        result = self._exec("data", action="functions", count=100)
        return _make_json_content(result)

    def _read_function(self, addr: str) -> Dict:
        result = self._exec("funcs", action="info", addr=addr, include_prototype=True)
        return _make_json_content(result)

    def _read_function_decompile(self, addr: str) -> Dict:
        result = self._exec("code", action="decompile", addr=addr)
        if isinstance(result, dict) and "pseudocode" in result:
            return _make_text_content(result["pseudocode"])
        return _make_json_content(result)

    def _read_function_disasm(self, addr: str) -> Dict:
        result = self._exec("code", action="disasm", addr=addr)
        if isinstance(result, dict) and "disassembly" in result:
            return _make_text_content(result["disassembly"])
        return _make_json_content(result)

    def _read_function_xrefs(self, addr: str) -> Dict:
        result = self._exec("code", action="xrefs_to", addr=addr)
        return _make_json_content(result)

    def _read_strings(self) -> Dict:
        result = self._exec("data", action="strings", count=200)
        return _make_json_content(result)

    def _read_imports(self) -> Dict:
        result = self._exec("data", action="imports", count=200)
        return _make_json_content(result)

    def _read_exports(self) -> Dict:
        result = self._exec("data", action="exports", count=200)
        return _make_json_content(result)

    def _read_structs(self) -> Dict:
        result = self._exec("types", action="list")
        return _make_json_content(result)

    def _read_bookmarks(self) -> Dict:
        result = self._exec("bookmarks", action="list")
        return _make_json_content(result)

    def _read_skills(self) -> Dict:
        """Read L3 task skills from the current session."""
        if not self.session_mgr:
            return _make_json_content({"error": "Session manager not available"})
        # Attempt to get skills for current session via session tool
        result = self._exec("session", action="list_skills")
        if isinstance(result, dict) and result.get("error"):
            return _make_json_content({"skills": [], "note": "No skills available or session tool not configured for list_skills"})
        return _make_json_content(result)

    def _read_facts(self) -> Dict:
        """Read L2 global facts."""
        if not self.global_facts:
            return _make_json_content({"error": "Global facts database not available"})
        facts = self.global_facts.query_facts(limit=100)
        return _make_json_content({
            "total": self.global_facts.count(),
            "facts": facts,
        })

    def _read_archive(self) -> Dict:
        """Read L4 session archive (activity log)."""
        if not self.session_mgr:
            return _make_json_content({"error": "Session manager not available"})
        result = self._exec("session", action="stats")
        if isinstance(result, dict) and result.get("error"):
            return _make_json_content({"archive": [], "note": "Archive not available"})
        return _make_json_content({
            "stats": result.get("stats", {}),
            "note": "L4 archive includes session stats and activity logs.",
        })
