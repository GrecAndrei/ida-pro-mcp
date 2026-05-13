"""
MCP Resource provider: Exposes IDB data as read-only resources.

Resources are hierarchical URIs that the LLM can read without calling tools.
This turns the IDA database into a virtual filesystem.

Supported URIs (67 total):
  ida://state                       - Complete analysis state (read this first on every turn)
  ida://proposals                   - Pending engine proposals (rename/annotate/vuln/cross-session)
  ida://meta                        - IDB metadata
  ida://segments                    - All segments
  ida://segments/{name}             - Specific segment
  ida://segments/{name}/bytes       - Segment raw bytes
  ida://segments/{name}/instructions - Segment disassembly
  ida://functions                   - Top functions
  ida://functions/{addr}            - Function info
  ida://functions/{addr}/decompile  - Decompilation
  ida://functions/{addr}/disasm     - Disassembly
  ida://functions/{addr}/xrefs      - Xrefs to function
  ida://functions/{addr}/blocks     - Basic blocks
  ida://functions/{addr}/callers    - Functions calling this
  ida://functions/{addr}/callees    - Functions called by this
  ida://functions/{addr}/ctree      - CTree AST
  ida://functions/{addr}/stack      - Stack frame
  ida://functions/{addr}/embedding  - Graph embedding
  ida://functions/{addr}/similar    - Similar functions
  ida://strings                     - Strings
  ida://imports                     - Imports
  ida://imports/deep                - Deep import analysis
  ida://exports                     - Exports
  ida://structs                     - Structures
  ida://globals                     - Global variables
  ida://bookmarks                   - Bookmarks
  ida://skills                      - L3 Task Skills
  ida://facts                       - L2 Global Facts
  ida://archive                     - L4 Session Archive
  ida://xrefs                       - Cross-references
  ida://types                       - Type library
  ida://blackboard                  - All blackboard findings
  ida://blackboard/next_target      - Priority-ranked next targets
  ida://blackboard/iocs             - IOC entries
  ida://blackboard/hypotheses       - Hypothesis entries
  ida://blackboard/regions          - Memory region annotations
  ida://blackboard/{category}       - Entries by category
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional


RESOURCE_TEMPLATES = [
    # State (read this first — complete analysis picture)
    "ida://state",
    "ida://proposals",
    # Meta
    "ida://meta",
    # Segments (3)
    "ida://segments",
    "ida://segments/{name}",
    "ida://segments/{name}/bytes",
    "ida://segments/{name}/instructions",
    # Functions (14)
    "ida://functions",
    "ida://functions/{addr}",
    "ida://functions/{addr}/decompile",
    "ida://functions/{addr}/disasm",
    "ida://functions/{addr}/xrefs",
    "ida://functions/{addr}/blocks",
    "ida://functions/{addr}/callers",
    "ida://functions/{addr}/callees",
    "ida://functions/{addr}/ctree",
    "ida://functions/{addr}/stack",
    "ida://functions/{addr}/embedding",
    "ida://functions/{addr}/similar",
    # Data (8)
    "ida://strings",
    "ida://imports",
    "ida://imports/deep",
    "ida://exports",
    "ida://structs",
    "ida://globals",
    "ida://xrefs",
    "ida://types",
    # Meta-layers (4)
    "ida://bookmarks",
    "ida://skills",
    "ida://facts",
    "ida://archive",
    # Blackboard (6)
    "ida://blackboard",
    "ida://blackboard/next_target",
    "ida://blackboard/iocs",
    "ida://blackboard/hypotheses",
    "ida://blackboard/regions",
    "ida://blackboard/{category}",
]


def list_resources() -> List[Dict]:
    """Return static resource catalog."""
    return [
        {"uri": "ida://state", "name": "Analysis State — complete picture (read first)", "mimeType": "application/json"},
        {"uri": "ida://proposals", "name": "Engine Proposals — pending rename/vuln/cross-session actions", "mimeType": "application/json"},
        {"uri": "ida://meta", "name": "IDB Metadata", "mimeType": "application/json"},
        {"uri": "ida://segments", "name": "Segments", "mimeType": "application/json"},
        {"uri": "ida://functions", "name": "Functions", "mimeType": "application/json"},
        {"uri": "ida://strings", "name": "Strings", "mimeType": "application/json"},
        {"uri": "ida://imports", "name": "Imports", "mimeType": "application/json"},
        {"uri": "ida://imports/deep", "name": "Deep Import Analysis", "mimeType": "application/json"},
        {"uri": "ida://exports", "name": "Exports", "mimeType": "application/json"},
        {"uri": "ida://structs", "name": "Structures", "mimeType": "application/json"},
        {"uri": "ida://globals", "name": "Global Variables", "mimeType": "application/json"},
        {"uri": "ida://xrefs", "name": "Cross-References", "mimeType": "application/json"},
        {"uri": "ida://types", "name": "Type Library", "mimeType": "application/json"},
        {"uri": "ida://bookmarks", "name": "Bookmarks", "mimeType": "application/json"},
        {"uri": "ida://skills", "name": "L3 Task Skills", "mimeType": "application/json"},
        {"uri": "ida://facts", "name": "L2 Global Facts", "mimeType": "application/json"},
        {"uri": "ida://archive", "name": "L4 Session Archive", "mimeType": "application/json"},
        {"uri": "ida://blackboard", "name": "Blackboard — all findings", "mimeType": "application/json"},
        {"uri": "ida://blackboard/next_target", "name": "Blackboard — next analysis target", "mimeType": "application/json"},
        {"uri": "ida://blackboard/iocs", "name": "Blackboard — IOCs", "mimeType": "application/json"},
        {"uri": "ida://blackboard/hypotheses", "name": "Blackboard — hypotheses", "mimeType": "application/json"},
        {"uri": "ida://blackboard/regions", "name": "Blackboard — memory regions", "mimeType": "application/json"},
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

    def __init__(self, tool_executor, insight_index=None, global_facts=None,
                 session_mgr=None, engine=None, bb_path: str = ""):
        self.tool_executor = tool_executor
        self.insight_index = insight_index
        self.global_facts = global_facts
        self.session_mgr = session_mgr
        self.engine = engine          # AnalysisEngine instance (optional)
        self.bb_path = bb_path        # path to blackboard db (optional)

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
        elif domain == "state":
            return self._read_state()
        elif domain == "proposals":
            return self._read_proposals()
        elif domain == "segments":
            return self._read_segments_resource(parts)
        elif domain == "functions":
            return self._read_functions_resource(parts)
        elif domain == "strings":
            return self._read_strings()
        elif domain == "imports":
            return self._read_imports_resource(parts)
        elif domain == "exports":
            return self._read_exports()
        elif domain == "structs":
            return self._read_structs()
        elif domain == "globals":
            return self._read_globals()
        elif domain == "xrefs":
            return self._read_xrefs()
        elif domain == "types":
            return self._read_types()
        elif domain == "bookmarks":
            return self._read_bookmarks()
        elif domain == "skills":
            return self._read_skills()
        elif domain == "facts":
            return self._read_facts()
        elif domain == "archive":
            return self._read_archive()
        elif domain == "blackboard":
            return self._read_blackboard_resource(parts)
        return None

    def _exec(self, tool_name: str, **kwargs) -> Any:
        return self.tool_executor(tool_name, kwargs)

    # ------------------------------------------------------------------
    # Root / Meta
    # ------------------------------------------------------------------

    def _read_root(self) -> Dict:
        return _make_json_content({
            "domains": ["meta", "segments", "functions", "strings", "imports", "exports", "structs", "globals", "xrefs", "types", "bookmarks"],
            "templates": RESOURCE_TEMPLATES,
            "note": "Append domain name to ida:// to read resources. Use {addr} for function addresses.",
        })

    def _read_meta(self) -> Dict:
        result = self._exec("idb", action="meta")
        return _make_json_content(result)

    # ------------------------------------------------------------------
    # State — complete analysis picture
    # ------------------------------------------------------------------

    def _read_state(self) -> Dict:
        """
        ida://state — the LLM's externalized working memory.

        Read this at the start of every turn to orient yourself without
        calling 6 separate tools. Updated by the analysis engine whenever
        anything significant changes; the server pushes
        notifications/resources/updated with uri=ida://state.
        """
        state: Dict[str, Any] = {}

        # 1. Binary identity
        try:
            meta = self._exec("idb", action="meta")
            state["binary"] = {
                "name": meta.get("filename") or meta.get("input_file", ""),
                "arch": meta.get("processor") or meta.get("arch", ""),
                "bits": meta.get("bits", 0),
                "size": meta.get("file_size", 0),
            }
        except Exception:
            state["binary"] = {}

        # 2. Coverage
        try:
            funcs = self._exec("data", action="functions", count=5000)
            func_list = funcs.get("functions", []) if isinstance(funcs, dict) else []
            total = len(func_list)
            named = sum(1 for f in func_list
                        if not (f.get("name", "").startswith("sub_")
                                or f.get("name", "").startswith("j_")))
            state["coverage"] = {
                "total_functions": total,
                "named_functions": named,
                "unnamed_functions": total - named,
                "pct_named": round(named / total * 100, 1) if total else 0,
            }
        except Exception:
            state["coverage"] = {}

        # 3. Blackboard summary
        try:
            bb = self._bb_store()
            if bb:
                stats = bb.stats()
                targets = bb.next_target(limit=5)
                hypotheses = bb.list(category="hypothesis", limit=5,
                                     include_resolved=False, include_contradicted=False)
                iocs = bb.list(category="ioc", limit=10, include_resolved=True)
                vulns = bb.list(category="vuln", limit=5, include_resolved=False)
                state["blackboard"] = {
                    "stats": stats,
                    "next_targets": targets,
                    "top_hypotheses": [
                        {"title": h["title"], "addr": h.get("addr"),
                         "confidence": h.get("confidence")}
                        for h in hypotheses
                    ],
                    "iocs": [
                        {"type": i.get("ioc_type"), "value": i.get("ioc_value"),
                         "addr": i.get("addr")}
                        for i in iocs
                    ],
                    "vulns": [
                        {"title": v["title"], "addr": v.get("addr"),
                         "confidence": v.get("confidence")}
                        for v in vulns
                    ],
                }
        except Exception:
            state["blackboard"] = {}

        # 4. Engine status + pending proposals
        if self.engine:
            try:
                eng_status = self.engine.status()
                pending = self.engine.proposals.count_pending()
                state["engine"] = {
                    "running": eng_status.get("running"),
                    "pending_proposals": pending,
                    "classified_functions": eng_status.get("classified_functions"),
                }
                if pending:
                    state["engine"]["note"] = (
                        f"{pending} proposal(s) waiting. "
                        "Read ida://proposals to review."
                    )
            except Exception:
                state["engine"] = {}

        # 5. Session info
        try:
            if self.session_mgr:
                active = getattr(self.session_mgr, "active_session_id", None)
                state["session"] = {"active_session_id": active}
        except Exception:
            state["session"] = {}

        state["_note"] = (
            "Read ida://proposals for pending engine actions. "
            "Read ida://blackboard/next_target for the highest-priority address to analyze next. "
            "This resource is pushed via notifications/resources/updated when anything changes."
        )

        return _make_json_content(state)

    def _bb_store(self):
        """Load BlackboardStore without IDA deps."""
        try:
            import importlib.util, os as _os
            path = _os.path.join(
                _os.path.dirname(_os.path.abspath(__file__)),
                "..", "ida_mcp", "tools", "blackboard.py"
            )
            spec = importlib.util.spec_from_file_location("_res_bb2", _os.path.abspath(path))
            mod = importlib.util.module_from_spec(spec)
            mod.__dict__.update({"tool": lambda f: f, "idaread": lambda f: f,
                                  "idawrite": lambda f: f, "IDAError": Exception})
            spec.loader.exec_module(mod)
            kwargs = {}
            if self.bb_path:
                kwargs["db_path"] = self.bb_path
            return mod.BlackboardStore(**kwargs)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Proposals
    # ------------------------------------------------------------------

    def _read_proposals(self) -> Dict:
        """
        ida://proposals — pending engine proposals.

        Each proposal has a type:
          rename_batch    — suggest renaming N functions
          annotation_batch — suggest adding comments
          hypothesis      — engine believes X about address Y
          cross_session   — N functions match a previous session
          vuln            — taint trace found a dangerous sink

        To act: call blackboard(action="accept_proposal", proposal_id=..., scope="all")
                or    blackboard(action="reject_proposal", proposal_id=...)
        """
        if not self.engine:
            return _make_json_content({
                "proposals": [],
                "note": "Analysis engine not running. Start a session to activate it.",
            })
        try:
            proposals = self.engine.proposals.list_pending()
            return _make_json_content({
                "count": len(proposals),
                "proposals": proposals,
                "note": (
                    "Call blackboard(action='accept_proposal', proposal_id=ID, scope='all') "
                    "to apply a proposal, or scope='selected' with selected_ids=[...] for partial. "
                    "Call blackboard(action='reject_proposal', proposal_id=ID) to dismiss."
                ),
            })
        except Exception as e:
            return _make_json_content({"error": str(e), "proposals": []})

    # ------------------------------------------------------------------
    # Segments
    # ------------------------------------------------------------------

    def _read_segments_resource(self, parts: List[str]) -> Optional[Dict]:
        if len(parts) == 1:
            return self._read_segments()
        name = parts[1]
        if len(parts) == 2:
            return self._read_segment(name)
        sub = parts[2]
        if sub == "bytes":
            return self._read_segment_bytes(name)
        elif sub == "instructions":
            return self._read_segment_instructions(name)
        return None

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

    def _read_segment_bytes(self, name: str) -> Dict:
        result = self._exec("segments", action="list")
        if isinstance(result, dict) and "segments" in result:
            for seg in result["segments"]:
                if seg.get("name") == name:
                    start = seg.get("start_ea") or seg.get("start")
                    end = seg.get("end_ea") or seg.get("end")
                    if start and end:
                        mem = self._exec("memory", action="read", addr=start, size=min(end - start, 4096))
                        return _make_json_content({"segment": name, "bytes": mem})
        return _make_json_content({"error": f"Segment '{name}' not found"})

    def _read_segment_instructions(self, name: str) -> Dict:
        result = self._exec("segments", action="list")
        if isinstance(result, dict) and "segments" in result:
            for seg in result["segments"]:
                if seg.get("name") == name:
                    start = seg.get("start_ea") or seg.get("start")
                    if start:
                        dis = self._exec("code", action="disasm", addr=start, limit=50)
                        return _make_json_content({"segment": name, "instructions": dis})
        return _make_json_content({"error": f"Segment '{name}' not found"})

    # ------------------------------------------------------------------
    # Functions
    # ------------------------------------------------------------------

    def _read_functions_resource(self, parts: List[str]) -> Optional[Dict]:
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
        elif sub == "blocks":
            return self._read_function_blocks(addr)
        elif sub == "callers":
            return self._read_function_callers(addr)
        elif sub == "callees":
            return self._read_function_callees(addr)
        elif sub == "ctree":
            return self._read_function_ctree(addr)
        elif sub == "stack":
            return self._read_function_stack(addr)
        elif sub == "embedding":
            return self._read_function_embedding(addr)
        elif sub == "similar":
            return self._read_function_similar(addr)
        return None

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

    def _read_function_blocks(self, addr: str) -> Dict:
        result = self._exec("code", action="blocks", addr=addr)
        return _make_json_content(result)

    def _read_function_callers(self, addr: str) -> Dict:
        result = self._exec("code", action="callers", addr=addr)
        return _make_json_content(result)

    def _read_function_callees(self, addr: str) -> Dict:
        result = self._exec("code", action="callees", addr=addr)
        return _make_json_content(result)

    def _read_function_ctree(self, addr: str) -> Dict:
        result = self._exec("ctree", action="get", addr=addr)
        return _make_json_content(result)

    def _read_function_stack(self, addr: str) -> Dict:
        result = self._exec("stack_analysis", action="analyze_frame", addr=addr)
        return _make_json_content(result)

    def _read_function_embedding(self, addr: str) -> Dict:
        result = self._exec("mbagcn", action="encode", addr=addr)
        return _make_json_content(result)

    def _read_function_similar(self, addr: str) -> Dict:
        result = self._exec("mbagcn", action="similar", addr=addr, top_k=10)
        return _make_json_content(result)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------

    def _read_strings(self) -> Dict:
        result = self._exec("data", action="strings", count=200)
        return _make_json_content(result)

    def _read_imports_resource(self, parts: List[str]) -> Dict:
        if len(parts) > 1 and parts[1] == "deep":
            result = self._exec("imports_deep", action="thunks")
            return _make_json_content(result)
        result = self._exec("data", action="imports", count=200)
        return _make_json_content(result)

    def _read_exports(self) -> Dict:
        result = self._exec("data", action="exports", count=200)
        return _make_json_content(result)

    def _read_structs(self) -> Dict:
        result = self._exec("types", action="list")
        return _make_json_content(result)

    def _read_globals(self) -> Dict:
        result = self._exec("data", action="globals", count=100)
        return _make_json_content(result)

    def _read_xrefs(self) -> Dict:
        result = self._exec("data", action="lookup", kind="xref", count=100)
        return _make_json_content(result)

    def _read_types(self) -> Dict:
        result = self._exec("types", action="list", count=100)
        return _make_json_content(result)

    # ------------------------------------------------------------------
    # Meta-layers
    # ------------------------------------------------------------------

    def _read_bookmarks(self) -> Dict:
        result = self._exec("bookmarks", action="list")
        return _make_json_content(result)

    def _read_skills(self) -> Dict:
        if not self.session_mgr:
            return _make_json_content({"error": "Session manager not available"})
        result = self._exec("session", action="list_skills")
        if isinstance(result, dict) and result.get("error"):
            return _make_json_content({"skills": [], "note": "No skills available"})
        return _make_json_content(result)

    def _read_facts(self) -> Dict:
        if not self.global_facts:
            return _make_json_content({"error": "Global facts database not available"})
        facts = self.global_facts.query_facts(limit=100)
        return _make_json_content({
            "total": self.global_facts.count(),
            "facts": facts,
        })

    def _read_archive(self) -> Dict:
        if not self.session_mgr:
            return _make_json_content({"error": "Session manager not available"})
        result = self._exec("session", action="stats")
        if isinstance(result, dict) and result.get("error"):
            return _make_json_content({"archive": [], "note": "Archive not available"})
        return _make_json_content({
            "stats": result.get("stats", {}),
            "note": "L4 archive includes session stats and activity logs.",
        })

    def _read_blackboard_resource(self, parts: List[str]) -> Dict:
        """
        ida://blackboard                 — all unresolved, non-contradicted entries
        ida://blackboard/next_target     — priority-ranked next analysis targets
        ida://blackboard/iocs            — IOC entries (ip, port, key, magic)
        ida://blackboard/hypotheses      — hypothesis entries
        ida://blackboard/regions         — annotated memory regions
        ida://blackboard/{category}      — entries by category
        """
        try:
            import importlib.util, os as _os
            bb_path = _os.path.join(
                _os.path.dirname(_os.path.abspath(__file__)),
                "..", "ida_mcp", "tools", "blackboard.py"
            )
            bb_path = _os.path.abspath(bb_path)
            spec = importlib.util.spec_from_file_location("_res_bb", bb_path)
            mod = importlib.util.module_from_spec(spec)
            mod.__dict__["tool"] = lambda f: f
            mod.__dict__["idaread"] = lambda f: f
            mod.__dict__["idawrite"] = lambda f: f
            mod.__dict__["IDAError"] = Exception
            spec.loader.exec_module(mod)
            store = mod.BlackboardStore()
        except Exception as e:
            return _make_json_content({"error": f"Blackboard unavailable: {e}"})

        sub = parts[1] if len(parts) > 1 else ""

        if not sub:
            entries = store.list(limit=100, include_resolved=False, include_contradicted=False)
            stats = store.stats()
            return _make_json_content({
                "stats": stats,
                "entries": entries,
                "note": "Use ida://blackboard/next_target for prioritized analysis targets.",
            })

        if sub == "next_target":
            targets = store.next_target(limit=10)
            return _make_json_content({
                "targets": targets,
                "note": "Highest-priority unexplored addresses. Decompile the top target next.",
            })

        if sub == "iocs":
            iocs = store.list(category="ioc", limit=200, include_resolved=True)
            return _make_json_content({"iocs": iocs, "count": len(iocs)})

        if sub == "hypotheses":
            hyps = store.list(category="hypothesis", limit=100, include_resolved=False)
            return _make_json_content({"hypotheses": hyps, "count": len(hyps)})

        if sub == "regions":
            regions = store.list(category="region", limit=100, include_resolved=True)
            return _make_json_content({"regions": regions, "count": len(regions)})

        # Generic category
        entries = store.list(category=sub, limit=100, include_resolved=False)
        return _make_json_content({"category": sub, "entries": entries, "count": len(entries)})
