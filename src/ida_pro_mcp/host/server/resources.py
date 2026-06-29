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
import time
from typing import Any, Dict, List, Optional

from ..errors import is_error_result

# TTL cache for ida://state coverage stats (expensive: calls data/functions)
_STATE_CACHE: Dict[str, Any] = {}
_STATE_CACHE_TTL = 30.0  # seconds


def invalidate_state_cache() -> None:
    """Call this when ida://state should be refreshed immediately."""
    _STATE_CACHE.clear()


RESOURCE_TEMPLATES = [
    # State (read this first — complete analysis picture)
    "ida://state",
    "ida://proposals",
    "ida://knowledge",
    "ida://knowledge/systems",
    "ida://knowledge/structs",
    "ida://knowledge/gaps",
    "ida://knowledge/attack_surface",
    "ida://knowledge/peripherals",
    "ida://knowledge/state_machines",
    "ida://usage",
    "ida://usage/session/{session_id}",
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
    # Frontier / Coverage (new)
    "ida://blackboard/frontier",
    "ida://blackboard/coverage",
    "ida://taint",
]


def list_resources() -> List[Dict]:
    """Return static resource catalog."""
    return [
        {"uri": "ida://state", "name": "Analysis State — complete picture (read first)", "mimeType": "text/plain"},
        {"uri": "ida://proposals", "name": "Engine Proposals — pending rename/vuln/cross-session actions", "mimeType": "application/json"},
        {"uri": "ida://knowledge", "name": "Knowledge Graph — systems/structs/gaps/attack surface", "mimeType": "application/json"},
        {"uri": "ida://knowledge/systems", "name": "Identified systems (call-graph clusters)", "mimeType": "application/json"},
        {"uri": "ida://knowledge/structs", "name": "Inferred data structures", "mimeType": "application/json"},
        {"uri": "ida://knowledge/gaps", "name": "Open gaps — expected but not found", "mimeType": "application/json"},
        {"uri": "ida://knowledge/attack_surface", "name": "Attack surface map", "mimeType": "application/json"},
        {"uri": "ida://knowledge/peripherals", "name": "Peripheral map (MMIO)", "mimeType": "application/json"},
        {"uri": "ida://knowledge/state_machines", "name": "Detected state machines", "mimeType": "application/json"},
        {"uri": "ida://usage", "name": "Usage intelligence — sequence model, effectiveness, drift", "mimeType": "application/json"},
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
        {"uri": "ida://blackboard/frontier", "name": "Frontier — ranked unvisited functions (read when choosing what to analyze next)", "mimeType": "application/json"},
        {"uri": "ida://blackboard/coverage", "name": "Coverage map — analyzed vs unvisited per cluster (read to understand progress)", "mimeType": "application/json"},
        {"uri": "ida://taint", "name": "Taint report — all source→sink paths (read after finding network/file input)", "mimeType": "application/json"},
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
                 session_mgr=None, engine=None, bb_path: str = "",
                 usage_intel=None):
        self.tool_executor = tool_executor
        self.insight_index = insight_index
        self.global_facts = global_facts
        self.session_mgr = session_mgr
        self.engine = engine
        self.bb_path = bb_path
        self.usage_intel = usage_intel  # UsageIntelligence instance

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
        elif domain == "knowledge":
            return self._read_knowledge(parts)
        elif domain == "usage":
            return self._read_usage(parts)
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
        elif domain == "taint":
            return self._read_taint()
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
            overview = self._exec("idb", action="overview")
            meta = overview.get("meta", {}) if isinstance(overview, dict) else {}
            summary = overview.get("summary", {}) if isinstance(overview, dict) else {}
            arch_profile = overview.get("architecture_profile", {}) if isinstance(overview, dict) else {}
            is_firmware = bool(
                (overview.get("firmware_detected") if isinstance(overview, dict) else False)
                or (arch_profile.get("raw_binary_mode") if isinstance(arch_profile, dict) else False)
            )
            if not is_firmware:
                # Fallback heuristic for older/partial IDB metadata payloads.
                ft_info = meta.get("file_type_info") if isinstance(meta.get("file_type_info"), dict) else {}
                ft_name = str(meta.get("file_type_effective") or ft_info.get("effective") or meta.get("file_type") or "").strip().lower()
                ft_id = meta.get("file_type_id")
                try:
                    ft_num = int(ft_id) if ft_id is not None else None
                except Exception:
                    ft_num = None
                proc = str(meta.get("processor") or meta.get("arch") or "").strip().lower()
                imports = (
                    summary.get("imports")
                    if isinstance(summary, dict) and summary.get("imports") is not None
                    else meta.get("import_count", 0)
                )
                try:
                    imports = int(imports or 0)
                except Exception:
                    imports = 0
                is_firmware = bool(
                    ft_name in {"", "raw", "unknown", "bin", "binary", "obj"}
                    or ft_num in {0, 2, 17}
                    or (proc in ("arm", "mips", "ppc", "msp430", "avr", "xtensa") and imports == 0)
                )
            state["binary"] = {
                "name": meta.get("binary_path") or meta.get("filename") or meta.get("input_file", ""),
                "arch": meta.get("processor") or meta.get("arch", ""),
                "bits": meta.get("bitness") or meta.get("bits", 0),
                "size": meta.get("image_size") or meta.get("file_size", 0),
                "imports": summary.get("imports", 0),
                "is_firmware": is_firmware,
            }
            if is_firmware:
                state["binary"]["firmware"] = True
        except Exception:
            state["binary"] = {}
            is_firmware = False

        # 2. Coverage (cached with 30s TTL — expensive on large binaries)
        cache_key = f"coverage_{id(self.tool_executor)}"
        cached = _STATE_CACHE.get(cache_key)
        if cached and time.time() - cached["_ts"] < _STATE_CACHE_TTL:
            state["coverage"] = cached["coverage"]
        else:
            try:
                funcs = self._exec("data", action="functions", count=5000)
                func_list = funcs.get("functions", []) if isinstance(funcs, dict) else []
                total = len(func_list)
                named = sum(1 for f in func_list
                            if not (f.get("name", "").startswith("sub_")
                                    or f.get("name", "").startswith("j_")))
                coverage = {
                    "total_functions": total,
                    "named_functions": named,
                    "unnamed_functions": total - named,
                    "pct_named": round(named / total * 100, 1) if total else 0,
                }
                state["coverage"] = coverage
                _STATE_CACHE[cache_key] = {"coverage": coverage, "_ts": time.time()}
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

        # 6. KnowledgeGraph summary + narrative
        try:
            import importlib.util as _ilu
            import os as _os
            # resources.py is in host/server/; knowledge_graph.py is in host/stores/.
            _kg_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                                     "..", "stores", "knowledge_graph.py")
            _spec = _ilu.spec_from_file_location("_state_kg", _kg_path)
            _kgmod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_kgmod)
            kg = _kgmod.KnowledgeGraph(self.bb_path) if self.bb_path else None
            if kg:
                state["knowledge_graph"] = kg.summary()
                # Open gaps
                gaps = kg.list_gaps(resolved=False)
                if gaps:
                    state["knowledge_graph"]["top_gaps"] = [
                        {"expected": g["expected"],
                         "candidates": g.get("candidates", [])[:2],
                         "priority": g.get("priority")}
                        for g in gaps[:5]
                    ]
                # Systems
                systems = kg.list_systems()
                if systems:
                    state["knowledge_graph"]["systems"] = [
                        {"name": s["name"],
                         "members": len(s.get("members", [])),
                         "coverage_pct": s.get("coverage_pct", 0)}
                        for s in systems[:8]
                    ]
        except Exception:
            pass

        # 7. Narrative — if available, return as plain text instead of JSON
        try:
            bb = self._bb_store()
            if bb:
                narratives = bb.list(category="narrative", limit=1,
                                     include_resolved=True)
                if narratives:
                    narrative_text = narratives[0].get("content", "")
                    if narrative_text and len(narrative_text) > 50:
                        # Prepend a compact JSON header so the LLM has machine-readable data too
                        import json as _json
                        header = _json.dumps({
                            "binary": state.get("binary", {}),
                            "coverage": state.get("coverage", {}),
                            "engine": state.get("engine", {}),
                            "knowledge_graph": state.get("knowledge_graph", {}),
                        }, separators=(",", ":"))
                        full_text = f"<!-- state:{header} -->\n\n{narrative_text}"
                        return {"uri": "", "mimeType": "text/plain", "text": full_text}
        except Exception:
            pass

        # Actionable guidance based on current state
        actions = []
        bb_state = state.get("blackboard", {})
        cov = state.get("coverage", {})
        eng = state.get("engine", {})
        binary = state.get("binary", {})

        if binary.get("is_firmware"):
            actions.append("firmware_view(action='triage_snapshot')")

        if eng.get("pending_proposals", 0) > 0:
            actions.append(f"blackboard(action='list', category='proposal') — {eng['pending_proposals']} pending")

        next_targets = bb_state.get("next_targets", [])
        if next_targets:
            top = next_targets[0]
            top_addr = top.get("addr", "")
            top_title = top.get("title", top_addr)[:50]
            actions.append(f"code(action='smart_decompile', addrs='{top_addr}') — {top_title}")

        vulns = bb_state.get("vulns", [])
        if vulns:
            v_addr = vulns[0].get("addr", "")
            actions.append(f"llm_helpers(action='dangerous_pattern_explainer', addr='{v_addr}')")

        pct = cov.get("pct_named", 100)
        total = cov.get("total_functions", 0)
        if total > 20 and pct < 40:
            actions.append(f"blackboard(action='frontier', limit=10) — {pct}% named, {total} functions")

        if not actions:
            actions.append("idb(action='summary')")
            actions.append("data(action='imports')")

        state["_next_actions"] = actions

        return _make_json_content(state)

    def _bb_store(self):
        """Load BlackboardStore without IDA deps."""
        try:
            import importlib.util
            import os as _os
            import sys as _sys
            import types as _types
            path = _os.path.join(
                _os.path.dirname(_os.path.abspath(__file__)),
                "..", "..", "ida_mcp", "tools", "blackboard.py"
            )
            spec = importlib.util.spec_from_file_location("_res_bb2", _os.path.abspath(path))
            mod = importlib.util.module_from_spec(spec)
            mod.__dict__.update({"tool": lambda f: f, "idaread": lambda f: f,
                                  "idawrite": lambda f: f, "IDAError": Exception})
            _stubs = ["idaapi","idc","idautils","ida_funcs","ida_bytes","ida_segment",
                      "ida_name","ida_typeinf","ida_nalt","ida_hexrays","ida_frame",
                      "ida_struct","ida_lines"]
            _saved = {m: _sys.modules.get(m) for m in _stubs}
            for m in _stubs:
                if m not in _sys.modules:
                    _sys.modules[m] = _types.ModuleType(m)
            if not hasattr(_sys.modules["idaapi"], "BADADDR"):
                _sys.modules["idaapi"].BADADDR = 0xFFFFFFFFFFFFFFFF
            try:
                spec.loader.exec_module(mod)
            finally:
                for m, orig in _saved.items():
                    if orig is None: _sys.modules.pop(m, None)
                    else: _sys.modules[m] = orig
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

    def _read_knowledge(self, parts: List[str]) -> Dict:
        """
        ida://knowledge              — full KG summary
        ida://knowledge/systems      — all systems
        ida://knowledge/structs      — all inferred structs
        ida://knowledge/gaps         — open gaps
        ida://knowledge/attack_surface — attack surface
        ida://knowledge/peripherals  — peripheral map
        ida://knowledge/state_machines — state machines
        """
        if not self.bb_path:
            return _make_json_content({"error": "No blackboard path available"})
        try:
            import importlib.util as _ilu
            import os as _os
            # resources.py is in host/server/; knowledge_graph.py is in host/stores/.
            _kg_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                                     "..", "stores", "knowledge_graph.py")
            _spec = _ilu.spec_from_file_location("_res_kg", _kg_path)
            _kgmod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_kgmod)
            kg = _kgmod.KnowledgeGraph(self.bb_path)
        except Exception as e:
            return _make_json_content({"error": f"KnowledgeGraph unavailable: {e}"})

        sub = parts[1] if len(parts) > 1 else ""

        if not sub:
            return _make_json_content({
                "summary": kg.summary(),
                "systems": kg.list_systems()[:5],
                "gaps": kg.list_gaps(resolved=False)[:5],
                "attack_surface": kg.list_attack_surface()[:5],
                "note": "Use ida://knowledge/systems, /gaps, /structs, /attack_surface, /peripherals, /state_machines for full lists.",
            })
        if sub == "systems":
            return _make_json_content({"systems": kg.list_systems()})
        if sub == "structs":
            return _make_json_content({"structs": kg.list_structs()})
        if sub == "gaps":
            open_gaps = kg.list_gaps(resolved=False)
            filled = kg.list_gaps(resolved=True)
            return _make_json_content({
                "open": open_gaps,
                "filled": filled,
                "note": "Open gaps are expected capabilities not yet found. Fill them to increase coverage.",
            })
        if sub == "attack_surface":
            return _make_json_content({"attack_surface": kg.list_attack_surface()})
        if sub == "peripherals":
            return _make_json_content({"peripherals": kg.list_peripherals()})
        if sub == "state_machines":
            return _make_json_content({"state_machines": kg.list_state_machines()})
        return _make_json_content({"error": f"Unknown knowledge sub-resource: {sub}"})

    # ------------------------------------------------------------------
    # Usage intelligence
    # ------------------------------------------------------------------

    def _read_usage(self, parts: List[str]) -> Dict:
        """
        ida://usage                    — global report (active sessions, current-session drift)
        ida://usage/session/{sid}      — per-session drift report
        """
        if not self.usage_intel:
            return _make_json_content({
                "error": "Usage intelligence not available",
                "note": "Start a session to activate the usage observer.",
            })
        sub = parts[1] if len(parts) > 1 else ""
        if sub == "session" and len(parts) > 2:
            sid = parts[2]
            return _make_json_content(self.usage_intel.session_report(sid))
        # Global report
        report = self.usage_intel.global_report()
        # Add current session drift if available
        if self.session_mgr:
            active = getattr(self.session_mgr, "active_session_id", None)
            if active:
                report["current_session"] = self.usage_intel.session_report(active)
        return _make_json_content(report)

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
        result = self._exec("agent", action="cfg_encode", addr=addr)
        return _make_json_content(result)

    def _read_function_similar(self, addr: str) -> Dict:
        result = self._exec("agent", action="cfg_similar", addr=addr, top_k=10)
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
        if is_error_result(result):
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
        if is_error_result(result):
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
            import importlib.util
            import os as _os
            bb_path = _os.path.join(
                _os.path.dirname(_os.path.abspath(__file__)),
                "..", "..", "ida_mcp", "tools", "blackboard.py"
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

        if sub == "frontier":
            # Ranked unvisited functions — read this when choosing what to analyze next
            try:
                from ..analysis.frontier import FrontierEngine
                idb_path = self.bb_path.replace(".blackboard.db", "") if self.bb_path else ""
                emb_db = idb_path + ".embeddings.db" if idb_path else ""
                fe = FrontierEngine(emb_db, self.bb_path or store.db_path)
                n = fe.refresh()
                if n < 3:
                    return _make_json_content({
                        "frontier": [],
                        "note": "Not enough indexed embeddings. Decompile some functions first, then re-read.",
                    })
                results = fe.frontier(limit=20)
                coverage = fe.coverage()
                lines = [
                    f"{r['addr']}  {r['name']}  score={r['score']:.3f}"
                    + (f"  near='{r['nearest_label_title'][:30]}'" if r.get("nearest_label_title") else "")
                    for r in results
                ]
                return _make_json_content({
                    "frontier": "\n".join(lines),
                    "items": results,
                    "count": len(results),
                    "coverage_pct": coverage["coverage_pct"],
                    "analyzed": coverage["analyzed"],
                    "unvisited": coverage["unvisited"],
                    "note": (
                        f"Coverage: {coverage['coverage_pct']}% ({coverage['analyzed']}/{coverage['total_indexed']} functions). "
                        "NEXT ACTION: code(action='smart_decompile', addrs='<top addr>') on the first result."
                    ),
                })
            except Exception as e:
                return _make_json_content({"error": str(e), "note": "Frontier requires indexed embeddings."})

        if sub == "coverage":
            try:
                from ..analysis.frontier import FrontierEngine
                idb_path = self.bb_path.replace(".blackboard.db", "") if self.bb_path else ""
                emb_db = idb_path + ".embeddings.db" if idb_path else ""
                fe = FrontierEngine(emb_db, self.bb_path or store.db_path)
                n = fe.refresh()
                if n < 1:
                    return _make_json_content({"coverage_pct": 0, "note": "No embeddings indexed yet."})
                cov = fe.coverage()
                cov["note"] = (
                    f"You have analyzed {cov['analyzed']}/{cov['total_indexed']} functions ({cov['coverage_pct']}%). "
                    f"Read ida://blackboard/frontier to get the {cov['unvisited']} unvisited functions ranked by priority."
                )
                return _make_json_content(cov)
            except Exception as e:
                return _make_json_content({"error": str(e)})

        # Generic category
        entries = store.list(category=sub, limit=100, include_resolved=False)
        return _make_json_content({"category": sub, "entries": entries, "count": len(entries)})

    def _read_taint(self) -> Dict:
        """ida://taint — full taint report (source→sink paths). Read after finding network/file input."""
        result = self._exec("taint", action="report", max_depth=4, max_paths=30)
        if isinstance(result, dict):
            result.setdefault("note", (
                "Taint report: all source→sink paths in the binary. "
                "For each finding, call llm_helpers(action='dangerous_pattern_explainer', addr='<sink_addr>') "
                "to get full exploitation analysis."
            ))
        return _make_json_content(result)
