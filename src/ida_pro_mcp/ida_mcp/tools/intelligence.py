"""Intelligence tool — embedding-based function classification, indexing,
similarity search, and evidence-card production.

Extracted from `agent.py` in the dedup pass (commit series: shim removal,
comment_mgr merge, firmware_bootstrap fold, **intelligence
extraction**). The 14 actions previously hung off `agent` now live here
because they have a distinct operational identity (embedder/classifier
lifecycle) and
dominated ~400 LOC of the agent dispatcher without sharing any of its
neighbor actions.

Payload shapes are preserved verbatim from the old `agent.*` actions
so any existing host-side call sites and CLIs continue to work. The
CLI shortcut `ida-pro-mcp-cli intelligence status` continues to call
`intelligence_status` as the action name; the tool name is now
`intelligence` rather than `agent`.
"""

import hashlib
import json
import os
import time

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import contextlib
import re
from typing import Any

# Known crypto constant values — imported from central registry

try:
    from ida_pro_mcp.host.intelligence.embeddings import build_decomp_document as _build_decomp_document
except ImportError:
    from host.intelligence.embeddings import build_decomp_document as _build_decomp_document  # type: ignore[import-not-found]

try:
    from .code_helpers import _build_function_structure_summary
except ImportError:
    from code_helpers import _build_function_structure_summary  # type: ignore[import-not-found]

def _parse_register_offset(op_str: str) -> Optional[tuple[str, int]]:
    op_str = op_str.lower()
    if '[' not in op_str or ']' not in op_str:
        return None
    inner = op_str.split('[')[1].split(']')[0].strip()
    tokens = re.split(r'(\+|\-)', inner)
    base_reg = None
    offset = 0
    current_sign = 1

    valid_regs = {'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                  'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                  'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'}

    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue
        if tok == '+':
            current_sign = 1
            continue
        if tok == '-':
            current_sign = -1
            continue

        if tok in valid_regs:
            if base_reg is None:
                base_reg = tok
        else:
            val = 0
            if tok.endswith('h'):
                with contextlib.suppress(ValueError):
                    val = int(tok[:-1], 16)
            elif tok.startswith('0x'):
                with contextlib.suppress(ValueError):
                    val = int(tok, 16)
            else:
                try:
                    val = int(tok, 10)
                except ValueError:
                    with contextlib.suppress(ValueError):
                        val = int(tok, 16)
            if val != 0:
                offset += current_sign * val

    if base_reg:
        return base_reg, offset
    return None

def _build_fast_signature(fea: int, func=None) -> str:
    """Build a fast signature string from disassembly + metadata (no decompile).
    Used by index_fast and index_range for fast embedding indexing."""
    if func is None:
        func = idaapi.get_func(fea)
    if not func:
        return ida_funcs.get_func_name(fea) or hex(fea)
    name = ida_funcs.get_func_name(fea) or hex(fea)
    parts = [name]
    # Keep the fast-index document deliberately small.  Embedding cost is
    # proportional to tokens, while name, APIs, string references, and a
    # short instruction sample carry the useful retrieval signal.  Full
    # decompilations remain available through index_batch.
    # API calls
    apis = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref in idautils.CodeRefsFrom(head, 0):
            ref_name = idc.get_name(ref) or ""
            if ref_name:
                apis.add(ref_name)
        if len(apis) > 12:
            break
    if apis:
        parts.append("apis:" + ",".join(sorted(apis)[:12]))
    # String refs
    str_refs = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref in idautils.DataRefsFrom(head):
            s = idc.get_strlit_contents(ref, -1, 0)
            if s:
                try:
                    s = s.decode("utf-8", errors="replace")[:48]
                    str_refs.add(s)
                except Exception:
                    pass
        if len(str_refs) > 4:
            break
    if str_refs:
        parts.append("strings:" + ",".join(sorted(str_refs)[:4]))
    _tag_remove = getattr(idc, "tag_remove", None)
    # A few instructions distinguish otherwise similar wrappers without
    # turning index_fast into a decompiler-sized embedding request.
    insns = []
    for head in idautils.Heads(func.start_ea, min(func.start_ea + 256, func.end_ea)):
        dis = idc.generate_disasm_line(head, 0)
        if dis:
            insns.append(_tag_remove(dis) if _tag_remove else dis)
        if len(insns) >= 6:
            break
    if insns:
        parts.append("code:" + "; ".join(i[:56] for i in insns))
    # Fast mode must remain Hex-Rays-free, but a compact CFG + call-target
    # summary carries control-flow semantics that instruction samples lose.
    try:
        structure = _build_function_structure_summary(func, max_items=8)
        if structure.get("evidence"):
            parts.append(str(structure["evidence"])[:360])
    except Exception:
        pass
    return " | ".join(parts)[:768]

def _build_full_index_document(fea: int, name: str, pseudocode: str, func, embedder, cfunc=None) -> str:
    """Combine Hex-Rays pseudocode with compact IDA xref evidence."""
    max_chars = int(getattr(embedder, "decomp_document_chars", 1152) or 1152)
    document = _build_decomp_document(name, pseudocode, max_chars=max_chars)
    # A short function already retains its complete decompilation, including
    # visible calls and literals. Extra xref text only increases CPU inference
    # cost. For oversized functions it replaces sampled code at a fixed size
    # and can restore evidence omitted by the sampler.
    try:
        structure_evidence = str(
            _build_function_structure_summary(func, cfunc, max_items=8).get("evidence") or ""
        )[:420]
    except Exception:
        structure_evidence = ""
    appendages = [f"ida_structure: {structure_evidence}"] if structure_evidence else []
    if len(str(pseudocode or "").strip()) <= max_chars:
        if not appendages:
            return document
        suffix = "\n" + "\n".join(appendages)
        return document[: max(0, max_chars - len(suffix))] + suffix
    fast_parts = _build_fast_signature(fea, func).split(" | ")
    document_lower = document.lower()
    novel_parts: list[str] = []
    for part in fast_parts:
        if not part.startswith(("apis:", "strings:")):
            continue
        label, _, payload = part.partition(":")
        novel_values: list[str] = []
        for value in payload.split(","):
            value = value.strip()
            low = value.lower()
            unprefixed = re.sub(r"^(?:__imp_|_imp_|imp_|_+)", "", low)
            if not value or low in document_lower or (len(unprefixed) > 2 and unprefixed in document_lower):
                continue
            novel_values.append(value)
        if novel_values:
            novel_parts.append(f"{label}:{','.join(novel_values)}")
    evidence = " | ".join(novel_parts)[:256]
    if evidence:
        appendages.append(f"ida_refs: {evidence}")
    if not appendages:
        return document
    suffix = "\n" + "\n".join(appendages)
    if len(suffix) >= max_chars:
        return suffix[-max_chars:]
    return document[: max_chars - len(suffix)] + suffix

def _safe_decompile(ea, **kwargs):
    """Wrap ``ida_hexrays.decompile`` with an explicit plugin check.

    Audit §5.2 (decompile): the bare ``ida_hexrays.decompile(...)`` call
    sites in this file did not first call ``init_hexrays_plugin()``. On
    IDA configurations without Hex-Rays loaded (IDA Free, missing
    licence, headless idat without ``-Ohexrays``), ``decompile`` returns
    ``None`` or raises a Hex-Rays-internal error that surfaces as an
    opaque empty ``pseudo`` string downstream. This helper raises
    ``RuntimeError`` instead so the surrounding ``except Exception``
    blocks land in the existing "failed to decompile function" path.
    """
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("hexrays decompiler is not available in this IDA")
    return ida_hexrays.decompile(ea, **kwargs)

def _function_index_metadata(func) -> dict[str, Any]:
    """Collect search filters in one function walk."""
    api_count = 0
    string_count = 0
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref in idautils.CodeRefsFrom(head, 0):
            if idc.get_name(ref):
                api_count += 1
        for ref in idautils.DataRefsFrom(head):
            if idc.get_strlit_contents(ref, -1, 0):
                string_count += 1

    blocks = list(idaapi.FlowChart(func))
    edge_count = 0
    has_loops = False
    for block in blocks:
        successors = list(block.succs())
        edge_count += len(successors)
        if any(succ.start_ea <= block.start_ea for succ in successors):
            has_loops = True
    bb_count = len(blocks)
    cyclomatic = max(1, edge_count - bb_count + 2) if bb_count else 0
    return {
        "func_size": int(func.end_ea - func.start_ea),
        "bb_count": bb_count,
        "has_loops": 1 if has_loops else 0,
        "api_count": min(api_count, 999),
        "string_count": min(string_count, 999),
        "segment": ida_segment.get_segm_name(idaapi.getseg(func.start_ea)) or "",
        "is_thunk": 1 if (func.flags & idaapi.FUNC_THUNK) else 0,
        "cyclomatic": cyclomatic,
    }

def suggest_next_steps(kwargs: dict, default_addr: Any = None) -> dict:
    """Return up to 3 concrete tool calls the LLM should fire next.

    Opt-in replacement for the auto-nudge shotgun that used to inject 3-5
    directives into every decompile response. Only runs when the LLM
    explicitly calls `intelligence(action="suggest", ...)`.

    Args:
        kwargs:        caller-supplied kwargs. Recognized keys:
            tool     — the tool the LLM just called (e.g. "code")
            action   — the action it just took (e.g. "decompile")
            payload  — optional result dict the LLM is reasoning about
            addr     — function address (overrides default_addr)
        default_addr:  the function address from the parent call.

    Returns:
        {"ok": True, "based_on": {...}, "suggestions": [up to 3 entries]} on
        a meaningful context, or {"ok": True, "suggestions": [], "reason": "..."}
        when there is no obvious next step.
    """
    last_tool = str(kwargs.get("tool") or "").strip()
    last_action = str(kwargs.get("action") or "").strip()
    raw_payload = kwargs.get("payload")
    last_payload = raw_payload if isinstance(raw_payload, dict) else {}
    addr_kw = kwargs.get("addr")
    target_addr = (str(addr_kw or default_addr) if (addr_kw or default_addr) else "")

    suggestions: list = []

    # ---- code:decompile / smart_decompile / semantic_decompile ----
    if last_tool == "code" and last_action in (
        "decompile", "smart_decompile", "semantic_decompile"
    ) and target_addr:
        api_calls = last_payload.get("api_calls", []) or []
        if isinstance(api_calls, str):
            api_calls = [api_calls]
        behavior_tags = last_payload.get("behavior_tags", []) or []

        dangerous_sinks = {"strcpy", "strcat", "sprintf", "memcpy", "gets",
                            "system", "popen", "execve"}
        has_dangerous_sink = any(s in dangerous_sinks for s in api_calls)
        has_network = "network" in behavior_tags
        has_process_injection = "process_injection" in behavior_tags

        # One taint suggestion covering the strongest signal we have. The
        # old shotgun version emitted two (one for dangerous API, one for
        # network + dangerous API) for the same payload — the LLM only
        # needs one.
        if has_dangerous_sink or has_process_injection:
            # Pick the best source hint. If we have a network tag, prefer
            # the first network-ish API (recv, recvfrom) since that's the
            # actual taint source. Otherwise fall back to the first
            # dangerous sink so the taint engine has a real entry point.
            source = None
            if has_network:
                for candidate in ("recv", "recvfrom", "InternetReadFile",
                                  "InternetOpenUrl", "ReadFile"):
                    if candidate in api_calls:
                        source = candidate
                        break
            if not source:
                # Prefer the first dangerous sink we recognise; only as a
                # last resort fall back to the first API we saw.
                for s in api_calls:
                    if s in dangerous_sinks:
                        source = s
                        break
            if not source:
                source = api_calls[0] if api_calls else "recv"
            suggestions.append({
                "tool": "taint",
                "arguments": {"action": "trace", "addr": target_addr,
                               "source": source},
                "reason": (
                    "process-injection capability"
                    if has_process_injection
                    else ("network input + dangerous sink"
                          if has_network
                          else "dangerous API in decompiled function")
                ),
            })

        if any("crypto" in str(t).lower() for t in behavior_tags):
            suggestions.append({
                "tool": "crypto_id",
                "arguments": {"action": "identify", "addr": target_addr},
                "reason": "crypto pattern detected",
            })

        if not suggestions:
            suggestions.append({
                "tool": "code",
                "arguments": {"action": "xrefs_to", "addr": target_addr},
                "reason": "see what calls this function",
            })

    # ---- taint:trace / taint:report with vulns ----
    elif last_tool == "taint" and last_action in ("trace", "report"):
        vulns = last_payload.get("findings", last_payload.get("vulns", [])) or []
        if vulns:
            top = vulns[0] if isinstance(vulns[0], dict) else {}
            sink = str(top.get("sink_addr") or (top.get("path", [""])[-1] if isinstance(top.get("path"), list) else "") or target_addr)
            if sink:
                suggestions.append({
                    "tool": "code",
                    "arguments": {"action": "explain", "addr": sink},
                    "reason": "explain the confirmed vulnerability",
                })

    # ---- search:find / nl / behavior with results ----
    elif last_tool == "search" and last_action in ("find", "nl", "behavior"):
        items = last_payload.get("items", []) or []
        if items and isinstance(items[0], dict):
            top_addr = str(items[0].get("addr") or items[0].get("address") or items[0].get("ea") or "")
            if top_addr:
                suggestions.append({
                    "tool": "code",
                    "arguments": {"action": "smart_decompile", "addrs": top_addr},
                    "reason": "decompile the top result",
                })

    # ---- blackboard:frontier ----
    elif last_tool == "blackboard" and last_action == "frontier":
        items = last_payload.get("items", []) or []
        if items and isinstance(items[0], dict):
            top_addr = str(items[0].get("addr", ""))
            if top_addr:
                suggestions.append({
                    "tool": "code",
                    "arguments": {"action": "smart_decompile", "addrs": top_addr},
                    "reason": "highest-priority frontier target",
                })

    # ---- blackboard:coverage with low coverage ----
    elif last_tool == "blackboard" and last_action == "coverage":
        pct = last_payload.get("coverage_pct", 100)
        unvisited = last_payload.get("unvisited", 0)
        if pct < 30 and unvisited > 0:
            suggestions.append({
                "tool": "blackboard",
                "arguments": {"action": "frontier", "limit": 10},
                "reason": "get ranked frontier targets",
            })

    # ---- idb:overview with firmware_detected ----
    elif last_tool == "idb" and last_action == "overview":
        if last_payload.get("firmware_detected"):
            suggestions.append({
                "tool": "firmware_view",
                "arguments": {"action": "triage_snapshot"},
                "reason": "firmware-like binary — start with one-shot orientation",
            })

    # ---- firmware_view:scan_region with regions found ----
    elif last_tool == "firmware_view" and last_action == "scan_region":
        regions = last_payload.get("regions", []) or []
        if regions:
            suggestions.append({
                "tool": "firmware_view",
                "arguments": {"action": "carve_plan"},
                "reason": "plan retyping before applying changes",
            })

    # ---- firmware_view:carve_plan ----
    elif last_tool == "firmware_view" and last_action == "carve_plan":
        suggestions.append({
            "tool": "firmware_view",
            "arguments": {"action": "smart_carve", "apply": False},
            "reason": "dry-run the carve plan first",
        })

    # ---- firmware_view:smart_carve / auto_retype ----
    elif last_tool == "firmware_view" and last_action in ("smart_carve", "auto_retype"):
        if last_payload.get("applied"):
            suggestions.append({
                "tool": "search",
                "arguments": {"action": "func_by_sig", "pattern": "no_callers"},
                "reason": "find interrupt handlers / entry points after retyping",
            })

    # ---- packer:detect with do_not_unpack recommendation ----
    elif last_tool == "packer" and last_action == "detect":
        if last_payload.get("recommendation") == "do_not_unpack":
            suggestions.append({
                "tool": "search",
                "arguments": {"action": "find", "query": "cheat anticheat hook"},
                "reason": "confirm which anti-cheat strings are present",
            })

    if not suggestions:
        return {
            "ok": True,
            "suggestions": [],
            "reason": (
                "no obvious next step from this tool+action. "
                "try ida_session_state or ida_next_target"
            ),
        }

    return {
        "ok": True,
        "based_on": {
            "tool": last_tool or None,
            "action": last_action or None,
            "addr": target_addr or None,
        },
        "suggestions": suggestions[:3],
    }

@tool
@idaread
def intelligence(
    action: Annotated[
        Literal[
            "intelligence_status",
            "embedder_status",
            "reranker_status",
            "anchor_status",
            "refresh_anchors",
            "classify_text",
            "classify_function",
            "index_function",
            "index_batch",
            "index_fast",
            "index_range",
            "similar_functions",
            "semantic_search",
            "blackboard_search",
            "export_index_summary",
            "function_families",
        ],
        "Action: intelligence_status|embedder_status|reranker_status|anchor_status|refresh_anchors|classify_text|classify_function|index_function|index_batch|index_fast|index_range|similar_functions|semantic_search|blackboard_search|export_index_summary|function_families",
    ],
    addr: Annotated[Optional[str], "Address"] = None,
    query: Annotated[Optional[str], "Free-form text or comma-separated list"] = None,
    max_items: Annotated[Optional[int], "Top-K / explicit indexing cap"] = None,
    **kwargs,
) -> dict:
    """Intelligence subsystem: embedder, anchor classifier, function
    embedding index, semantic/blackboard search, evidence card production.

    intelligence_status - Combined embedder + reranker + anchors + indexes.
    embedder_status     - Embedder backend only (alias of the above).
    reranker_status     - Cross-encoder reranker backend only.
    anchor_status       - BehaviorClassifier ANCHORS count/loaded/hash.
    refresh_anchors     - (re)compute anchor embeddings for the given behaviors.
    classify_text       - BehaviorClassifier.classify on a free-form string.
    classify_function   - decompile `addr` then BehaviorClassifier.classify.
    index_function      - decompile + embed + store `addr` into the per-IDB index.
    index_batch         - decompile + embed + store every selected function.
    similar_functions   - k-NN cosine scan over the per-IDB index for `addr`.
    semantic_search     - free-form text → query vector → k-NN over the index.
    blackboard_search   - free-form text → related_by_behavior on the blackboard.
    export_index_summary - return index path/size/metadata .
    function_families   - cluster lookalike functions by embedding cosine; each
                          family gets a centroid summary, a representative member,
                          and per-member deltas. Optionally marks every member
                          examined in one call (mark_examined=true).
    """
    try:
        try:
            from ida_pro_mcp.services import (
                BehaviorClassifier,
                BgeCodeEmbedder,
                FunctionEmbeddingIndex,
            )
        except ImportError:
            try:
                from host.intelligence.core import (  # type: ignore
                    BehaviorClassifier,
                    BgeCodeEmbedder,
                    FunctionEmbeddingIndex,
                )
            except ImportError:
                return make_error(MCPError.IDA_ERROR, "intelligence components unavailable")

        embedder = BgeCodeEmbedder()

        # Embeddings are an opt-in workload.  Do not let ordinary context or
        # behavior enrichment cold-start llama.cpp; only the operations whose
        # public purpose is semantic indexing/retrieval activate it.
        embedding_actions = {
            "refresh_anchors",
            "classify_text",
            "classify_function",
            "index_function",
            "index_batch",
            "index_fast",
            "index_range",
            "similar_functions",
            "semantic_search",
            "blackboard_search",
        }
        if action in embedding_actions and not embedder.ensure_ready():
            return make_error(
                MCPError.IDA_ERROR,
                "Embedding backend unavailable; semantic operation was not started.",
                hint="Configure an embedding model and llama-server, then retry.",
            )

        def _classifier():
            # Indexing and semantic search do not use behavior anchors. Starting
            # their 22 background embeddings here competes with the function
            # batch on CPU and used to dominate cold indexing time.
            return BehaviorClassifier.instance(embedder)

        def _index_for_current_idb():
            # Audit §5.2 (idb path): previously this returned
            # FunctionEmbeddingIndex(".embeddings.db", ...) when the IDB
            # path was empty (no open database, headless probe). That
            # writes the per-binary embedding index to CWD and silently
            # cross-pollutes any other session that lands in the same
            # directory. Fail loudly instead — `intelligence_status`
            # already wraps this call in try/except so its index-count
            # field gracefully shows zero; explicit indexing actions
            # (index_function / index_batch / similar_functions /
            # semantic_search / export_index_summary / evidence_card)
            # surface the error to the caller via handle_error().
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ""
            if not idb_path:
                raise RuntimeError(
                    "no active IDB path; embedding index requires an open database"
                )
            db_path = idb_path + ".embeddings.db"
            return FunctionEmbeddingIndex(db_path, embedder), db_path

        def _persist_embedder_state(idx, action_name: str, thresholds: dict | None = None):
            return {"persisted": False, "embedding_state_id": ""}

        if action in ("intelligence_status", "embedder_status", "reranker_status"):
            classifier = _classifier()
            est = embedder.status(probe=bool(kwargs.get("probe", False)), deep_hash=bool(kwargs.get("deep_hash", False)))
            try:
                from ida_pro_mcp.host.intelligence.rerank import Reranker
                rstatus = Reranker().status(probe=bool(kwargs.get("probe", False)))
            except Exception:
                rstatus = {"backend": "local", "enabled": False, "profile": None, "model_exists": False, "ready": False}
            if action == "reranker_status":
                return {"ok": True, "reranker": rstatus}
            loaded = len(getattr(classifier, "_anchor_embs", {}) or {})
            total = len(getattr(classifier, "ANCHORS", {}) or {})
            idx_count = 0
            active_indexes = 0
            try:
                idx, idx_path = _index_for_current_idb()
                idx_count = int(idx.size)
                active_indexes = 1 if idx_path else 0
            except Exception:
                pass
            try:
                if idx_count > 0:
                    _persist_embedder_state(idx, "intelligence_status")
            except Exception:
                pass
            return {
                "ok": True,
                "embedder": est,
                "reranker": rstatus,
                "anchors": {
                    "count": total,
                    "loaded": loaded,
                    "anchor_set_hash": hashlib.sha256(
                        json.dumps(classifier.ANCHORS, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    ).hexdigest(),
                },
                "indexes": {
                    "active_binaries": active_indexes,
                    "functions_indexed": idx_count,
                },
            }

        if action == "anchor_status":
            classifier = _classifier()
            loaded = len(getattr(classifier, "_anchor_embs", {}) or {})
            total = len(getattr(classifier, "ANCHORS", {}) or {})
            return {
                "ok": True,
                "count": total,
                "loaded": loaded,
                "anchor_set_hash": hashlib.sha256(
                    json.dumps(classifier.ANCHORS, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
            }

        if action == "refresh_anchors":
            classifier = _classifier()
            behaviors = []
            if query:
                from ida_pro_mcp.services import parse_str_list
                behaviors = parse_str_list(str(query))
            classifier.refresh_anchors(behaviors or None)
            loaded = len(getattr(classifier, "_anchor_embs", {}) or {})
            return {"ok": True, "refreshed": behaviors or "all", "loaded": loaded}

        if action == "classify_text":
            classifier = _classifier()
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for classify_text")
            threshold = float(kwargs.get("threshold", 0.25))
            top_k = int(kwargs.get("top_k", 4))
            block = bool(kwargs.get("block", False))
            rows = classifier.classify(str(query), threshold=threshold, top_k=top_k, block=block)
            return {
                "ok": True,
                "backend": embedder.backend,
                "behaviors": rows,
            }

        if action == "classify_function":
            classifier = _classifier()
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for classify_function")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            try:
                cfunc = _safe_decompile(ea)
                pseudo = str(cfunc) if cfunc else ""
            except Exception:
                pseudo = ""
            if not pseudo:
                return make_error(MCPError.IDA_ERROR, "failed to decompile function")
            threshold = float(kwargs.get("threshold", 0.25))
            top_k = int(kwargs.get("top_k", 4))
            block = bool(kwargs.get("block", False))
            rows = classifier.classify(pseudo, threshold=threshold, top_k=top_k, block=block)
            return {
                "ok": True,
                "addr": hex(ea),
                "name": ida_funcs.get_func_name(ea),
                "backend": embedder.backend,
                "behaviors": rows,
            }

        if action == "index_function":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for index_function")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            try:
                cfunc = _safe_decompile(ea)
                pseudo = str(cfunc) if cfunc else ""
            except Exception:
                pseudo = ""
            if not pseudo:
                return make_error(MCPError.IDA_ERROR, "failed to decompile function")
            idx, db_path = _index_for_current_idb()
            name = ida_funcs.get_func_name(ea) or hex(ea)
            func = idaapi.get_func(ea)
            document = _build_full_index_document(ea, name, pseudo, func, embedder)
            metadata = _function_index_metadata(func) if func else {}
            metadata["index_quality"] = "full"
            metadata["source_chars"] = len(pseudo)
            if not idx.index(hex(ea), name, document, metadata):
                return make_error(
                    MCPError.IDA_ERROR,
                    "Embedding backend unavailable; the function was not indexed.",
                    hint="Configure bge-code-v1 and llama-server, then retry indexing.",
                )
            _persist_embedder_state(idx, "index_function")
            return {
                "ok": True,
                "addr": hex(ea),
                "name": name,
                "index": {
                    "path": db_path,
                    "size": idx.size,
                    "quality_counts": idx.quality_counts(),
                },
            }

        if action in ("index_batch", "index_fast", "index_range"):
            # Shared range-resolution logic for all indexing actions.
            #
            # Range spec (all optional, combine freely):
            #   start / end     — single address range [start, end)
            #   addr + radius   — range [addr-radius, addr+radius)
            #   ranges          — list of {start, end} dicts for multiple areas
            #   min_size / max_size — filter functions by byte size
            #   limit           — max functions to index
            #   query           — only index functions matching name filter
            #
            # Examples:
            #   index everything:                index_fast()
            #   single range:                    index_fast(start="0x401000", end="0x405000")
            #   radius around a function:        index_fast(addr="0x401000", radius=0x1000)
            #   multiple ranges:                 index_fast(ranges=[{"start":"0x401000","end":"0x402000"}, {"start":"0x500000","end":"0x501000"}])
            #   size filter:                     index_fast(min_size=100, max_size=5000)
            #   named functions in a range:      index_fast(query="octvm_*", start="0x400000", end="0x500000")

            # ---- resolve target ranges ----
            ranges = []
            raw_ranges = kwargs.get("ranges")
            if raw_ranges and isinstance(raw_ranges, list):
                for r in raw_ranges:
                    if isinstance(r, dict):
                        r_start = r.get("start") or r.get("addr") or r.get("begin")
                        r_end = r.get("end") or r.get("stop")
                        if r_start and r_end:
                            try:
                                s = int(str(r_start), 0)
                                e = int(str(r_end), 0)
                                if e > s:
                                    ranges.append((s, e))
                            except (ValueError, TypeError):
                                pass
            # single range via start/end
            if not ranges:
                raw_start = kwargs.get("start") or addr or kwargs.get("begin")
                raw_end = kwargs.get("end") or kwargs.get("stop")
                raw_radius = kwargs.get("radius")
                if raw_start and raw_end:
                    try:
                        s = int(str(raw_start), 0)
                        e = int(str(raw_end), 0)
                        if e > s:
                            ranges.append((s, e))
                    except (ValueError, TypeError):
                        pass
                elif raw_start and raw_radius:
                    try:
                        c = int(str(raw_start), 0)
                        r = abs(int(str(raw_radius), 0))
                        try:
                            from ida_pro_mcp.host.intelligence.scope_window import (
                                radius_address_range,
                            )
                        except ImportError:
                            from host.intelligence.scope_window import (  # type: ignore
                                radius_address_range,
                            )
                        ranges.append(radius_address_range(c, r))
                    except (ValueError, TypeError):
                        pass
            # size filters
            min_size = kwargs.get("min_size")
            max_size = kwargs.get("max_size")
            try:
                min_size = int(min_size) if min_size is not None else None
            except (ValueError, TypeError):
                min_size = None
            try:
                max_size = int(max_size) if max_size is not None else None
            except (ValueError, TypeError):
                max_size = None
            # name filter
            name_filter = query or kwargs.get("query")
            name_matcher = compile_smart_pattern(name_filter, case_sensitive=False) if name_filter else None
            # Explicit limits are resumable. Omission means every matching
            # function; unlike the old default, a complete index is not
            # silently capped at 25 entries.
            raw_limit = kwargs.get("index_limit", kwargs.get("limit", max_items))
            try:
                limit = max(0, int(raw_limit)) if raw_limit is not None else 0
            except (ValueError, TypeError):
                limit = 0
            raw_cursor = kwargs.get("start_after") or kwargs.get("cursor")
            try:
                start_after = int(str(raw_cursor), 0) if raw_cursor not in (None, "") else None
            except (ValueError, TypeError):
                return make_error(MCPError.INVALID_ARGS, "cursor must be a hexadecimal address")

            requested_mode = str(kwargs.get("mode") or "").strip().lower()
            use_decompile = requested_mode == "full" or (
                action == "index_batch" and requested_mode != "fast"
            )
            quality = "full" if use_decompile else "fast"
            if raw_limit is None and requested_mode == "full" and action != "index_batch":
                try:
                    available_cpus = len(os.sched_getaffinity(0))
                except (AttributeError, OSError):
                    available_cpus = max(1, os.cpu_count() or 1)
                try:
                    configured_pass_size = int(os.environ.get("IDA_MCP_FULL_INDEX_PASS_SIZE", "0") or 0)
                except (ValueError, TypeError):
                    configured_pass_size = 0
                limit = max(1, min(64, configured_pass_size or min(32, max(8, available_cpus * 2))))
            action_label = action

            idx, db_path = _index_for_current_idb()
            started_at = time.monotonic()
            count = 0
            failures = 0
            skipped = 0
            eligible: list[tuple[int, Any, str]] = []
            for fea in idautils.Functions():
                try:
                    func = idaapi.get_func(fea)
                    if not func:
                        failures += 1
                        continue
                    # Match semantic search: include only functions whose entry EA
                    # lies inside the requested half-open radius/range window.
                    if ranges:
                        from ida_pro_mcp.host.intelligence.scope_window import function_entry_in_ranges
                        in_range = function_entry_in_ranges(fea, ranges)
                        if not in_range:
                            skipped += 1
                            continue
                    # size filter
                    func_size = int(func.end_ea - func.start_ea)
                    if min_size is not None and func_size < min_size:
                        skipped += 1
                        continue
                    if max_size is not None and func_size > max_size:
                        skipped += 1
                        continue
                    # name filter
                    name = ida_funcs.get_func_name(fea) or hex(fea)
                    if name_matcher and not name_matcher(name):
                        skipped += 1
                        continue
                    eligible.append((fea, func, name))
                except Exception:
                    failures += 1

            eligible_count = len(eligible)
            remaining_candidates = [row for row in eligible if start_after is None or row[0] > start_after]
            selected = remaining_candidates[:limit] if limit else remaining_candidates
            has_more = len(selected) < len(remaining_candidates)
            next_cursor = hex(selected[-1][0]) if has_more and selected else None
            retry_required = False
            retry_cursor = None
            retry_remaining = 0

            try:
                env_commit_batch = int(os.environ.get("IDA_MCP_INDEX_COMMIT_BATCH", "0") or 0)
            except (ValueError, TypeError):
                env_commit_batch = 0
            default_commit_batch = 8 if use_decompile else 64
            commit_batch = max(1, min(128, env_commit_batch or default_commit_batch))
            max_document_chars = int(getattr(embedder, "decomp_document_chars", 1152) or 1152)
            decompile_seconds = 0.0
            decompile_failures = 0
            embed_seconds = 0.0
            pseudocode_chars = 0
            document_chars = 0
            attempted = 0

            for offset in range(0, len(selected), commit_batch):
                pending: list[tuple[str, str, str, dict[str, Any]]] = []
                for fea, func, name in selected[offset : offset + commit_batch]:
                    try:
                        item_quality = quality
                        source_chars = 0
                        if use_decompile:
                            decompile_started = time.monotonic()
                            try:
                                cfunc = _safe_decompile(fea)
                            except Exception:
                                cfunc = None
                            pseudo = str(cfunc) if cfunc else ""
                            decompile_seconds += time.monotonic() - decompile_started
                            if pseudo:
                                source_chars = len(pseudo)
                                pseudocode_chars += source_chars
                                text = _build_full_index_document(fea, name, pseudo, func, embedder, cfunc)
                            else:
                                # Some thunks/library stubs are not Hex-Rays
                                # decompilable. Keep complete search coverage
                                # with an explicit, lower-quality fallback.
                                decompile_failures += 1
                                item_quality = "fast_fallback"
                                text = _build_fast_signature(fea, func)
                                source_chars = len(text)
                        else:
                            text = _build_fast_signature(fea, func)
                            source_chars = len(text)
                        if not text:
                            failures += 1
                            continue
                        md = _function_index_metadata(func)
                        md["index_quality"] = item_quality
                        md["source_chars"] = source_chars
                        document_chars += len(text)
                        pending.append((hex(fea), name, text, md))
                    except Exception:
                        failures += 1
                if not pending:
                    continue
                attempted += len(pending)
                embed_started = time.monotonic()
                batch_result = idx.index_many(pending)
                embed_seconds += time.monotonic() - embed_started
                count += int(batch_result["indexed"])
                batch_failed = int(batch_result["failed"])
                failures += batch_failed
                if batch_failed:
                    # A timed-out llama-server cannot reliably cancel its
                    # in-flight request.  The embedder recycles it, so stop
                    # this IDA call immediately and resume from before this
                    # batch.  Advancing past it would falsely mark a full
                    # decompilation index complete while silently losing
                    # functions.
                    retry_required = True
                    resume_after = batch_result.get("resume_after_ea")
                    retry_cursor = str(resume_after) if resume_after else (
                        hex(selected[offset - 1][0]) if offset else
                        (hex(start_after) if start_after is not None else None)
                    )
                    resume_index = offset
                    if resume_after:
                        for local_index, row in enumerate(selected[offset : offset + len(pending)]):
                            if hex(row[0]) == str(resume_after):
                                resume_index = offset + local_index + 1
                                break
                    retry_remaining = len(selected) - resume_index
                    break
            if count == 0 and not retry_required:
                return make_error(
                    MCPError.IDA_ERROR,
                    "No embeddings were created; semantic search is unavailable.",
                    hint="Check embedder_status, then retry indexing after the returned cursor.",
                    details={
                        "failed": failures,
                        "skipped": skipped,
                        "index_path": db_path,
                        "retry_required": retry_required,
                        "next_cursor": retry_cursor,
                    },
                )
            # count == 0 AND retry_required: the first batch of this pass
            # failed entirely, but earlier passes may have already indexed
            # functions (e.g. 30/40 done). Report the retry cursor so the
            # background orchestrator resumes from before the failed batch
            # instead of treating a partial index as a total failure.
            _persist_embedder_state(idx, action_label)
            quality_counts = idx.quality_counts()
            if use_decompile:
                quality_coverage = int(quality_counts.get("full", 0)) + int(
                    quality_counts.get("fast_fallback", 0)
                )
            else:
                quality_coverage = sum(int(value) for value in quality_counts.values())
            return {
                "ok": True,
                "indexed": count,
                "attempted": attempted,
                "failed": failures,
                "decompile_failed": decompile_failures,
                "skipped": skipped,
                "eligible": eligible_count,
                "pass_limit": limit or None,
                "complete": not has_more and not retry_required,
                "fully_indexed": (
                    not has_more and not retry_required and failures == 0
                    and quality_coverage >= eligible_count
                ),
                "remaining": (
                    retry_remaining + max(0, len(remaining_candidates) - len(selected))
                    if retry_required else max(0, len(remaining_candidates) - len(selected))
                ),
                "next_cursor": retry_cursor if retry_required else next_cursor,
                "retry_required": retry_required,
                "ranges_specified": len(ranges),
                "index": {
                    "path": db_path,
                    "size": idx.size,
                    "quality_counts": quality_counts,
                    "requested_quality_coverage": quality_coverage,
                },
                "mode": "decompile" if use_decompile else "fast",
                "quality": quality,
                "timing": {
                    "total_seconds": round(time.monotonic() - started_at, 3),
                    "decompile_seconds": round(decompile_seconds, 3),
                    "embedding_seconds": round(embed_seconds, 3),
                },
                "input": {
                    "pseudocode_chars": pseudocode_chars,
                    "document_chars": document_chars,
                    "max_document_chars": max_document_chars if use_decompile else None,
                },
            }

        if action == "similar_functions":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for similar_functions")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            threshold = float(kwargs.get("threshold", 0.55))
            top_k = max(1, int(kwargs.get("top_k", max_items or 25)))
            try:
                cfunc = _safe_decompile(ea)
                pseudo = str(cfunc) if cfunc else ""
            except Exception:
                pseudo = ""
            if not pseudo:
                return make_error(MCPError.IDA_ERROR, "failed to decompile function")
            idx, db_path = _index_for_current_idb()
            if idx.size == 0:
                return make_error(
                    MCPError.NO_RESULTS,
                    "No functions indexed yet. Index your functions to enable semantic search.",
                    hint="Index your functions first:\n  index_fast:  seconds, disassembly-based (good for quick triage)\n  index_batch: minutes, decompile-based (best quality embeddings)",
                )
            qname = ida_funcs.get_func_name(ea) or hex(ea)
            func = idaapi.get_func(ea)
            document = _build_full_index_document(ea, qname, pseudo, func, embedder)
            metadata = _function_index_metadata(func) if func else {}
            metadata["index_quality"] = "full"
            metadata["source_chars"] = len(pseudo)
            idx.index_async(hex(ea), qname, document, metadata)
            similar = idx.similar(document, top_k=top_k, exclude_ea=hex(ea), threshold=threshold)
            _persist_embedder_state(
                idx,
                "similar_functions",
                thresholds={"similarity_threshold": float(threshold)},
            )
            return {
                "ok": True,
                "query_addr": hex(ea),
                "query_name": qname,
                "similar": similar,
                "index": {"path": db_path, "size": idx.size},
            }

        if action == "semantic_search":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for semantic_search")
            top_k = max(1, int(kwargs.get("top_k", max_items or 25)))
            threshold = float(kwargs.get("threshold", 0.0))
            idx, db_path = _index_for_current_idb()
            if idx.size == 0:
                return make_error(
                    MCPError.NO_RESULTS,
                    "No functions indexed yet. Index your functions to enable semantic search.",
                    hint="Index your functions first:\n  index_fast:  seconds, disassembly-based (good for quick triage)\n  index_batch: minutes, decompile-based (best quality embeddings)",
                )
            rows = idx.search(str(query), top_k=top_k, threshold=threshold)
            _persist_embedder_state(
                idx,
                "semantic_search",
                thresholds={"semantic_threshold": float(threshold)},
            )
            return {
                "ok": True,
                "query": str(query),
                "backend": embedder.backend,
                "search_strategy": "hybrid_function_index",
                "matches": rows,
                "index": {"path": db_path, "size": idx.size},
            }

        if action == "blackboard_search":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for blackboard_search")
            try:
                from ida_pro_mcp.ida_mcp.tools.blackboard import blackboard as blackboard_tool
            except Exception:
                return make_error(MCPError.IDA_ERROR, "blackboard tool unavailable")
            top_k = max(1, int(kwargs.get("top_k", max_items or 25)))
            threshold = float(kwargs.get("threshold", 0.0))
            try:
                res = blackboard_tool(
                    action="related_by_behavior",
                    query=str(query),
                    top_k=top_k,
                    threshold=threshold,
                    include_resolved=bool(kwargs.get("include_resolved", False)),
                )
            except Exception as exc:
                return make_error(MCPError.IDA_ERROR, f"blackboard_search failed: {exc}")
            return {
                "ok": True,
                "query": str(query),
                "backend": embedder.backend,
                "blackboard": res,
            }

        if action == "export_index_summary":
            idx, db_path = _index_for_current_idb()
            meta = {}
            try:
                meta = idx.metadata()
            except Exception:
                meta = {}
            _persist_embedder_state(idx, "export_index_summary")
            return {
                "ok": True,
                "index": {
                    "path": db_path,
                    "size": idx.size,
                    "metadata": meta,
                },
            }

        if action == "function_families":
            try:
                from ida_pro_mcp.host.intelligence.families import compute_function_families
            except Exception:
                return make_error(MCPError.IDA_ERROR, "function families module unavailable")
            idx, db_path = _index_for_current_idb()
            if idx.size == 0:
                return make_error(
                    MCPError.NO_RESULTS,
                    "No functions indexed yet. Index your functions to find families.",
                    hint="Index your functions first:\n  index_fast:  seconds, disassembly-based (good for quick triage)\n  index_batch: minutes, decompile-based (best quality embeddings)",
                )
            address_ranges = None
            if kwargs.get("start") or kwargs.get("end"):
                try:
                    from ida_pro_mcp.ida_mcp.tools._common import validate_range
                    _s, _e, _err = validate_range(
                        kwargs.get("start"), kwargs.get("end")
                    )
                    if _err:
                        return _err
                    address_ranges = [(_s, _e)]
                except Exception:
                    address_ranges = None
            if addr and not address_ranges:
                try:
                    from ida_pro_mcp.host.intelligence.scope_window import radius_address_range
                    radius = int(kwargs.get("radius", 0x1000))
                    if radius > 0:
                        _center, _cerr = validate_addr(addr, require_func=False)
                        if not _cerr and _center:
                            _rs, _re = radius_address_range(int(_center), radius)
                            address_ranges = [(_rs, _re)]
                except Exception:
                    address_ranges = None

            min_size = max(2, int(kwargs.get("min_size", 2)))
            min_similarity = min(1.0, max(0.0, float(kwargs.get("min_similarity", 0.85))))
            limit = max(1, min(100, int(kwargs.get("limit", max_items or 25))))
            result = compute_function_families(
                idx,
                min_size=min_size,
                min_similarity=min_similarity,
                address_ranges=address_ranges,
                name_filter=str(kwargs.get("name_filter") or kwargs.get("query") or ""),
                limit=limit,
            )
            _persist_embedder_state(
                idx,
                "function_families",
                thresholds={"min_similarity": float(min_similarity), "min_size": float(min_size)},
            )

            # Group mark_examined: record every family member as examined in one
            # call so the agent reads one representative per family, not all N.
            if kwargs.get("mark_examined"):
                try:
                    from blackboard import BlackboardStore  # type: ignore
                    store = BlackboardStore()
                    verdict = str(kwargs.get("verdict") or "boring")
                    marked = 0
                    for family in result.get("families", []):
                        note = family.get("summary", "")
                        for member in family.get("members", []):
                            store.record_examination(
                                addr=str(member.get("ea") or ""),
                                verdict=verdict,
                                note=note,
                                name=str(member.get("name") or ""),
                            )
                            marked += 1
                    result["marked_examined"] = marked
                except Exception as exc:
                    result["mark_examined_error"] = str(exc)

            return {
                "ok": True,
                "backend": embedder.backend,
                **result,
                "index": {"path": db_path, "size": idx.size},
            }

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
