"""Intelligence tool — embedding-based function classification, indexing,
similarity search, and evidence-card production.

Extracted from `agent.py` in the dedup pass (commit series: shim removal,
mbagcn fold, comment_mgr merge, firmware_bootstrap fold, **intelligence
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

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from .string_ops import shannon_entropy as _shannon_entropy
except ImportError:
    try:
        from string_ops import shannon_entropy as _shannon_entropy
    except ImportError:
        from ida_pro_mcp.ida_mcp.tools.string_ops import shannon_entropy as _shannon_entropy

import contextlib
import re
from collections import Counter
from typing import Any

# Known crypto constant values — imported from central registry
from ida_pro_mcp.ida_mcp.support.crypto_registry import CRYPTO_CONSTANT_NAMES as _CRYPTO_CONSTS


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
    # API calls
    apis = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref in idautils.CodeRefsFrom(head, 0):
            ref_name = idc.get_name(ref) or ""
            if ref_name:
                apis.add(ref_name)
        if len(apis) > 20:
            break
    if apis:
        parts.append("apis:" + ",".join(sorted(apis)[:20]))
    # String refs
    str_refs = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref in idautils.DataRefsFrom(head):
            s = idc.get_strlit_contents(ref, -1, 0)
            if s:
                try:
                    s = s.decode("utf-8", errors="replace")[:60]
                    str_refs.add(s)
                except Exception:
                    pass
        if len(str_refs) > 10:
            break
    if str_refs:
        parts.append("strings:" + ",".join(sorted(str_refs)[:10]))
    _tag_remove = getattr(idc, "tag_remove", None)
    # First 15 instructions
    insns = []
    for head in idautils.Heads(func.start_ea, min(func.start_ea + 256, func.end_ea)):
        dis = idc.generate_disasm_line(head, 0)
        if dis:
            insns.append(_tag_remove(dis) if _tag_remove else dis)
        if len(insns) >= 15:
            break
    if insns:
        parts.append("code:" + "; ".join(i[:80] for i in insns))
    return " | ".join(parts)


def _extract_function_attributes(func_ea: int) -> dict[str, Any]:
    """Extract deterministic attributes for a single function using only IDA APIs.

    Avoids Hex-Rays decompilation to maximize performance.
    """
    func = ida_funcs.get_func(func_ea)
    if not func:
        return {}

    start = func.start_ea
    end = func.end_ea
    size = end - start
    name = idc.get_func_name(start) or f"sub_{start:X}"
    seg = idaapi.getseg(start)
    seg_name = ida_segment.get_segm_name(seg) if seg else ""

    # Flags
    flags = func.flags
    is_thunk = 1 if (flags & idaapi.FUNC_THUNK) else 0
    is_library = 1 if (flags & idaapi.FUNC_LIB) else 0

    # Instruction counts
    mnem_counts: Counter = Counter()
    bb_count = 0
    has_loops = 0
    max_loop_depth = 0
    apis: set[str] = set()
    strings: list[tuple[str, int]] = []
    data_refs = 0
    crypto_constants: list[tuple[int, int]] = []  # (value, ea)
    struct_accesses: dict[str, dict[int, list[str]]] = {}

    # Walk basic blocks
    import ida_ua
    flow = idaapi.FlowChart(func)
    block_descriptors = []
    for block in flow:
        bb_count += 1
        inst_count = sum(1 for _ in idautils.Heads(block.start_ea, block.end_ea))
        in_degree = sum(1 for _ in block.preds()) if hasattr(block, "preds") else 0
        out_degree = sum(1 for _ in block.succs()) if hasattr(block, "succs") else 0
        block_descriptors.append(f"{in_degree}:{out_degree}:{inst_count}")

        for ea in idautils.Heads(block.start_ea, block.end_ea):
            mnem = idc.print_insn_mnem(ea)
            if not mnem:
                continue
            mnem_l = mnem.lower()
            mnem_counts[mnem_l] += 1

            # API calls via xrefs
            if mnem_l in ("call", "jmp"):
                for xref in idautils.XrefsFrom(ea, 0):
                    if xref.type in (idaapi.fl_CN, idaapi.fl_CF):
                        tgt_name = idc.get_name(xref.to)
                        if tgt_name:
                            apis.add(tgt_name)

            # String refs via operand xrefs
            for i in range(idaapi.UA_MAXOP):
                op_type = idc.get_operand_type(ea, i)
                if op_type == idc.o_imm:
                    val = idc.get_operand_value(ea, i)
                    s = idc.get_strlit_contents(val)
                    if s:
                        txt = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s)
                        if len(txt) >= 4:
                            strings.append((txt[:256], val))
                    # Check for crypto constants in immediates
                    if val in _CRYPTO_CONSTS:
                        crypto_constants.append((val, ea))

            # Decode instruction to check operands for crypto constants and register offsets
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea) > 0:
                for op in insn.ops:
                    if op.type == ida_ua.o_imm:
                        val = op.value
                        if val in _CRYPTO_CONSTS and (val, ea) not in crypto_constants:
                            crypto_constants.append((val, ea))

                # Process register offset accesses for struct reconstruction
                for i in range(idaapi.UA_MAXOP):
                    op_type = idc.get_operand_type(ea, i)
                    if op_type in (idc.o_displ, idc.o_phrase):
                        op_str = idc.print_operand(ea, i)
                        parsed = _parse_register_offset(op_str)
                        if parsed:
                            base_reg, offset = parsed
                            if base_reg not in ('rsp', 'esp', 'rbp', 'ebp'):
                                dtype = insn.ops[i].dtype
                                dtype_sizes = {0: 1, 1: 2, 2: 4, 7: 8}
                                size = dtype_sizes.get(dtype, 4)
                                type_guesses = {1: "char", 2: "short", 4: "int", 8: "void*"}
                                t_guess = type_guesses.get(size, "int")

                                struct_accesses.setdefault(base_reg, {})
                                struct_accesses[base_reg].setdefault(offset, []).append(t_guess)

            # Data refs
            for xref in idautils.XrefsFrom(ea, 0):
                if xref.iscode == 0:
                    data_refs += 1

    # Check for loops via back-edges in flow chart
    for block in flow:
        loop_depth = 0
        for succ in block.succs():
            if succ.start_ea <= block.start_ea:
                has_loops = 1
                loop_depth += 1
        max_loop_depth = max(max_loop_depth, loop_depth)

    # Cyclomatic complexity: E - N + 2P
    edges = sum(len(list(b.succs())) for b in flow)
    cyclomatic = edges - bb_count + 2

    # Xref counts
    incoming = sum(1 for _ in idautils.XrefsTo(start, 0))
    outgoing = sum(1 for _ in idautils.XrefsFrom(start, 0))

    # Entropy
    func_bytes = ida_bytes.get_bytes(start, min(size, 4096))
    entropy = _shannon_entropy(func_bytes) if func_bytes else 0.0

    # Derived metrics
    total_insns = sum(mnem_counts.values())
    xor_ratio = round(mnem_counts.get("xor", 0) / max(1, total_insns), 4)
    has_crypto_constants = 1 if crypto_constants else 0

    # Hash of CFG
    block_descriptors.sort()
    cfg_desc_str = ",".join(block_descriptors)
    cfg_hash = hashlib.sha256(cfg_desc_str.encode("utf-8")).hexdigest()[:16] if block_descriptors else None

    # Format reconstructed structs
    reconstructed_structs = []
    for reg, offsets in struct_accesses.items():
        fields = []
        for offset in sorted(offsets.keys()):
            guesses = offsets[offset]
            best_type = Counter(guesses).most_common(1)[0][0]
            fields.append({
                "offset": offset,
                "offset_hex": f"0x{offset:x}",
                "type": best_type
            })
        if fields:
            reconstructed_structs.append({
                "base_register": reg,
                "fields": fields
            })

    return {
        "ea": start,
        "name": name,
        "size": size,
        "segment": seg_name,
        "is_thunk": is_thunk,
        "is_library": is_library,
        "bb_count": bb_count,
        "cyclomatic_complexity": max(1, cyclomatic),
        "incoming_xrefs": incoming,
        "outgoing_xrefs": outgoing,
        "entropy": entropy,
        "call_count": mnem_counts.get("call", 0),
        "xor_count": mnem_counts.get("xor", 0),
        "mov_count": mnem_counts.get("mov", 0) + mnem_counts.get("movzx", 0) + mnem_counts.get("movsx", 0),
        "cmp_count": mnem_counts.get("cmp", 0),
        "jmp_count": mnem_counts.get("jmp", 0) + mnem_counts.get("je", 0) + mnem_counts.get("jne", 0) + mnem_counts.get("jz", 0) + mnem_counts.get("jnz", 0),
        "ret_count": mnem_counts.get("ret", 0) + mnem_counts.get("retn", 0),
        "push_count": mnem_counts.get("push", 0),
        "pop_count": mnem_counts.get("pop", 0),
        "lea_count": mnem_counts.get("lea", 0),
        "test_count": mnem_counts.get("test", 0),
        "api_count": len(apis),
        "string_count": len(strings),
        "data_ref_count": data_refs,
        "has_loops": has_loops,
        "max_loop_depth": max_loop_depth,
        "has_crypto_constants": has_crypto_constants,
        "xor_ratio": xor_ratio,
        "apis": sorted(apis),
        "strings": strings,
        "crypto_constants": crypto_constants,
        "cfg_hash": cfg_hash,
        "reconstructed_structs": reconstructed_structs,
    }


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
                "tool": "string_ops",
                "arguments": {"action": "indicators"},
                "reason": "confirm which anti-cheat strings are present",
            })

    if not suggestions:
        return {
            "ok": True,
            "suggestions": [],
            "reason": (
                "no obvious next step from this tool+action. "
                "try idb(action='state') or blackboard(action='frontier')"
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
        ],
        "Action: intelligence_status|embedder_status|anchor_status|refresh_anchors|classify_text|classify_function|index_function|index_batch|index_fast|index_range|similar_functions|semantic_search|blackboard_search|export_index_summary",
    ],
    addr: Annotated[Optional[str], "Address"] = None,
    query: Annotated[Optional[str], "Free-form text or comma-separated list"] = None,
    max_items: Annotated[int, "Top-K / batch cap"] = 25,
    **kwargs,
) -> dict:
    """Intelligence subsystem: embedder, anchor classifier, function
    embedding index, semantic/blackboard search, evidence card production.

    intelligence_status - Combined embedder + anchors + indexes.
    embedder_status     - Embedder backend only (alias of the above).
    anchor_status       - BehaviorClassifier ANCHORS count/loaded/hash.
    refresh_anchors     - (re)compute anchor embeddings for the given behaviors.
    classify_text       - BehaviorClassifier.classify on a free-form string.
    classify_function   - decompile `addr` then BehaviorClassifier.classify.
    index_function      - decompile + embed + store `addr` into the per-IDB index.
    index_batch         - decompile + embed + store every function (capped by max_items).
    similar_functions   - k-NN cosine scan over the per-IDB index for `addr`.
    semantic_search     - free-form text → query vector → k-NN over the index.
    blackboard_search   - free-form text → related_by_behavior on the blackboard.
    export_index_summary - return index path/size/metadata .
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
        classifier = BehaviorClassifier.instance(embedder)

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

        if action in ("intelligence_status", "embedder_status"):
            est = embedder.status(probe=bool(kwargs.get("probe", False)), deep_hash=bool(kwargs.get("deep_hash", False)))
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
            behaviors = []
            if query:
                from ida_pro_mcp.services import parse_str_list
                behaviors = parse_str_list(str(query))
            classifier.refresh_anchors(behaviors or None)
            loaded = len(getattr(classifier, "_anchor_embs", {}) or {})
            return {"ok": True, "refreshed": behaviors or "all", "loaded": loaded}

        if action == "classify_text":
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
            idx.index(hex(ea), name, pseudo)
            _persist_embedder_state(idx, "index_function")
            return {
                "ok": True,
                "addr": hex(ea),
                "name": name,
                "index": {"path": db_path, "size": idx.size},
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
                        ranges.append((c - r, c + r))
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
            # limit
            try:
                limit = max(1, int(kwargs.get("limit", max_items) or 0))
            except (ValueError, TypeError):
                limit = 0  # 0 = unlimited
            # mode
            use_decompile = (action == "index_batch")
            action_label = action

            idx, db_path = _index_for_current_idb()
            count = 0
            failures = 0
            skipped = 0
            for fea in idautils.Functions():
                if limit and count >= limit:
                    break
                try:
                    func = idaapi.get_func(fea)
                    if not func:
                        failures += 1
                        continue
                    # range filter: function must overlap at least one range
                    if ranges:
                        in_range = any(s <= fea < e or s < func.end_ea <= e for s, e in ranges)
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
                    # build signature / pseudocode
                    if use_decompile:
                        cfunc = _safe_decompile(fea)
                        pseudo = str(cfunc) if cfunc else ""
                        if not pseudo:
                            failures += 1
                            continue
                        text = pseudo
                    else:
                        text = _build_fast_signature(fea, func)
                    # Collect structural metadata for filtering
                    flow = idaapi.FlowChart(func)
                    bb_count = sum(1 for _ in flow)
                    # Count API calls and string refs
                    api_count = 0
                    string_count = 0
                    for head in idautils.Heads(func.start_ea, func.end_ea):
                        for ref in idautils.CodeRefsFrom(head, 0):
                            ref_name = idc.get_name(ref) or ""
                            if ref_name:
                                api_count += 1
                        if api_count > 200:
                            break
                    for head in idautils.Heads(func.start_ea, func.end_ea):
                        for ref in idautils.DataRefsFrom(head):
                            s = idc.get_strlit_contents(ref, -1, 0)
                            if s:
                                string_count += 1
                        if string_count > 100:
                            break
                    seg = ida_segment.get_segm_name(idaapi.getseg(fea)) or ""
                    is_thunk = 1 if (func.flags & idaapi.FUNC_THUNK) else 0
                    cyclomatic = max(0, bb_count - 1)
                    md = {
                        "func_size": func_size,
                        "bb_count": bb_count,
                        "has_loops": 0,
                        "api_count": min(api_count, 999),
                        "string_count": min(string_count, 999),
                        "segment": seg,
                        "is_thunk": is_thunk,
                        "cyclomatic": cyclomatic,
                    }
                    idx.index(hex(fea), name, text, metadata=md)
                    count += 1
                except Exception:
                    failures += 1
            _persist_embedder_state(idx, action_label)
            return {
                "ok": True,
                "indexed": count,
                "failed": failures,
                "skipped": skipped,
                "ranges_specified": len(ranges),
                "index": {"path": db_path, "size": idx.size},
                "mode": "decompile" if use_decompile else "fast",
            }

        if action == "similar_functions":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for similar_functions")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            threshold = float(kwargs.get("threshold", 0.55))
            top_k = max(1, int(kwargs.get("top_k", max_items)))
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
            idx.index_async(hex(ea), qname, pseudo)
            similar = idx.similar(pseudo, top_k=top_k, exclude_ea=hex(ea), threshold=threshold)
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
            top_k = max(1, int(kwargs.get("top_k", max_items)))
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
            top_k = max(1, int(kwargs.get("top_k", max_items)))
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

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
