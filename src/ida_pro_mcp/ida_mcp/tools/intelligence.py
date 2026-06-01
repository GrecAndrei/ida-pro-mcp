"""Intelligence tool — embedding-based function classification, indexing,
similarity search, and evidence-card production.

Extracted from `agent.py` in the dedup pass (commit series: shim removal,
mbagcn fold, comment_mgr merge, firmware_bootstrap fold, **intelligence
extraction**). The 14 actions previously hung off `agent` now live here
because they have a distinct operational identity (embedder/classifier
lifecycle, capsule persistence, evidence card construction) and
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

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


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
            "similar_functions",
            "semantic_search",
            "blackboard_search",
            "export_index_summary",
            "evidence_card",
        ],
        "Action: intelligence_status|embedder_status|anchor_status|refresh_anchors|classify_text|classify_function|index_function|index_batch|similar_functions|semantic_search|blackboard_search|export_index_summary|evidence_card",
    ],
    addr: Annotated[Optional[str], "Address"] = None,
    query: Annotated[Optional[str], "Free-form text or comma-separated list"] = None,
    max_items: Annotated[int, "Top-K / batch cap"] = 25,
    **kwargs,
) -> dict:
    """Intelligence subsystem: embedder, anchor classifier, function
    embedding index, semantic/blackboard search, evidence card production.

    intelligence_status - Combined embedder + anchors + indexes + capsule state.
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
    export_index_summary - return index path/size/metadata + persist capsule state.
    evidence_card       - combined claim+evidence card (anchor + similar + capsule).
    """
    try:
        try:
            from ida_pro_mcp.host.intelligence_core import (
                BgeCodeEmbedder,
                BehaviorClassifier,
                FunctionEmbeddingIndex,
            )
        except ImportError:
            try:
                from host.intelligence_core import (  # type: ignore
                    BgeCodeEmbedder,
                    BehaviorClassifier,
                    FunctionEmbeddingIndex,
                )
            except ImportError:
                return make_error(MCPError.IDA_ERROR, "intelligence components unavailable")

        embedder = BgeCodeEmbedder()
        classifier = BehaviorClassifier.instance(embedder)

        def _index_for_current_idb():
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ""
            db_path = idb_path + ".embeddings.db"
            return FunctionEmbeddingIndex(db_path, embedder), db_path

        def _persist_embedder_state(idx, action_name: str, thresholds: dict | None = None):
            capsule_path = str(os.environ.get("IDA_MCP_CAPSULE", "") or "").strip()
            if not capsule_path:
                return {"persisted": False, "capsule_path": "", "embedding_state_id": ""}
            try:
                from ida_pro_mcp.capsule import CapsuleStore

                anchor_hash = hashlib.sha256(
                    json.dumps(classifier.ANCHORS, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                anchor_meta = {
                    "anchor_count": len(classifier.ANCHORS),
                    "anchor_hash_sha256": anchor_hash,
                    "anchor_version": f"sha256:{anchor_hash[:16]}",
                }
                state = idx.capsule_state(
                    anchor_metadata=anchor_meta,
                    thresholds=(thresholds or {}),
                    recent_limit=64,
                )
                state.setdefault("index_metadata", {})["source_action"] = action_name
                with CapsuleStore.open(capsule_path) as cap:
                    if not cap.is_initialized():
                        cap.init(project_name="ida-session", created_by="ida-pro-mcp-intelligence")
                    sid = cap.add_embedding_state(state)
                return {"persisted": True, "capsule_path": capsule_path, "embedding_state_id": sid}
            except Exception:
                return {"persisted": False, "capsule_path": capsule_path, "embedding_state_id": ""}

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
            persisted_state = {"persisted": False, "capsule_path": "", "embedding_state_id": ""}
            try:
                if idx_count > 0:
                    persisted_state = _persist_embedder_state(idx, "intelligence_status")
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
                "capsule_embedding_state": persisted_state,
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
                behaviors = [x.strip() for x in str(query).split(",") if x.strip()]
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
                cfunc = ida_hexrays.decompile(ea)
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
                cfunc = ida_hexrays.decompile(ea)
                pseudo = str(cfunc) if cfunc else ""
            except Exception:
                pseudo = ""
            if not pseudo:
                return make_error(MCPError.IDA_ERROR, "failed to decompile function")
            idx, db_path = _index_for_current_idb()
            name = ida_funcs.get_func_name(ea) or hex(ea)
            idx.index(hex(ea), name, pseudo)
            persisted_state = _persist_embedder_state(idx, "index_function")
            return {
                "ok": True,
                "addr": hex(ea),
                "name": name,
                "index": {"path": db_path, "size": idx.size},
                "capsule_embedding_state": persisted_state,
            }

        if action == "index_batch":
            limit = max(1, int(kwargs.get("limit", max_items)))
            idx, db_path = _index_for_current_idb()
            count = 0
            failures = 0
            for fea in idautils.Functions():
                if count >= limit:
                    break
                try:
                    cfunc = ida_hexrays.decompile(fea)
                    pseudo = str(cfunc) if cfunc else ""
                    if not pseudo:
                        failures += 1
                        continue
                    name = ida_funcs.get_func_name(fea) or hex(fea)
                    idx.index(hex(fea), name, pseudo)
                    count += 1
                except Exception:
                    failures += 1
            persisted_state = _persist_embedder_state(idx, "index_batch")
            return {
                "ok": True,
                "indexed": count,
                "failed": failures,
                "index": {"path": db_path, "size": idx.size},
                "capsule_embedding_state": persisted_state,
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
                cfunc = ida_hexrays.decompile(ea)
                pseudo = str(cfunc) if cfunc else ""
            except Exception:
                pseudo = ""
            if not pseudo:
                return make_error(MCPError.IDA_ERROR, "failed to decompile function")
            idx, db_path = _index_for_current_idb()
            qname = ida_funcs.get_func_name(ea) or hex(ea)
            idx.index_async(hex(ea), qname, pseudo)
            similar = idx.similar(pseudo, top_k=top_k, exclude_ea=hex(ea), threshold=threshold)
            persisted_state = _persist_embedder_state(
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
                "capsule_embedding_state": persisted_state,
            }

        if action == "semantic_search":
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required for semantic_search")
            top_k = max(1, int(kwargs.get("top_k", max_items)))
            threshold = float(kwargs.get("threshold", 0.0))
            idx, db_path = _index_for_current_idb()
            qvec = embedder.embed(str(query))
            rows = idx.similar_vec(qvec, top_k=top_k, threshold=threshold)
            persisted_state = _persist_embedder_state(
                idx,
                "semantic_search",
                thresholds={"semantic_threshold": float(threshold)},
            )
            return {
                "ok": True,
                "query": str(query),
                "backend": embedder.backend,
                "matches": rows,
                "index": {"path": db_path, "size": idx.size},
                "capsule_embedding_state": persisted_state,
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
            persisted_state = _persist_embedder_state(idx, "export_index_summary")
            return {
                "ok": True,
                "index": {
                    "path": db_path,
                    "size": idx.size,
                    "metadata": meta,
                },
                "capsule_embedding_state": persisted_state,
            }

        if action == "evidence_card":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for evidence_card")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            try:
                cfunc = ida_hexrays.decompile(ea)
                pseudo = str(cfunc) if cfunc else ""
            except Exception:
                pseudo = ""
            if not pseudo:
                return make_error(MCPError.IDA_ERROR, "failed to decompile function")

            threshold = float(kwargs.get("threshold", 0.25))
            top_k = int(kwargs.get("top_k", 4))
            behavior_rows = classifier.classify(pseudo, threshold=threshold, top_k=top_k, block=False)
            idx, db_path = _index_for_current_idb()
            qname = ida_funcs.get_func_name(ea) or hex(ea)
            idx.index_async(hex(ea), qname, pseudo)
            similar = idx.similar(pseudo, top_k=max(1, int(kwargs.get("similar_top_k", 3))), exclude_ea=hex(ea), threshold=0.0)

            top_behavior = behavior_rows[0] if behavior_rows else {}
            top_conf = float(top_behavior.get("confidence", 0.0) or 0.0)
            claim_behavior = str(top_behavior.get("behavior") or "unknown_behavior")
            claim = f"Function may implement {claim_behavior.replace('_', ' ')} behavior."
            evidence = []
            if behavior_rows:
                evidence.append(
                    {
                        "type": "behavior_anchor",
                        "value": claim_behavior,
                        "confidence": round(top_conf, 4),
                        "source": "BehaviorClassifier",
                        "explain": top_behavior.get("explain", []),
                    }
                )
            if similar:
                evidence.append(
                    {
                        "type": "similar_function",
                        "addr": similar[0].get("ea"),
                        "name": similar[0].get("name"),
                        "similarity": similar[0].get("similarity"),
                        "source": "FunctionEmbeddingIndex",
                    }
                )
            card = {
                "claim": claim,
                "claim_type": "behavior_triage",
                "confidence": round(top_conf, 4),
                "evidence": evidence,
                "source_refs": [
                    {
                        "backend": "ida",
                        "binary_id": idaapi.get_path(idaapi.PATH_TYPE_IDB) or "",
                        "object_kind": "function",
                        "stable_ref": hex(ea),
                        "name": qname,
                    }
                ],
                "required_followup": {
                    "tool": "code",
                    "action": "callers",
                    "addr": hex(ea),
                },
            }

            persisted = False
            persisted_id = ""
            capsule_path = str(os.environ.get("IDA_MCP_CAPSULE", "") or "").strip()
            if capsule_path:
                try:
                    from ida_pro_mcp.capsule import CapsuleStore

                    with CapsuleStore.open(capsule_path) as cap:
                        if not cap.is_initialized():
                            cap.init(project_name="ida-session", created_by="ida-pro-mcp-intelligence")
                        persisted_id = cap.add_evidence_card(
                            claim=card["claim"],
                            claim_type=card["claim_type"],
                            confidence=card["confidence"],
                            evidence=card["evidence"],
                            source_refs=card["source_refs"],
                            metadata={
                                "addr": hex(ea),
                                "name": qname,
                                "index_path": db_path,
                            },
                        )
                        persisted = True
                except Exception:
                    persisted = False
                    persisted_id = ""

            return {
                "ok": True,
                "addr": hex(ea),
                "name": qname,
                "card": card,
                "persisted": persisted,
                "persisted_id": persisted_id,
            }

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)
