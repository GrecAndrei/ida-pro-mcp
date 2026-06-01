
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import glob
import hashlib
import json
import shutil
import subprocess
import tempfile
import time

try:
    from ...host.casefile_helpers import build_chain_of_custody, build_risk_summary, to_markdown_casefile
except Exception:
    build_chain_of_custody = None  # type: ignore
    build_risk_summary = None  # type: ignore
    to_markdown_casefile = None  # type: ignore


# ============================================================================
# 12. FILES - Database and file operations
# ============================================================================

@tool
@unsafe
@idawrite
def project(
    action: Annotated[Literal[
        "save", "close", "open", "load_binary",
        "list_recent", "get_cwd", "set_cwd", 
        "list_dir", "exists",
        "evidence_graph", "knowledge_merge", "confidence_model", "replay_pipeline",
        "hypothesis_tracker", "temporal_reasoning", "semantic_artifact_diff",
        "ai_governance", "knowledge_debt", "casefile_export"
    ], "Action"],
    path: Annotated[Optional[str], "File path"] = None,
    base_addr: Annotated[Optional[str], "Base address for load_binary"] = None,
    content: Annotated[Optional[str], "Content to write, or mode for open"] = None,
    **kwargs
) -> dict:
    """
    File/DB operations with provenance and collaboration intelligence workflows.
    
    ACTIONS:
    
    open - Open file in new IDA instance (multi-session support!)
        Params: path (REQUIRED), content (optional: "load"|"overwrite"|"-c -B"...)
        Returns: {ok, path, mode, pid, cmd, existing_db, session_file}
        Example: files(action="open", path="C:/samples/malware.exe")
        Example: files(action="open", path="C:/samples/mal.exe", content="overwrite")
        Behavior:
          - Default ("load"): Opens existing .i64/.idb if found, else creates new
          - "overwrite": Forces new database creation (deletes existing)
          - Custom flags: Pass IDA CLI flags like "-c -B -A"
        
    evidence_graph - Build/store evidence-linked findings graph
    knowledge_merge - Merge two session metadata records with conflict analysis
    confidence_model - Score rename/type findings by provenance signal quality
    replay_pipeline - Record/replay deterministic analysis steps and compare drift
    hypothesis_tracker - Track hypotheses with validation lifecycle
    temporal_reasoning - Build timeline view from session and provenance events
    semantic_artifact_diff - Semantic run/session comparison with behavior tags
    ai_governance - Trust-weighted governance checks for AI annotations
    knowledge_debt - Detect analysis debt hotspots and prioritize remediation
    casefile_export - Export chain-of-custody style casefile artifact

    save - Save current database
    close - Close database (in headless: ready for next file)
    load_binary - Load additional binary into current IDB
    list_recent - List recently opened files
    get_cwd/set_cwd - Working directory management
    list_dir - Directory listing
    exists - File system existence checks
    """
    try:
        import os

        def _runtime_root() -> str:
            explicit = os.environ.get("IDA_MCP_CACHE_DIR") or os.environ.get("IDA_MCP_DATA_DIR")
            if explicit:
                return explicit
            home = os.path.expanduser("~")
            if os.name == "nt":
                base = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
            elif sys.platform == "darwin":
                base = os.path.join(home, "Library", "Application Support")
            else:
                base = os.environ.get("XDG_STATE_HOME") or os.path.join(home, ".local", "state")
            return os.path.join(base, "ida-pro-mcp")

        def _session_dir() -> str:
            return os.path.join(_runtime_root(), "sessions")

        def _discover_sessions(limit: int = 200):
            sessions = []
            sdir = _session_dir()
            if not os.path.isdir(sdir):
                return sessions
            pattern = os.path.join(sdir, "SID_*_metadata.json")
            for meta_path in sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)[:limit]:
                try:
                    with open(meta_path, "r", encoding="utf-8", errors="replace") as fh:
                        data = json.load(fh)
                except Exception:
                    data = {}
                base = os.path.basename(meta_path)
                sid_guess = ""
                if "_" in base:
                    parts = base.split("_")
                    if len(parts) >= 2:
                        sid_guess = parts[1]
                sid = str(data.get("session_id") or sid_guess)
                sessions.append(
                    {
                        "session_id": sid,
                        "binary_path": data.get("binary_path"),
                        "idb_path": data.get("idb_path"),
                        "created_at": data.get("created_at"),
                        "updated_at": data.get("updated_at"),
                        "metadata_path": meta_path,
                    }
                )
            return sessions

        def _new_sid(seed: str) -> str:
            digest = hashlib.sha1(f"{seed}:{time.time()}:{os.getpid()}".encode("utf-8", errors="ignore")).hexdigest()
            return digest[:8].upper()

        def _resolve_ida_exe() -> Optional[str]:
            candidates = [
                os.environ.get("IDA_EXE"),
                os.environ.get("IDAT_EXE"),
                shutil.which("idat64"),
                shutil.which("ida64"),
                shutil.which("idat"),
                shutil.which("ida"),
            ]
            for item in candidates:
                if item and os.path.isfile(item):
                    return item
            return None

        def _split_user_flags(raw: Optional[str]) -> list[str]:
            if not raw:
                return []
            text = str(raw).strip()
            if not text:
                return []
            if text in ("load", "overwrite"):
                return []
            if text.startswith("["):
                try:
                    parsed = json.loads(text)
                    if isinstance(parsed, list):
                        return [str(x) for x in parsed if str(x).strip()]
                except Exception:
                    pass
            return [x for x in text.split(" ") if x]

        def _provenance_dir() -> str:
            pdir = os.path.join(_runtime_root(), "provenance")
            os.makedirs(pdir, exist_ok=True)
            return pdir

        def _read_json(path_: str, default):
            if not os.path.exists(path_):
                return default
            try:
                with open(path_, "r", encoding="utf-8", errors="replace") as fh:
                    return json.load(fh)
            except Exception:
                return default

        def _write_json(path_: str, payload):
            with open(path_, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)

        def _now_iso() -> str:
            try:
                from datetime import datetime, timezone

                return datetime.now(timezone.utc).isoformat()
            except Exception:
                return str(time.time())

        def _session_by_id(sid: str):
            sid_u = str(sid or "").strip().upper()
            for item in _discover_sessions(limit=1000):
                if str(item.get("session_id", "")).upper() == sid_u:
                    return item
            return None
        
        if action == "save":
            import ida_loader
            if ida_loader.save_database(path or "", 0):
                return {"ok": True, "path": path or idc.get_idb_path()}
            return make_error(MCPError.IDA_ERROR, "Failed to save database")
        
        elif action == "close":
            # HEADLESS ONLY: Close current database
            try:
                import idapro
                if hasattr(idapro, 'close_database'):
                    idapro.close_database()
                    return {"ok": True, "note": "Database closed."}
            except ImportError:
                pass

            # GUI fallback: attempt close action, then safe process exit fallback.
            for ui_action in ("CloseBase", "Close"):
                try:
                    if ida_kernwin.find_action(ui_action) is not None:
                        triggered = ida_kernwin.process_ui_action(ui_action)
                        return {"ok": True, "closed": bool(triggered), "mode": "gui_action", "action": ui_action}
                except Exception:
                    continue
            try:
                # Graceful fallback that still gives the caller explicit behavior.
                idc.save_database("", 0)
            except Exception:
                pass
            return {
                "ok": True,
                "closed": False,
                "mode": "fallback",
                "note": "Could not close only the database in this runtime; use host session.close for full runtime teardown.",
            }
        
        elif action == "open":
            if not path: return make_error(MCPError.INVALID_ARGS, "path required")
            path, err = validate_path_safe(path)
            if err: return err
            
            if not os.path.exists(path):
                return make_error(MCPError.FILE_NOT_FOUND, f"File not found: {path}")
            
            # HEADLESS: Use internal API
            try:
                import idapro
                if hasattr(idapro, 'open_database'):
                    res = idapro.open_database(path, run_auto_analysis=True)
                    if res == 0: return {"ok": True, "path": path, "mode": "headless"}
                    return make_error(MCPError.IDA_ERROR, f"open_database failed: {res}")
            except ImportError:
                pass

            # GUI/runtime fallback: spawn a separate IDA process for the target path.
            exe = _resolve_ida_exe()
            if not exe:
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    "Could not resolve IDA executable for GUI fallback open",
                    hint="Set IDA_EXE/IDAT_EXE or ensure idat64 is on PATH.",
                )

            mode = (content or "load").strip().lower() if isinstance(content, str) else "load"
            user_flags = _split_user_flags(content if isinstance(content, str) else None)
            cmd = [exe]
            if mode == "overwrite":
                cmd.extend(["-c"])
            cmd.extend(user_flags)
            cmd.append(path)
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                sid = _new_sid(path)
                sdir = _session_dir()
                os.makedirs(sdir, exist_ok=True)
                meta_path = os.path.join(sdir, f"SID_{sid}_metadata.json")
                meta = {
                    "session_id": sid,
                    "binary_path": path,
                    "idb_path": None,
                    "created_at": time.time(),
                    "updated_at": time.time(),
                    "runtime_pid": int(proc.pid),
                    "spawned_external": True,
                    "source": "project.open",
                    "cmd": cmd,
                }
                try:
                    with open(meta_path, "w", encoding="utf-8") as fh:
                        json.dump(meta, fh, indent=2)
                except Exception:
                    meta_path = None
                return {
                    "ok": True,
                    "path": path,
                    "mode": "spawned",
                    "pid": int(proc.pid),
                    "cmd": cmd,
                    "session_id": sid,
                    "session_metadata": meta_path,
                    "note": "Opened in a new IDA process and recorded as an external session entry; host session.create remains the preferred managed workflow.",
                }
            except Exception as e:
                return make_error(MCPError.IDA_ERROR, f"Failed to spawn IDA: {e}", details={"cmd": cmd})
        
        elif action == "load_binary":
            if not path: return make_error(MCPError.INVALID_ARGS, "path required")
            path, err = validate_path_safe(path)
            if err: return err

            ba = 0
            if base_addr:
                ba, err = validate_addr(base_addr)
                if err: return err
            
            import ida_loader
            if ida_loader.load_binary_file(path, None, 0, 0, ba, 0):
                return {"ok": True, "path": path, "base_addr": hex(ba)}
            return make_error(MCPError.IDA_ERROR, "Failed to load binary file")
        
        elif action == "list_recent":
            import ida_diskio
            recent = []
            if hasattr(ida_diskio, "get_ida_recent_file_count"):
                for i in range(ida_diskio.get_ida_recent_file_count()):
                    f = ida_diskio.get_ida_recent_file(i)
                    if f: recent.append(f)
            return {"ok": True, "recent": recent}
        
        elif action == "get_cwd":
            return {"ok": True, "cwd": os.getcwd()}
        
        elif action == "set_cwd":
            if not path: return make_error(MCPError.INVALID_ARGS, "path required")
            path, err = validate_path_safe(path)
            if err: return err
            os.chdir(path)
            return {"ok": True, "cwd": path}
        
        elif action == "list_dir":
            target = path or os.getcwd()
            target, err = validate_path_safe(target)
            if err: return err
            if not os.path.exists(target): return make_error(MCPError.FILE_NOT_FOUND, target)
            entries = []
            for name in os.listdir(target):
                full = os.path.join(target, name)
                entries.append({
                    "name": name,
                    "is_dir": os.path.isdir(full),
                    "size": os.path.getsize(full) if os.path.isfile(full) else 0
                })
            return {"ok": True, "path": target, "entries": entries}
        
        elif action == "exists":
            if not path: return make_error(MCPError.INVALID_ARGS, "path required")
            path, err = validate_path_safe(path)
            if err: return err
            return {"ok": True, "path": path, "exists": os.path.exists(path), "is_file": os.path.isfile(path), "is_dir": os.path.isdir(path)}
        
        elif action == "evidence_graph":
            pdir = _provenance_dir()
            findings_path = os.path.join(pdir, "findings.json")
            findings = _read_json(findings_path, [])
            finding_id = str(kwargs.get("finding_id") or f"F-{int(time.time() * 1000)}")
            evidence_raw = kwargs.get("evidence")
            if evidence_raw is not None:
                evidence_items = []
                if isinstance(evidence_raw, str):
                    try:
                        parsed = json.loads(evidence_raw)
                        if isinstance(parsed, list):
                            evidence_items = parsed
                        elif isinstance(parsed, dict):
                            evidence_items = [parsed]
                    except Exception:
                        evidence_items = [{"kind": "text", "value": evidence_raw}]
                elif isinstance(evidence_raw, dict):
                    evidence_items = [evidence_raw]
                elif isinstance(evidence_raw, list):
                    evidence_items = [x for x in evidence_raw if isinstance(x, dict)]

                findings.append(
                    {
                        "finding_id": finding_id,
                        "title": kwargs.get("title") or kwargs.get("claim") or "untitled_finding",
                        "created_at": _now_iso(),
                        "session_id": kwargs.get("session_id"),
                        "evidence": evidence_items,
                    }
                )
                _write_json(findings_path, findings)

            nodes = []
            edges = []
            for item in findings[-500:]:
                fid = str(item.get("finding_id", ""))
                if not fid:
                    continue
                nodes.append({"id": fid, "type": "finding", "title": item.get("title")})
                for idx, ev in enumerate(item.get("evidence") or []):
                    eid = f"{fid}:e{idx}"
                    nodes.append(
                        {
                            "id": eid,
                            "type": ev.get("kind") or "evidence",
                            "addr": ev.get("addr"),
                            "source": ev.get("source"),
                        }
                    )
                    edges.append({"from": fid, "to": eid, "relation": "supported_by"})

            return {
                "ok": True,
                "finding_count": len(findings),
                "node_count": len(nodes),
                "edge_count": len(edges),
                "nodes": nodes[:500],
                "edges": edges[:1000],
            }

        elif action == "knowledge_merge":
            sid_a = str(kwargs.get("session_a") or kwargs.get("left") or "")
            sid_b = str(kwargs.get("session_b") or kwargs.get("right") or "")
            if not sid_a or not sid_b:
                return make_error(MCPError.INVALID_ARGS, "session_a and session_b required")

            a = _session_by_id(sid_a)
            b = _session_by_id(sid_b)
            if not a or not b:
                return make_error(MCPError.NOT_FOUND, "One or both sessions not found")

            conflicts = []
            for key in ("binary_path", "idb_path"):
                av = a.get(key)
                bv = b.get(key)
                if av and bv and av != bv:
                    conflicts.append({"field": key, "left": av, "right": bv})

            merged = {
                "session_ids": [a.get("session_id"), b.get("session_id")],
                "binary_path": a.get("binary_path") or b.get("binary_path"),
                "idb_path": a.get("idb_path") or b.get("idb_path"),
                "created_at": min(x for x in [a.get("created_at"), b.get("created_at")] if x is not None)
                if (a.get("created_at") is not None or b.get("created_at") is not None)
                else None,
                "updated_at": max(x for x in [a.get("updated_at"), b.get("updated_at")] if x is not None)
                if (a.get("updated_at") is not None or b.get("updated_at") is not None)
                else None,
            }
            return {
                "ok": True,
                "merged": merged,
                "conflicts": conflicts,
                "conflict_count": len(conflicts),
                "confidence": round(1.0 - min(len(conflicts), 3) * 0.25, 2),
            }

        elif action == "confidence_model":
            items = kwargs.get("items")
            if isinstance(items, str):
                try:
                    items = json.loads(items)
                except Exception:
                    items = None
            if not isinstance(items, list):
                items = []

            source_weight = {"manual": 1.0, "ai": 0.65, "inferred": 0.5, "imported": 0.75}
            scored = []
            for row in items[:1000]:
                if not isinstance(row, dict):
                    continue
                source = str(row.get("source") or "inferred").lower()
                corroboration = max(0, int(row.get("corroboration") or 0))
                contradictions = max(0, int(row.get("contradictions") or 0))
                base = source_weight.get(source, 0.5)
                score = max(0.0, min(1.0, base + min(corroboration, 6) * 0.05 - min(contradictions, 6) * 0.1))
                scored.append(
                    {
                        "target": row.get("target"),
                        "kind": row.get("kind") or "symbol",
                        "source": source,
                        "score": round(score, 3),
                    }
                )
            score_vals = sorted(float(x.get("score", 0.0) or 0.0) for x in scored)
            if score_vals:
                q50 = score_vals[len(score_vals) // 2]
                q75 = score_vals[min(len(score_vals) - 1, int(round((len(score_vals) - 1) * 0.75)))]
                high_gate = q75 + max(0.0, q75 - q50)
                low_gate = q50
            else:
                high_gate = 0.8
                low_gate = 0.5
            high = sum(1 for x in scored if float(x.get("score", 0.0) or 0.0) >= high_gate)
            low = sum(1 for x in scored if float(x.get("score", 0.0) or 0.0) < low_gate)
            return {"ok": True, "count": len(scored), "high_confidence": high, "low_confidence": low, "scores": scored[:200]}

        elif action == "replay_pipeline":
            pdir = _provenance_dir()
            replay_path = os.path.join(pdir, "replay_log.json")
            replay = _read_json(replay_path, [])
            mode = str(kwargs.get("mode") or "record").lower()
            if mode == "record":
                step = {
                    "id": f"R-{int(time.time() * 1000)}",
                    "timestamp": _now_iso(),
                    "tool": kwargs.get("tool"),
                    "action_name": kwargs.get("action_name"),
                    "arguments": kwargs.get("arguments"),
                    "result_fingerprint": kwargs.get("result_fingerprint"),
                }
                replay.append(step)
                _write_json(replay_path, replay[-5000:])
                return {"ok": True, "mode": "record", "recorded": True, "step": step, "total_steps": len(replay)}
            if mode == "replay":
                baseline = kwargs.get("baseline_fingerprint")
                current = kwargs.get("current_fingerprint")
                drift = bool(baseline and current and baseline != current)
                return {
                    "ok": True,
                    "mode": "replay",
                    "steps": replay[-200:],
                    "step_count": len(replay),
                    "drift_detected": drift,
                    "baseline_fingerprint": baseline,
                    "current_fingerprint": current,
                }
            return make_error(MCPError.INVALID_ARGS, "mode must be record|replay")

        elif action == "hypothesis_tracker":
            pdir = _provenance_dir()
            hyp_path = os.path.join(pdir, "hypotheses.json")
            hyps = _read_json(hyp_path, [])
            mode = str(kwargs.get("mode") or "upsert").lower()
            if mode == "upsert":
                hid = str(kwargs.get("hypothesis_id") or f"H-{int(time.time() * 1000)}")
                statement = kwargs.get("statement") or kwargs.get("text")
                if not statement:
                    return make_error(MCPError.INVALID_ARGS, "statement required")
                status = str(kwargs.get("status") or "unknown")
                item = {
                    "hypothesis_id": hid,
                    "statement": statement,
                    "status": status,
                    "updated_at": _now_iso(),
                    "evidence": kwargs.get("evidence"),
                }
                replaced = False
                for i, existing in enumerate(hyps):
                    if str(existing.get("hypothesis_id")) == hid:
                        hyps[i] = {**existing, **item}
                        replaced = True
                        break
                if not replaced:
                    item["created_at"] = item["updated_at"]
                    hyps.append(item)
                _write_json(hyp_path, hyps[-2000:])
                return {"ok": True, "mode": "upsert", "item": item, "total": len(hyps)}
            if mode == "validate":
                supported = [h for h in hyps if str(h.get("status")) == "supported"]
                refuted = [h for h in hyps if str(h.get("status")) == "refuted"]
                unknown = [h for h in hyps if str(h.get("status")) not in ("supported", "refuted")]
                return {
                    "ok": True,
                    "mode": "validate",
                    "supported": len(supported),
                    "refuted": len(refuted),
                    "unknown": len(unknown),
                    "items": hyps[-200:],
                }
            return make_error(MCPError.INVALID_ARGS, "mode must be upsert|validate")

        elif action == "temporal_reasoning":
            events = []
            for sess in _discover_sessions(limit=500):
                events.append(
                    {
                        "type": "session",
                        "session_id": sess.get("session_id"),
                        "created_at": sess.get("created_at"),
                        "updated_at": sess.get("updated_at"),
                        "binary_path": sess.get("binary_path"),
                    }
                )
            pdir = _provenance_dir()
            findings = _read_json(os.path.join(pdir, "findings.json"), [])
            hyps = _read_json(os.path.join(pdir, "hypotheses.json"), [])
            for f in findings[-1000:]:
                events.append({"type": "finding", "id": f.get("finding_id"), "timestamp": f.get("created_at")})
            for h in hyps[-1000:]:
                events.append({"type": "hypothesis", "id": h.get("hypothesis_id"), "timestamp": h.get("updated_at")})
            events.sort(key=lambda x: str(x.get("timestamp") or x.get("updated_at") or x.get("created_at")))
            return {"ok": True, "event_count": len(events), "timeline": events[-1000:]}

        elif action == "semantic_artifact_diff":
            left = kwargs.get("left") or kwargs.get("artifact_a")
            right = kwargs.get("right") or kwargs.get("artifact_b")
            left_tags = set(kwargs.get("left_tags") or [])
            right_tags = set(kwargs.get("right_tags") or [])
            if isinstance(left_tags, str):
                left_tags = {x.strip() for x in left_tags.split(",") if x.strip()}
            if isinstance(right_tags, str):
                right_tags = {x.strip() for x in right_tags.split(",") if x.strip()}
            shared = sorted(left_tags & right_tags)
            only_left = sorted(left_tags - right_tags)
            only_right = sorted(right_tags - left_tags)
            similarity = round(len(shared) / max(1, len(left_tags | right_tags)), 3)
            return {
                "ok": True,
                "left": left,
                "right": right,
                "shared_behaviors": shared,
                "left_only": only_left,
                "right_only": only_right,
                "semantic_similarity": similarity,
            }

        elif action == "ai_governance":
            pdir = _provenance_dir()
            ai_path = os.path.join(pdir, "ai_annotations.json")
            records = _read_json(ai_path, [])
            mode = str(kwargs.get("mode") or "submit").lower()
            if mode == "submit":
                rec = {
                    "id": f"A-{int(time.time() * 1000)}",
                    "timestamp": _now_iso(),
                    "reviewer": kwargs.get("reviewer"),
                    "author_type": kwargs.get("author_type") or "ai",
                    "target": kwargs.get("target"),
                    "change_type": kwargs.get("change_type"),
                    "approved": bool(kwargs.get("approved", False)),
                    "policy": kwargs.get("policy") or "default",
                }
                records.append(rec)
                _write_json(ai_path, records[-5000:])
                return {"ok": True, "mode": "submit", "record": rec, "total": len(records)}
            approved = sum(1 for r in records if r.get("approved"))
            denied = len(records) - approved
            return {
                "ok": True,
                "mode": "report",
                "total": len(records),
                "approved": approved,
                "denied_or_pending": denied,
                "approval_rate": round((approved / len(records)) * 100, 1) if records else 0.0,
            }

        elif action == "knowledge_debt":
            pdir = _provenance_dir()
            findings = _read_json(os.path.join(pdir, "findings.json"), [])
            hyps = _read_json(os.path.join(pdir, "hypotheses.json"), [])
            ai_records = _read_json(os.path.join(pdir, "ai_annotations.json"), [])
            unresolved_hyp = [h for h in hyps if str(h.get("status")) not in ("supported", "refuted")]
            low_evidence = [f for f in findings if len(f.get("evidence") or []) < 2]
            unreviewed_ai = [r for r in ai_records if not r.get("approved")]
            debt_index = len(unresolved_hyp) * 2 + len(low_evidence) + len(unreviewed_ai)
            return {
                "ok": True,
                "debt_index": debt_index,
                "unresolved_hypotheses": len(unresolved_hyp),
                "low_evidence_findings": len(low_evidence),
                "unreviewed_ai_annotations": len(unreviewed_ai),
                "priority": "high" if debt_index >= 25 else ("medium" if debt_index >= 10 else "low"),
            }

        elif action == "casefile_export":
            pdir = _provenance_dir()
            findings = _read_json(os.path.join(pdir, "findings.json"), [])
            hyps = _read_json(os.path.join(pdir, "hypotheses.json"), [])
            ai_records = _read_json(os.path.join(pdir, "ai_annotations.json"), [])
            replay = _read_json(os.path.join(pdir, "replay_log.json"), [])
            sessions = _discover_sessions(limit=200)
            export_format = str(kwargs.get("format") or "json").lower()
            risk_summary = build_risk_summary(findings, hyps, ai_records) if build_risk_summary else {}
            chain = build_chain_of_custody(sessions, replay, ai_records) if build_chain_of_custody else []
            payload = {
                "generated_at": _now_iso(),
                "source_binary": idaapi.get_input_file_path() if hasattr(idaapi, "get_input_file_path") else None,
                "idb_path": idc.get_idb_path() if hasattr(idc, "get_idb_path") else None,
                "sessions": sessions,
                "findings": findings[-500:],
                "hypotheses": hyps[-500:],
                "ai_governance": ai_records[-500:],
                "risk_summary": risk_summary,
                "chain_of_custody": chain,
            }
            payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8", errors="replace")
            payload_digest = hashlib.sha256(payload_bytes).hexdigest()
            payload["integrity"] = {
                "algorithm": "sha256",
                "scope": "payload_excluding_integrity",
                "sha256": payload_digest,
            }

            out_path = kwargs.get("output_path") or path
            if out_path:
                out_path, err = validate_path_safe(out_path)
                if err:
                    return err
                if export_format == "markdown" and to_markdown_casefile is not None:
                    with open(out_path, "w", encoding="utf-8") as fh:
                        fh.write(to_markdown_casefile({
                            **payload,
                            "summary": {
                                "sessions": len(sessions),
                                "findings": len(payload["findings"]),
                                "hypotheses": len(payload["hypotheses"]),
                                "ai_records": len(payload["ai_governance"]),
                            },
                        }))
                else:
                    with open(out_path, "w", encoding="utf-8") as fh:
                        json.dump(payload, fh, indent=2)
            return {"ok": True, "exported": bool(out_path), "path": out_path, "integrity": payload["integrity"], "summary": {
                "sessions": len(sessions),
                "findings": len(payload["findings"]),
                "hypotheses": len(payload["hypotheses"]),
                "ai_records": len(payload["ai_governance"]),
                "chain_events": len(chain),
                "risk_level": risk_summary.get("risk_level") if isinstance(risk_summary, dict) else None,
            }}
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 13. PLUGINS - Plugin operations
# ============================================================================
