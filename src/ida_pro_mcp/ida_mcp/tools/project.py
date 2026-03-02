
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
        "list_dir", "exists", "read", "write", "sessions", "batch"
    ], "Action"],
    path: Annotated[Optional[str], "File path or JSON array of paths for batch"] = None,
    base_addr: Annotated[Optional[str], "Base address for load_binary"] = None,
    content: Annotated[Optional[str], "Content to write, or mode for open"] = None,
    **kwargs
) -> dict:
    """
    File and Database I/O with MULTI-FILE BATCH ANALYSIS support.
    
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
        
    batch - MULTI-FILE BATCH ANALYSIS (headless mode only!)
        Params: path (JSON array of paths OR directory path)
        Returns: {analyzed, failed, total, results: [{path, ok, functions, md5}]}
        Example: files(action="batch", path='["file1.exe", "file2.exe"]')
        Example: files(action="batch", path="C:/samples/")
        Note: Requires idalib-mcp headless mode. Analyzes each file sequentially.
        
    sessions - List all spawned IDA sessions
        Returns: {sessions: [{pid, path, port, started}], current: {pid, path}}
        Example: files(action="sessions")
        
    save - Save current database
    close - Close database (in headless: ready for next file)
    load_binary - Load additional binary into current IDB
    list_recent - List recently opened files
    get_cwd/set_cwd - Working directory management
    list_dir - Directory listing
    exists/read/write - File system operations
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
        
        if action == "sessions":
            current = {
                "pid": os.getpid(),
                "binary_path": idaapi.get_input_file_path() if hasattr(idaapi, "get_input_file_path") else None,
                "idb_path": idc.get_idb_path() if hasattr(idc, "get_idb_path") else None,
                "cwd": os.getcwd(),
                "runtime_dir": _runtime_root(),
            }
            sessions = _discover_sessions()
            return {
                "ok": True,
                "current": current,
                "sessions": sessions,
                "count": len(sessions),
                "note": "Host session tool is preferred, but project.sessions now provides runtime-discovered session metadata.",
            }
        
        elif action == "save":
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
        
        elif action == "read":
            if not path: return make_error(MCPError.INVALID_ARGS, "path required")
            path, err = validate_path_safe(path)
            if err: return err
            if not os.path.exists(path): return make_error(MCPError.FILE_NOT_FOUND, path)
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return {"ok": True, "path": path, "content": f.read()}
        
        elif action == "write":
            if not path or content is None: return make_error(MCPError.INVALID_ARGS, "path and content required")
            path, err = validate_path_safe(path)
            if err: return err
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            return {"ok": True, "path": path, "size": len(content)}
        
        elif action == "batch":
            if not path: return make_error(MCPError.INVALID_ARGS, "path required")
            candidates = []
            raw = str(path).strip()
            if raw.startswith("["):
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, list):
                        candidates = [str(p) for p in parsed]
                except Exception:
                    return make_error(MCPError.INVALID_ARGS, "Invalid JSON list for batch path")
            elif os.path.isdir(raw):
                for name in sorted(os.listdir(raw)):
                    full = os.path.join(raw, name)
                    if os.path.isfile(full):
                        candidates.append(full)
            else:
                candidates = [raw]

            if not candidates:
                return make_error(MCPError.INVALID_ARGS, "No files found for batch analysis")

            out = []
            analyzed = 0
            failed = 0
            for item in candidates:
                try:
                    resolved, err = validate_path_safe(item)
                    if err:
                        failed += 1
                        out.append({"path": item, "ok": False, "error": err.get("message", "invalid path")})
                        continue
                    if not os.path.isfile(resolved):
                        failed += 1
                        out.append({"path": resolved, "ok": False, "error": "not a file"})
                        continue

                    size = os.path.getsize(resolved)
                    digest = hashlib.sha256()
                    with open(resolved, "rb") as fh:
                        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                            digest.update(chunk)
                    out.append(
                        {
                            "path": resolved,
                            "ok": True,
                            "size": size,
                            "sha256": digest.hexdigest(),
                            "name": os.path.basename(resolved),
                        }
                    )
                    analyzed += 1
                except Exception as e:
                    failed += 1
                    out.append({"path": item, "ok": False, "error": str(e)})

            return {
                "ok": True,
                "analyzed": analyzed,
                "failed": failed,
                "total": len(candidates),
                "results": out,
                "note": "Batch path now performs portable pre-analysis metadata extraction. Use host session/batch for full multi-runtime analysis.",
            }
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 13. PLUGINS - Plugin operations
# ============================================================================
