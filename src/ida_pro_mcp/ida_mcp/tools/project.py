
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


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
        
        if action == "sessions":
            # This is now handled by the stdio host's session tool
            return make_error(MCPError.NOT_IMPLEMENTED, "Use 'session' tool for session management", "The 'files.sessions' action is deprecated.")
        
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
            
            return make_error(MCPError.NOT_IMPLEMENTED, "Closing database only supported in headless/idalib mode")
        
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
            
            return make_error(MCPError.NOT_IMPLEMENTED, "Opening new files via 'files.open' requires headless mode. For GUI mode, use 'session.create' from the host.")
        
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
            # Simplified batch analysis for headless mode
            if not path: return make_error(MCPError.INVALID_ARGS, "path required")
            
            # Implementation detail: Real batch analysis should be handled by the MCP Host 
            # to manage multiple IDA processes. This is a stub for internal use.
            return make_error(MCPError.NOT_IMPLEMENTED, "Batch analysis should be performed via the host-level session manager.")
        
        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 13. PLUGINS - Plugin operations
# ============================================================================
