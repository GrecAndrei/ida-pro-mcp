
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 13. PLUGINS - Plugin operations
# ============================================================================

@tool
@unsafe
@idawrite
def plugins(
    action: Annotated[Literal["list", "run"], "Action: list|run"],
    name: Annotated[Optional[str], "Plugin name (for run)"] = None,
    arg: Annotated[int, "Plugin argument"] = 0,
    **kwargs
) -> dict:
    """
    Manage IDA plugins.
    
    Actions:
    - list: List loaded plugins (Note: May not be supported in newer IDA versions).
    - run: Run a plugin by name.
    
    Arguments:
    - name: Plugin name (e.g. "Hex-Rays Decompiler").
    - arg: Integer argument for the plugin run call.
    """
    try:
        import ida_loader
        import pathlib
        
        if action == "list":
            # IDA 9 removed old plugin-enumeration API; provide filesystem-based fallback.
            plugin_dirs = []
            try:
                idadir = os.environ.get("IDADIR")
                if idadir:
                    plugin_dirs.append(os.path.join(idadir, "plugins"))
            except Exception:
                pass
            try:
                idausr = os.environ.get("IDAUSR") or os.path.join(pathlib.Path.home(), ".idapro")
                plugin_dirs.append(os.path.join(str(idausr), "plugins"))
            except Exception:
                pass

            discovered = []
            seen = set()
            exts = (".py", ".pyc", ".p64", ".plw", ".dll", ".so", ".dylib")
            for d in plugin_dirs:
                if not d or not os.path.isdir(d):
                    continue
                try:
                    for entry in os.listdir(d):
                        if not entry.lower().endswith(exts):
                            continue
                        full = os.path.join(d, entry)
                        key = os.path.realpath(full)
                        if key in seen:
                            continue
                        seen.add(key)
                        discovered.append({"name": entry, "path": full})
                except Exception:
                    continue

            return {
                "ok": True,
                "plugins": sorted(discovered, key=lambda x: x["name"].lower()),
                "count": len(discovered),
                "note": "Filesystem-based plugin listing (runtime enumeration API not available in this IDA build).",
            }

        elif action == "run":
            if not name:
                return make_error(MCPError.INVALID_ARGS, "name required")
            # Try to run plugin by name
            plugin = ida_loader.find_plugin(name, True)
            if plugin in (None, -1):
                return make_error(MCPError.FILE_NOT_FOUND, f"Plugin not found: {name}")
            if ida_loader.run_plugin(plugin, arg):
                return {"ok": True, "name": name}
            return make_error(MCPError.IDA_ERROR, f"Failed to run plugin: {name}")

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
    except Exception as e:
        return handle_error(e)


# ============================================================================
# 14. TRACE - Trace operations
# ============================================================================
