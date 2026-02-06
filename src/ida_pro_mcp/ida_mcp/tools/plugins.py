
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
        
        if action == "list":
            # Plugin enumeration API removed in IDA 9
            return make_error(MCPError.NOT_IMPLEMENTED, "Plugin listing not supported in this IDA version")

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
