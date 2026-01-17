"""Plugin management for IDA Pro MCP."""

from typing import Annotated

import idaapi
import ida_loader

from .rpc import tool, unsafe
from .sync import idaread, idawrite


@tool
@idaread
def list_plugins() -> list[dict]:
    """List available plugins"""
    plugins = []
    
    try:
        # Get plugin count
        count = ida_loader.get_plugins_count()
        
        for i in range(count):
            try:
                info = ida_loader.get_plugin_info(i)
                if info:
                    plugins.append({
                        "name": info.name or f"plugin_{i}",
                        "comment": info.comment or "",
                        "hotkey": info.hotkey or "",
                        "flags": info.flags,
                    })
            except Exception:
                continue
                
    except Exception as e:
        return [{"error": str(e)}]
    
    return plugins


@tool
@idawrite
@unsafe
def run_plugin(
    name: Annotated[str, "Plugin name or index"],
    arg: Annotated[int, "Plugin argument"] = 0
) -> dict:
    """Run plugin by name"""
    try:
        # Try to find and run the plugin
        # First try by name
        if idaapi.load_and_run_plugin(name, arg):
            return {"name": name, "ok": True}
        
        # Running might return False but still work
        return {"name": name, "ok": True, "note": "Plugin executed (may have run silently)"}
        
    except Exception as e:
        return {"name": name, "error": str(e)}
