"""
plugins — thin compatibility alias for misc(action="plugin_list"|"plugin_run").

Per AGENTS.md: `plugins` -> `misc`. This shim exists so the tool loader can
discover the `plugins` name while the real implementation lives in misc.py.
"""

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

try:
    from .misc import misc as _misc
except ImportError:
    from misc import misc as _misc  # type: ignore[import-not-found]


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
    Manage IDA plugins. Alias for misc(action="plugin_list"|"plugin_run").

    Actions:
    - list: Discover plugins via filesystem scan.
    - run: Run a plugin by name.
    """
    if action == "list":
        return _misc(action="plugin_list", **kwargs)
    elif action == "run":
        return _misc(action="plugin_run", name=name, arg=arg, **kwargs)
    return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
