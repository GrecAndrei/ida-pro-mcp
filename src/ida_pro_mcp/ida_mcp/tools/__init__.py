"""IDA Pro MCP tools package.

This package intentionally avoids eager imports so a single optional-tool import
failure does not break loading unrelated tools.
"""

from importlib import import_module

__all__ = [
    "idb",
    "code",
    "data",
    "search",
    "types",
    "memory",
    "modify",
    "misc",
    "funcs",
    "segments",
    "symbols",
    "graph",
    "ctree",
    "imports_deep",
    "stack_analysis",
    "calc",
    "intelligence",
    "wiki",
    "analysis",
    "batch",
    "gadgets",
    "annotation",
    "blackboard",
    "governance",
    "knowledge",
    "firmware",
]

# Mapping from tool name to module name (when they differ)
_TOOL_MODULE_MAP = {
    "governance": "governance_engine",
    # name == module name; explicit entry keeps the registry uniform.
    "firmware": "firmware",
}


def __getattr__(name):
    if name in __all__:
        module_name = _TOOL_MODULE_MAP.get(name, name)
        module = import_module(f".{module_name}", __name__)
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals().keys()) | set(__all__))
