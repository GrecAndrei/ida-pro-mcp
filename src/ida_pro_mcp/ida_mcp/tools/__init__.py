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
    "debug",
    "funcs",
    "segments",
    "project",
    "fixups",
    "data_ops",
    "firmware_view",
    "microcode",
    "graph",
    "bulk",
    "calc",
    "ctree",
    "lumina",
    "symbols",
    "patterns",
    "export",
    "history",
    "entropy",
    "imports_deep",
    "nav",
    "trace_analysis",
    "hooks",
    "coverage",
    "intelligence",
    "wiki",
    "yara_hunt",
    "analysis",
    "batch",
    "deobfuscate",
    "crypto_id",
    "abi",
    "summarize",
    "compare",
    "stack_analysis",
    "classify",
    "protocol",
    "gadgets",
    "annotation",
    "xref_analysis",
    "string_ops",
    "cfg_analysis",
    "binary_info",
    "blackboard",
    "governance",
    "knowledge",
    "packer",
    "struct_recover",
    "emulate",
    "bindiff",
]

# Mapping from tool name to module name (when they differ)
_TOOL_MODULE_MAP = {
    "governance": "governance_engine",
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
