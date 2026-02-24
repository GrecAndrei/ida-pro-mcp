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
    "plugins",
    "trace",
    "fixups",
    "data_ops",
    "agent",
    "microcode",
    "graph",
    "bulk",
    "calc",
    "ctree",
    "diff",
    "lumina",
    "symbols",
    "patterns",
    "structs",
    "emulate",
    "export",
    "history",
    "entropy",
    "imports_deep",
    "comments_ai",
    "nav",
    "colorize",
    "trace_analysis",
    "hooks",
    "taint",
    "coverage",
    "wiki",
    "yara_hunt",
    "analysis",
    "query",
    "edit",
    "batch",
    "vuln_scan",
    "deobfuscate",
    "crypto_id",
    "abi",
    "summarize",
    "compare",
    "stack_analysis",
    "classify",
    "protocol",
    "c2_detect",
    "gadgets",
    "annotation",
    "xref_analysis",
    "string_ops",
    "cfg_analysis",
    "binary_info",
    "llm_helpers",
]


def __getattr__(name):
    if name in __all__:
        module = import_module(f".{name}", __name__)
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals().keys()) | set(__all__))
