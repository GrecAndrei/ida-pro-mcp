"""security — Unified security analysis tool.

Merges: packer, hooks, deobfuscate, crypto_id, entropy, protocol, taint
into a single tool with a flat action namespace.

All sub-tool implementations remain in their original files as plain functions.
This file is the single MCP entry point.
"""

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from typing import Annotated, Optional

# Import sub-tool implementations (now plain functions, no @tool registration)
from . import deobfuscate as _deobf_mod
from . import crypto_id as _crypto_mod
from . import entropy as _entropy_mod
from . import hooks as _hooks_mod
from . import packer as _packer_mod
from . import taint as _taint_mod

# protocol is optional (heavy dependency on BehaviorClassifier)
try:
    from . import protocol as _protocol_mod
except Exception:
    _protocol_mod = None  # type: ignore

# ── Action routing table ────────────────────────────────────────────────────
# Maps action name → (module, function_name)
_ACTION_MAP: dict[str, tuple] = {}

def _register(source_module, actions: list[str]):
    """Register actions from a source module."""
    func = None
    # Find the main tool function in the module
    for name in dir(source_module):
        obj = getattr(source_module, name)
        if callable(obj) and not name.startswith("_"):
            # Check if it was a @tool function by looking for the action param
            import inspect
            try:
                sig = inspect.signature(obj)
                if "action" in sig.parameters:
                    func = obj
                    break
            except Exception:
                pass
    if func is None:
        return
    for action_name in actions:
        _ACTION_MAP[action_name] = func

# Register all actions from each sub-tool
_register(_packer_mod, ["detect", "profile", "guide", "status", "script"])
_register(_hooks_mod, ["suggest", "generate_frida", "generate_detours", "find_targets", "inline_hooks"])
_register(_deobf_mod, ["detect_encoding", "stack_strings", "dead_code", "api_hashing",
                        "dynamic_dispatch", "anti_disasm", "decode_attempt"])
# deobfuscate's "detect" conflicts with packer's "detect" — prefix it
_register(_deobf_mod, ["deobf_detect"])
_register(_crypto_mod, ["identify", "constants", "encoding", "checksums", "entropy_analysis", "aes_ni"])
_register(_entropy_mod, ["section", "region", "packed_detect", "crypto_detect",
                          "compare", "window", "summary"])
_register(_taint_mod, ["sources", "sinks", "trace", "paths", "report"])
if _protocol_mod is not None:
    _register(_protocol_mod, [
        "detect_protocol", "parsers", "serializers", "handlers", "endpoints",
        "tls_config", "socket_flow", "packet_struct", "magic_numbers",
        "state_machine", "reconstruct", "trace_handler", "export_spec",
    ])

# Alias mapping for disambiguation
_ACTION_ALIASES = {
    # deobfuscate's "detect" → "deobf_detect"
    "deobf_detect": ("deobfuscate", "detect"),
    # protocol's "detect" → "detect_protocol"
    "detect_protocol": ("protocol", "detect"),
}


@tool
@idaread
def security(
    action: Annotated[str, "Security analysis action"],
    addr: Annotated[Optional[str], "Address or function to analyze"] = None,
    limit: Annotated[int, "Max results"] = 50,
    **kwargs,
) -> dict:
    """Unified security analysis tool.

    Combines packer detection, deobfuscation, crypto identification,
    entropy analysis, hook generation, protocol analysis, and taint
    analysis into a single tool.

    ACTIONS BY CATEGORY:

    Packer (5): detect, profile, guide, status, script
    Deobfuscation (8): deobf_detect, detect_encoding, stack_strings, dead_code,
                        api_hashing, dynamic_dispatch, anti_disasm, decode_attempt
    Crypto (6): identify, constants, encoding, checksums, entropy_analysis, aes_ni
    Entropy (7): section, region, packed_detect, crypto_detect, compare, window, summary
    Hooks (5): suggest, generate_frida, generate_detours, find_targets, inline_hooks
    Protocol (13): detect_protocol, parsers, serializers, handlers, endpoints,
                   tls_config, socket_flow, packet_struct, magic_numbers,
                   state_machine, reconstruct, trace_handler, export_spec
    Taint (5): sources, sinks, trace, paths, report

    Examples:
      security(action="identify") — find crypto algorithms
      security(action="trace", source="recv") — taint from recv to sinks
      security(action="detect") — quick packer detection
      security(action="deobf_detect") — deobfuscation analysis
      security(action="packed_detect") — find high-entropy windows
      security(action="suggest", category="network") — hook suggestions
      security(action="report") — full taint report
    """
    # Resolve aliases
    resolved = _ACTION_ALIASES.get(action)
    if resolved:
        module_name, real_action = resolved
        kwargs["action"] = real_action
    else:
        kwargs["action"] = action

    # Find the handler
    handler = _ACTION_MAP.get(action)
    if handler is None:
        # Try the resolved action
        if resolved:
            handler = _ACTION_MAP.get(resolved[1])
    if handler is None:
        return make_error(
            MCPError.INVALID_ARGS,
            f"Unknown security action: '{action}'",
            hint=f"Available: {', '.join(sorted(_ACTION_MAP.keys()))}",
        )

    # Route to the handler
    try:
        import inspect
        sig = inspect.signature(handler)
        # Build kwargs for the handler, only passing what it accepts
        call_kwargs = {}
        handler_params = set(sig.parameters.keys())
        # Always pass action
        call_kwargs["action"] = kwargs.get("action", action)
        # Pass common params if accepted
        for param in ("addr", "limit", "rules", "size", "context_bytes",
                       "include_func", "include_anti_debug", "include_drm",
                       "code", "max_string_scan", "category", "func_name",
                       "source", "max_depth", "max_paths", "key", "depth",
                       "threshold", "end_addr", "window", "step",
                       "min_entropy", "decode", "query", "probe",
                       "deep_hash", "include_context", "top_k",
                       "max_items", "max_strings"):
            if param in handler_params and param in kwargs:
                call_kwargs[param] = kwargs[param]
            elif param in handler_params and param == "addr" and addr is not None:
                call_kwargs["addr"] = addr
            elif param in handler_params and param == "limit":
                call_kwargs["limit"] = limit
        # Pass any remaining kwargs that the handler accepts
        for k, v in kwargs.items():
            if k not in call_kwargs and k in handler_params:
                call_kwargs[k] = v

        return handler(**call_kwargs)
    except Exception as e:
        return handle_error(e)
