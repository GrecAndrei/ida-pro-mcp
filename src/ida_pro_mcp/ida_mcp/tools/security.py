"""security — Unified security analysis tool.

11 actions covering all security concerns.  Merges 7 former tools (49 actions)
into a flat namespace with real orchestration, not wrapper delegation.

Actions:
  detect         — orchestrator: packer + entropy + crypto + anti-analysis + obfuscation
  decode         — decode bytes at addr (XOR brute force, Base64)
  analyze        — scan functions for patterns (what=stack_strings|dead_code|api_hashing|
                   dynamic_dispatch|anti_disasm|crypto_constants|encoding|checksums|aes_ni)
  hook           — generate instrumentation script (method=frida|detours|inline)
  hook_targets   — find interesting functions to hook (by category)
  protocol       — detect protocol usage, find parsers/serializers/handlers/endpoints
  protocol_spec  — recover protocol structure (packet_struct, magic_numbers, state_machine,
                   reconstruct, trace_handler, export_spec)
  taint          — trace data flow from source to sinks
  taint_sources  — list all taint sources (imports + blackboard IOCs)
  taint_report   — full report: all sources → all reachable sinks
  eval           — run custom Python in security namespace
"""

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from typing import Annotated, Optional
import sys
import time

# ── Import sub-tool implementations (plain functions, no @tool) ──────────────
from . import packer as _packer_mod
from . import deobfuscate as _deobf_mod
from . import crypto_id as _crypto_mod
from . import entropy as _entropy_mod
from . import hooks as _hooks_mod
from . import taint as _taint_mod

try:
    from . import protocol as _protocol_mod
except Exception:
    _protocol_mod = None


# ── detect: orchestrator ─────────────────────────────────────────────────────

def _run_detect(addr, limit, include_anti_debug, include_drm, max_string_scan):
    """Run packer + entropy + crypto + deobfuscation in one pass."""
    results = {}
    ts = time.time()

    # 1. Packer detection (the core)
    try:
        packer_result = _packer_mod.packer(
            action="detect",
            include_anti_debug=include_anti_debug,
            include_drm=include_drm,
            max_string_scan=max_string_scan,
        )
        results["packer"] = packer_result
    except Exception as e:
        results["packer"] = {"error": str(e)}

    # 2. Per-section entropy summary
    try:
        ent_result = _entropy_mod.entropy(action="section", limit=limit)
        results["entropy"] = ent_result
    except Exception as e:
        results["entropy"] = {"error": str(e)}

    # 3. Crypto constant scanning
    try:
        crypto_result = _crypto_mod.crypto_id(action="identify", limit=limit)
        results["crypto"] = {
            "algorithms": crypto_result.get("algorithms_found", []),
            "count": crypto_result.get("count", 0),
        }
    except Exception as e:
        results["crypto"] = {"error": str(e)}

    # 4. Obfuscation signal scan (deterministic, fast)
    try:
        deobf_result = _deobf_mod.deobfuscate(action="detect", addr=addr, limit=limit)
        results["obfuscation"] = {
            "classifier": deobf_result.get("classifier"),
            "count": deobf_result.get("count", 0),
            "findings": deobf_result.get("findings", ""),
        }
    except Exception as e:
        results["obfuscation"] = {"error": str(e)}

    # Build unified summary
    packer_data = results.get("packer", {})
    classification = packer_data.get("classification", {})
    recommendation = packer_data.get("recommendation", "unknown")

    summary_parts = []
    packer_name = classification.get("packer", "none")
    if packer_name != "none":
        summary_parts.append(f"packer={packer_name}({classification.get('confidence', 0)})")

    crypto_algos = results.get("crypto", {}).get("algorithms", [])
    if crypto_algos:
        summary_parts.append(f"crypto={','.join(crypto_algos)}")

    obf_count = results.get("obfuscation", {}).get("count", 0)
    if obf_count:
        summary_parts.append(f"obfuscation_signals={obf_count}")

    return {
        "ok": True,
        "action": "detect",
        "ts": round(ts, 3),
        "summary": "  ".join(summary_parts) if summary_parts else "clean",
        "recommendation": recommendation,
        "warning": packer_data.get("warning"),
        **results,
    }


# ── analyze: scan functions for patterns ─────────────────────────────────────

_ANALYZE_DISPATCH = {
    "stack_strings": lambda addr, limit, **kw: _deobf_mod.deobfuscate(action="stack_strings", addr=addr, limit=limit),
    "dead_code":     lambda addr, limit, **kw: _deobf_mod.deobfuscate(action="dead_code", addr=addr, limit=limit),
    "api_hashing":   lambda addr, limit, **kw: _deobf_mod.deobfuscate(action="api_hashing", addr=addr, limit=limit),
    "dynamic_dispatch": lambda addr, limit, **kw: _deobf_mod.deobfuscate(action="dynamic_dispatch", addr=addr, limit=limit),
    "anti_disasm":   lambda addr, limit, **kw: _deobf_mod.deobfuscate(action="anti_disasm", addr=addr, limit=limit),
    "crypto_constants": lambda addr, limit, **kw: _crypto_mod.crypto_id(action="constants", limit=limit),
    "encoding":      lambda addr, limit, **kw: _crypto_mod.crypto_id(action="encoding", limit=limit),
    "checksums":     lambda addr, limit, **kw: _crypto_mod.crypto_id(action="checksums", limit=limit),
    "aes_ni":        lambda addr, limit, **kw: _crypto_mod.crypto_id(action="aes_ni", limit=limit),
    "entropy_high":  lambda addr, limit, **kw: _crypto_mod.crypto_id(action="entropy_analysis", limit=limit),
}


def _run_analyze(what, addr, limit, **kwargs):
    handler = _ANALYZE_DISPATCH.get(what)
    if not handler:
        return make_error(
            MCPError.INVALID_ARGS,
            f"Unknown analyze target: '{what}'",
            hint=f"Available: {', '.join(sorted(_ANALYZE_DISPATCH.keys()))}",
        )
    return handler(addr, limit, **kwargs)


# ── hook: generate instrumentation ───────────────────────────────────────────

def _run_hook(method, addr, func_name, category):
    if method == "frida":
        return _hooks_mod.hooks(action="generate_frida", addr=addr, func_name=func_name)
    elif method == "detours":
        return _hooks_mod.hooks(action="generate_detours", addr=addr, func_name=func_name)
    elif method == "inline":
        return _hooks_mod.hooks(action="inline_hooks", addr=addr)
    else:
        return make_error(
            MCPError.INVALID_ARGS,
            f"Unknown hook method: '{method}'",
            hint="Available: frida, detours, inline",
        )


# ── hook_targets: find interesting functions ─────────────────────────────────

def _run_hook_targets(category, addr, limit):
    if category:
        return _hooks_mod.hooks(action="suggest", category=category)
    return _hooks_mod.hooks(action="find_targets")


# ── protocol: orchestrator for protocol detection ────────────────────────────

def _run_protocol(addr, limit):
    if _protocol_mod is None:
        return make_error(MCPError.INVALID_ARGS, "Protocol module not available")
    return _protocol_mod.protocol(action="detect", addr=addr, limit=limit)


# ── protocol_spec: recover protocol structure ────────────────────────────────

_PROTOCOL_SPEC_ACTIONS = {
    "packet_struct", "magic_numbers", "state_machine", "reconstruct",
    "trace_handler", "export_spec", "parsers", "serializers", "handlers",
    "endpoints", "tls_config", "socket_flow",
}


def _run_protocol_spec(what, addr, limit):
    if _protocol_mod is None:
        return make_error(MCPError.INVALID_ARGS, "Protocol module not available")
    if what not in _PROTOCOL_SPEC_ACTIONS:
        return make_error(
            MCPError.INVALID_ARGS,
            f"Unknown protocol_spec target: '{what}'",
            hint=f"Available: {', '.join(sorted(_PROTOCOL_SPEC_ACTIONS))}",
        )
    return _protocol_mod.protocol(action=what, addr=addr, limit=limit)


# ── taint: trace from source to sink ─────────────────────────────────────────

def _run_taint(source, addr, max_depth, max_paths):
    return _taint_mod.taint(
        action="trace", addr=addr, source=source,
        max_depth=max_depth, max_paths=max_paths,
    )


def _run_taint_sources(limit):
    return _taint_mod.taint(action="sources")


def _run_taint_report(max_depth, max_paths):
    return _taint_mod.taint(action="report", max_depth=max_depth, max_paths=max_paths)


# ── eval: run custom Python ──────────────────────────────────────────────────

_SCRIPT_SAFE_BUILTINS = {
    "abs", "all", "any", "bin", "bool", "bytes", "callable", "chr",
    "dict", "divmod", "enumerate", "filter", "float", "format", "frozenset",
    "hash", "hex", "id", "int", "isinstance", "issubclass", "iter", "len",
    "list", "map", "max", "min", "next", "object", "oct", "ord", "pow",
    "print", "range", "repr", "reversed", "round", "set", "slice", "sorted",
    "str", "sum", "tuple", "type", "vars", "zip",
}

_MAX_SCRIPT_CHARS = 16384
_MAX_SCRIPT_OUTPUT = 200000


def _run_eval(code, extra_globals):
    import builtins as _b
    import json as _json

    if not code or not isinstance(code, str):
        return make_error(MCPError.INVALID_ARGS, "eval requires non-empty 'code' (Python expression)")
    if len(code) > _MAX_SCRIPT_CHARS:
        return make_error(MCPError.INVALID_ARGS, f"script code exceeds {_MAX_SCRIPT_CHARS} characters")

    forbidden = {"open", "exec", "eval", "__import__", "compile", "input"}
    for tok in forbidden:
        if tok + "(" in code or tok + " " in code or code.startswith(tok):
            return make_error(MCPError.INVALID_ARGS, f"script may not use '{tok}'")

    safe_b = {k: getattr(_b, k) for k in _SCRIPT_SAFE_BUILTINS if hasattr(_b, k)}
    ns = {
        # All sub-tool functions available for custom composition
        "packer": _packer_mod.packer,
        "deobfuscate": _deobf_mod.deobfuscate,
        "crypto_id": _crypto_mod.crypto_id,
        "entropy": _entropy_mod.entropy,
        "hooks": _hooks_mod.hooks,
        "taint": _taint_mod.taint,
        "protocol": _protocol_mod.protocol if _protocol_mod else None,
        # IDA SDK
        "idaapi": sys.modules.get("idaapi"),
        "idautils": sys.modules.get("idautils"),
        "idc": sys.modules.get("idc"),
        "ida_bytes": sys.modules.get("ida_bytes"),
        "ida_nalt": sys.modules.get("ida_nalt"),
        "ida_segment": sys.modules.get("ida_segment"),
        "ida_funcs": sys.modules.get("ida_funcs"),
        "ida_ida": sys.modules.get("ida_ida"),
        # stdlib
        "json": __import__("json"),
        "os": __import__("os"),
        "re": __import__("re"),
        "time": __import__("time"),
        "math": __import__("math"),
        "struct": __import__("struct"),
        "collections": __import__("collections"),
        "hashlib": __import__("hashlib"),
        "__builtins__": safe_b,
    }
    if extra_globals:
        for k, v in extra_globals.items():
            if isinstance(k, str) and k.isidentifier():
                ns[k] = v

    try:
        try:
            value = eval(compile(code, "<security-eval>", "eval"), ns)
        except SyntaxError:
            exec(compile(code, "<security-eval>", "exec"), ns)
            value = ns.get("result")
    except Exception as e:
        return make_error(MCPError.IDA_ERROR, f"script raised: {type(e).__name__}: {e}")

    serialized = value
    try:
        if isinstance(serialized, (dict, list, str, int, float, bool, type(None))):
            raw = _json.dumps(serialized, default=str, ensure_ascii=False)
            if len(raw) > _MAX_SCRIPT_OUTPUT:
                raw = raw[:_MAX_SCRIPT_OUTPUT] + "...[truncated]"
                try:
                    serialized = _json.loads(raw)
                except Exception:
                    serialized = {"_truncated": True, "preview": raw}
    except Exception:
        pass
    return {"ok": True, "result": serialized}


# ── Main entry point ─────────────────────────────────────────────────────────

@tool
@idaread
def security(
    action: Annotated[str, "Security analysis action"],
    addr: Annotated[Optional[str], "Address or function to analyze"] = None,
    limit: Annotated[int, "Max results"] = 50,
    what: Annotated[Optional[str], "Sub-target for analyze/protocol_spec"] = None,
    source: Annotated[Optional[str], "Taint source name or address"] = None,
    method: Annotated[Optional[str], "Hook method: frida|detours|inline"] = None,
    category: Annotated[Optional[str], "Hook category: network|file|crypto|registry|process"] = None,
    func_name: Annotated[Optional[str], "Function name for hook generation"] = None,
    max_depth: Annotated[int, "Max call-graph depth for taint"] = 5,
    max_paths: Annotated[int, "Max paths to return"] = 20,
    key: Annotated[Optional[str], "Decryption key for decode (hex)"] = None,
    code: Annotated[Optional[str], "Python code for eval action"] = None,
    include_anti_debug: Annotated[bool, "Include anti-debug detection in detect"] = True,
    include_drm: Annotated[bool, "Include anti-cheat detection in detect"] = True,
    **kwargs,
) -> dict:
    """Unified security analysis.

    ACTIONS:

    detect — Full security sweep. Runs packer detection, per-section entropy,
        crypto constant scanning, and obfuscation signal analysis in one pass.
        Returns classification, recommendation, entropy map, crypto algorithms
        found, and obfuscation signals.

    decode — Decode bytes at addr. Brute-forces single-byte XOR keys and
        checks for Base64. Params: addr (required), key (optional hex).

    analyze — Scan functions for specific security patterns. Requires `what`:
        stack_strings, dead_code, api_hashing, dynamic_dispatch, anti_disasm,
        crypto_constants, encoding, checksums, aes_ni, entropy_high.
        Params: what (required), addr (optional, scopes to function).

    hook — Generate instrumentation code. Requires `method`:
        frida — Frida JavaScript hook script
        detours — Microsoft Detours C++ template
        inline — inline hook / trampoline points
        Params: method (required), addr or func_name.

    hook_targets — Find interesting functions to hook.
        Params: category (optional: network|file|crypto|registry|process).

    protocol — Detect protocol usage in the binary.
        Params: addr (optional).

    protocol_spec — Recover protocol structure. Requires `what`:
        parsers, serializers, handlers, endpoints, tls_config, socket_flow,
        packet_struct, magic_numbers, state_machine, reconstruct,
        trace_handler, export_spec.

    taint — Trace data flow from a source to dangerous sinks.
        Params: source (required: import name or address).

    taint_sources — List all taint sources (imports + blackboard IOCs).

    taint_report — Full taint report: all sources → all reachable sinks.

    eval — Run custom Python with access to all sub-tool functions, IDA SDK,
        and stdlib. Params: code (required).
    """
    try:
        if action == "detect":
            return _run_detect(addr, limit, include_anti_debug, include_drm, kwargs.get("max_string_scan", 5000))

        elif action == "decode":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for decode")
            ea, err = validate_addr(addr)
            if err:
                return err
            return _deobf_mod.deobfuscate(action="decode_attempt", addr=addr, limit=limit, key=key)

        elif action == "analyze":
            if not what:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "what required for analyze",
                    hint=f"Available: {', '.join(sorted(_ANALYZE_DISPATCH.keys()))}",
                )
            return _run_analyze(what, addr, limit, **kwargs)

        elif action == "hook":
            if not method:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "method required for hook",
                    hint="Available: frida, detours, inline",
                )
            if not addr and not func_name:
                return make_error(MCPError.INVALID_ARGS, "addr or func_name required for hook")
            return _run_hook(method, addr, func_name, category)

        elif action == "hook_targets":
            return _run_hook_targets(category, addr, limit)

        elif action == "protocol":
            return _run_protocol(addr, limit)

        elif action == "protocol_spec":
            if not what:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "what required for protocol_spec",
                    hint=f"Available: {', '.join(sorted(_PROTOCOL_SPEC_ACTIONS))}",
                )
            return _run_protocol_spec(what, addr, limit)

        elif action == "taint":
            if not source and not addr:
                return make_error(MCPError.INVALID_ARGS, "source or addr required for taint")
            return _run_taint(source, addr, max_depth, max_paths)

        elif action == "taint_sources":
            return _run_taint_sources(limit)

        elif action == "taint_report":
            return _run_taint_report(max_depth, max_paths)

        elif action == "eval":
            return _run_eval(code, kwargs.get("globals"))

        else:
            return make_error(
                MCPError.INVALID_ARGS,
                f"Unknown security action: '{action}'",
                hint="Available: detect, decode, analyze, hook, hook_targets, protocol, "
                     "protocol_spec, taint, taint_sources, taint_report, eval",
            )

    except Exception as e:
        return handle_error(e)
