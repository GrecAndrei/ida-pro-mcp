"""
Packer / protector / anti-cheat detection for game cheat binaries.

Orchestrates the existing MCP tool surface (entropy, binary_info, data,
string_ops, deobfuscate, segments) to produce a single assessment of:

  1. Whether the binary is packed and with what packer (UPX, MPRESS,
     VMProtect, Themida, custom, unknown).
  2. Anti-debug / anti-VM indicators.
  3. Anti-anti-cheat strings (EAC / BattlEye / nProtect / Vanguard /
     Xigncode references) that suggest the target is a game cheat.
  4. A recommended workflow category (auto_unpack, guided_unpack,
     manual_only, do_not_unpack) and a structured workflow breakdown
     (concrete tool calls the LLM can fire + external steps the user
     must do).
  5. A script action that lets the LLM run its own detection logic in
     the packer's namespace.

No new dependencies. No entropy / pattern matching reinvented where
existing tools already do it.
"""
from __future__ import annotations

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


_PACKER_SIGNATURES = [
    {
        "name": "upx_section_names",
        "weight": 0.9,
        "evidence": [],
        "label": "UPX",
        "check": "section_names",
        "patterns": [".UPX0", ".UPX1", ".UPX2", "UPX!", "UPX0", "UPX1"],
    },
    {
        "name": "upx_marker_strings",
        "weight": 0.95,
        "evidence": [],
        "label": "UPX",
        "check": "strings",
        "patterns": ["$Info: This file is packed with the UPX executable packer", "$Id: UPX"],
    },
    {
        "name": "mpress_section_names",
        "weight": 0.85,
        "evidence": [],
        "label": "MPRESS",
        "check": "section_names",
        "patterns": [".MPRESS1", ".MPRESS2"],
    },
    {
        "name": "vmprotect_strings",
        "weight": 0.9,
        "evidence": [],
        "label": "VMProtect",
        "check": "strings",
        "patterns": ["VMProtect", "VMP0", "VMP1", "VMP2", ".vmp0", ".vmp1"],
    },
    {
        "name": "vmprotect_section_names",
        "weight": 0.85,
        "evidence": [],
        "label": "VMProtect",
        "check": "section_names",
        "patterns": [".vmp0", ".vmp1", ".vmp2"],
    },
    {
        "name": "themida_strings",
        "weight": 0.85,
        "evidence": [],
        "label": "Themida",
        "check": "strings",
        "patterns": ["Themida", "WinLicense", ".themida"],
    },
    {
        "name": "aspack_section_names",
        "weight": 0.8,
        "evidence": [],
        "label": "ASPack",
        "check": "section_names",
        "patterns": [".aspack", ".adata"],
    },
    {
        "name": "petite_section_names",
        "weight": 0.8,
        "evidence": [],
        "label": "Petite",
        "check": "section_names",
        "patterns": [".petite"],
    },
    {
        "name": "kkrunchy_section_names",
        "weight": 0.75,
        "evidence": [],
        "label": "kkrunchy",
        "check": "section_names",
        "patterns": [".kkrunchy", "kkrunchy"],
    },
]

# Anti-debug / anti-VM API indicators. These appear in the binary's import
# table or as string references. Most packers strip imports, so a positive
# match on an unpacked binary strongly suggests malware / cheat intent.
_ANTI_DEBUG_APIS = [
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "NtQuerySystemInformation",
    "OutputDebugStringA",
    "OutputDebugStringW",
    "NtSetInformationThread",
    "NtClose",
    "UnhandledExceptionFilter",
    "NtQueryObject",
]

# Anti-VM / sandbox indicators (string references, not imports).
_ANTI_VM_STRINGS = [
    "SbieDll.dll",        # Sandboxie
    "Sbx",
    "vmtoolsd.exe",       # VMware
    "vmware",             # VMware
    "vboxservice",        # VirtualBox
    "vboxguest",          # VirtualBox
    "vbox",               # VirtualBox generic
    "qemu",               # QEMU
    "xen",                # Xen
    "cuckoomon",          # Cuckoo
    "snxhk.dll",          # Avast sandbox
    "sbiedll",            # Sandboxie alt
    "vmcheck",
    "wine_get_unix_file_name",
]

# Game anti-cheat references. When a binary that looks like a cheat DLL
# references these strings, the recommendation flips to do_not_unpack and
# we surface a warning.
_GAME_ANTI_CHEAT = {
    "EasyAntiCheat": ["EasyAntiCheat", "easyanticheat", "eac.dll", "eac_x64.dll", "EasyAntiCheat_x64.sys"],
    "BattlEye": ["BattlEye", "BEDaisy", "BEClient", "BEService", "battleye"],
    "nProtect": ["nProtect", "GameGuard", "GGAuth", "GameMon.des", "npptnt2.sys"],
    "Vanguard": ["Vanguard", "vgk.sys", "vgkboot.sys", "Riot Vanguard"],
    "Xigncode": ["Xigncode", "XIGNCODE", "XignCodeService"],
    "FACEIT": ["FACEIT", "faceit_ac"],
    "PunkBuster": ["PunkBuster", "PnkBstrA", "PnkBstrB", "pbcl.dll", "pbag.dll"],
    "EAC_Alt": ["anticheat", "anti-cheat"],
}


_DISPLAY_NAME = {
    "upx": "UPX",
    "mpress": "MPRESS",
    "aspack": "ASPack",
    "petite": "Petite",
    "kkrunchy": "kkrunchy",
    "vmprotect": "VMProtect",
    "themida": "Themida",
    "custom_or_unknown": "custom/unknown protector",
    "none": "unpacked",
}


# ---------------------------------------------------------------------------
# Cheap raw-byte / metadata probes
# ---------------------------------------------------------------------------

def _scan_section_names() -> list[str]:
    names: list[str] = []
    try:
        for ea in idautils.Segments():
            seg = ida_segment.getseg(ea)
            if not seg:
                continue
            try:
                name = ida_segment.get_segm_name(seg) or ""
            except Exception:
                name = ""
            if name:
                names.append(name)
    except Exception:
        pass
    return names


def _scan_string_references(max_strings: int = 5000) -> list[str]:
    """Return lowercased string contents from IDA's string list, capped.

    Uses idaapi.get_strlist_qty + get_string to avoid iterating the whole
    IDB. Cheap on packed binaries (strlist is small) and bounded on large
    unpacked binaries.
    """
    out: list[str] = []
    try:
        if not hasattr(idaapi, "get_strlist_qty"):
            return out
        qty = int(idaapi.get_strlist_qty())
        n = min(qty, max_strings)
        for i in range(n):
            try:
                si = idaapi.get_string(i)
                if not si:
                    continue
                text = ""
                try:
                    if hasattr(si, "str"):
                        text = str(si.str or "")
                except Exception:
                    pass
                if not text and hasattr(si, "contents"):
                    try:
                        raw = bytes(si.contents or b"")
                        text = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    except Exception:
                        text = ""
                if text:
                    out.append(text.lower())
            except Exception:
                continue
    except Exception:
        pass
    return out


def _scan_import_names() -> list[str]:
    names: list[str] = []
    try:
        for i in range(int(ida_nalt.get_import_module_qty())):
            try:
                def cb(ea, name, ordinal):
                    if name:
                        names.append(str(name))
                    return True
                ida_nalt.enum_import_names(i, cb)
            except Exception:
                continue
    except Exception:
        pass
    return names


def _read_section_bytes(seg_name_pattern: str, max_bytes: int = 0x10000) -> bytes:
    """Read up to max_bytes from the first segment whose name matches pattern."""
    pat = seg_name_pattern.lower()
    try:
        for ea in idautils.Segments():
            seg = ida_segment.getseg(ea)
            if not seg:
                continue
            try:
                name = (ida_segment.get_segm_name(seg) or "").lower()
            except Exception:
                name = ""
            if pat in name:
                size = int(seg.size()) if seg.size() else 0
                size = min(size, max_bytes)
                if size <= 0:
                    return b""
                try:
                    return bytes(ida_bytes.get_bytes(seg.start_ea, size) or b"")
                except Exception:
                    return b""
    except Exception:
        pass
    return b""


def _section_entropy_quick() -> dict:
    """Return per-segment entropy via the existing binary_info tool."""
    try:
        try: from .binary_info import binary_info
        except ImportError: from binary_info import binary_info  # type: ignore[import-not-found]
        result = binary_info(action="sections", limit=32)
        sections = result.get("sections") if isinstance(result, dict) else None
        if not sections:
            return {}
        out = {}
        for s in sections:
            if not isinstance(s, dict):
                continue
            name = str(s.get("name") or "")
            ent = s.get("entropy")
            if name and isinstance(ent, (int, float)):
                out[name] = float(ent)
        return out
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Indicator evaluation (pure-Python; unit-tested)
# ---------------------------------------------------------------------------

def _evaluate_signatures(section_names: list[str], strings: list[str]) -> list[dict]:
    indicators: list[dict] = []
    s_names_lc = [s.lower() for s in section_names]
    s_blob = "\n".join(strings).lower()
    for sig in _PACKER_SIGNATURES:
        matched = False
        evidence: list[str] = []
        if sig["check"] == "section_names":
            for pat in sig["patterns"]:
                p = pat.lower()
                for n in s_names_lc:
                    if p in n:
                        matched = True
                        evidence.append(n)
        elif sig["check"] == "strings":
            for pat in sig["patterns"]:
                if pat.lower() in s_blob:
                    matched = True
                    evidence.append(pat)
        # If strings are empty (packed binary stripped), also fall back to
        # scanning section bytes for the literal pattern.
        if not matched and sig["check"] == "strings":
            for pat in sig["patterns"]:
                pat_bytes = pat.encode("utf-8", errors="ignore")
                if not pat_bytes or len(pat_bytes) < 4:
                    continue
                for sec_name in s_names_lc:
                    blob = _read_section_bytes(sec_name, max_bytes=0x20000)
                    if blob and pat_bytes in blob:
                        matched = True
                        evidence.append(f"section:{sec_name}")
                        break
                if matched:
                    break
        indicators.append({
            "name": sig["name"],
            "label": sig["label"],
            "weight": sig["weight"],
            "matched": matched,
            "evidence": evidence[:5],
        })
    return indicators


def _evaluate_entropy_indicators(section_entropy: dict) -> list[dict]:
    out: list[dict] = []
    text_segments = []
    for name, ent in section_entropy.items():
        low = name.lower()
        if low in (".text", "text", "code", ".code"):
            text_segments.append((name, ent))
    text_ent = max((e for _, e in text_segments), default=None)
    if text_ent is not None:
        out.append({
            "name": "text_segment_entropy",
            "weight": 0.6,
            "matched": bool(text_ent >= 7.2),
            "evidence": [f"{text_ent:.3f} (threshold 7.2)"] if text_ent >= 7.2 else [f"{text_ent:.3f}"],
        })
    high_count = sum(1 for e in section_entropy.values() if e >= 7.2)
    if high_count:
        out.append({
            "name": "high_entropy_segments",
            "weight": 0.3,
            "matched": high_count >= 2,
            "evidence": [f"{high_count} segment(s) >= 7.2"],
        })
    return out


def _evaluate_anti_analysis(imports: list[str], strings: list[str]) -> list[dict]:
    out: list[dict] = []
    imports_lc = [i.lower() for i in imports]
    s_blob = "\n".join(strings)
    anti_debug_hits = [a for a in _ANTI_DEBUG_APIS if a.lower() in imports_lc]
    if anti_debug_hits:
        out.append({
            "name": "anti_debug_imports",
            "weight": 0.4,
            "matched": True,
            "evidence": anti_debug_hits[:8],
        })
    anti_debug_strings = [a for a in _ANTI_DEBUG_APIS if a.lower() in s_blob]
    if anti_debug_strings and not anti_debug_hits:
        out.append({
            "name": "anti_debug_strings",
            "weight": 0.25,
            "matched": True,
            "evidence": anti_debug_strings[:8],
        })
    anti_vm_hits = [a for a in _ANTI_VM_STRINGS if a.lower() in s_blob]
    if anti_vm_hits:
        out.append({
            "name": "anti_vm_strings",
            "weight": 0.25,
            "matched": True,
            "evidence": anti_vm_hits[:8],
        })
    return out


def _evaluate_drm(strings: list[str], imports: list[str]) -> dict:
    s_blob = "\n".join(strings).lower()
    i_blob = "\n".join(imports).lower()
    anti_cheat_modules: list[str] = []
    anti_cheat_strings: list[str] = []
    for ac_name, patterns in _GAME_ANTI_CHEAT.items():
        for pat in patterns:
            pl = pat.lower()
            if pl in i_blob:
                anti_cheat_modules.append(f"{ac_name}:{pat}")
            elif pl in s_blob:
                anti_cheat_strings.append(f"{ac_name}:{pat}")
    anti_cheat_modules = sorted(set(anti_cheat_modules))
    anti_cheat_strings = sorted(set(anti_cheat_strings))
    indicators = []
    if anti_cheat_modules:
        indicators.append("anti_cheat_imports")
    if anti_cheat_strings:
        indicators.append("anti_cheat_string_ref")
    note = None
    if anti_cheat_modules or anti_cheat_strings:
        note = (
            "Binary references game anti-cheat. Treat as adversarial: do not "
            "execute in a non-isolated environment. Unpacking may trigger AC "
            "detection on protected games."
        )
    return {
        "anti_cheat_modules": anti_cheat_modules,
        "anti_cheat_strings": anti_cheat_strings,
        "indicators": indicators,
        "note": note,
    }


def _classify(indicators: list[dict], drm: dict) -> dict:
    """Pick the most likely packer + a confidence score in [0, 1]."""
    label_votes: dict[str, float] = {}
    matched = [i for i in indicators if i["matched"]]
    for ind in matched:
        label = ind.get("label")
        if not label:
            continue
        label_votes[label] = label_votes.get(label, 0.0) + float(ind.get("weight", 0.0))
    if not label_votes:
        for ind in matched:
            if ind["name"] in ("text_segment_entropy", "high_entropy_segments"):
                return {
                    "packer": "custom_or_unknown",
                    "confidence": 0.4,
                    "fallback": "high_entropy_no_signature",
                }
        return {"packer": "none", "confidence": 0.0, "fallback": None}
    best_label = max(label_votes, key=label_votes.get)
    raw = label_votes[best_label]
    # Confidence: a single high-weight signature match is strong evidence
    # (weight IS the confidence); multiple matches accumulate. Cap at 0.98.
    confidence = min(0.98, max(0.2, raw))
    return {
        "packer": best_label.lower(),
        "confidence": round(confidence, 2),
        "fallback": "custom_or_unknown" if confidence < 0.6 else None,
    }


def _recommend(classification: dict, matched_count: int, drm: dict) -> tuple[str, str | None]:
    packer = classification.get("packer") or "none"
    confidence = float(classification.get("confidence") or 0.0)
    display = _DISPLAY_NAME.get(packer, packer)

    if drm.get("anti_cheat_modules") or drm.get("anti_cheat_strings"):
        return (
            "do_not_unpack",
            "Anti-cheat references detected. Do not unpack or execute on a "
            "production system. Continue static analysis on the packed "
            "binary only.",
        )

    if packer == "none" and matched_count == 0:
        return ("none", None)
    if packer in ("upx", "mpress", "aspack", "petite", "kkrunchy") and confidence >= 0.7:
        return ("auto_unpack", None)
    if packer in ("vmprotect", "themida"):
        return (
            "guided_unpack",
            f"{display} requires a debug-based OEP finding workflow. "
            "Use hardware execution breakpoints at suspicious transitions and "
            "trace to OEP.",
        )
    if packer == "custom_or_unknown" and confidence >= 0.4:
        return (
            "manual_only",
            "Packing signature not in the known list. Entropy and string "
            "behavior suggest obfuscation. Use trace-based OEP finding with "
            "anti-debug bypass.",
        )
    if confidence < 0.4:
        return (
            "manual_only",
            "Low confidence. No strong signature match. Re-run with "
            "packer(action='profile') for a deeper scan.",
        )
    return ("guided_unpack", None)


# ---------------------------------------------------------------------------
# Structured workflow: concrete tool calls the LLM can fire, plus external
# steps the user must perform. No bash-as-string, no <placeholder>s in
# tool_call arguments — if we don't have a real value we don't pretend.
# ---------------------------------------------------------------------------

def _workflow_for(classification: dict, drm: dict, binary_path: str) -> dict:
    """Build a structured workflow breakdown for the recommendation.

    Returns:
        {
          "static_steps": [{"tool": "...", "arguments": {...}, "purpose": "..."}],
          "external_steps": [{"description": "...", "user_action": True}],
        }
    """
    rec = (classification or {}).get("packer") or "none"
    static_steps: list[dict] = []
    external_steps: list[dict] = []

    if drm.get("anti_cheat_modules") or drm.get("anti_cheat_strings"):
        # do_not_unpack — keep static analysis only
        static_steps.extend([
            {"tool": "string_ops", "arguments": {"action": "indicators"},
             "purpose": "Confirm which anti-cheat strings are present"},
            {"tool": "deobfuscate", "arguments": {"action": "detect"},
             "purpose": "Look for string-decoding or anti-tamper patterns"},
            {"tool": "binary_info", "arguments": {"action": "sections"},
             "purpose": "Inspect section layout for unusual permissions"},
        ])
        return {"static_steps": static_steps, "external_steps": external_steps}

    if rec in ("upx", "mpress", "aspack", "petite", "kkrunchy"):
        # auto_unpack: user must run the unpacker CLI
        ext = {"description": (
            f"Run the {_DISPLAY_NAME.get(rec, rec)} unpacker to produce a clean "
            "binary. Then re-open the unpacked file in IDA."
        ), "user_action": True}
        # Suggest a command hint only if we know the binary path
        if binary_path:
            ext["command_hint"] = _suggest_unpack_command(rec, binary_path)
        external_steps.append(ext)
        static_steps.append({
            "tool": "entropy", "arguments": {"action": "section"},
            "purpose": "Confirm pre-unpack entropy distribution",
        })
        return {"static_steps": static_steps, "external_steps": external_steps}

    if rec in ("vmprotect", "themida"):
        # guided_unpack: concrete debug calls, no placeholders
        start_ea = _safe_start_ea()
        if start_ea:
            static_steps.append({
                "tool": "debug",
                "arguments": {"action": "add_hw_bp", "type": "execute",
                              "addr": hex(start_ea)},
                "purpose": "Hardware execution breakpoint at the entry point",
            })
        static_steps.extend([
            {"tool": "debug", "arguments": {"action": "start"},
             "purpose": "Start the binary under the debugger"},
            {"tool": "trace_analysis", "arguments": {"action": "anti_analysis_detect"},
             "purpose": "Identify anti-debug / anti-VM dispatchers in the trace"},
            {"tool": "trace_analysis", "arguments": {"action": "import_trace"},
             "purpose": "Capture the import resolution trace (decryption key)"},
        ])
        return {"static_steps": static_steps, "external_steps": external_steps}

    # manual_only / custom_or_unknown
    static_steps.extend([
        {"tool": "entropy", "arguments": {"action": "window", "window": 4096, "step": 2048},
         "purpose": "Sliding-window entropy scan to find OEP candidates"},
        {"tool": "deobfuscate", "arguments": {"action": "detect"},
         "purpose": "Identify obfuscation primitives"},
        {"tool": "trace_analysis", "arguments": {"action": "anti_analysis_detect"},
         "purpose": "Anti-analysis dispatchers"},
    ])
    return {"static_steps": static_steps, "external_steps": external_steps}


def _suggest_unpack_command(packer: str, binary_path: str) -> str | None:
    """Return a shell command hint the user can run, or None if unknown."""
    if not binary_path:
        return None
    name_map = {
        "upx": "upx -d",
        "mpress": "mpress -d",  # not all builds support -d
        "aspack": "aspack -d",  # aspack -d may be unsupported; user must verify
        "petite": "petite -d",
        "kkrunchy": "kkrunchy -d",
    }
    cmd = name_map.get(packer)
    if not cmd:
        return None
    return f"{cmd} {binary_path}"


def _safe_start_ea() -> int:
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_get_start_ea"):
            ea = int(ida_ida.inf_get_start_ea())
            if ea and ea != idaapi.BADADDR:
                return ea
    except Exception:
        pass
    return 0


# ---------------------------------------------------------------------------
# Per-process detection cache
# ---------------------------------------------------------------------------

_PCK_CACHE: dict = {}


def _packer_cached() -> dict | None:
    cached = _PCK_CACHE.get("last")
    return cached or None


def _packer_cache_set(result: dict) -> None:
    clean = {k: v for k, v in result.items() if not k.startswith("_")}
    _PCK_CACHE["last"] = clean


# ---------------------------------------------------------------------------
# Script action — let the LLM run its own detection in the packer namespace
# ---------------------------------------------------------------------------

# The script action exposes every packer helper + the IDA SDK + a few safe
# stdlib modules. The LLM is already trusted to call any tool; this just
# gives it a single round-trip to compose custom logic.

_SCRIPT_SAFE_BUILTINS = {
    "abs", "all", "any", "bin", "bool", "bytes", "callable", "chr",
    "dict", "divmod", "enumerate", "filter", "float", "format", "frozenset",
    "hash", "hex", "id", "int", "isinstance", "issubclass", "iter", "len",
    "list", "map", "max", "min", "next", "object", "oct", "ord", "pow",
    "print", "range", "repr", "reversed", "round", "set", "slice", "sorted",
    "str", "sum", "tuple", "type", "vars", "zip",
}


def _build_script_namespace(extra: dict | None = None) -> dict:
    """Build the namespace for packer(action='script') eval.

    Exposes packer helpers, IDA SDK, and a whitelisted set of builtins.
    Does NOT expose: open (file IO), exec, eval (nested), __import__.
    """
    import builtins as _b
    safe_b = {k: getattr(_b, k) for k in _SCRIPT_SAFE_BUILTINS if hasattr(_b, k)}
    ns: dict = {
        # packer internals
        "_classify": _classify,
        "_evaluate_signatures": _evaluate_signatures,
        "_evaluate_entropy_indicators": _evaluate_entropy_indicators,
        "_evaluate_anti_analysis": _evaluate_anti_analysis,
        "_evaluate_drm": _evaluate_drm,
        "_scan_section_names": _scan_section_names,
        "_scan_string_references": _scan_string_references,
        "_scan_import_names": _scan_import_names,
        "_section_entropy_quick": _section_entropy_quick,
        "_workflow_for": _workflow_for,
        "_recommend": _recommend,
        "_PACKER_SIGNATURES": _PACKER_SIGNATURES,
        "_GAME_ANTI_CHEAT": _GAME_ANTI_CHEAT,
        "_DISPLAY_NAME": _DISPLAY_NAME,
        # IDA SDK (best effort; absent in test stub)
        "idaapi": sys.modules.get("idaapi"),
        "idautils": sys.modules.get("idautils"),
        "idc": sys.modules.get("idc"),
        "ida_bytes": sys.modules.get("ida_bytes"),
        "ida_nalt": sys.modules.get("ida_nalt"),
        "ida_segment": sys.modules.get("ida_segment"),
        "ida_entry": sys.modules.get("ida_entry"),
        "ida_kernwin": sys.modules.get("ida_kernwin"),
        "ida_funcs": sys.modules.get("ida_funcs"),
        "ida_ida": sys.modules.get("ida_ida"),
        "ida_name": sys.modules.get("ida_name"),
        # stdlib
        "json": __import__("json"),
        "os": __import__("os"),
        "re": __import__("re"),
        "time": __import__("time"),
        "math": __import__("math"),
        "struct": __import__("struct"),
        "collections": __import__("collections"),
        "hashlib": __import__("hashlib"),
        # limited builtins
        "__builtins__": safe_b,
    }
    if extra:
        for k, v in extra.items():
            if isinstance(k, str) and k.isidentifier():
                ns[k] = v
    return ns


# ---------------------------------------------------------------------------
# Top-level handler
# ---------------------------------------------------------------------------

@tool
def packer(
    action: Annotated[Literal["detect", "profile", "guide", "status", "script"],
                      "Action: detect|profile|guide|status|script"] = "detect",
    include_anti_debug: Annotated[bool, "Include anti-debug/anti-VM detection"] = True,
    include_drm: Annotated[bool, "Include game anti-cheat detection"] = True,
    code: Annotated[Optional[str], "Python source for action='script'"] = None,
    max_string_scan: Annotated[int, "Cap on string-list size to scan"] = 5000,
    **kwargs,
) -> Any:
    """
    Packer / protector / anti-cheat detection and guided unpack workflow.

    ACTIONS:

    detect - Quick packer classification + anti-debug/anti-cheat indicators.
        Reads sections, strings, imports, and per-section entropy. Returns
        {binary, indicators[], drm{}, entropy, classification{...},
         recommendation, warning, workflow{static_steps,external_steps}}.

    profile - Same as detect, also runs entropy(packed_detect) for a
        sliding-window view. Slower on large binaries.

    guide - Return the workflow from the cached detection without re-scanning.
        Use after 'detect' / 'profile' to drive the next phase. workflow has
        concrete static_steps (tool calls the LLM can fire) and
        external_steps (things only the user can do).

    status - Return the cached detection result; falls back to detect.

    script - Run a Python expression in the packer's namespace. The
        expression has access to every detection helper, the IDA SDK,
        json/os/re/math/struct/collections/hashlib, and a whitelisted
        builtin set. Returns the value of the expression. Use this when
        the canned detection is not enough — e.g. custom signature
        scan, custom entropy threshold, or reasoning over indicators.
        Example: packer(action='script',
                        code='_classify(_evaluate_signatures(["UPX0"], []), {})')
    """
    try:
        if action == "script":
            return _run_script(code, kwargs.get("globals"))

        if action == "guide":
            cached = _packer_cached()
            if not cached:
                return {
                    "ok": True,
                    "workflow": {"static_steps": [], "external_steps": []},
                    "note": "No prior detection. Run packer(action='detect') first.",
                }
            return {
                "ok": True,
                "workflow": cached.get("workflow", {}),
                "classification": cached.get("classification"),
                "recommendation": cached.get("recommendation"),
                "warning": cached.get("warning"),
            }

        if action == "status":
            cached = _packer_cached()
            if cached:
                return {"ok": True, "cached": True, **cached}

        # detect / profile
        section_names = _scan_section_names()
        section_entropy = _section_entropy_quick()
        if action == "profile":
            try:
                try: from .entropy import entropy
                except ImportError: from entropy import entropy  # type: ignore[import-not-found]
                ent_result = entropy(action="packed_detect", limit=20)
            except Exception:
                ent_result = {}
        else:
            ent_result = {}
        strings = _scan_string_references(max_strings=max_string_scan)
        imports = _scan_import_names()

        indicators: list[dict] = []
        indicators.extend(_evaluate_signatures(section_names, strings))
        indicators.extend(_evaluate_entropy_indicators(section_entropy))
        if include_anti_debug:
            indicators.extend(_evaluate_anti_analysis(imports, strings))
        drm: dict = {"anti_cheat_modules": [], "anti_cheat_strings": [], "indicators": [], "note": None}
        if include_drm:
            drm = _evaluate_drm(strings, imports)
        if ent_result:
            windows = ent_result.get("windows") if isinstance(ent_result, dict) else None
            if isinstance(windows, list) and windows:
                indicators.append({
                    "name": "sliding_window_packed_detect",
                    "weight": 0.3,
                    "matched": True,
                    "evidence": [str(w)[:80] for w in windows[:3]],
                })

        classification = _classify(indicators, drm)
        matched_count = sum(1 for i in indicators if i["matched"])
        recommendation, warning = _recommend(classification, matched_count, drm)

        binary_path = ""
        try:
            binary_path = idaapi.get_input_file_path() or ""
        except Exception:
            binary_path = ""
        workflow = _workflow_for(classification, drm, binary_path)

        result = {
            "ok": True,
            "ts": round(time.time(), 3),
            "binary": os.path.basename(binary_path) if binary_path else "",
            "binary_path": binary_path,
            "indicators": indicators,
            "drm": drm,
            "entropy": section_entropy,
            "classification": classification,
            "recommendation": recommendation,
            "warning": warning,
            "workflow": workflow,
            "_profile": action == "profile",
        }
        _packer_cache_set(result)
        return result
    except Exception as e:
        return handle_error(e, "packer")


# ---------------------------------------------------------------------------
# Script evaluation
# ---------------------------------------------------------------------------

_MAX_SCRIPT_CHARS = 16384
_MAX_SCRIPT_OUTPUT = 200000


def _run_script(code: str | None, extra_globals: dict | None) -> dict:
    if not code or not isinstance(code, str):
        return {
            "ok": False,
            "error": "packer(action='script') requires non-empty 'code' (Python expression)",
        }
    if len(code) > _MAX_SCRIPT_CHARS:
        return {
            "ok": False,
            "error": f"script code exceeds {_MAX_SCRIPT_CHARS} characters",
        }
    # Disallow obviously dangerous builtins that the whitelist does not include.
    forbidden = {"open", "exec", "eval", "__import__", "compile", "input"}
    for tok in forbidden:
        if tok + "(" in code or tok + " " in code or code.startswith(tok):
            # Loose check; refuse anything that looks like the dangerous
            # builtin is being used. False positives are acceptable here —
            # the LLM can wrap the value in a helper if needed.
            return {
                "ok": False,
                "error": f"script may not use '{tok}'; use packer helpers or IDA SDK instead",
            }
    ns = _build_script_namespace(extra_globals)
    try:
        # Try expression first; fall back to a statement suite.
        try:
            value = eval(compile(code, "<packer-script>", "eval"), ns)
        except SyntaxError:
            exec(compile(code, "<packer-script>", "exec"), ns)
            value = ns.get("result", None)
    except Exception as e:
        return {
            "ok": False,
            "error": f"script raised: {type(e).__name__}: {e}",
        }
    # Truncate large outputs so a runaway script can't blow the context window.
    serialized: Any = value
    try:
        if isinstance(serialized, (dict, list, str, int, float, bool, type(None))):
            raw = json.dumps(serialized, default=str, ensure_ascii=False)
            if len(raw) > _MAX_SCRIPT_OUTPUT:
                raw = raw[:_MAX_SCRIPT_OUTPUT] + "...[truncated]"
                try:
                    serialized = json.loads(raw)
                except Exception:
                    serialized = {"_truncated": True, "preview": raw}
    except Exception:
        pass
    return {"ok": True, "result": serialized}
