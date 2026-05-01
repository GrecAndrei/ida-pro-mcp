
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import hashlib
import re
from collections import OrderedDict


# ============================================================================
# YARA_HUNT - Surgical Pattern Matching with Context & Attribution
# ============================================================================

# LRU cache for compiled YARA rules: hash -> compiled_rule
_RULE_CACHE = OrderedDict()
_MAX_RULE_CACHE = 32


def _get_rules_dir():
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(_script_dir))))
    return os.path.join(_repo_root, "rules")


def _load_rule_text(spec: str) -> tuple[Optional[str], Optional[dict]]:
    if ("rule" in spec and "{" in spec) or ("\n" in spec and "strings:" in spec):
        return spec, None
    rule_path, path_err = validate_path_safe(spec)
    if path_err:
        return None, path_err
    if not os.path.exists(rule_path):
        return None, make_error(MCPError.FILE_NOT_FOUND, f"Rule file not found: {rule_path}")
    with open(rule_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read(), None


def _parse_hex_pattern(expr: str):
    tokens = [t.strip() for t in expr.strip().split() if t.strip()]
    if not tokens:
        return None
    out = []
    for tok in tokens:
        up = tok.upper()
        if up in ("??", "?"):
            out.append(None)
            continue
        if len(up) != 2 or any(c not in "0123456789ABCDEF?" for c in up):
            return None
        hi = None if up[0] == "?" else int(up[0], 16)
        lo = None if up[1] == "?" else int(up[1], 16)
        out.append((hi, lo))
    return out


def _extract_fallback_patterns(rule_text: str):
    literal_pat = re.compile(r'"([^"\\]*(?:\\.[^"\\]*)*)"')
    hex_pat = re.compile(r"\{([0-9A-Fa-f?\s]+)\}")
    literals = []
    hexes = []
    for m in literal_pat.finditer(rule_text):
        raw = m.group(1)
        try:
            decoded = bytes(raw, "utf-8").decode("unicode_escape")
        except Exception:
            decoded = raw
        if decoded:
            literals.append(decoded.encode("utf-8", errors="ignore"))
    for m in hex_pat.finditer(rule_text):
        parsed = _parse_hex_pattern(m.group(1))
        if parsed:
            hexes.append(parsed)
    return literals, hexes


def _match_hex_window(window: bytes, pattern) -> bool:
    if len(window) < len(pattern):
        return False
    for i, spec in enumerate(pattern):
        b = window[i]
        if spec is None:
            continue
        hi, lo = spec
        if hi is not None and ((b >> 4) & 0xF) != hi:
            return False
        if lo is not None and (b & 0xF) != lo:
            return False
    return True


def _find_hex_matches(data: bytes, pattern):
    plen = len(pattern)
    if plen == 0 or len(data) < plen:
        return []
    hits = []
    for i in range(0, len(data) - plen + 1):
        if _match_hex_window(data[i : i + plen], pattern):
            hits.append(i)
    return hits


def _get_function_for_addr(ea: int) -> Optional[str]:
    func = idaapi.get_func(ea)
    if func:
        return idc.get_func_name(func.start_ea) or None
    return None


def _get_match_context(region_base: int, match_offset: int, data: bytes, context_bytes: int = 16):
    """Get hex/ascii context around a match."""
    abs_addr = region_base + match_offset
    start = max(0, match_offset - context_bytes)
    end = min(len(data), match_offset + context_bytes)
    context_data = data[start:end]
    hex_part = " ".join(f"{b:02x}" for b in context_data)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in context_data)
    return {
        "addr": hex(abs_addr),
        "hex_context": hex_part,
        "ascii_context": ascii_part,
        "match_offset_in_context": match_offset - start,
    }


def _extract_strings_from_match(region_base: int, match_offset: int, data: bytes, max_strings: int = 5):
    """Extract ASCII/UTF-16 strings near a match."""
    strings = []
    start = max(0, match_offset - 64)
    end = min(len(data), match_offset + 128)
    window = data[start:end]
    # ASCII
    i = 0
    while i < len(window):
        j = i
        while j < len(window) and 32 <= window[j] <= 126:
            j += 1
        if j - i >= 4:
            strings.append({
                "addr": hex(region_base + start + i),
                "text": window[i:j].decode("ascii", errors="replace"),
                "encoding": "ascii",
            })
            if len(strings) >= max_strings:
                break
        i = j + 1 if j == i else j
    # UTF-16-LE
    if len(strings) < max_strings:
        i = 0
        while i < len(window) - 1:
            j = i
            while j < len(window) - 1 and 32 <= window[j] <= 126 and window[j+1] == 0:
                j += 2
            if j - i >= 8:
                try:
                    text = window[i:j].decode("utf-16-le", errors="replace")
                    strings.append({
                        "addr": hex(region_base + start + i),
                        "text": text,
                        "encoding": "utf-16-le",
                    })
                    if len(strings) >= max_strings:
                        break
                except Exception:
                    pass
            i = j + 2 if j == i else j
    return strings


def _compile_rule_cached(rule_text: str, yara_module):
    """Compile a YARA rule with LRU caching."""
    rule_hash = hashlib.sha256(rule_text.encode()).hexdigest()
    if rule_hash in _RULE_CACHE:
        _RULE_CACHE.move_to_end(rule_hash)
        return _RULE_CACHE[rule_hash]
    compiled = yara_module.compile(source=rule_text)
    _RULE_CACHE[rule_hash] = compiled
    if len(_RULE_CACHE) > _MAX_RULE_CACHE:
        _RULE_CACHE.popitem(last=False)
    return compiled


@tool
@idaread
def yara_hunt(
    action: Annotated[Literal[
        "scan", "compile", "list_rules", "match_context", "extract_strings", "xref_matches"
    ], "Action: scan|compile|list_rules|match_context|extract_strings|xref_matches"],
    rules: Annotated[Optional[str], "YARA rules text or file path"] = None,
    addr: Annotated[Optional[str], "Specific address or segment to scan"] = None,
    size: Annotated[int, "Scan size (if addr specified)"] = 0,
    context_bytes: Annotated[int, "Context bytes around match (for match_context)"] = 16,
    include_func: Annotated[bool, "Include function attribution for matches"] = True,
    **kwargs
) -> dict:
    """
    Surgical pattern matching using YARA with context extraction and function attribution.

    Actions:
    - scan: Scan the binary or a memory range with YARA rules.
    - compile: Verify that a YARA rule string is valid.
    - list_rules: List pre-defined YARA rules in the 'rules/' directory.
    - match_context: Scan and return matches with surrounding hex/ascii context.
    - extract_strings: Scan and extract strings near each match.
    - xref_matches: Scan and find cross-references to matched addresses.

    Arguments:
    - rules: YARA rule text, file path, or rule name from rules/ directory.
    - addr: Start address for targeted scan. If omitted, scans all segments.
    - size: Number of bytes to scan from addr.
    - context_bytes: Bytes of context to include around each match.
    - include_func: Include function name for each match.
    """
    try:
        rules_dir = _get_rules_dir()

        if action == "list_rules":
            if not os.path.exists(rules_dir):
                os.makedirs(rules_dir, exist_ok=True)
            files = [f for f in os.listdir(rules_dir) if f.endswith(".yar") or f.endswith(".yara")]
            return {"ok": True, "rules": files, "dir": rules_dir}

        yara = None
        try:
            import yara
        except ImportError:
            yara = None

        if action == "compile":
            if not rules:
                return make_error(MCPError.INVALID_ARGS, "rules required")
            if yara is not None:
                try:
                    yara.compile(source=rules)
                    return {"ok": True, "status": "Valid YARA rule", "engine": "yara-python"}
                except Exception as e:
                    return make_error(MCPError.INVALID_ARGS, f"YARA compilation failed: {e}")
            rule_text, load_err = _load_rule_text(rules)
            if load_err:
                return load_err
            literal_patterns, hex_patterns = _extract_fallback_patterns(rule_text or "")
            if not literal_patterns and not hex_patterns:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "Fallback validator could not parse any literal/hex pattern from rule",
                    hint="Install yara-python for full syntax validation.",
                )
            return {
                "ok": True,
                "status": "Rule accepted by fallback parser",
                "engine": "fallback-pattern-scanner",
                "literal_patterns": len(literal_patterns),
                "hex_patterns": len(hex_patterns),
            }

        if action in ("scan", "match_context", "extract_strings", "xref_matches"):
            if not rules:
                return make_error(MCPError.INVALID_ARGS, "rules (text or path) required")

            rule_text, load_err = _load_rule_text(rules)
            if load_err:
                return load_err

            compiled = None
            if yara is not None:
                try:
                    if "rule" in rules and "{" in rules:
                        compiled = _compile_rule_cached(rules, yara)
                    else:
                        rule_path, err = validate_path_safe(rules)
                        if err:
                            return err
                        with open(rule_path, "r", encoding="utf-8", errors="replace") as f:
                            file_text = f.read()
                        compiled = _compile_rule_cached(file_text, yara)
                except Exception as e:
                    return make_error(MCPError.INVALID_ARGS, f"YARA compilation failed: {e}")
            else:
                literal_patterns, hex_patterns = _extract_fallback_patterns(rule_text or "")
                if not literal_patterns and not hex_patterns:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "Fallback scanner could not extract literal/hex patterns from rule text",
                        hint="Install yara-python for full YARA support or include quoted strings / hex byte patterns.",
                    )

            # Get data to scan
            scan_regions = []
            if addr:
                ea = parse_address(addr)
                scan_size = size if size > 0 else 0x1000
                data = ida_bytes.get_bytes(ea, scan_size)
                if not data:
                    return make_error(MCPError.ADDRESS_INVALID, hex(ea))
                scan_regions.append((ea, data))
            else:
                for seg_ea in idautils.Segments():
                    seg = idaapi.getseg(seg_ea)
                    if not seg:
                        continue
                    data = ida_bytes.get_bytes(seg.start_ea, seg.size())
                    if data:
                        scan_regions.append((seg.start_ea, data))

            results = []
            if compiled is not None:
                for region_base, data in scan_regions:
                    matches = compiled.match(data=data)
                    for m in matches:
                        for off, name, val in m.strings:
                            abs_addr = region_base + off
                            entry = {
                                "rule": m.rule,
                                "addr": hex(abs_addr),
                                "string": name,
                                "data": val.hex(" ")[:32] if hasattr(val, "hex") else "",
                            }
                            if include_func:
                                entry["function"] = _get_function_for_addr(abs_addr)
                            if action in ("match_context", "extract_strings", "xref_matches"):
                                entry["context"] = _get_match_context(region_base, off, data, context_bytes)
                            if action in ("extract_strings", "xref_matches"):
                                entry["near_strings"] = _extract_strings_from_match(region_base, off, data)
                            if action == "xref_matches":
                                xrefs = []
                                for xref in idautils.XrefsTo(abs_addr, 0):
                                    xrefs.append(f"{hex(xref.frm)}  ({'code' if xref.iscode else 'data'})")
                                entry["xrefs"] = xrefs[:10]
                            results.append(entry)
                            if len(results) >= 500:
                                break
                        if len(results) >= 500:
                            break
                    if len(results) >= 500:
                        break
                return {"ok": True, "matches": results, "engine": "yara-python", "action": action}

            # Fallback lightweight matcher
            literal_patterns, hex_patterns = _extract_fallback_patterns(rule_text or "")
            for region_base, data in scan_regions:
                for pat in literal_patterns:
                    start = 0
                    while True:
                        idx = data.find(pat, start)
                        if idx < 0:
                            break
                        abs_addr = region_base + idx
                        entry = {
                            "rule": "fallback",
                            "addr": hex(abs_addr),
                            "string": f"literal:{pat[:48].decode('utf-8', errors='replace')}",
                        }
                        if include_func:
                            entry["function"] = _get_function_for_addr(abs_addr)
                        if action in ("match_context", "extract_strings", "xref_matches"):
                            entry["context"] = _get_match_context(region_base, idx, data, context_bytes)
                        if action in ("extract_strings", "xref_matches"):
                            entry["near_strings"] = _extract_strings_from_match(region_base, idx, data)
                        if action == "xref_matches":
                            xrefs = []
                            for xref in idautils.XrefsTo(abs_addr, 0):
                                xrefs.append(f"{hex(xref.frm)}  ({'code' if xref.iscode else 'data'})")
                            entry["xrefs"] = xrefs[:10]
                        results.append(entry)
                        if len(results) >= 500:
                            break
                        start = idx + 1
                    if len(results) >= 500:
                        break
                if len(results) >= 500:
                    break
                for hpat in hex_patterns:
                    for idx in _find_hex_matches(data, hpat):
                        abs_addr = region_base + idx
                        entry = {
                            "rule": "fallback",
                            "addr": hex(abs_addr),
                            "string": f"hex_len={len(hpat)}",
                        }
                        if include_func:
                            entry["function"] = _get_function_for_addr(abs_addr)
                        if action in ("match_context", "extract_strings", "xref_matches"):
                            entry["context"] = _get_match_context(region_base, idx, data, context_bytes)
                        if action in ("extract_strings", "xref_matches"):
                            entry["near_strings"] = _extract_strings_from_match(region_base, idx, data)
                        if action == "xref_matches":
                            xrefs = []
                            for xref in idautils.XrefsTo(abs_addr, 0):
                                xrefs.append(f"{hex(xref.frm)}  ({'code' if xref.iscode else 'data'})")
                            entry["xrefs"] = xrefs[:10]
                        results.append(entry)
                        if len(results) >= 500:
                            break
                    if len(results) >= 500:
                        break
                if len(results) >= 500:
                    break

            return {
                "ok": True,
                "matches": results,
                "engine": "fallback-pattern-scanner",
                "action": action,
                "note": "yara-python unavailable; used limited literal/hex matching fallback.",
            }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
