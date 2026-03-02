
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

@tool
@idaread
def yara_hunt(
    action: Annotated[Literal["scan", "compile", "list_rules"], "Action: scan|compile|list_rules"],
    rules: Annotated[Optional[str], "YARA rules text or file path"] = None,
    addr: Annotated[Optional[str], "Specific address or segment to scan"] = None,
    size: Annotated[int, "Scan size (if addr specified)"] = 0,
    **kwargs
) -> dict:
    """
    Surgical pattern matching using YARA.
    
    Actions:
    - scan: Scan the binary or a memory range with YARA rules.
    - compile: Verify that a YARA rule string is valid.
    - list_rules: List pre-defined YARA rules in the 'rules/' directory.
    """
    try:
        import re

        # Use script path to find rules, not os.getcwd() which may be wrong
        _script_dir = os.path.dirname(os.path.abspath(__file__))
        _repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(_script_dir))))
        rules_dir = os.path.join(_repo_root, "rules")

        def _load_rule_text(spec: str) -> tuple[Optional[str], Optional[dict]]:
            # inline rule source
            if ("rule" in spec and "{" in spec) or ("\n" in spec):
                return spec, None
            # file path
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

        # list_rules should work even when yara-python is unavailable
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
        
        if action == "scan":
            if not rules: return make_error(MCPError.INVALID_ARGS, "rules (text or path) required")

            rule_text, load_err = _load_rule_text(rules)
            if load_err:
                return load_err

            compiled = None
            if yara is not None:
                try:
                    if "rule" in rules and "{" in rules:  # Direct text
                        compiled = yara.compile(source=rules)
                    else:
                        rule_path, err = validate_path_safe(rules)
                        if err:
                            return err
                        compiled = yara.compile(filepath=rule_path)
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
                if not data: return make_error(MCPError.ADDRESS_INVALID, hex(ea))
                scan_regions.append((ea, data))
            else:
                for seg_ea in idautils.Segments():
                    seg = idaapi.getseg(seg_ea)
                    if not seg: continue
                    data = ida_bytes.get_bytes(seg.start_ea, seg.size())
                    if data:
                        scan_regions.append((seg.start_ea, data))

            results = []
            if compiled is not None:
                for region_base, data in scan_regions:
                    matches = compiled.match(data=data)
                    for m in matches:
                        for off, name, val in m.strings:
                            results.append(
                                {
                                    "rule": m.rule,
                                    "addr": hex(region_base + off),
                                    "string": name,
                                    "data": val.hex(" ")[:32] if hasattr(val, "hex") else "",
                                }
                            )
                            if len(results) >= 500:
                                break
                        if len(results) >= 500:
                            break
                    if len(results) >= 500:
                        break
                return {"ok": True, "matches": results, "engine": "yara-python"}

            # Fallback lightweight matcher.
            literal_patterns, hex_patterns = _extract_fallback_patterns(rule_text or "")
            for region_base, data in scan_regions:
                for pat in literal_patterns:
                    start = 0
                    while True:
                        idx = data.find(pat, start)
                        if idx < 0:
                            break
                        results.append(
                            {
                                "rule": "fallback",
                                "addr": hex(region_base + idx),
                                "string": f"literal:{pat[:48].decode('utf-8', errors='replace')}",
                            }
                        )
                        if len(results) >= 500:
                            break
                        start = idx + 1
                    if len(results) >= 500:
                        break
                if len(results) >= 500:
                    break
                for hpat in hex_patterns:
                    for idx in _find_hex_matches(data, hpat):
                        results.append(
                            {
                                "rule": "fallback",
                                "addr": hex(region_base + idx),
                                "string": f"hex_len={len(hpat)}",
                            }
                        )
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
                "note": "yara-python unavailable; used limited literal/hex matching fallback.",
            }

        elif action == "compile":
            if not rules: return make_error(MCPError.INVALID_ARGS, "rules required")
            if yara is not None:
                try:
                    yara.compile(source=rules)
                    return {"ok": True, "status": "Valid YARA rule", "engine": "yara-python"}
                except Exception as e:
                    return make_error(MCPError.INVALID_ARGS, f"YARA compilation failed: {e}")
            # Fallback validation: ensure we can parse at least one literal/hex token.
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

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
            
    except Exception as e:
        return handle_error(e)
