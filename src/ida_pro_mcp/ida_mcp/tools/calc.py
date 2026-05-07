
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import re
try:
    from .semantic_matching import normalize_action, semantic_score, semantic_tokens
except ImportError:
    from semantic_matching import normalize_action, semantic_score, semantic_tokens  # type: ignore[import-not-found]


_CALC_ACTIONS = {"eval", "offset", "convert", "resolve", "deref", "chain", "align"}
_CALC_ACTION_ALIASES = {
    "evaluate": "eval",
    "expression": "eval",
    "compute": "eval",
    "distance": "offset",
    "delta": "offset",
    "diff": "offset",
    "difference": "offset",
    "cast": "convert",
    "conversion": "convert",
    "translate": "convert",
    "va": "resolve",
    "rva": "resolve",
    "foa": "resolve",
    "map": "resolve",
    "pointer": "deref",
    "read": "deref",
    "readmem": "deref",
    "pointer_chain": "chain",
    "chase": "chain",
    "walk": "chain",
    "alignment": "align",
    "round": "align",
}


_INT_SUFFIX_RE = re.compile(r"^\s*([+-]?(?:0x[0-9a-fA-F_]+|\d[\d_]*))(?:\s*([kKmMgGtT]))?\s*$")


def _semantic_tokens(text: str) -> list[str]:
    """Extract lowercase alphanumeric semantic tokens (length >= 2)."""
    return semantic_tokens(text)


def _semantic_score(query: str, candidate: str) -> float:
    """Compute semantic match score for action/symbol matching.

    Heuristic weights:
    - Exact match bonus: +120
    - Substring bonus: +55
    - Token overlap bonus: up to +45
    - Sequence similarity bonus: up to +20
    """
    return semantic_score(query, candidate, substring_bonus=55.0)


def _normalize_calc_action(raw_action: Optional[str], fallback: str = "eval") -> str:
    """Normalize calc action via exact action, alias mapping, then semantic fuzzy match.

    Returns *fallback* when semantic confidence remains below 32.0.
    """
    return normalize_action(
        raw_action,
        actions=tuple(_CALC_ACTIONS),
        aliases=_CALC_ACTION_ALIASES,
        fallback=fallback,
        threshold=32.0,
        substring_bonus=55.0,
    )


@tool
@idaread
def calc(
    action: Annotated[Literal["eval", "offset", "convert", "resolve", "deref", "chain", "align"],
                       "Action: eval|offset|convert|resolve|deref|chain|align"],
    expr: Annotated[Optional[str], "Expression to evaluate (e.g. '0x401000 + 0x100')"] = None,
    addr: Annotated[Optional[str], "Address for conversion/resolution"] = None,
    target: Annotated[Optional[str], "Target address for offset calculation"] = None,
    value: Annotated[Optional[Union[str, int]], "Value for conversion/alignment"] = None,
    type: Annotated[Optional[str], "Value type (u8/u16/u32/u64/s8/s16/s32/s64/f32/f64/ptr/bytes/string)"] = None,
    size: Annotated[Optional[int], "Size in bytes for bytes/ptr/alignment"] = None,
    offsets: Annotated[Optional[Union[str, list]], "Offset chain for pointer chasing"] = None,
    semantic_action: Annotated[Optional[str], "Optional semantic action alias (e.g. evaluate/delta/pointer_chain)"] = None,
    intent: Annotated[Optional[str], "Optional natural-language intent/query used for semantic inference"] = None,
    to_va: Annotated[bool, "For resolve: treat addr/value as file offset and convert to VA"] = False,
    from_file: Annotated[bool, "Alias for to_va"] = False,
    deref_depth: Annotated[int, "For deref: pointer depth to follow (1 = single read)"] = 1,
    **kwargs
) -> dict:
    """
    Address calculation and number conversion utilities (r2-style).

    ACTIONS:

    eval - Evaluate a mathematical expression involving addresses
        Returns: {expr, value, value_hex}
        Example: calc(action="eval", expr="0x401000 + 0x50")

    offset - Calculate the distance between two addresses
        Returns: {from, to, delta_hex, delta_int, abs_delta}
        Example: calc(action="offset", addr="0x401000", target="0x401050")

    convert - Convert a value to Hex, Dec, Bin, and ASCII
        Returns: {hex, dec, bin, oct, ascii, bitmask, signed32/64, unsigned32/64}
        Example: calc(action="convert", value="1234")

    resolve - Convert between Virtual Address (VA) and File Offset
        Returns: {va, file_offset, segment, segment_start, segment_end, direction}
        Example: calc(action="resolve", addr="0x401000")

    deref - Read a typed value from memory
        Returns: {addr, type, value, value_hex?, value_dec?, depth?, steps?}
        Example: calc(action="deref", addr="0x401000", type="u32")

    chain - Follow a pointer chain with offsets
        Returns: {base, offsets, steps, final}
        Example: calc(action="chain", addr="0x401000", offsets="0x10,0x20")

    align - Align a value/address to a boundary
        Returns: {value, alignment, aligned_down, aligned_up}
        Example: calc(action="align", value="0x401003", size=0x10)

    EXTRA:
    - semantic_action: Optional alias/intent action override (evaluate/delta/pointer_chain/etc)
    - intent: Optional natural-language query used for semantic action/value inference
    - to_va/from_file: In resolve mode, treat input as file offset and map to VA
    - deref_depth: Number of pointer dereference hops when type=ptr
    """
    try:
        interpreted_action = None
        nl_query = str(intent or kwargs.get("query") or "").strip()
        normalized_action = _normalize_calc_action(semantic_action or action, fallback=action)
        if normalized_action != action:
            action = normalized_action
            interpreted_action = normalized_action
        if action == "eval" and nl_query:
            ql = nl_query.lower()
            if ql.startswith("offset ") or "distance between" in ql or "delta between" in ql:
                action = "offset"
                interpreted_action = "offset"
            elif ql.startswith("align ") or "alignment" in ql:
                action = "align"
                interpreted_action = "align"
            elif ql.startswith("resolve ") or "file offset" in ql or "virtual address" in ql:
                action = "resolve"
                interpreted_action = "resolve"
            elif "pointer chain" in ql:
                action = "chain"
                interpreted_action = "chain"
            elif ql.startswith("deref ") or ql.startswith("read "):
                action = "deref"
                interpreted_action = "deref"

        def _semantic_symbol_match(text_val: object) -> int:
            """Resolve free-form symbol text to best EA using semantic scoring.

            Returns a resolved EA when the best candidate score is >= 30.0;
            otherwise returns idaapi.BADADDR.
            """
            query_text = str(text_val or "").strip()
            if not query_text:
                return idaapi.BADADDR
            matcher = compile_smart_pattern(query_text, case_sensitive=False)
            best = (0.0, idaapi.BADADDR)
            for ea, name in idautils.Names():
                if not name or not matcher(name):
                    continue
                score = _semantic_score(query_text, name)
                if name.lower() == query_text.lower():
                    score += 40.0
                if score > best[0]:
                    best = (score, ea)
            return best[1] if best[1] != idaapi.BADADDR and best[0] >= 30.0 else idaapi.BADADDR

        def _finalize(resp: dict):
            if interpreted_action:
                resp["interpreted_action"] = interpreted_action
            return resp

        def resolve_int(val):
            if val is None:
                raise ValueError("value required")
            if isinstance(val, int):
                return val
            if isinstance(val, str):
                m = _INT_SUFFIX_RE.match(val)
                if m:
                    base_txt = m.group(1).replace("_", "")
                    suffix = (m.group(2) or "").lower()
                    n = int(base_txt, 0)
                    scale = {
                        "": 1,
                        "k": 1024,
                        "m": 1024 ** 2,
                        "g": 1024 ** 3,
                        "t": 1024 ** 4,
                    }[suffix]
                    return n * scale
                try:
                    return int(val, 0)
                except ValueError:
                    ea = idc.get_name_ea_simple(val)
                    if ea != idaapi.BADADDR:
                        return ea
                    sem_ea = _semantic_symbol_match(val)
                    if sem_ea != idaapi.BADADDR:
                        return sem_ea
            raise ValueError(f"Invalid value: {val}")

        def resolve_addr(val):
            if isinstance(val, int):
                return val
            if isinstance(val, str):
                m = _INT_SUFFIX_RE.match(val)
                if m:
                    base_txt = m.group(1).replace("_", "")
                    suffix = (m.group(2) or "").lower()
                    n = int(base_txt, 0)
                    scale = {
                        "": 1,
                        "k": 1024,
                        "m": 1024 ** 2,
                        "g": 1024 ** 3,
                        "t": 1024 ** 4,
                    }[suffix]
                    return n * scale
                try:
                    return int(val, 0)
                except ValueError:
                    ea = idc.get_name_ea_simple(val)
                    if ea != idaapi.BADADDR:
                        return ea
                    sem_ea = _semantic_symbol_match(val)
                    if sem_ea != idaapi.BADADDR:
                        return sem_ea
            raise ValueError(f"Invalid address: {val}")

        def ptr_size():
            if hasattr(idaapi, "inf_is_64bit"):
                return 8 if idaapi.inf_is_64bit() else 4
            try:
                inf = idaapi.get_inf_structure()
                return 8 if inf.is_64bit() else 4
            except Exception:
                return 8 if (idc.get_inf_attr(idc.INF_LFLAGS) & 0x100) else 4

        def _is_be():
            try:
                import ida_ida as _ida_ida
                if hasattr(_ida_ida, "inf_is_be"):
                    return _ida_ida.inf_is_be()
            except Exception:
                pass
            try:
                inf = idaapi.get_inf_structure()
                return inf.is_be() if hasattr(inf, "is_be") else False
            except Exception:
                return False

        def read_int(ea, width, signed=False):
            data = ida_bytes.get_bytes(ea, width)
            if not data or len(data) != width:
                raise ValueError(f"Could not read {width} bytes from {hex(ea)}")
            import struct
            endian = ">" if _is_be() else "<"
            fmts = {
                (1, False): f"{endian}B", (1, True): f"{endian}b",
                (2, False): f"{endian}H", (2, True): f"{endian}h",
                (4, False): f"{endian}I", (4, True): f"{endian}i",
                (8, False): f"{endian}Q", (8, True): f"{endian}q",
            }
            return struct.unpack(fmts[(width, signed)], data)[0]

        def read_float(ea, width):
            data = ida_bytes.get_bytes(ea, width)
            if not data or len(data) != width:
                raise ValueError(f"Could not read {width} bytes from {hex(ea)}")
            import struct
            endian = ">" if _is_be() else "<"
            return struct.unpack(f"{endian}f" if width == 4 else f"{endian}d", data)[0]

        def read_ptr(ea, width=None):
            width = width or ptr_size()
            return read_int(ea, width, signed=False)

        def read_typed(ea, val_type, val_size):
            if val_type == "bytes":
                if not val_size:
                    raise ValueError("size required for bytes")
                data = ida_bytes.get_bytes(ea, val_size)
                if not data:
                    raise ValueError(f"Could not read {val_size} bytes from {hex(ea)}")
                return " ".join(f"{x:02x}" for x in data)
            if val_type == "u8":
                return read_int(ea, 1, False)
            if val_type == "u16":
                return read_int(ea, 2, False)
            if val_type == "u32":
                return read_int(ea, 4, False)
            if val_type == "u64":
                return read_int(ea, 8, False)
            if val_type == "s8":
                return read_int(ea, 1, True)
            if val_type == "s16":
                return read_int(ea, 2, True)
            if val_type == "s32":
                return read_int(ea, 4, True)
            if val_type == "s64":
                return read_int(ea, 8, True)
            if val_type == "f32":
                return read_float(ea, 4)
            if val_type == "f64":
                return read_float(ea, 8)
            if val_type == "ptr":
                return read_ptr(ea, val_size)
            if val_type == "string":
                s = idc.get_strlit_contents(ea, -1, 0)
                if not s:
                    return None
                if isinstance(s, bytes):
                    if len(s) > 65536:
                        s = s[:65536]
                    return s.decode("utf-8", errors="replace")
                else:
                    return str(s)[:65536]
            raise ValueError(f"Unknown type: {val_type}")

        def eval_expr(expression):
            import re
            # Safety: limit expression length
            if len(expression) > 1024:
                raise ValueError("Expression too long (max 1024 chars)")
            # Safety: reject dangerous patterns
            _forbidden = re.compile(r'__\w+__|import\s*\(|exec\s*\(|eval\s*\(|compile\s*\(|open\s*\(|getattr\s*\(|setattr\s*\(')
            if _forbidden.search(expression):
                raise ValueError("Expression contains forbidden constructs")
            names = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', expression)
            namespace = {
                "hex": hex, "int": int, "abs": abs,
                "BADADDR": idaapi.BADADDR
            }
            namespace.update({
                "u8": lambda a: read_int(resolve_addr(a), 1, False),
                "u16": lambda a: read_int(resolve_addr(a), 2, False),
                "u32": lambda a: read_int(resolve_addr(a), 4, False),
                "u64": lambda a: read_int(resolve_addr(a), 8, False),
                "s8": lambda a: read_int(resolve_addr(a), 1, True),
                "s16": lambda a: read_int(resolve_addr(a), 2, True),
                "s32": lambda a: read_int(resolve_addr(a), 4, True),
                "s64": lambda a: read_int(resolve_addr(a), 8, True),
                "f32": lambda a: read_float(resolve_addr(a), 4),
                "f64": lambda a: read_float(resolve_addr(a), 8),
                "ptr": lambda a, w=None: read_ptr(resolve_addr(a), w),
            })
            for name in names:
                if name not in namespace:
                    ea = idc.get_name_ea_simple(name)
                    if ea != idaapi.BADADDR:
                        namespace[name] = ea
            return eval(expression, {"__builtins__": {}}, namespace)  # noqa: S307

        if action == "eval":
            if not expr and nl_query:
                expr = nl_query
            if not expr:
                return make_error(MCPError.INVALID_ARGS, "expr required")
            # Evaluates expressions like "0x401000 + 0x100" or "main + 0x20"
            try:
                res = eval_expr(expr)
                return _finalize({
                    "ok": True,
                    "expr": expr,
                    "value": res,
                    "value_hex": hex(res) if isinstance(res, int) else str(res)
                })
            except Exception as e:
                return make_error(MCPError.INVALID_ARGS, f"Evaluation error: {expr} ({e})")

        elif action == "offset":
            if (not addr or not target) and nl_query:
                m = re.search(r"between\s+(.+?)\s+(?:and|to)\s+(.+)$", nl_query, re.IGNORECASE)
                if m:
                    addr = addr or m.group(1).strip()
                    target = target or m.group(2).strip()
            if not addr or not target:
                return make_error(MCPError.INVALID_ARGS, "addr and target required")
            try:
                ea1 = resolve_addr(addr)
                ea2 = resolve_addr(target)
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
            
            delta = ea2 - ea1
            return _finalize({
                "ok": True,
                "from": hex(ea1),
                "to": hex(ea2),
                "delta_hex": hex(delta) if delta >= 0 else f"-{hex(abs(delta))}",
                "delta_int": delta,
                "abs_delta": abs(delta),
            })

        elif action == "convert":
            if value is None:
                return make_error(MCPError.INVALID_ARGS, "value required")

            # Parse value
            try:
                v = resolve_int(value)
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
                
            # ASCII representation (4/8 bytes)
            import struct
            try:
                ascii_val = ""
                for b in struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF):
                    if 32 <= b <= 126:
                        ascii_val += chr(b)
                    else:
                        ascii_val += "."
            except Exception:
                ascii_val = "n/a"
                
            return _finalize({
                "ok": True,
                "hex": hex(v),
                "dec": v,
                "bin": bin(v),
                "oct": oct(v),
                "ascii": ascii_val,
                "bytes_le_64": " ".join(f"{b:02x}" for b in struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)),
                "bytes_be_64": " ".join(f"{b:02x}" for b in struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF)),
                "bitmask": f"{v:064b}" if v >= 0 else "n/a",
                "signed32": ((v + (1 << 31)) % (1 << 32)) - (1 << 31),
                "unsigned32": v & 0xFFFFFFFF,
                "signed64": ((v + (1 << 63)) % (1 << 64)) - (1 << 63),
                "unsigned64": v & 0xFFFFFFFFFFFFFFFF,
            })

        elif action == "resolve":
            reverse = bool(to_va or from_file)
            source = addr if addr is not None else value
            if source is None and nl_query:
                source = nl_query
            if isinstance(source, str) and source:
                sl = source.lower()
                if any(k in sl for k in ("foa", "file", "offset")):
                    reverse = True
                m = re.search(r"(0x[0-9a-fA-F_]+|\d[\d_]*)", source)
                if m:
                    source = m.group(1)
            if source is None:
                return make_error(MCPError.INVALID_ARGS, "addr or value required")
            try:
                ea = resolve_addr(source)
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))

            if reverse:
                file_off = ea
                va = ida_nalt.get_fileregion_ea(file_off)
                if va == idaapi.BADADDR:
                    return make_error(MCPError.INVALID_ARGS, f"File offset {hex(file_off)} not mapped")
                seg = idaapi.getseg(va)
                seg_name = ida_segment.get_segm_name(seg) if seg else "none"
                return _finalize({
                    "ok": True,
                    "file_offset": hex(file_off),
                    "va": hex(va),
                    "segment": seg_name,
                    "segment_start": hex(seg.start_ea) if seg else None,
                    "segment_end": hex(seg.end_ea) if seg else None,
                    "direction": "file_offset_to_va",
                })
            
            # Get file offset
            file_off = ida_nalt.get_fileregion_offset(ea)
            seg = idaapi.getseg(ea)
            seg_name = ida_segment.get_segm_name(seg) if seg else "none"
            
            return _finalize({
                "ok": True,
                "va": hex(ea),
                "file_offset": hex(file_off) if file_off != -1 else "not in file",
                "segment": seg_name,
                "segment_start": hex(seg.start_ea) if seg else None,
                "segment_end": hex(seg.end_ea) if seg else None,
                "direction": "va_to_file_offset",
            })

        elif action == "deref":
            if not addr and nl_query:
                addr = nl_query
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            try:
                ea = resolve_addr(addr)
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
            val_type = type or "ptr"
            try:
                deref_depth = max(1, min(32, int(deref_depth)))
            except Exception:
                deref_depth = 1
            try:
                if val_type == "ptr" and deref_depth > 1:
                    steps = []
                    cur = ea
                    value_out = None
                    seen = set()
                    for depth in range(1, deref_depth + 1):
                        if cur in seen:
                            steps.append({"depth": depth, "addr": hex(cur), "terminated": "loop_detected"})
                            break
                        seen.add(cur)
                        value_out = read_typed(cur, val_type, size)
                        if not isinstance(value_out, int):
                            steps.append({"depth": depth, "addr": hex(cur), "terminated": "non_pointer_value"})
                            break
                        if value_out in (0, idaapi.BADADDR):
                            steps.append({"depth": depth, "addr": hex(cur), "value": value_out, "terminated": "null_or_badaddr"})
                            break
                        nxt = value_out
                        steps.append({"depth": depth, "addr": hex(cur), "value": value_out, "value_hex": hex(value_out)})
                        cur = nxt
                else:
                    value_out = read_typed(ea, val_type, size)
                    steps = None
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
            resp = {"ok": True, "addr": hex(ea), "type": val_type, "value": value_out}
            if val_type in ("u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "ptr"):
                resp["value_hex"] = hex(value_out)
                if isinstance(value_out, int):
                    resp["value_dec"] = value_out
            if val_type == "bytes":
                resp["size"] = size
            if val_type == "string":
                resp["length"] = len(value_out) if value_out else 0
            if steps:
                resp["depth"] = deref_depth
                resp["steps"] = steps
            return _finalize(resp)

        elif action == "chain":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required")
            if offsets is None:
                if nl_query:
                    parsed_offs = re.findall(r"[-+]?0x[0-9a-fA-F]+|[-+]?\d+", nl_query)
                    if parsed_offs:
                        offsets = parsed_offs
                if offsets is None:
                    return make_error(MCPError.INVALID_ARGS, "offsets required")
            try:
                ea = resolve_addr(addr)
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
            try:
                offs = normalize_list_input(offsets)
                if len(offs) == 1 and isinstance(offs[0], str):
                    compact = offs[0].replace("->", ",").replace(";", ",")
                    parts = [p.strip() for p in compact.split(",") if p.strip()]
                    if len(parts) > 1:
                        offs = parts
                if not offs:
                    return make_error(MCPError.INVALID_ARGS, "offsets required")
                offs_int = [resolve_int(o) for o in offs]
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
            steps = []
            current = ea
            try:
                for off in offs_int:
                    pval = read_ptr(current, size)
                    if pval in (0, idaapi.BADADDR):
                        steps.append({"ptr": hex(pval), "offset": off, "terminated": "null_or_badaddr"})
                        break
                    next_addr = pval + off
                    steps.append({"ptr": hex(pval), "offset": off, "addr": hex(next_addr)})
                    current = next_addr
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
            return _finalize({"ok": True, "base": hex(ea), "offsets": offs_int, "steps": steps, "final": hex(current)})

        elif action == "align":
            if size is None:
                # Backward-compatible fallback: if caller passed value and addr/expr, treat value as alignment.
                if value is not None and (addr is not None or expr is not None):
                    try:
                        size = resolve_int(value)
                    except ValueError:
                        pass
            if size is None:
                return make_error(MCPError.INVALID_ARGS, "size (alignment) required")
            try:
                alignment = int(size)
            except Exception:
                return make_error(MCPError.INVALID_ARGS, "Invalid alignment size")
            if alignment <= 0:
                return make_error(MCPError.INVALID_ARGS, "Alignment must be > 0")
            try:
                if addr is not None:
                    align_val = resolve_addr(addr)
                elif expr is not None:
                    align_val = eval_expr(expr)
                    if not isinstance(align_val, int):
                        return make_error(MCPError.INVALID_ARGS, "Expression must evaluate to int")
                else:
                    align_val = resolve_int(value)
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))
            except Exception as e:
                return make_error(MCPError.INVALID_ARGS, f"Evaluation error: {expr} ({e})")
            if alignment & (alignment - 1) == 0:
                aligned_down = align_val & ~(alignment - 1)
            else:
                aligned_down = (align_val // alignment) * alignment
            aligned_up = aligned_down if align_val == aligned_down else aligned_down + alignment
            nearest = aligned_down if abs(align_val - aligned_down) <= abs(aligned_up - align_val) else aligned_up
            return _finalize({
                "ok": True,
                "value": align_val,
                "alignment": alignment,
                "aligned_down": aligned_down,
                "aligned_up": aligned_up,
                "nearest": nearest,
                "aligned_down_hex": hex(aligned_down),
                "aligned_up_hex": hex(aligned_up),
                "nearest_hex": hex(nearest),
            })

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
            
    except Exception as e:
        return handle_error(e)
