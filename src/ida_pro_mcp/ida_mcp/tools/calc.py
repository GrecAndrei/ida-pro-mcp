
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# IDA 9.4 EA-based API shims (see ida_mcp/compat.py).
try:
    from .. import compat as _compat
except ImportError:
    try:
        from ida_mcp import compat as _compat  # type: ignore[import-not-found,no-redef]
    except ImportError:
        import compat as _compat  # type: ignore[import-not-found,no-redef]

import json
import re
import struct


from ida_pro_mcp.services import parse_str_list

try:
    from ..support.semantic_matching import semantic_scores
except ImportError:
    from support.semantic_matching import semantic_scores  # type: ignore[import-not-found]


_CALC_ACTIONS = {"eval", "offset", "convert", "resolve", "deref", "chain", "align", "bitops"}
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
    "bitwise": "bitops",
    "bitop": "bitops",
    "xor": "bitops",
    "and": "bitops",
    "or": "bitops",
    "not": "bitops",
    "shift": "bitops",
}


_INT_SUFFIX_RE = re.compile(r"^\s*([+-]?(?:0x[0-9a-fA-F_]+|\d[\d_]*))(?:\s*([kKmMgGtT]))?\s*$")


def _normalize_calc_action(raw_action: Optional[str], fallback: str = "eval") -> str:
    """Normalize calc action via exact action, alias mapping, then semantic fuzzy match.

    Uses adaptive score gating over candidate actions to avoid brittle fixed thresholds.
    """
    txt = str(raw_action or "").strip().lower()
    if not txt:
        return fallback
    if txt in _CALC_ACTIONS:
        return txt
    if txt in _CALC_ACTION_ALIASES:
        return _CALC_ACTION_ALIASES[txt]

    acts = list(_CALC_ACTIONS)
    scored = list(
        zip(
            semantic_scores(txt, acts, top_n=len(acts), substring_bonus=55.0),
            acts,
            strict=False,
        )
    )
    if not scored:
        return fallback
    scored.sort(key=lambda x: x[0], reverse=True)
    top_score, top_act = scored[0]
    # An all-zero score distribution means the query shares no signal with
    # any action; the adaptive gate collapses to 0 and would pass the top
    # tie-break. With no winner, fall back to the caller's default action.
    if float(top_score) <= 0.0:
        return fallback
    vals = sorted(float(x[0]) for x in scored)
    q50 = vals[len(vals) // 2]
    q75 = vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.75)))]
    gate = q50 + max(0.0, q75 - q50)
    return top_act if float(top_score) >= float(gate) else fallback


@tool
@idaread
def calc(
    action: Annotated[Literal["eval", "offset", "convert", "resolve", "deref", "chain", "align", "bitops"],
                       "Action: eval|offset|convert|resolve|deref|chain|align|bitops"],
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
    persist: Annotated[bool, "If true, write question + answer to blackboard so the LLM doesn't have to remember the result"] = False,
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

    bitops - Bitwise operations (and/or/xor/not/shl/shr)
        Returns: {op, lhs, rhs?, result, result_hex, result_bin}
        Example: calc(action="bitops", value="0xff", target="0x10", bit_op="xor")

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
            elif any(k in ql for k in (" xor ", " and ", " or ", " shift ", " bitwise ")):
                action = "bitops"
                interpreted_action = "bitops"

        def _semantic_symbol_match(text_val: object) -> int:
            """Resolve free-form symbol text to best EA using semantic scoring.

            Returns a resolved EA when best score clears adaptive candidate gate.
            """
            query_text = str(text_val or "").strip()
            if not query_text:
                return idaapi.BADADDR
            matcher = compile_smart_pattern(query_text, case_sensitive=False)
            candidates = []
            for ea, name in idautils.Names():
                if not name or not matcher(name):
                    continue
                candidates.append((ea, name))
            if not candidates:
                return idaapi.BADADDR
            scores = semantic_scores(
                query_text,
                [name for _, name in candidates],
                top_n=48,
                substring_bonus=55.0,
            )
            scored_cands = []
            for (ea, name), score in zip(candidates, scores, strict=False):
                if name.lower() == query_text.lower():
                    score += 40.0
                scored_cands.append((score, ea))
            scored_cands.sort(key=lambda x: x[0], reverse=True)
            vals = sorted(float(x[0]) for x in scored_cands)
            q50 = vals[len(vals) // 2]
            q75 = vals[min(len(vals) - 1, int(round((len(vals) - 1) * 0.75)))]
            gate = q50 + max(0.0, q75 - q50)
            return scored_cands[0][1] if float(scored_cands[0][0]) >= float(gate) else idaapi.BADADDR

        # Snapshot the user's input so the persist path can record question
        # AND answer (not just the answer). This dict is keyed by the same
        # names the calc() signature uses, so the persist helper can pull
        # the original string the LLM typed — not whatever the action
        # branch mangled it into.
        input_summary: dict = {
            "action": action,
            "expr": expr,
            "addr": addr,
            "value": value,
            "offsets": offsets,
            "type": type,
            "size": size,
            "to_va": to_va,
        }

        def _finalize(resp: dict):
            if interpreted_action:
                resp["interpreted_action"] = interpreted_action
            # Opt-in: write question + answer to blackboard only when the
            # LLM explicitly asks. This is the fix for the broken
            # _calc_auto_capture that (a) skipped eval entirely, (b) lost
            # the question for resolve, and (c) looked at the wrong key
            # for chain. The new helper uses the input snapshot above so
            # the question is preserved exactly as the LLM typed it.
            if persist and resp.get("ok") and action in (
                "eval", "resolve", "deref", "chain"
            ):
                _calc_persist_capture(input_summary, resp, action)
            return resp

        def resolve_ea(val, label="value"):
            """Resolve a value/address from int, hex string, symbol name, or NL query.

            All string parsing is delegated to the shared canonical parser
            (tools/_common.parse_address_canonical) so a bare in-image token
            like ``80000000`` and its ``0x80000000`` spelling resolve to the
            same EA everywhere: hex-by-default for in-image bare tokens,
            symbol-first, and ADDRESS_INVALID for ambiguous/unmapped tokens
            (never a silent decimal reinterpretation).
            """
            if val is None:
                raise ValueError(f"{label} required")
            if isinstance(val, int):
                return val
            if isinstance(val, str):
                s = val.strip()
                # Value-context literals the address parser intentionally
                # rejects: suffix-scaled magnitudes ('1k', '2m') and signed
                # numbers (chain offsets, bitops operands). Neither is a bare
                # address token, so each keeps its numeric semantics.
                m = _INT_SUFFIX_RE.match(s)
                if m and m.group(2):
                    base_txt = m.group(1).replace("_", "")
                    scale = {
                        "k": 1024,
                        "m": 1024 ** 2,
                        "g": 1024 ** 3,
                        "t": 1024 ** 4,
                    }[m.group(2).lower()]
                    return int(base_txt, 0) * scale
                if s[:1] in "+-":
                    try:
                        return int(s, 0)
                    except ValueError:
                        raise ValueError(f"Invalid {label}: {val}") from None
                # Symbol-first: an exact symbol wins over any literal reading,
                # so sub_401000 is the symbol's EA, never the number 401000.
                try:
                    sym_ea = idc.get_name_ea_simple(s)
                    if sym_ea != idaapi.BADADDR:
                        return sym_ea
                except Exception:
                    pass
                # Everything else — 0x-prefixed hex, bare in-image hex, or an
                # ambiguous/unmapped/garbage token — goes through the single
                # canonical address parser.
                ea, err = parse_address_canonical(s)
                if ea is not None:
                    return ea
                if err is not None and isinstance(err, dict):
                    msg = err.get("message") or f"Invalid {label}: {val}"
                    hint = err.get("hint")
                    if isinstance(hint, str) and hint:
                        msg = f"{msg} {hint}"
                    # Non-numeric garbage may still be a fuzzy symbol match.
                    if not s.isdigit() and not s.lower().startswith("0x"):
                        sem_ea = _semantic_symbol_match(val)
                        if sem_ea != idaapi.BADADDR:
                            return sem_ea
                    raise ValueError(msg)
                raise ValueError(f"Invalid {label}: {val}")
            raise ValueError(f"Invalid {label}: {val}")

        def resolve_int(val):
            return resolve_ea(val, "value")

        def resolve_addr(val):
            return resolve_ea(val, "address")

        def ptr_size():
            return 8 if _inf_bitness() == 64 else 4

        def _is_be():
            return _inf_is_be()

        def read_int(ea, width, signed=False):
            data = ida_bytes.get_bytes(ea, width)
            if not data or len(data) != width:
                raise ValueError(f"Could not read {width} bytes from {hex(ea)}")

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
                    # No string literal is defined at this address (raw blobs,
                    # unanalyzed data, hand-built tables). Fall back to a bounded
                    # printable-run scan so deref still yields text on opaque
                    # regions — mirrors memory.py's read type="string" fallback.
                    raw = ida_bytes.get_bytes(ea, 65536)
                    if raw:
                        chars = []
                        for b in raw:
                            if b == 0:
                                break
                            if 32 <= b <= 126:
                                chars.append(chr(b))
                            else:
                                break
                        if chars:
                            return "".join(chars)
                    return None
                if isinstance(s, bytes):
                    if len(s) > 65536:
                        s = s[:65536]
                    return s.decode("utf-8", errors="replace")
                else:
                    return str(s)[:65536]
            raise ValueError(f"Unknown type: {val_type}")

        def eval_expr(expression):
            import ast
            # Safety: limit expression length
            if len(expression) > 1024:
                raise ValueError("Expression too long (max 1024 chars)")
            # Safety: reject dangerous text patterns early.
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

            tree = ast.parse(expression, mode="eval")
            allowed_binops = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.BitOr, ast.BitAnd, ast.BitXor, ast.LShift, ast.RShift)
            allowed_unary = (ast.UAdd, ast.USub, ast.Invert)
            allowed_cmps = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE)
            allowed_bools = (ast.And, ast.Or)

            def _eval_node(node):
                if isinstance(node, ast.Expression):
                    return _eval_node(node.body)
                if isinstance(node, ast.Constant):
                    if isinstance(node.value, (int, float, bool)):
                        return node.value
                    raise ValueError("Only numeric/bool constants are allowed")
                if isinstance(node, ast.Name):
                    if node.id in namespace:
                        return namespace[node.id]
                    raise ValueError(f"Unknown name: {node.id}")
                if isinstance(node, ast.BinOp):
                    if not isinstance(node.op, allowed_binops):
                        raise ValueError("Operator not allowed")
                    lhs = _eval_node(node.left)
                    rhs = _eval_node(node.right)
                    op = node.op
                    if isinstance(op, ast.Add): return lhs + rhs
                    if isinstance(op, ast.Sub): return lhs - rhs
                    if isinstance(op, ast.Mult): return lhs * rhs
                    if isinstance(op, ast.Div): return lhs / rhs
                    if isinstance(op, ast.FloorDiv): return lhs // rhs
                    if isinstance(op, ast.Mod): return lhs % rhs
                    if isinstance(op, ast.BitOr): return lhs | rhs
                    if isinstance(op, ast.BitAnd): return lhs & rhs
                    if isinstance(op, ast.BitXor): return lhs ^ rhs
                    if isinstance(op, ast.LShift): return lhs << rhs
                    if isinstance(op, ast.RShift): return lhs >> rhs
                    raise ValueError("Unsupported binary operation")
                if isinstance(node, ast.UnaryOp):
                    if not isinstance(node.op, allowed_unary):
                        raise ValueError("Unary operator not allowed")
                    val = _eval_node(node.operand)
                    if isinstance(node.op, ast.UAdd): return +val
                    if isinstance(node.op, ast.USub): return -val
                    if isinstance(node.op, ast.Invert): return ~val
                    raise ValueError("Unsupported unary operation")
                if isinstance(node, ast.BoolOp):
                    if not isinstance(node.op, allowed_bools):
                        raise ValueError("Boolean operator not allowed")
                    vals = [_eval_node(v) for v in node.values]
                    return all(vals) if isinstance(node.op, ast.And) else any(vals)
                if isinstance(node, ast.Compare):
                    lhs = _eval_node(node.left)
                    for op, comp in zip(node.ops, node.comparators, strict=False):
                        if not isinstance(op, allowed_cmps):
                            raise ValueError("Comparison operator not allowed")
                        rhs = _eval_node(comp)
                        ok = (
                            (isinstance(op, ast.Eq) and lhs == rhs) or
                            (isinstance(op, ast.NotEq) and lhs != rhs) or
                            (isinstance(op, ast.Lt) and lhs < rhs) or
                            (isinstance(op, ast.LtE) and lhs <= rhs) or
                            (isinstance(op, ast.Gt) and lhs > rhs) or
                            (isinstance(op, ast.GtE) and lhs >= rhs)
                        )
                        if not ok:
                            return False
                        lhs = rhs
                    return True
                if isinstance(node, ast.Call):
                    if not isinstance(node.func, ast.Name):
                        raise ValueError("Only direct function calls are allowed")
                    fname = node.func.id
                    if fname not in namespace:
                        raise ValueError(f"Function not allowed: {fname}")
                    fn = namespace[fname]
                    args = [_eval_node(a) for a in node.args]
                    if any(not isinstance(a, (int, float, bool)) for a in args):
                        raise ValueError("Only numeric/bool arguments are allowed")
                    return fn(*args)
                raise ValueError(f"Unsupported expression node: {type(node).__name__}")

            return _eval_node(tree)

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
                # NL-sniffing applies only to free-text intent queries. A
                # verbatim addr/value is resolved as-is: a numeric substring
                # inside a symbol (sub_401000) must not be mistaken for a
                # literal value, and keywords in a name (set_file_offset)
                # must not flip the mapping direction.
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

            # IDA 9.x moved the file<->VA mapping helpers out of ida_nalt into
            # idaapi (and ida_loader). Resolve them robustly across versions.
            _get_fro = (getattr(idaapi, "get_fileregion_offset", None)
                        or getattr(ida_nalt, "get_fileregion_offset", None))
            _get_frea = (getattr(idaapi, "get_fileregion_ea", None)
                         or getattr(ida_nalt, "get_fileregion_ea", None))
            if not _get_fro or not _get_frea:
                return make_error(
                    MCPError.IDA_ERROR,
                    "fileregion mapping helpers unavailable in this IDA build",
                )

            if reverse:
                file_off = ea
                va = _get_frea(file_off)
                if va == idaapi.BADADDR:
                    return make_error(MCPError.INVALID_ARGS, f"File offset {hex(file_off)} not mapped")
                seg = idaapi.getseg(va)
                seg_name = _compat.get_segment_name(va) if seg else "none"
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
            file_off = _get_fro(ea)
            if file_off == idaapi.BADADDR:
                # Headerless raw blobs carry no segment-to-file mapping, so
                # get_fileregion_offset returns BADADDR for every VA. Surface
                # that as a crisp error instead of a confusing "not in file"
                # value that looks like a real offset.
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"No file offset for VA {hex(ea)}: this image has no file mapping "
                    "(headerless raw blob loaded without segment-to-file mapping)",
                    hint="The VA is mapped in the database but not backed by a file "
                         "region, so there is no file offset to resolve. Use the "
                         "address itself (0x-prefixed) or a segment name instead.",
                )
            seg = idaapi.getseg(ea)
            seg_name = _compat.get_segment_name(ea) if seg else "none"

            return _finalize({
                "ok": True,
                "va": hex(ea),
                "file_offset": hex(file_off),
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
                    parts = parse_str_list(compact)
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
            is_power_of_2 = (alignment & (alignment - 1)) == 0
            aligned_down = (align_val & ~(alignment - 1)) if is_power_of_2 else (align_val // alignment) * alignment
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

        elif action == "bitops":
            op = str(kwargs.get("bit_op") or kwargs.get("op") or "").strip().lower()
            if not op and nl_query:
                q = nl_query.lower()
                if " xor " in q:
                    op = "xor"
                elif " and " in q:
                    op = "and"
                elif " or " in q:
                    op = "or"
                elif " not " in q:
                    op = "not"
                elif " shl " in q or "<<" in q:
                    op = "shl"
                elif " shr " in q or ">>" in q:
                    op = "shr"
            if op not in {"and", "or", "xor", "not", "shl", "shr"}:
                return make_error(MCPError.INVALID_ARGS, "bit_op/op required: and|or|xor|not|shl|shr")

            if value is None and addr is not None:
                value = addr
            if value is None:
                return make_error(MCPError.INVALID_ARGS, "value required for bitops")
            try:
                lhs = resolve_int(value)
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))

            rhs = None
            if op != "not":
                if target is None:
                    return make_error(MCPError.INVALID_ARGS, "target required for bitops op (except not)")
                try:
                    rhs = resolve_int(target)
                except ValueError as e:
                    return make_error(MCPError.INVALID_ARGS, str(e))

            if op == "and":
                out = lhs & int(rhs)
            elif op == "or":
                out = lhs | int(rhs)
            elif op == "xor":
                out = lhs ^ int(rhs)
            elif op == "not":
                out = ~lhs
            elif op == "shl":
                out = lhs << int(rhs)
            else:  # shr
                out = lhs >> int(rhs)

            return _finalize(
                {
                    "ok": True,
                    "op": op,
                    "lhs": lhs,
                    "rhs": rhs,
                    "result": out,
                    "result_hex": hex(out),
                    "result_bin": bin(out),
                    "result_u32": out & 0xFFFFFFFF,
                    "result_u64": out & 0xFFFFFFFFFFFFFFFF,
                }
            )

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


def _calc_persist_capture(input_summary: dict, result: dict, action: str) -> None:
    """Opt-in: write question + answer to the blackboard.

    Called only when the LLM passed `persist=True` to calc(). Default is
    off so the LLM gets the "set it and forget it" benefit of external
    memory for math without the silent-side-effect bloat of always-on
    auto-capture.

    The previous implementation was broken: it captured the answer but
    lost the question (the most valuable part for "what did I just
    ask?"), skipped `eval` entirely, and looked at the wrong response
    key for `chain`. This version pulls the original `expr`, `addr`,
    `offsets`, etc. from the input snapshot so the LLM's question is
    preserved verbatim.
    """
    try:
        from .blackboard import BlackboardStore
    except ImportError:
        try:
            from blackboard import BlackboardStore  # type: ignore
        except ImportError:
            return
    try:
        store = BlackboardStore()
    except Exception:
        return

    # Build a (question, answer, title, content, addr) tuple per action.
    # The question is the LLM's original input; the answer is what
    # the action returned. Both are written so a later session can see
    # "I asked X and got Y" without having to guess.
    if action == "eval":
        question = input_summary.get("expr") or ""
        answer = result.get("value")
        if not question or answer is None:
            return
        answer_str = hex(answer) if isinstance(answer, int) else str(answer)
        title = f"calc(eval): {question} = {answer_str}"
        content = json.dumps({
            "tool": "calc", "action": "eval",
            "expr": question, "value": answer,
        }, sort_keys=True)
        entry_addr = ""

    elif action == "resolve":
        question = input_summary.get("addr") or input_summary.get("value") or ""
        answer = result.get("va") or result.get("file_offset") or ""
        if not question or not answer:
            return
        title = f"calc(resolve): {question} -> {answer}"
        content = json.dumps({
            "tool": "calc", "action": "resolve",
            "addr": question, "va": answer,
            "file_offset": result.get("file_offset"),
            "segment": result.get("segment"),
            "direction": result.get("direction"),
        }, sort_keys=True)
        entry_addr = answer

    elif action == "deref":
        question = input_summary.get("addr") or ""
        answer = result.get("value")
        if not question or answer is None:
            return
        answer_str = hex(answer) if isinstance(answer, int) else str(answer)
        title = f"calc(deref): {question} = {answer_str}"
        content = json.dumps({
            "tool": "calc", "action": "deref",
            "addr": question,
            "type": result.get("type"),
            "value": answer,
            "depth": result.get("depth"),
        }, sort_keys=True)
        entry_addr = question

    elif action == "chain":
        question_addr = input_summary.get("addr") or ""
        offsets = input_summary.get("offsets")
        if isinstance(offsets, str):
            offsets = [offsets]
        steps = result.get("steps") or []
        final = result.get("final") or ""
        if not question_addr or not steps or not final:
            return
        offsets_str = ",".join(str(o) for o in (offsets or []))
        title = f"calc(chain): {question_addr} +[{offsets_str}] -> {final}"
        content = json.dumps({
            "tool": "calc", "action": "chain",
            "addr": question_addr, "offsets": offsets,
            "steps": steps, "final": final,
        }, sort_keys=True)
        entry_addr = question_addr

    else:
        return

    # Dedup: don't write twice. Match on (addr, category, title) — a
    # different question with the same answer is a different entry.
    if store.exists_similar(entry_addr or title, f"calc_{action}", title):
        return
    try:
        store.write(
            title=title,
            content=content,
            category=f"calc_{action}",
            addr=entry_addr,
            tags=["auto", "calc", "persist", action],
            confidence=0.85,
            source="calc.persist",
        )
    except Exception:
        pass
