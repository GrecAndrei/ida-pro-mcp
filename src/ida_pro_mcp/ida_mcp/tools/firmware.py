"""
Firmware-shaping tool for headerless / raw-blob binaries.

Resurrects the deleted ``firmware_view`` capability as an IDA-side ``firmware``
tool — the mission's differentiator vs radare2.  The old mega-tool was removed
in b191581; the RISC-V raw-arch inference survived in ``arch_profile.py`` but
the vector-table / RTOS / carve shaping had no home, leaving the host-side
``firmware_detected`` flag (idb.py) advertised-but-shapeless.  This module is
the IDA-side surface that gives those signals actionable shape.

Five actions:

    detect_vector_table  — rank candidate ISR/pointer tables: LE/BE runs of
        pointer-width words whose entries fall inside mapped segments.
        Returns ``{base, count, first_entries, confidence}`` per candidate.
    detect_load_base     — validate load-base hypotheses by decoding the
        reset-vector + prologue (reusing ``arch_utils`` return/GP heuristics).
    detect_mmio          — MMIO-style address ranges outside the RAM/ROM
        mapping, grouped by 4KB page density (mirrors the raw-blob MMIO
        scorer).  Returns ``{ranges, registers_hint}``.
    rtos_scan            — lightweight FreeRTOS/HAL signature scan over symbol
        names, string literals, and raw mapped bytes.  Returns ``{matches}``.
    carve                — define a new segment from a byte range (governed
        write), mirroring ``segments`` action=add.  Optionally writes the
        carved bytes to a file via a ``file``/``path`` kwarg.

Scope notes (per the WO-F1 design): ``pointer_sweep`` is covered by
``search(action='data_value')`` (WO-S6) and is intentionally NOT duplicated
here; ``auto_retype`` is deferred until the type-inference stack lands.
"""

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

# _common does not re-export parse_address_safe (not in its __all__); import it
# here so carve/detect windows can address unmapped regions (mirrors segments.py).
try:
    from ida_mcp.error_handling import parse_address_safe
except ImportError:
    try:
        from ida_pro_mcp.ida_mcp.error_handling import parse_address_safe
    except ImportError:
        from error_handling import parse_address_safe  # type: ignore[import-not-found]

# arch_utils is not re-exported by the isolated-test _common stub; import the
# multi-arch helpers directly so the module is self-contained in both real IDA
# and the host unit-test harness.
try:
    from ..support.arch_utils import (
        get_arch,
        get_prologue_pattern,
        is_arm_family,
        is_riscv_family,
    )
except ImportError:
    from support.arch_utils import (  # type: ignore[import-not-found]
        get_arch,
        get_prologue_pattern,
        is_arm_family,
        is_riscv_family,
    )


# ============================================================================
# Infrastructure helpers (self-contained; no dependency on _common._inf_*)
# ============================================================================

def _fw_min_ea():
    """Lowest mapped address, or None when the IDB is not usable."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_get_min_ea"):
            return int(ida_ida.inf_get_min_ea())
    except Exception:
        pass
    try:
        return int(idaapi.inf_get_min_ea())
    except Exception:
        pass
    return None


def _fw_max_ea():
    """Highest mapped address, or None when the IDB is not usable."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_get_max_ea"):
            return int(ida_ida.inf_get_max_ea())
    except Exception:
        pass
    try:
        return int(idaapi.inf_get_max_ea())
    except Exception:
        pass
    return None


def _fw_ptr_size():
    """Pointer width of the current IDB (4 or 8), defaulting to 4."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_is_64bit") and ida_ida.inf_is_64bit():
            return 8
        if hasattr(ida_ida, "inf_get_app_bitness"):
            bits = int(ida_ida.inf_get_app_bitness())
            if bits == 32:
                return 4
    except Exception:
        pass
    try:
        if bool(idaapi.inf_is_64bit()):
            return 8
    except Exception:
        pass
    return 4


def _fw_is_be():
    """True when the IDB is big-endian."""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_is_be"):
            return bool(ida_ida.inf_is_be())
    except Exception:
        pass
    try:
        return bool(idaapi.inf_is_be())
    except Exception:
        return False


def _fw_image_bounds():
    """Return (min_ea, max_ea) for the mapped image or (None, None)."""
    min_ea = _fw_min_ea()
    max_ea = _fw_max_ea()
    if min_ea in (None, idaapi.BADADDR) or max_ea in (None, idaapi.BADADDR) or max_ea <= min_ea:
        return None, None
    return int(min_ea), int(max_ea)


def _fw_parse_range(start, end):
    """Resolve a [start, end) window to ints. Returns (s, e, None) or (None, None, err)."""
    if not start or not end:
        return None, None, make_error(MCPError.INVALID_ARGS,
                                      "start and end must be provided together")
    s_ea, err = parse_address_safe(start)
    if err:
        return None, None, err
    e_ea, err = parse_address_safe(end)
    if err:
        return None, None, err
    if s_ea >= e_ea:
        return None, None, make_error(MCPError.INVALID_ARG_VALUE,
                                      f"start ({hex(s_ea)}) must be less than end ({hex(e_ea)})")
    return int(s_ea), int(e_ea), None


def _addr_is_mapped(v):
    """True when a value resolves inside a mapped segment."""
    try:
        return bool(idaapi.is_mapped(int(v)))
    except Exception:
        return False


def _read_word_bytes(ea, size):
    """Read *size* bytes at *ea*, or None when unavailable/short."""
    try:
        data = ida_bytes.get_bytes(int(ea), int(size))
    except Exception:
        return None
    if not data or len(data) < int(size):
        return None
    return data[:int(size)]


def _read_bytes_range(s_ea, e_ea, cap=1 << 20):
    """Read the mapped byte range [s_ea, e_ea) bounded by *cap*."""
    size = int(min(int(e_ea) - int(s_ea), cap))
    if size <= 0:
        return b""
    try:
        data = ida_bytes.get_bytes(int(s_ea), size)
    except Exception:
        data = None
    return data or b""


def _decode_word(data, endian):
    return int.from_bytes(data, "little" if endian == "le" else "big", signed=False)


# ============================================================================
# detect_vector_table
# ============================================================================

_FW_MIN_RUN = 2  # a single mapped pointer is not a "table"


def _fw_table_candidate(run_base, run, endian, word_size):
    count = len(run)
    confidence = round(min(0.98, 0.5 + count * 0.08), 3)
    return {
        "base": hex(run_base),
        "count": count,
        "first_entries": [hex(v) for _ea, v in run[:8]],
        "endian": endian,
        "word_size": word_size,
        "confidence": confidence,
    }


def _detect_vector_table(s_ea, e_ea, base, word, endian, limit):
    """Scan candidate ISR/pointer tables and return ranked candidates."""
    if base:
        b_ea, err = parse_address_safe(base)
        if err:
            return err
        scan_s = int(b_ea)
    else:
        scan_s = int(s_ea)
    scan_e = int(e_ea)

    word_lower = str(word or "auto").lower()
    if word_lower not in ("auto", "u32", "u16"):
        return make_error(MCPError.INVALID_ARGS,
                          f"word must be 'auto', 'u32', or 'u16', got {word!r}")
    if word_lower == "auto":
        # Try the native pointer width first, then fall back to u32: headerless
        # 64-bit images often commit a 32-bit ISR table even when the toolchain
        # is LP64, and the wider scan finds nothing.  Only 16/32-bit widths are
        # vector-table word sizes, so an 8-byte native pointer is skipped.
        ptr_size = _fw_ptr_size() or 4
        word_sizes = []
        for _w in (ptr_size, 4):
            if _w in (2, 4) and _w not in word_sizes:
                word_sizes.append(_w)
        if not word_sizes:
            return make_error(MCPError.INVALID_ARGS,
                              f"No supported vector-table word size for pointer width {ptr_size}")
    else:
        word_sizes = [{"u32": 4, "u16": 2}[word_lower]]

    endian_lower = str(endian or "both").lower()
    if endian_lower not in ("le", "be", "both"):
        return make_error(MCPError.INVALID_ARGS,
                          f"endian must be 'both', 'le', or 'be', got {endian!r}")
    endians = ["le", "be"] if endian_lower == "both" else [endian_lower]

    candidates = []
    chosen_word_size = word_sizes[0]
    for word_size in word_sizes:
        for enc in endians:
            run_base = None
            run = []
            ea = scan_s
            while ea + word_size <= scan_e:
                data = _read_word_bytes(ea, word_size)
                val = _decode_word(data, enc) if data is not None and len(data) == word_size else None
                if val is not None and _addr_is_mapped(val):
                    if run_base is None:
                        run_base = ea
                        run = []
                    run.append((ea, val))
                else:
                    if run_base is not None and len(run) >= _FW_MIN_RUN:
                        candidates.append(_fw_table_candidate(run_base, run, enc, word_size))
                    run_base = None
                    run = []
                ea += word_size
            if run_base is not None and len(run) >= _FW_MIN_RUN:
                candidates.append(_fw_table_candidate(run_base, run, enc, word_size))
        if candidates:
            chosen_word_size = word_size
            break

    # Rank: longest run first; ties prefer little-endian then the lower base.
    candidates.sort(key=lambda c: (-c["count"], 0 if c["endian"] == "le" else 1,
                                   int(c["base"], 16)))
    candidates = candidates[:max(1, int(limit or 32))]
    return {
        "ok": True,
        "action": "detect_vector_table",
        "candidates": candidates,
        "count": len(candidates),
        "note": (
            f"Scanned {hex(scan_s)}..{hex(scan_e)} for {chosen_word_size * 8}-bit "
            f"{'/'.join(endians)} pointer runs whose entries resolve inside the "
            "mapped image. The top candidate is the longest such run."
        ),
    }


# ============================================================================
# detect_load_base
# ============================================================================

_COMMON_LOAD_BASES = (
    0x0, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
    0x80000000, 0xA0000000, 0xBFC00000,
)


def _default_load_base_candidates(s_ea, e_ea, ptr_size, limit=12):
    """Derive likely load bases from pointer density in the first 256 bytes."""
    image_size = e_ea - s_ea
    cands = [int(s_ea)]
    if image_size <= 0 or ptr_size <= 0:
        return cands
    hits = {}
    chunk_end = min(e_ea, s_ea + 256)
    ea = s_ea
    while ea + ptr_size <= chunk_end:
        data = _read_word_bytes(ea, ptr_size)
        if data is not None:
            v = _decode_word(data, "le" if not _fw_is_be() else "be")
            for cb in _COMMON_LOAD_BASES:
                if cb <= v < cb + image_size:
                    hits[cb] = hits.get(cb, 0) + 1
                    break
        ea += ptr_size
    for cb, n in sorted(hits.items(), key=lambda kv: -kv[1]):
        if n >= 2 and cb not in cands:
            cands.append(cb)
    return cands[:limit]


def _riscv_jal_target(ea, insn):
    """Decode a RISC-V ``jal``/``j`` instruction's absolute target, or None."""
    if (insn & 0x7F) != 0x6F:
        return None
    imm = (((insn >> 31) << 20)
           | (((insn >> 21) & 0x3FF) << 1)
           | (((insn >> 20) & 0x1) << 11)
           | (((insn >> 12) & 0xFF) << 12))
    if imm & (1 << 20):
        imm -= (1 << 21)
    return int(ea) + imm


def _read_instructions(ea, count, step=4):
    """Collect up to *count* {ea, mnemonic} pairs starting at *ea*."""
    out = []
    cur = int(ea)
    for _ in range(int(count)):
        try:
            mnem = idc.print_insn_mnem(cur)
        except Exception:
            mnem = ""
        if not mnem:
            break
        out.append((cur, mnem))
        cur += int(step)
    return out


def _has_riscv_gp_init(prologue):
    """Detect the canonical RISC-V GP init pair: ``auipc gp, hi20; addi gp, gp, lo12``."""
    for i, (ea, mnem) in enumerate(prologue):
        if mnem.lower() != "auipc":
            continue
        try:
            op0 = str(idc.print_operand(ea, 0) or "").strip().lower()
        except Exception:
            op0 = ""
        if op0 not in ("gp", "x3"):
            continue
        for j in range(i + 1, min(i + 3, len(prologue))):
            _ea2, mnem2 = prologue[j]
            if mnem2.lower() != "addi":
                continue
            try:
                op0b = str(idc.print_operand(_ea2, 0) or "").strip().lower()
            except Exception:
                op0b = ""
            if op0b == op0:
                return True
    return False


def _count_hypothetical_pointers(s_ea, e_ea, b, ptr_size):
    """Count pointer words inside [s_ea, e_ea) that fall in [b, b + image_size)."""
    count = 0
    image_size = e_ea - s_ea
    if image_size <= 0:
        return 0
    ea = s_ea
    while ea + ptr_size <= e_ea:
        data = _read_word_bytes(ea, ptr_size)
        if data is not None:
            v = _decode_word(data, "le" if not _fw_is_be() else "be")
            if b <= v < b + image_size:
                count += 1
        ea += ptr_size
    return count


def _validate_load_base(b, arch, ptr_size, s_ea, e_ea):
    """Score one load-base hypothesis by decoding the reset-vector + prologue."""
    evidence = []
    score = 0.0

    if s_ea <= b < e_ea:
        data = _read_word_bytes(b, min(4, ptr_size))
        if data is None:
            evidence.append(f"no readable word at {hex(b)}")
            return {"base": hex(b), "confidence": 0.05, "evidence": evidence}
        raw = _decode_word(data, "le" if not _fw_is_be() else "be")
        if is_riscv_family(arch):
            tgt = _riscv_jal_target(b, raw)
            if tgt is not None and s_ea <= tgt < e_ea:
                score += 0.6
                evidence.append(f"reset vector at {hex(b)} jumps to mapped {hex(tgt)}")
                prologue = _read_instructions(tgt, 4, step=4)
                if prologue:
                    pattern = get_prologue_pattern([m for _e, m in prologue], arch)
                    if pattern != "unknown":
                        score += 0.2
                        evidence.append(f"reset-handler prologue at {hex(tgt)}: {pattern}")
                    if _has_riscv_gp_init(prologue):
                        score += 0.15
                        evidence.append(f"GP init (auipc/addi gp) at {hex(tgt)}")
            elif tgt is not None:
                evidence.append(f"reset vector at {hex(b)} jumps outside the mapped image to {hex(tgt)}")
            else:
                evidence.append(f"word at {hex(b)} is not a RISC-V jal/jump")
        elif is_arm_family(arch):
            reset_ptr = raw & ~1  # clear Thumb bit
            if s_ea <= reset_ptr < e_ea:
                score += 0.6
                evidence.append(f"reset vector pointer {hex(raw)} resolves to mapped {hex(reset_ptr)}")
            else:
                evidence.append(f"reset vector pointer {hex(raw)} does not resolve into the mapped image")
        elif s_ea <= raw < e_ea:
            score += 0.5
            evidence.append(f"word at {hex(b)} resolves inside the mapped image")
        else:
            evidence.append(f"word at {hex(b)} ({hex(raw)}) does not resolve into the mapped image")
    else:
        # Hypothesis outside the current mapping: check pointer-density fall-in.
        ptr_count = _count_hypothetical_pointers(s_ea, e_ea, b, ptr_size)
        if ptr_count >= 3:
            score += min(0.6, 0.4 + ptr_count * 0.03)
            evidence.append(f"{ptr_count} pointer words fall inside hypothetical {hex(b)}..{hex(b + (e_ea - s_ea))}")
        else:
            evidence.append(f"only {ptr_count} pointer word(s) fall inside the hypothetical range for {hex(b)}")

    confidence = round(min(0.97, max(0.05, score + 0.1)), 3)
    return {"base": hex(b), "confidence": confidence, "evidence": evidence}


def _detect_load_base(s_ea, e_ea, base_candidates, limit):
    arch = get_arch()
    ptr_size = _fw_ptr_size() or 4
    if base_candidates is not None:
        if not isinstance(base_candidates, (list, tuple)):
            return make_error(MCPError.INVALID_ARGS,
                              "base_candidates must be a list of hex addresses")
        cands = []
        for c in base_candidates:
            try:
                cands.append(int(str(c), 0))
            except (ValueError, TypeError):
                return make_error(MCPError.INVALID_ARGS, f"Invalid base candidate {c!r}")
    else:
        cands = _default_load_base_candidates(s_ea, e_ea, ptr_size)

    results = []
    for b in cands:
        results.append(_validate_load_base(b, arch, ptr_size, s_ea, e_ea))
    # Deduplicate by base, keeping the highest-confidence validation.
    seen = {}
    for r in results:
        prev = seen.get(r["base"])
        if prev is None or r["confidence"] > prev["confidence"]:
            seen[r["base"]] = r
    results = sorted(seen.values(), key=lambda r: -r["confidence"])
    results = results[:max(1, int(limit or 32))]
    return {
        "ok": True,
        "action": "detect_load_base",
        "arch": arch,
        "candidates": results,
        "recommended_base": results[0]["base"] if results else None,
        "note": (
            "Candidates are ranked by reset-vector + prologue plausibility. "
            "Set the correct load base when loading a raw blob, or rebase with "
            "Edit -> Segments -> Rebase in IDA."
        ),
    }


# ============================================================================
# detect_mmio
# ============================================================================

_KNOWN_PERIPHERAL_RANGES = [
    (0x40000000, 0x5FFFFFFF, "ARM Cortex-M peripheral space", "arm_cortex_m"),
    (0xE0000000, 0xFFFFFFFF, "ARM system control space", "arm_cortex_m"),
    (0x3FF00000, 0x3FFFFFFF, "ESP32 peripheral space", "esp32"),
    (0x60000000, 0x6FFFFFFF, "ESP32 IO MUX space", "esp32"),
    (0x40000000, 0x40FFFFFF, "nRF52 peripheral space", "nrf52"),
    (0x50000000, 0x503FFFFF, "RP2040 AHB/APB space", "rp2040"),
    (0x10000000, 0x100FFFFF, "generic SoC peripheral window", "generic"),
    (0xA0000000, 0xBFFFFFFF, "MIPS KSEG1 uncached peripherals", "mips"),
]

_MMIO_MIN_VALUE = 0x10000000  # ignore small immediates / ASCII noise


def _peripheral_match(v):
    for lo, hi, name, family in _KNOWN_PERIPHERAL_RANGES:
        if lo <= v <= hi:
            return name, family
    return None


def _detect_mmio(s_ea, e_ea, addr, addr_radius, limit):
    if addr:
        a_ea, err = parse_address_safe(addr)
        if err:
            return err
        radius = max(0, int(addr_radius or 0))
        scan_s = max(int(s_ea), a_ea - radius)
        scan_e = min(int(e_ea), a_ea + radius)
    else:
        scan_s, scan_e = int(s_ea), int(e_ea)
    if scan_s >= scan_e:
        return {
            "ok": True, "action": "detect_mmio", "scan_window": None,
            "ranges": [], "registers_hint": None,
            "note": "Empty scan window; nothing to inspect.",
        }

    # Register words are 32-bit even on 64-bit blobs (peripheral cells).
    word_size = 4
    pages = {}
    ea = scan_s
    while ea + word_size <= scan_e:
        data = _read_word_bytes(ea, word_size)
        if data is not None:
            v = _decode_word(data, "le" if not _fw_is_be() else "be")
            if v and v >= _MMIO_MIN_VALUE and not _addr_is_mapped(v):
                page = v & ~0xFFF
                # A page overlapping the mapped image is RAM/ROM, not a
                # peripheral window — stray instruction words routinely decode
                # to addresses just past the image end and would otherwise
                # shadow the image's own page as an MMIO candidate.  Guarded
                # with ``not`` (not ``continue``) so the scan cursor advances.
                if not (page < scan_e and page + 0x1000 > scan_s):
                    rec = pages.setdefault(page, {
                        "base": hex(page),
                        "count": 0,
                        "peripheral_name": None,
                        "chip_family": None,
                        "example_registers": [],
                    })
                    rec["count"] += 1
                    if len(rec["example_registers"]) < 5:
                        rec["example_registers"].append(hex(v))
                    match = _peripheral_match(v)
                    if match:
                        rec["peripheral_name"] = rec["peripheral_name"] or match[0]
                        rec["chip_family"] = rec["chip_family"] or match[1]
        ea += word_size

    ranges = sorted(pages.values(), key=lambda r: -r["count"])
    ranges = ranges[:max(1, int(limit or 32))]
    families = {}
    for r in ranges:
        f = r["chip_family"]
        if f:
            families[f] = families.get(f, 0) + r["count"]
    likely_family = max(families, key=families.get) if families else None
    registers_hint = {
        "distinct_pages": len(pages),
        "likely_family": likely_family,
        "top_registers": ranges[0]["example_registers"][:4] if ranges else [],
    }
    return {
        "ok": True,
        "action": "detect_mmio",
        "scan_window": {"start": hex(scan_s), "end": hex(scan_e)},
        "ranges": ranges,
        "registers_hint": registers_hint,
        "note": (
            "MMIO-style pages are register words that resolve outside the mapped "
            "RAM/ROM image, grouped by 4KB page density. Functions referencing "
            "these pages are likely HAL/driver code."
        ),
    }


# ============================================================================
# rtos_scan
# ============================================================================

_RTOS_SIGNATURES = {
    "FreeRTOS": ("freertos", "xtaskcreate", "xqueuereceive", "vtaskdelay",
                 "pvportmalloc", "xsemaphoretake", "tcb_t"),
    "ThreadX": ("threadx", "tx_thread_create", "tx_queue_receive",
                "tx_semaphore_get", "tx_thread_sleep"),
    "Zephyr": ("zephyr", "k_thread_create", "k_sem_take", "k_queue_get", "z_swap"),
    "RT-Thread": ("rtthread", "rt_thread_create", "rt_thread_init"),
    "uC/OS": ("ucos", "os_task_create", "os_q_pend"),
    "HAL": ("hal_uart", "hal_dma", "hal_gpio", "hal_spi", "stm32hal", "rtc_hal"),
}


def _rtos_scan(s_ea, e_ea, query, limit):
    names = []
    try:
        for _ea, nm in idautils.Names():
            if nm:
                names.append(str(nm))
    except Exception:
        pass
    strings = []
    try:
        for s in idautils.Strings():
            try:
                strings.append(str(s))
            except Exception:
                continue
            if len(strings) >= 2000:
                break
    except Exception:
        pass
    blob = "\n".join(names[:2000] + strings[:2000]).lower()

    raw = _read_bytes_range(s_ea, e_ea)
    raw_lower = raw.lower()

    matches = []
    for rtos, sigs in _RTOS_SIGNATURES.items():
        hits = []
        for sig in sigs:
            if sig in blob or sig.encode("ascii", "ignore") in raw_lower:
                hits.append(sig)
        if not hits:
            continue
        if query and query.lower() not in rtos.lower() \
                and not any(query.lower() in h for h in hits):
            continue
        confidence = round(min(0.95, 0.35 + len(hits) * 0.15), 3)
        matches.append({"rtos": rtos, "confidence": confidence, "evidence": hits[:10]})

    matches.sort(key=lambda m: -m["confidence"])
    matches = matches[:max(1, int(limit or 32))]
    return {
        "ok": True,
        "action": "rtos_scan",
        "matches": matches,
        "detected": matches[0]["rtos"] if matches else None,
        "query": query or "",
        "note": (
            "Signature scan over symbol names, string literals, and raw mapped "
            "bytes. TCB patterns / task-creation thunks / HAL_UART & HAL_DMA "
            "symbols drive the FreeRTOS and HAL hits."
        ),
    }


# ============================================================================
# carve
# ============================================================================

def _perms_string(perm):
    out = "r"
    if perm & getattr(idaapi, "SEGPERM_WRITE", 2):
        out += "w"
    if perm & getattr(idaapi, "SEGPERM_EXEC", 4):
        out += "x"
    return out


def _carve(start, end, name, sclass, limit, kwargs):
    if not start or not end:
        return make_error(MCPError.INVALID_ARGS,
                          "start and end are required for carve")
    s_ea, err = parse_address_safe(start)
    if err:
        return err
    e_ea, err = parse_address_safe(end)
    if err:
        return err
    if s_ea >= e_ea:
        return make_error(MCPError.INVALID_ARG_VALUE,
                          f"start ({hex(s_ea)}) must be less than end ({hex(e_ea)})")

    seg_name = name or kwargs.get("segment_name") or f"carve_{s_ea:x}_{e_ea:x}"
    sclass = sclass or "DATA"
    sclass_upper = str(sclass).upper()

    existing = idaapi.getseg(s_ea)
    if existing:
        return make_error(MCPError.SEGMENT_OVERLAP,
                          f"Address {hex(s_ea)} already belongs to segment "
                          f"'{_compat.get_segment_name(s_ea)}'")

    seg = idaapi.segment_t()
    seg.start_ea, seg.end_ea = s_ea, e_ea
    # Derive permissions from the segment class (mirrors segments.add) so a code
    # carve on an opaque blob is actually analyzed as code.
    perm = getattr(idaapi, "SEGPERM_READ", 1)
    if sclass_upper in ("CODE", "XTRN"):
        perm |= getattr(idaapi, "SEGPERM_EXEC", 4)
    elif sclass_upper == "BSS":
        perm |= getattr(idaapi, "SEGPERM_WRITE", 2)
    seg.perm = perm
    if not idaapi.add_segm_ex(seg, seg_name, sclass, 0):
        return make_error(MCPError.IDA_ERROR,
                          f"Failed to carve segment '{seg_name}' at {hex(s_ea)}-{hex(e_ea)}")

    result = {
        "ok": True,
        "action": "carve",
        "start": hex(s_ea),
        "end": hex(e_ea),
        "name": seg_name,
        "class": sclass,
        "perms": _perms_string(perm),
        "size": e_ea - s_ea,
    }

    # Optional file export (governed write; only reachable via a declared kwarg).
    out_file = kwargs.get("file") or kwargs.get("path")
    if out_file:
        data = ida_bytes.get_bytes(s_ea, e_ea - s_ea) or b""
        try:
            with open(str(out_file), "wb") as f:
                f.write(data)
            result["saved_to"] = str(out_file)
        except OSError as exc:
            result["save_error"] = str(exc)
    return result


# ============================================================================
# The tool
# ============================================================================

@tool
@idawrite
def firmware(
    action: Annotated[Literal["detect_vector_table", "detect_load_base", "detect_mmio",
                              "rtos_scan", "carve"],
                       "Action: detect_vector_table|detect_load_base|detect_mmio|rtos_scan|carve"],
    start: Annotated[Optional[str], "Inclusive start address of the scan/carve window (hex)"] = None,
    end: Annotated[Optional[str], "Exclusive end address of the scan/carve window (hex)"] = None,
    addr: Annotated[Optional[str], "Anchor address (hex) around which to scan for MMIO"] = None,
    limit: Annotated[int, "Maximum result items"] = 32,
    base: Annotated[Optional[str], "Vector-table base to scan (hex); default: whole mapped image"] = None,
    word: Annotated[str, "Vector-table entry width: auto|u32|u16"] = "auto",
    endian: Annotated[str, "Byte order to probe for the vector table: both|le|be"] = "both",
    base_candidates: Annotated[Optional[list], "Load-base hypotheses to validate (hex strings)"] = None,
    addr_radius: Annotated[int, "Radius (bytes) around `addr` to scan for MMIO"] = 4096,
    query: Annotated[str, "RTOS/HAL signature filter"] = "",
    name: Annotated[Optional[str], "Name for the carved segment"] = None,
    sclass: Annotated[str, "Segment class for carve: CODE|DATA|BSS|CONST|STACK|XTRN"] = "DATA",
    **kwargs,
) -> dict:
    """Firmware shaping for headerless / raw-blob binaries.

    ====== ACTIONS ======

    detect_vector_table — Scan candidate ISR/pointer tables.
        Params: base (optional table base), word ('auto'|'u32'|'u16'),
                endian ('both'|'le'|'be'), start/end (scan window)
        Returns: {candidates: [{base, count, first_entries, confidence}]}

    detect_load_base — Validate load-base hypotheses for a raw blob.
        Params: base_candidates (optional list of hex bases); default derives
                candidates from pointer density + the current base
        Returns: {candidates: [{base, confidence, evidence}], recommended_base}

    detect_mmio — Locate MMIO-style peripheral pages.
        Params: addr (optional anchor), addr_radius (bytes around addr)
        Returns: {ranges: [{base, count, peripheral_name, example_registers}],
                  registers_hint}

    rtos_scan — Lightweight RTOS/HAL signature scan.
        Params: query (optional filter, e.g. 'freertos' or 'hal')
        Returns: {matches: [{rtos, confidence, evidence}], detected}

    carve — Define a new segment from a byte range (governed write).
        Params: start, end (required), name (optional), sclass
        Returns: {start, end, name, class, perms, size}

    pointer_sweep lives in search(action='data_value'); auto_retype is deferred
    until the type-inference stack lands.
    """
    try:
        action_lower = str(action or "").strip().lower()
        if action_lower not in ("detect_vector_table", "detect_load_base",
                                "detect_mmio", "rtos_scan", "carve"):
            return make_error(MCPError.INVALID_ARGS,
                              f"Unknown action: '{action}'. Valid actions: "
                              "detect_vector_table, detect_load_base, detect_mmio, "
                              "rtos_scan, carve")
        limit = max(1, min(int(limit or 32), 512))

        if action_lower == "carve":
            return _carve(start, end, name, sclass, limit, kwargs)

        min_ea, max_ea = _fw_image_bounds()
        if min_ea is None:
            return make_error(MCPError.IDA_ERROR,
                              "IDB bounds are unavailable; open or map a binary "
                              "before firmware detection")
        s_ea, e_ea = min_ea, max_ea
        if start or end:
            ws, we, err = _fw_parse_range(start, end)
            if err:
                return err
            s_ea, e_ea = ws, we

        if action_lower == "detect_vector_table":
            return _detect_vector_table(s_ea, e_ea, base, word, endian, limit)
        if action_lower == "detect_load_base":
            return _detect_load_base(s_ea, e_ea, base_candidates, limit)
        if action_lower == "detect_mmio":
            return _detect_mmio(s_ea, e_ea, addr, addr_radius, limit)
        if action_lower == "rtos_scan":
            return _rtos_scan(s_ea, e_ea, query, limit)

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: '{action}'")
    except Exception as e:
        return handle_error(e, "firmware")
