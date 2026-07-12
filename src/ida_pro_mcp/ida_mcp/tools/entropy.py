
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


# ============================================================================
# 31. ENTROPY - Entropy Analysis
# ============================================================================

def entropy(
    action: Annotated[Literal["section", "region", "packed_detect", "crypto_detect", "compare", "window", "summary"],
                      "Action: section|region|packed_detect|crypto_detect|compare|window|summary"],
    addr: Annotated[Optional[str], "Start address for region/compare/window"] = None,
    size: Annotated[int, "Size in bytes for region analysis"] = 4096,
    threshold: Annotated[float, "Entropy threshold (0.0-8.0)"] = 7.0,
    end_addr: Annotated[Optional[str], "End address for comparison/window"] = None,
    window: Annotated[int, "Sliding window size for scans"] = 4096,
    step: Annotated[int, "Sliding step size for scans"] = 1024,
    limit: Annotated[int, "Max results"] = 50,
    **kwargs
) -> dict:
    """
    Entropy and heuristic analysis for detecting packed or encrypted code.

    Actions:
    - section: Calculate entropy for each segment in the database with window stats.
    - region: Calculate entropy for a specific memory range with histogram.
    - packed_detect: Find windows with suspiciously high entropy.
    - crypto_detect: Search for known cryptographic constants and S-Boxes.
    - compare: Compare the entropy of two memory regions.
    - window: Sliding-window scan for a region.
    - summary: Global entropy summary across segments.
    """
    try:
        import math
        from collections import Counter

        def calc_entropy(start_ea, length):
            data = ida_bytes.get_bytes(start_ea, length)
            if not data: return 0.0
            occ = Counter(data)
            ent = 0.0
            for count in occ.values():
                p = count / len(data)
                ent -= p * math.log2(p)
            return round(ent, 4)

        def histogram(data, top=10):
            if not data:
                return ""
            occ = Counter(data)
            common = occ.most_common(top)
            return ", ".join(f"0x{b:02x}={c}" for b, c in common)

        def window_scan(start_ea, length):
            """Returns list of (addr, window_size, entropy) tuples for internal use."""
            results = []
            if length <= 0:
                return results
            end_ea = start_ea + length
            cur = start_ea
            while cur + window <= end_ea and len(results) < limit:
                ent = calc_entropy(cur, window)
                results.append((cur, window, ent))
                cur += max(1, step)
            return results

        def format_windows(windows):
            """Format window tuples as compact text lines."""
            return "\n".join(f"{hex(addr)}  size={sz}  ent={ent}" for addr, sz, ent in windows)

        def search_pattern(pattern_bytes):
            hits = []
            if not pattern_bytes:
                return hits
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                data = ida_bytes.get_bytes(seg.start_ea, seg.size())
                if not data:
                    continue
                idx = data.find(pattern_bytes)
                if idx != -1:
                    hits.append(hex(seg.start_ea + idx))
            return hits

        if action == "region":
            if not addr: return make_error(MCPError.INVALID_ARGS, "addr required")
            ea, err = validate_addr(addr)
            if err: return err
            data = ida_bytes.get_bytes(ea, size) or b""
            return {
                "ok": True,
                "addr": hex(ea),
                "size": size,
                "entropy": calc_entropy(ea, size),
                "null_ratio": round((data.count(0) / len(data)), 4) if data else 0.0,
                "histogram": histogram(data, top=10),
            }

        elif action == "section":
            section_lines = []
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg: continue
                scan_size = min(seg.size(), 0x100000)
                ent = calc_entropy(seg.start_ea, scan_size) # Cap at 1MB for speed
                windows = window_scan(seg.start_ea, scan_size)
                if windows:
                    ents = [w[2] for w in windows]
                    high_ratio = round(sum(1 for e in ents if e >= threshold) / len(ents), 4)
                    stats = f"min={min(ents)}  max={max(ents)}  avg={round(sum(ents)/len(ents), 4)}  high={high_ratio}"
                else:
                    stats = f"ent={ent}"
                packed = "PACKED" if ent > threshold else ""
                section_lines.append(f"{ida_segment.get_segm_name(seg)}  {hex(seg.start_ea)}  ent={ent}  {stats}  {packed}")
            return {"ok": True, "sections": "\n".join(section_lines)}

        elif action == "packed_detect":
            finding_lines = []
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg: continue
                scan_size = min(seg.size(), 0x200000)
                windows = window_scan(seg.start_ea, scan_size)
                seg_name = ida_segment.get_segm_name(seg)
                for addr, sz, ent_val in windows:
                    if ent_val >= threshold:
                        finding_lines.append(f"{seg_name}  {hex(addr)}  size={sz}  ent={ent_val}  HIGH_ENTROPY")
                        if len(finding_lines) >= limit:
                            break
                if len(finding_lines) >= limit:
                    break
            return {"ok": True, "findings": "\n".join(finding_lines), "count": len(finding_lines)}

        elif action == "crypto_detect":
            # AES S-Box and SHA-256 K constants
            aes_sbox = bytes([
                0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
                0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
                0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
                0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
                0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
                0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
                0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
                0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
                0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
                0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
                0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
                0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
                0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
                0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
                0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
                0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
            ])
            sha256_k = bytes([
                0x42,0x8a,0x2f,0x98,0x71,0x37,0x44,0x91,0xb5,0xc0,0xfb,0xcf,0xe9,0xb5,0xdb,0xa5,
                0x39,0x56,0xc2,0x5b,0x59,0xf1,0x11,0xf1,0x92,0x3f,0x82,0xa4,0xab,0x1c,0x5e,0xd5
            ])
            hits = {
                "aes_sbox": search_pattern(aes_sbox),
                "sha256_k": search_pattern(sha256_k),
            }
            return {"ok": True, "hits": hits}

        elif action == "compare":
            if not addr or not end_addr:
                return make_error(MCPError.INVALID_ARGS, "addr and end_addr required")
            s1, err = validate_addr(addr)
            if err: return err
            s2, err = validate_addr(end_addr)
            if err: return err
            e1 = calc_entropy(s1, size)
            e2 = calc_entropy(s2, size)
            return {
                "ok": True,
                "region_a": {"addr": hex(s1), "size": size, "entropy": e1},
                "region_b": {"addr": hex(s2), "size": size, "entropy": e2},
                "delta": round(e1 - e2, 4),
            }

        elif action == "window":
            if not addr or not end_addr:
                return make_error(MCPError.INVALID_ARGS, "addr and end_addr required")
            s_ea, e_ea, err = validate_range(addr, end_addr)
            if err: return err
            windows = window_scan(s_ea, e_ea - s_ea)
            return {"ok": True, "start": hex(s_ea), "end": hex(e_ea), "windows": format_windows(windows), "count": len(windows)}

        elif action == "summary":
            section_lines = []
            total_entropy = []
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg: continue
                scan_size = min(seg.size(), 0x100000)
                ent = calc_entropy(seg.start_ea, scan_size)
                section_lines.append(f"{ida_segment.get_segm_name(seg)}  ent={ent}")
                total_entropy.append(ent)
            avg = round(sum(total_entropy) / len(total_entropy), 4) if total_entropy else 0.0
            return {"ok": True, "avg_entropy": avg, "sections": "\n".join(section_lines)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)


# ============================================================================
# 32. IMPORTS_DEEP - Deep Import Analysis
# ============================================================================
