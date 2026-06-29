
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]



# ============================================================================
# BINARY_INFO - Binary Metadata and Format Analysis for LLMs
# ============================================================================

@tool
@idaread
def binary_info(
    action: Annotated[Literal["headers", "sections", "relocations", "resources", "debug_info", "compiler", "linker", "timestamps", "checksums", "overlay"],
                      "Binary info action"],
    addr: Annotated[Optional[str], "Address for specific queries"] = None,
    limit: Annotated[int, "Max results"] = 50,
    **kwargs,
) -> dict:
    """
    Binary metadata and format analysis.

    Actions:
    - headers: Parse and return PE/ELF/Mach-O headers in structured format
    - sections: Detailed section/segment info (permissions, entropy, characteristics)
    - relocations: List relocations/fixups with types
    - resources: List embedded resources (PE resources, version info)
    - debug_info: Detect debug information availability (PDB, DWARF, symbols)
    - compiler: Detect compiler and version (MSVC, GCC, Clang, etc.)
    - linker: Detect linker information
    - timestamps: Extract all timestamps (compile time, debug time, etc.)
    - checksums: Verify checksums (PE checksum, section hashes)
    - overlay: Detect and analyze overlay data (data appended after PE)
    """
    try:
        from collections import Counter

        import ida_entry
        info = idaapi.get_inf_structure() if hasattr(idaapi, 'get_inf_structure') else None
        file_type = _inf_filetype_id()
        proc_name = _inf_procname()

        # Determine binary format
        is_pe = file_type in (idaapi.f_PE, idaapi.f_COFF) if hasattr(idaapi, 'f_PE') else False
        is_elf = file_type == idaapi.f_ELF if hasattr(idaapi, 'f_ELF') else False
        is_macho = file_type == idaapi.f_MACHO if hasattr(idaapi, 'f_MACHO') else False

        fmt_name = "PE" if is_pe else "ELF" if is_elf else "Mach-O" if is_macho else "RAW" if file_type in (0, 2, 17) else _filetype_name(file_type).upper()

        if action == "headers":
            # Entry points
            entries = []
            for i in range(ida_entry.get_entry_qty()):
                ordinal = ida_entry.get_entry_ordinal(i)
                ea = ida_entry.get_entry(ordinal)
                name = ida_entry.get_entry_name(ordinal) or ""
                entries.append(f"{hex(ea)}  ord={ordinal}  {name}")
                if len(entries) >= limit:
                    break

            min_ea = _inf_min_ea() if info else 0
            max_ea = _inf_max_ea() if info else 0

            bitness = _inf_bitness()
            lines = [
                f"format: {fmt_name}",
                f"processor: {proc_name}",
                f"bitness: {bitness}",
                f"image_base: {hex(min_ea)}",
                f"image_end: {hex(max_ea)}",
                f"image_size: {hex_size(max_ea - min_ea)}",
                f"entry_count: {ida_entry.get_entry_qty()}",
            ]
            if entries:
                lines.append("entries:\n  " + "\n  ".join(entries))

            return {"ok": True, "headers": "\n".join(lines)}

        elif action == "sections":
            import math as _math

            def calc_entropy(start_ea, length):
                data = ida_bytes.get_bytes(start_ea, min(length, 0x100000))
                if not data:
                    return 0.0
                occ = Counter(data)
                ent = 0.0
                for count in occ.values():
                    p = count / len(data)
                    ent -= p * _math.log2(p)
                return round(ent, 4)

            sections = []
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                name = ida_segment.get_segm_name(seg)
                perm_str = ""
                read_mask = getattr(idaapi, "SEGPERM_READ", 1)
                write_mask = getattr(idaapi, "SEGPERM_WRITE", 2)
                exec_mask = getattr(idaapi, "SEGPERM_EXEC", 4)
                perm_str += "R" if seg.perm & read_mask else "-"
                perm_str += "W" if seg.perm & write_mask else "-"
                perm_str += "X" if seg.perm & exec_mask else "-"
                seg_class = ida_segment.get_segm_class(seg) or ""
                ent = calc_entropy(seg.start_ea, seg.size())
                sections.append(
                    f"{name}  {hex(seg.start_ea)}-{hex(seg.end_ea)}  "
                    f"size={hex_size(seg.size())}  perm={perm_str}  "
                    f"class={seg_class}  entropy={ent}"
                )
                if len(sections) >= limit:
                    break
            return {"ok": True, "sections": "\n".join(sections), "count": len(sections)}

        elif action == "relocations":
            results = []
            # Use ida_fixups if available
            try:
                import ida_fixups
                fixup_ea = ida_fixups.get_first_fixup_ea()
                while fixup_ea != idaapi.BADADDR and len(results) < limit:
                    fd = ida_fixups.fixup_data_t()
                    if ida_fixups.get_fixup(fd, fixup_ea):
                        ftype = fd.get_type()
                        results.append(f"{hex(fixup_ea)}  type={ftype}  target={hex(fd.off)}")
                    fixup_ea = ida_fixups.get_next_fixup_ea(fixup_ea)
            except (ImportError, AttributeError):
                results.append("Fixup API not available in this IDA version")
            return {"ok": True, "relocations": "\n".join(results), "count": len(results)}

        elif action == "resources":
            results = []
            # Look for resource segment
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                name = ida_segment.get_segm_name(seg)
                if name.lower() in (".rsrc", "rsrc", ".rdata"):
                    results.append(f"Resource segment: {name}  {hex(seg.start_ea)}-{hex(seg.end_ea)}  size={hex_size(seg.size())}")
            # Try to find version info strings
            for s in idautils.Strings():
                raw = idc.get_strlit_contents(s.ea, -1, idc.get_str_type(s.ea) or 0)
                if raw:
                    try:
                        text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
                    except Exception:
                        text = repr(raw)
                    if any(kw in text.lower() for kw in ("fileversion", "productversion", "companyname", "filedescription", "originalfilename")):
                        results.append(f"{hex(s.ea)}  {text}")
                        if len(results) >= limit:
                            break
            if not results:
                results.append("No resources detected")
            return {"ok": True, "resources": "\n".join(results), "count": len(results)}

        elif action == "debug_info":
            indicators = []
            # Check for debug segments
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                name = ida_segment.get_segm_name(seg)
                if any(d in name.lower() for d in (".debug", "dwarf", ".pdata", ".eh_frame")):
                    indicators.append(f"Debug segment: {name}  {hex(seg.start_ea)}")
            # Check input file path for PDB
            input_path = idaapi.get_input_file_path()
            if input_path:
                indicators.append(f"Input file: {input_path}")
            # Check if symbols are loaded (named functions vs sub_)
            named = 0
            total = 0
            for ea in idautils.Functions():
                total += 1
                name = idc.get_func_name(ea)
                if name and not name.startswith("sub_"):
                    named += 1
                if total >= 1000:
                    break
            ratio = named / total if total else 0
            indicators.append(f"Symbol coverage: {named}/{total} named functions ({ratio:.1%})")
            if ratio > 0.5:
                indicators.append("Debug symbols likely present")
            else:
                indicators.append("Stripped binary (limited symbols)")
            return {"ok": True, "debug_info": "\n".join(indicators)}

        elif action == "compiler":
            signatures = []
            # Check for compiler-specific strings
            compiler_patterns = {
                "MSVC": ["Microsoft Visual C++", "MSVC", "_MSC_VER", "cl.exe", ".CRT"],
                "GCC": ["GCC:", "GNU C", "__GNUC__", "gcc", "libgcc"],
                "Clang": ["clang", "LLVM", "__clang__"],
                "MinGW": ["mingw", "MinGW", "__MINGW"],
                "Borland": ["Borland", "Delphi", "__BORLANDC__"],
                "Watcom": ["WATCOM", "__WATCOMC__"],
                "Intel": ["Intel(R) C++", "__INTEL_COMPILER", "__ICC"],
            }
            detected = set()
            for s in idautils.Strings():
                raw = idc.get_strlit_contents(s.ea, -1, idc.get_str_type(s.ea) or 0)
                if not raw:
                    continue
                try:
                    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
                except Exception:
                    continue
                for compiler, patterns in compiler_patterns.items():
                    for pat in patterns:
                        if pat in text:
                            detected.add(compiler)
                            signatures.append(f"{compiler}: matched '{pat}' at {hex(s.ea)}")
                            break
                if len(signatures) >= limit:
                    break

            # Check for known compiler signatures in code
            # Rich header (MSVC), .comment section (GCC)
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                name = ida_segment.get_segm_name(seg)
                if name == ".comment":
                    data = ida_bytes.get_bytes(seg.start_ea, min(seg.size(), 256))
                    if data:
                        signatures.append(f"Comment section: {data.decode('ascii', errors='replace').strip()}")

            if not detected:
                signatures.append("Compiler not definitively identified")

            return {"ok": True, "detected_compilers": list(detected), "evidence": "\n".join(signatures)}

        elif action == "linker":
            indicators = []
            # Check for linker-specific sections and strings
            linker_sections = {
                ".reloc": "PE linker",
                ".dynamic": "ELF dynamic linker",
                ".interp": "ELF interpreter",
                ".got": "ELF GOT (dynamic linking)",
                ".plt": "ELF PLT (dynamic linking)",
                ".idata": "PE import directory",
                ".edata": "PE export directory",
            }
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                name = ida_segment.get_segm_name(seg)
                if name in linker_sections:
                    indicators.append(f"{linker_sections[name]}: {name}  {hex(seg.start_ea)}")

            # Check for linker strings
            for s in idautils.Strings():
                raw = idc.get_strlit_contents(s.ea, -1, idc.get_str_type(s.ea) or 0)
                if not raw:
                    continue
                try:
                    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
                except Exception:
                    continue
                if any(lk in text.lower() for lk in ("linker", "ld-linux", "link.exe", "lld")):
                    indicators.append(f"Linker string at {hex(s.ea)}: {text[:100]}")
                    if len(indicators) >= limit:
                        break

            if not indicators:
                indicators.append("No specific linker information detected")
            return {"ok": True, "linker_info": "\n".join(indicators)}

        elif action == "timestamps":
            timestamps = []
            # PE timestamp from headers (use IDA's stored info)
            try:
                import ida_netnode
                # PE header timestamp is often at offset 0x8 in COFF header
                pe_node = ida_netnode.netnode("$ PE header")
                if pe_node != idaapi.BADADDR:
                    timestamps.append("PE header node found")
            except (ImportError, Exception):
                pass

            # Look for timestamp-like strings
            for s in idautils.Strings():
                raw = idc.get_strlit_contents(s.ea, -1, idc.get_str_type(s.ea) or 0)
                if not raw:
                    continue
                try:
                    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
                except Exception:
                    continue
                # Match date patterns
                import re
                if re.search(r'\d{4}[-/]\d{2}[-/]\d{2}', text) or \
                   re.search(r'(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}', text):
                    timestamps.append(f"{hex(s.ea)}  {text[:100]}")
                    if len(timestamps) >= limit:
                        break

            if not timestamps:
                timestamps.append("No timestamps detected")
            return {"ok": True, "timestamps": "\n".join(timestamps)}

        elif action == "checksums":
            import hashlib
            results = []
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if not seg:
                    continue
                name = ida_segment.get_segm_name(seg)
                data = ida_bytes.get_bytes(seg.start_ea, min(seg.size(), 0x1000000))
                if data:
                    md5 = hashlib.md5(data).hexdigest()
                    sha1 = hashlib.sha1(data).hexdigest()[:16]
                    results.append(f"{name}  size={hex_size(len(data))}  md5={md5}  sha1={sha1}...")
                if len(results) >= limit:
                    break

            # Overall binary hash
            input_path = idaapi.get_input_file_path()
            if input_path:
                results.insert(0, f"input_file: {input_path}")
                try:
                    input_md5 = ida_nalt.retrieve_input_file_md5()
                    if input_md5:
                        results.insert(1, f"input_md5: {input_md5.hex() if isinstance(input_md5, bytes) else input_md5}")
                except Exception:
                    pass

            return {"ok": True, "checksums": "\n".join(results)}

        elif action == "overlay":
            results = []
            # Check for data beyond last section
            max_seg_end = 0
            for seg_ea in idautils.Segments():
                seg = idaapi.getseg(seg_ea)
                if seg and seg.end_ea > max_seg_end:
                    max_seg_end = seg.end_ea

            input_path = idaapi.get_input_file_path()
            if input_path:
                try:
                    file_size = os.path.getsize(input_path)
                    results.append(f"Input file: {input_path}")
                    results.append(f"File size: {hex_size(file_size)}")
                    results.append(f"Max segment end: {hex(max_seg_end)}")
                    # Check if IDA loaded all of the file
                    image_size = _inf_max_ea() - _inf_min_ea()
                    if file_size > image_size:
                        overlay_size = file_size - image_size
                        results.append(f"Potential overlay: {hex_size(overlay_size)} bytes beyond mapped image")
                    else:
                        results.append("No overlay detected")
                except OSError:
                    results.append("Cannot access input file for overlay check")
            else:
                results.append("Input file path not available")

            return {"ok": True, "overlay": "\n".join(results)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
