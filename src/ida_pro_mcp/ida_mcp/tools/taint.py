"""
taint — Data flow taint analysis from sources to dangerous sinks.

Traces how user-controlled data (network recv, file read, user input)
flows through the call graph and decompiler variable graph to reach
dangerous operations (memcpy, strcpy, system, exec, etc.).

Actions:
  trace   — trace taint from a source address forward to sinks
  sources — list known taint sources in the binary (imports + blackboard IOCs)
  sinks   — list dangerous sinks reachable from a source
  paths   — show full taint paths (source → intermediate → sink)
  report  — full taint report: all sources, all reachable sinks, all paths
"""

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

from typing import Optional, List, Dict, Set, Tuple, Any


# ── Known taint sources (user-controlled input) ───────────────────────────────

TAINT_SOURCES = {
    # Network
    "recv", "recvfrom", "recvmsg", "WSARecv", "WSARecvFrom",
    "read", "fread", "fgets", "gets",
    # File
    "fread", "fgets", "gets", "scanf", "sscanf", "fscanf",
    # Environment
    "getenv", "getenv_s",
    # Windows
    "ReadFile", "RegQueryValueEx", "GetEnvironmentVariable",
    "WinHttpReceiveResponse", "InternetReadFile",
    # Firmware: UART receive (common naming patterns across MCU SDKs)
    "UART_Receive", "UART_Read", "uart_read", "uart_receive", "uart_getc",
    "HAL_UART_Receive", "HAL_UART_Receive_IT", "HAL_UART_Receive_DMA",
    "USART_ReceiveData", "USART_GetFlagStatus",
    "Serial_Read", "serial_read", "serial_getchar",
    # Firmware: DMA receive buffers
    "DMA_Receive", "dma_read", "HAL_DMA_Start", "HAL_DMA_PollForTransfer",
    # Firmware: SPI/I2C/USB receive
    "SPI_Receive", "HAL_SPI_Receive", "HAL_I2C_Master_Receive",
    "HAL_I2C_Slave_Receive", "USB_ReadPacket", "USBD_LL_DataOutStage",
    "HAL_PCD_DataOutStageCallback",
    # Firmware: network stack (lwIP, FreeRTOS+TCP)
    "pbuf_alloc", "netconn_recv", "xNetworkInterfaceInput",
    "FreeRTOS_recv", "FreeRTOS_recvfrom",
    # Firmware: MMIO reads (generic — matched by name pattern in _get_import_addrs)
    # These are detected via blackboard IOC entries with ioc_type='mmio_input'
}

# ── Dangerous sinks ───────────────────────────────────────────────────────────

DANGEROUS_SINKS = {
    # Memory corruption
    "memcpy": "buffer_overflow",
    "memmove": "buffer_overflow",
    "strcpy": "buffer_overflow",
    "strncpy": "buffer_overflow",
    "strcat": "buffer_overflow",
    "strncat": "buffer_overflow",
    "sprintf": "format_string",
    "vsprintf": "format_string",
    "snprintf": "format_string",
    "gets": "buffer_overflow",
    "scanf": "buffer_overflow",
    # Command execution
    "system": "command_injection",
    "exec": "command_injection",
    "execve": "command_injection",
    "execl": "command_injection",
    "popen": "command_injection",
    "ShellExecute": "command_injection",
    "WinExec": "command_injection",
    "CreateProcess": "command_injection",
    # Memory operations
    "VirtualAlloc": "memory_control",
    "WriteProcessMemory": "process_injection",
    "mmap": "memory_control",
    # Firmware: unsafe UART/network transmit with attacker-controlled data
    "UART_Transmit": "firmware_output_injection",
    "HAL_UART_Transmit": "firmware_output_injection",
    "netconn_write": "firmware_output_injection",
    "FreeRTOS_send": "firmware_output_injection",
    # Firmware: flash write (attacker-controlled data written to flash = persistent compromise)
    "HAL_FLASH_Program": "firmware_flash_write",
    "flash_write": "firmware_flash_write",
    "spi_flash_write": "firmware_flash_write",
}


def _get_import_addrs(name_set: set) -> Dict[str, int]:
    """Return {name: ea} for all imports matching name_set."""
    result = {}
    try:
        for i in range(idaapi.get_import_module_qty()):
            def _cb(ea, name, ord_):
                if name and name in name_set:
                    result[name] = ea
                return True
            idaapi.enum_import_names(i, _cb)
    except Exception:
        pass
    return result


def _callers_of(ea: int, max_depth: int, visited: Set[int]) -> List[Tuple[int, int, List[int]]]:
    """
    BFS: find all functions that can reach ea through the call graph.
    Returns list of (caller_ea, depth, path).
    """
    results = []
    queue = [(ea, 0, [ea])]
    while queue:
        curr, depth, path = queue.pop(0)
        if depth >= max_depth:
            continue
        for xref in idautils.CodeRefsTo(curr, 0):
            fn = idaapi.get_func(xref)
            if not fn:
                continue
            fea = fn.start_ea
            if fea in visited:
                continue
            visited.add(fea)
            new_path = path + [fea]
            results.append((fea, depth + 1, new_path))
            queue.append((fea, depth + 1, new_path))
    return results


def _callees_of(ea: int, max_depth: int, visited: Set[int]) -> List[Tuple[int, int, List[int]]]:
    """
    BFS forward: find all functions reachable from ea through the call graph.
    Returns list of (callee_ea, depth, path).
    """
    results = []
    queue = [(ea, 0, [ea])]
    while queue:
        curr, depth, path = queue.pop(0)
        if depth >= max_depth:
            continue
        fn = idaapi.get_func(curr)
        if not fn:
            continue
        for item in idautils.FuncItems(fn.start_ea):
            for xref in idautils.XrefsFrom(item, 0):
                if not xref.iscode:
                    continue
                target_fn = idaapi.get_func(xref.to)
                target_ea = target_fn.start_ea if target_fn else xref.to
                if target_ea in visited:
                    continue
                visited.add(target_ea)
                new_path = path + [target_ea]
                results.append((target_ea, depth + 1, new_path))
                queue.append((target_ea, depth + 1, new_path))
    return results


def _check_decompiler_dataflow_regex(source_ea: int, sink_ea: int) -> Optional[str]:
    """
    Check if source_ea's output variable flows into sink_ea's arguments
    via the decompiler variable dependency graph.
    Returns a description if taint flows, None otherwise.
    """
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return None
        # Decompile the function containing source_ea
        fn = idaapi.get_func(source_ea)
        if not fn:
            return None
        cfunc = ida_hexrays.decompile(fn.start_ea)
        if not cfunc:
            return None
        pseudo = str(cfunc)
        # Look for the sink name in the same function
        sink_name = idc.get_name(sink_ea) or ""
        if sink_name and sink_name in pseudo:
            # Find the variable that receives the source output
            import re
            # Pattern: var = source_func(...) ... sink_func(..., var, ...)
            source_name = idc.get_name(source_ea) or ""
            if source_name:
                assign_match = re.search(
                    rf'(\w+)\s*=\s*{re.escape(source_name)}\s*\(', pseudo
                )
                if assign_match:
                    tainted_var = assign_match.group(1)
                    # Check if tainted_var appears in sink call
                    sink_match = re.search(
                        rf'{re.escape(sink_name)}\s*\([^)]*\b{re.escape(tainted_var)}\b', pseudo
                    )
                    if sink_match:
                        return f"{tainted_var} = {source_name}(...) → {sink_name}(..., {tainted_var}, ...)"
        return None
    except Exception:
        return None


def _collect_mop_mregs(mop, out: Set[int]) -> None:
    """Best-effort recursive extraction of micro-register ids from a mop_t tree."""
    if mop is None:
        return
    try:
        if hasattr(mop, "r"):
            r = int(getattr(mop, "r"))
            if r >= 0:
                out.add(r)
    except Exception:
        pass
    # Common nested operand containers in Hex-Rays mop_t shapes.
    for child_attr in ("l", "r", "d", "a", "f", "g", "pair", "obj"):
        child = getattr(mop, child_attr, None)
        if child is None:
            continue
        if isinstance(child, (list, tuple)):
            for c in child:
                _collect_mop_mregs(c, out)
        else:
            _collect_mop_mregs(child, out)


def _insn_uses_taint(insn, tainted_mregs: Set[int]) -> bool:
    used: Set[int] = set()
    _collect_mop_mregs(getattr(insn, "l", None), used)
    _collect_mop_mregs(getattr(insn, "r", None), used)
    return any(r in tainted_mregs for r in used)


def _insn_defs(insn) -> Set[int]:
    defs: Set[int] = set()
    _collect_mop_mregs(getattr(insn, "d", None), defs)
    return defs


def _check_microcode_dataflow(source_ea: int, sink_ea: int) -> Optional[str]:
    """
    Real microcode def-use walk using a fixpoint over tainted mregs.
    """
    try:
        if not hasattr(ida_hexrays, "init_hexrays_plugin") or not ida_hexrays.init_hexrays_plugin():
            return None
        fn = idaapi.get_func(source_ea)
        if not fn:
            return None
        cfunc = ida_hexrays.decompile(fn.start_ea)
        if not cfunc:
            return None
        mba = getattr(cfunc, "mba", None)
        if mba is None:
            return None

        source_name = (idc.get_name(source_ea) or hex_ea(source_ea)).lower()
        sink_name = (idc.get_name(sink_ea) or hex_ea(sink_ea)).lower()
        m_call = getattr(ida_hexrays, "m_call", None)

        # Seed taint from source call assignment, then propagate until stable.
        tainted_mregs: Set[int] = set()
        seen_source = False
        seen_sink = False

        changed = True
        iterations = 0
        max_iter = max(4, int(getattr(mba, "qty", 0) or 0) * 2)
        while changed and iterations < max_iter:
            changed = False
            iterations += 1
            for bi in range(int(getattr(mba, "qty", 0) or 0)):
                blk = mba.get_mblock(bi)
                insn = getattr(blk, "head", None)
                while insn:
                    txt = str(insn)
                    low = txt.lower()

                    # Seed from source call occurrences.
                    if source_name and source_name in low and "call" in low:
                        seen_source = True
                        defs = _insn_defs(insn)
                        for d in defs:
                            if d not in tainted_mregs:
                                tainted_mregs.add(d)
                                changed = True

                    uses_taint = _insn_uses_taint(insn, tainted_mregs)
                    defs = _insn_defs(insn)
                    if uses_taint and defs:
                        for d in defs:
                            if d not in tainted_mregs:
                                tainted_mregs.add(d)
                                changed = True

                    # m_call propagation: tainted arg -> tainted return def.
                    try:
                        is_call = (m_call is not None and int(getattr(insn, "opcode", -1)) == int(m_call)) or ("call" in low)
                    except Exception:
                        is_call = "call" in low
                    if is_call and uses_taint and defs:
                        for d in defs:
                            if d not in tainted_mregs:
                                tainted_mregs.add(d)
                                changed = True

                    if sink_name and sink_name in low and uses_taint:
                        seen_sink = True

                    insn = getattr(insn, "next", None)

        if seen_source and seen_sink:
            return f"microcode_ssa def-use: {source_name} -> tainted mregs -> {sink_name}"
        return None
    except Exception:
        return None


def _dataflow_signal(source_ea: int, sink_ea: int) -> Dict[str, Any]:
    mc = _check_microcode_dataflow(source_ea, sink_ea)
    if mc:
        return {"desc": mc, "confidence": "high", "method": "microcode_ssa"}
    rx = _check_decompiler_dataflow_regex(source_ea, sink_ea)
    if rx:
        return {"desc": rx, "confidence": "low", "method": "regex"}
    return {"desc": None, "confidence": "medium", "method": "callgraph"}


@tool
@idaread
def taint(
    action: str = "trace",
    addr: Optional[str] = None,
    source: Optional[str] = None,
    max_depth: int = 5,
    max_paths: int = 20,
    **kwargs
) -> dict:
    """
    Data flow taint analysis from user-controlled sources to dangerous sinks.

    Actions:
      sources — list all taint sources in the binary (network/file/env imports + blackboard IOCs)
      sinks   — list dangerous sinks reachable from a given source address
      trace   — trace taint forward from addr/source, find all reachable sinks
      paths   — show full call-graph paths from source to each sink
      report  — full report: all sources → all reachable sinks with paths

    Examples:
      taint(action="sources")
      taint(action="trace", addr="0x401000")
      taint(action="trace", source="recv")
      taint(action="paths", source="recv", max_depth=4)
      taint(action="report")
    """
    try:
        if action == "sources":
            # Find all taint sources in the binary
            import_sources = _get_import_addrs(TAINT_SOURCES)
            result = []
            for name, ea in sorted(import_sources.items()):
                callers = list(idautils.CodeRefsTo(ea, 0))
                result.append({
                    "name": name,
                    "addr": hex_ea(ea),
                    "caller_count": len(callers),
                    "type": "import",
                })
            # Also check blackboard IOCs
            try:
                from blackboard import BlackboardStore  # type: ignore
                store = BlackboardStore()
                iocs = store.list(category="ioc", include_resolved=False, limit=50)
                for ioc in iocs:
                    ioc_type = ioc.get("ioc_type", "")
                    if ioc_type in ("ip_port", "url", "domain", "mmio_input", "dma_buffer", "uart_rx"):
                        result.append({
                            "name": ioc.get("title", ""),
                            "addr": ioc.get("addr", ""),
                            "type": "ioc",
                            "category": ioc_type,
                            "ioc_value": ioc.get("ioc_value", ""),
                        })
            except Exception:
                pass
            # Also scan for firmware MMIO read patterns in names (sub_ functions near peripheral addresses)
            try:
                _MMIO_PATTERNS = ("UART", "uart", "DMA", "dma", "SPI", "I2C", "USB", "ETH", "WIFI", "BLE")
                for ea, name in idautils.Names():
                    if any(p in name for p in _MMIO_PATTERNS) and ("Receive" in name or "Read" in name or "Get" in name):
                        if name not in {r["name"] for r in result}:
                            callers = list(idautils.CodeRefsTo(ea, 0))
                            result.append({
                                "name": name,
                                "addr": hex_ea(ea),
                                "caller_count": len(callers),
                                "type": "firmware_peripheral",
                            })
            except Exception:
                pass
            return {"ok": True, "sources": result, "count": len(result)}

        elif action in ("sinks", "trace", "paths"):
            # Resolve source address
            source_ea = None
            source_name = source or ""

            if addr:
                ea, err = validate_addr(addr)
                if err:
                    return err
                source_ea = ea
                if not source_name:
                    source_name = idc.get_name(ea) or hex_ea(ea)
            elif source:
                # Look up by import name
                imports = _get_import_addrs({source})
                if imports:
                    source_ea = list(imports.values())[0]
                    source_name = source
                else:
                    # Try as address
                    try:
                        source_ea = int(source, 16)
                        source_name = idc.get_name(source_ea) or source
                    except Exception:
                        return make_error(MCPError.INVALID_ARGS,
                                          f"Source '{source}' not found as import or address")
            else:
                return make_error(MCPError.INVALID_ARGS, "addr or source required")

            # Find dangerous sinks reachable from source_ea
            sink_addrs = _get_import_addrs(set(DANGEROUS_SINKS.keys()))
            visited: Set[int] = {source_ea}
            reachable = _callees_of(source_ea, max_depth=max_depth, visited=visited)

            # Check which reachable functions are dangerous sinks
            reachable_eas = {ea for ea, _, _ in reachable}
            found_sinks = []
            for sink_name, sink_ea in sink_addrs.items():
                if sink_ea in reachable_eas or sink_ea == source_ea:
                    # Find the path to this sink
                    path_to_sink = None
                    for ea, depth, path in reachable:
                        if ea == sink_ea:
                            path_to_sink = [hex_ea(p) for p in path]
                            break
                    # Check decompiler dataflow for direct taint
                    flow = _dataflow_signal(source_ea, sink_ea)
                    dataflow_desc = flow.get("desc")
                    conf_label = str(flow.get("confidence") or "medium")
                    conf_num = {"high": 0.9, "medium": 0.6, "low": 0.45}.get(conf_label, 0.6)
                    found_sinks.append({
                        "sink": sink_name,
                        "sink_addr": hex_ea(sink_ea),
                        "vuln_type": DANGEROUS_SINKS.get(sink_name, "unknown"),
                        "depth": len(path_to_sink) - 1 if path_to_sink else -1,
                        "path": path_to_sink,
                        "dataflow": dataflow_desc,
                        "confidence": conf_num,
                        "confidence_level": conf_label,
                        "analysis_method": flow.get("method"),
                        "inference_method": flow.get("method"),
                    })

            # Sort by depth (closest sinks first)
            found_sinks.sort(key=lambda x: x["depth"] if x["depth"] >= 0 else 999)

            if action == "sinks":
                return {
                    "ok": True,
                    "source": source_name,
                    "source_addr": hex_ea(source_ea),
                    "sinks": found_sinks[:max_paths],
                    "count": len(found_sinks),
                }
            elif action == "trace":
                # Write vuln entries to blackboard for high-confidence findings
                try:
                    from blackboard import BlackboardStore  # type: ignore
                    store = BlackboardStore()
                    conf_vals = sorted(float(s.get("confidence", 0.0) or 0.0) for s in found_sinks)
                    if conf_vals:
                        q50 = conf_vals[len(conf_vals) // 2]
                        q75 = conf_vals[min(len(conf_vals) - 1, int(round((len(conf_vals) - 1) * 0.75)))]
                        write_gate = q75 + max(0.0, q75 - q50)
                    else:
                        write_gate = 0.8
                    for s in found_sinks:
                        if float(s.get("confidence", 0.0) or 0.0) >= write_gate:
                            title = f"Taint: {source_name} → {s['sink']}"
                            existing = store.list(category="vuln", addr=hex_ea(source_ea))
                            if not any(s["sink"] in e.get("title", "") for e in existing):
                                store.write(
                                    title=title,
                                    content=s.get("dataflow") or f"Path depth: {s['depth']}",
                                    category="vuln",
                                    addr=hex_ea(source_ea),
                                    tags=["taint", s["vuln_type"], source_name],
                                    confidence=s["confidence"],
                                    source="taint_tool",
                                    source_type="engine_taint",
                                    evidence=[{
                                        "type": "taint",
                                        "value": f"{source_name}→{s['sink']}",
                                        "weight": s["confidence"],
                                        "ts": __import__("time").time(),
                                    }],
                                )
                except Exception:
                    pass
                return {
                    "ok": True,
                    "source": source_name,
                    "source_addr": hex_ea(source_ea),
                    "sinks_found": len(found_sinks),
                    "sinks": found_sinks[:max_paths],
                    "reachable_functions": len(reachable),
                    "note": "High-confidence findings written to blackboard as vuln entries.",
                }
            else:  # paths
                return {
                    "ok": True,
                    "source": source_name,
                    "source_addr": hex_ea(source_ea),
                    "paths": [
                        {
                            "sink": s["sink"],
                            "vuln_type": s["vuln_type"],
                            "path": s["path"],
                            "depth": s["depth"],
                            "dataflow": s["dataflow"],
                        }
                        for s in found_sinks[:max_paths]
                    ],
                    "count": len(found_sinks),
                }

        elif action == "report":
            # Full report: all sources → all reachable sinks
            import_sources = _get_import_addrs(TAINT_SOURCES)
            all_findings = []
            for src_name, src_ea in import_sources.items():
                callers = list(idautils.CodeRefsTo(src_ea, 0))
                if not callers:
                    continue  # unused import
                sink_addrs = _get_import_addrs(set(DANGEROUS_SINKS.keys()))
                visited: Set[int] = {src_ea}
                reachable = _callees_of(src_ea, max_depth=max_depth, visited=visited)
                reachable_eas = {ea for ea, _, _ in reachable}
                for sink_name, sink_ea in sink_addrs.items():
                    if sink_ea in reachable_eas:
                        path_to_sink = None
                        for ea, depth, path in reachable:
                            if ea == sink_ea:
                                path_to_sink = [hex_ea(p) for p in path[:6]]
                                break
                        all_findings.append({
                            "source": src_name,
                            "source_addr": hex_ea(src_ea),
                            "sink": sink_name,
                            "sink_addr": hex_ea(sink_ea),
                            "vuln_type": DANGEROUS_SINKS.get(sink_name, "unknown"),
                            "depth": len(path_to_sink) - 1 if path_to_sink else -1,
                            "path_summary": " → ".join(
                                idc.get_name(int(p, 16)) or p
                                for p in (path_to_sink or [])[:4]
                            ),
                        })
                if len(all_findings) >= max_paths * 3:
                    break

            all_findings.sort(key=lambda x: x["depth"] if x["depth"] >= 0 else 999)
            return {
                "ok": True,
                "findings": all_findings[:max_paths],
                "total": len(all_findings),
                "sources_checked": len(import_sources),
                "note": "Use taint(action='trace', source='recv') for detailed analysis of a specific source.",
            }

        else:
            return make_error(MCPError.ACTION_NOT_FOUND, f"Unknown action: {action}",
                              hint="Valid: sources, sinks, trace, paths, report")

    except Exception as e:
        return handle_error(e)
