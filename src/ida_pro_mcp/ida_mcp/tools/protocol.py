try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import re

# ============================================================================
# PROTOCOL - Network Protocol Structure Analysis for LLMs
# ============================================================================

# BehaviorClassifier-based protocol detection
try:
    from ida_pro_mcp.services import BehaviorClassifier, BgeCodeEmbedder
except ImportError:
    try:
        from host.intelligence.core import BehaviorClassifier, BgeCodeEmbedder  # type: ignore
    except ImportError:
        BgeCodeEmbedder = None  # type: ignore
        BehaviorClassifier = None  # type: ignore

# Blackboard for auto-writing findings
try:
    from .blackboard import BlackboardStore
except ImportError:
    try:
        from blackboard import BlackboardStore  # type: ignore[import-not-found]
    except ImportError:
        BlackboardStore = None  # type: ignore

# Protocol-specific anchors for BehaviorClassifier
_PROTOCOL_ANCHORS = {
    "http_protocol": "HTTP_GET HTTP_POST Content-Type User-Agent url_encode http_connect recv_response parse_headers",
    "tls_ssl": "SSL_connect TLS_client_hello certificate_verify handshake_state cipher_suite x509",
    "custom_binary": "magic_bytes packet_header length_field checksum_verify parse_packet serialize_packet",
    "dns_protocol": "dns_query dns_response A_record AAAA_record resolve_hostname nslookup",
    "smtp_ftp": "EHLO MAIL FROM RCPT TO DATA QUIT FTP_connect PASV PORT",
}


class _ProtocolClassifier(BehaviorClassifier if BehaviorClassifier else object):
    """BehaviorClassifier subclass with protocol-specific anchors."""
    ANCHORS = _PROTOCOL_ANCHORS
    _shared = None
    _shared_lock = __import__("threading").Lock()

    @classmethod
    def instance(cls, embedder):
        with cls._shared_lock:
            if cls._shared is None:
                cls._shared = cls(embedder)
                cls._shared._preload_anchors_async()
        return cls._shared


def _get_protocol_classifier():
    """Return protocol classifier instance or None."""
    if BehaviorClassifier is None or BgeCodeEmbedder is None:
        return None
    try:
        embedder = BgeCodeEmbedder()
        return _ProtocolClassifier.instance(embedder)
    except Exception:
        return None


def _bb_write(title, content, addr=None, tags=None):
    """Auto-write protocol finding to blackboard."""
    if BlackboardStore is None:
        return None
    try:
        store = BlackboardStore()
        return store.write(
            title=title, content=content, category="protocol",
            addr=addr, tags=tags or ["protocol"], confidence=0.8,
        )
    except Exception:
        return None


_NETWORK_APIS = {
    "socket": ["socket", "WSASocket", "WSASocketA", "WSASocketW"],
    "connect": ["connect", "WSAConnect"],
    "bind": ["bind"],
    "listen": ["listen"],
    "accept": ["accept", "WSAAccept"],
    "send": ["send", "sendto", "WSASend", "WSASendTo"],
    "recv": ["recv", "recvfrom", "WSARecv", "WSARecvFrom"],
    "close": ["closesocket", "close", "shutdown"],
    "dns": ["getaddrinfo", "gethostbyname", "gethostbyaddr"],
    "http": ["InternetOpen", "InternetConnect", "HttpOpenRequest",
             "HttpSendRequest", "WinHttpOpen", "WinHttpConnect",
             "curl_easy_init", "curl_easy_perform"],
    "tls": ["SSL_new", "SSL_connect", "SSL_accept", "SSL_read", "SSL_write",
            "SSL_CTX_new", "SSL_CTX_set_cipher_list",
            "mbedtls_ssl_handshake", "mbedtls_ssl_read"],
    "byte_order": ["ntohs", "ntohl", "htons", "htonl"],
    "init": ["WSAStartup", "WSACleanup"],
}

_ALL_NETWORK_APIS = set()
for _apis in _NETWORK_APIS.values():
    _ALL_NETWORK_APIS.update(a.lower() for a in _apis)

_TLS_CONFIG_APIS = [
    "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites",
    "SSL_CTX_set_verify", "SSL_CTX_load_verify_locations",
    "SSL_CTX_use_certificate_file", "SSL_CTX_use_PrivateKey_file",
    "SSL_CTX_set_min_proto_version", "SSL_CTX_set_max_proto_version",
    "SSL_get_peer_certificate", "SSL_get_verify_result",
    "mbedtls_ssl_conf_authmode", "mbedtls_ssl_conf_ca_chain",
    "mbedtls_x509_crt_parse",
]

_SOCKET_LIFECYCLE = {
    "create": ["socket", "WSASocket", "WSASocketA", "WSASocketW"],
    "configure": ["setsockopt", "getsockopt", "ioctlsocket", "bind"],
    "connect": ["connect", "WSAConnect"],
    "listen": ["listen", "accept", "WSAAccept"],
    "io": ["send", "sendto", "recv", "recvfrom", "WSASend", "WSARecv",
           "SSL_read", "SSL_write", "select", "poll"],
    "close": ["closesocket", "close", "shutdown", "SSL_shutdown"],
}

_KNOWN_MAGIC = {
    0x474554: ("HTTP GET", "ASCII 'GET'"),
    0x504F5354: ("HTTP POST", "ASCII 'POST'"),
    0x48545450: ("HTTP", "ASCII 'HTTP'"),
    0x16030100: ("TLS 1.0 Handshake", "TLS record layer"),
    0x16030300: ("TLS 1.2 Handshake", "TLS record layer"),
    0x16030301: ("TLS 1.0 ClientHello", "TLS record"),
    0x16030303: ("TLS 1.2 ClientHello", "TLS record"),
    0x4D515454: ("MQTT", "ASCII 'MQTT'"),
    0x89504E47: ("PNG", "PNG header"),
    0x7F454C46: ("ELF", "ELF header"),
    0x504B0304: ("ZIP/APK", "PK header"),
}


def _get_all_strings(max_strings=50000):
    results = []
    sc = idautils.Strings()
    for idx, s in enumerate(sc):
        if idx >= max_strings:
            break
        val = str(s)
        if val:
            results.append((s.ea, val, s.length))
    return results


def _find_api_xrefs(api_name, max_xrefs=5000):
    results = []
    ea = ida_name.get_name_ea(idaapi.BADADDR, api_name)
    if ea == idaapi.BADADDR:
        for suffix in ("A", "W", "@plt", "@PLT"):
            ea = ida_name.get_name_ea(idaapi.BADADDR, api_name + suffix)
            if ea != idaapi.BADADDR:
                break
    if ea == idaapi.BADADDR:
        return results
    for idx, xref in enumerate(idautils.XrefsTo(ea, 0)):
        if idx >= max_xrefs:
            break
        fn = ida_funcs.get_func(xref.frm)
        if fn:
            fname = idc.get_func_name(fn.start_ea)
            results.append((fn.start_ea, fname))
    return results


def _get_func_callees(func_ea, max_refs=2000):
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return []
    callees = []
    seen = set()
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        if len(callees) >= max_refs:
            break
        for xref in idautils.CodeRefsFrom(head, 0):
            if xref not in seen:
                seen.add(xref)
                name = idc.get_func_name(xref) or ida_name.get_name(xref)
                if name:
                    callees.append((xref, name))
                    if len(callees) >= max_refs:
                        break
    return callees


def _get_func_strings(func_ea, max_refs=500):
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return []
    strings = []
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        if len(strings) >= max_refs:
            break
        for dref in idautils.DataRefsFrom(head):
            if len(strings) >= max_refs:
                break
            stype = idc.get_str_type(dref)
            if stype is not None and stype >= 0:
                s = idc.get_strlit_contents(dref, -1, stype)
                if s:
                    s = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                    if s not in strings:
                        strings.append(s)
    return strings


def _count_switch_cases(func_ea):
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return 0
    count = 0
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        si = idaapi.get_switch_info(head)
        if si:
            count += si.get_jtable_size()
    return count


def _strip_api_suffix(name):
    for suffix in ("A", "W", "@plt", "@PLT"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def _match_query(text, matcher):
    if not matcher:
        return True
    return bool(matcher("" if text is None else str(text)))


# ============================================================================
# Protocol reconstruction helpers
# ============================================================================

def _get_switch_targets(func_ea):
    """Get switch/case targets from a dispatch function.

    Returns list of (case_value, target_ea) tuples.
    """
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return []
    targets = []
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        si = idaapi.get_switch_info(head)
        if si:
            results = idaapi.calc_switch_cases(head, si)
            if results:
                for case_idx in range(len(results)):
                    case_values = results[case_idx]
                    # Each case may have multiple values; get the target
                    target = si.jumps + case_idx * si.get_jtable_element_size()
                    ida_bytes.get_dword(target) if si.get_jtable_element_size() == 4 else ida_bytes.get_qword(target)
                    # Try reading target from jump table
                    jt_ea = si.jumps + case_idx * si.get_jtable_element_size()
                    if si.get_jtable_element_size() == 4:
                        tgt = ida_bytes.get_dword(jt_ea)
                        if si.get_shift() > 0:
                            tgt = (tgt << si.get_shift()) + si.elbase
                        elif si.flags & idaapi.SWI_ELBASE:
                            tgt += si.elbase
                    else:
                        tgt = ida_bytes.get_qword(jt_ea)
                    for cv in case_values:
                        targets.append((int(cv), tgt))
    return targets


def _trace_buffer_accesses(func_ea):
    """Trace sequential buffer reads in a handler function.

    Decompiles the function and looks for patterns like:
    - buf[offset] or *(type*)(buf + offset)
    - ntohs(*(uint16_t*)(buf + 4))
    - memcpy(dst, buf + 8, len)

    Returns list of field dicts: {offset, size, type_hint, validation, line}.
    """
    fields = []
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return fields
    except Exception:
        return fields

    sv = cfunc.get_pseudocode()
    lines = []
    for i in range(sv.size()):
        lines.append(ida_lines.tag_remove(sv[i].line).strip())

    # Patterns for buffer access with offset arithmetic
    # Match: *(type*)(buf + offset), buf[offset], BYTE1(x), etc.
    ptr_arith_re = re.compile(
        r'\*\s*\(\s*(?:_?)?(u?int(?:8|16|32|64)_t|char|BYTE|WORD|DWORD|QWORD|short|int|long)\s*\*\s*\)'
        r'\s*\(\s*\w+\s*\+\s*(\d+)\s*\)'
    )
    re.compile(r'(\w+)\[(\d+)\]')
    ntohs_re = re.compile(r'(ntohs|ntohl|htons|htonl|__builtin_bswap(?:16|32|64))\s*\(')
    memcpy_re = re.compile(r'memcpy\s*\(\s*\w+\s*,\s*\w+\s*\+\s*(\d+)\s*,\s*(\d+)\s*\)')
    comparison_re = re.compile(r'(?:if|while|for)\s*\(.*?(\w+)\s*([<>=!]+)\s*(\d+)')

    # Size mapping for type names
    type_sizes = {
        "uint8_t": 1, "int8_t": 1, "char": 1, "BYTE": 1, "byte": 1,
        "uint16_t": 2, "int16_t": 2, "short": 2, "WORD": 2,
        "uint32_t": 4, "int32_t": 4, "int": 4, "DWORD": 4,
        "uint64_t": 8, "int64_t": 8, "long": 8, "QWORD": 8,
    }

    seen_offsets = set()
    for line in lines:
        # Pointer arithmetic access: *(uint16_t*)(buf + 4)
        for m in ptr_arith_re.finditer(line):
            type_name = m.group(1)
            offset = int(m.group(2))
            size = type_sizes.get(type_name, 4)
            is_unsigned = type_name.startswith("u") or type_name in ("BYTE", "WORD", "DWORD", "QWORD")
            has_byteswap = bool(ntohs_re.search(line))
            if offset not in seen_offsets:
                seen_offsets.add(offset)
                fields.append({
                    "offset": offset,
                    "size": size,
                    "type_hint": type_name,
                    "signed": not is_unsigned,
                    "network_order": has_byteswap,
                    "line": line[:120],
                })

        # memcpy with offset: memcpy(dst, buf + 8, 32)
        for m in memcpy_re.finditer(line):
            offset = int(m.group(1))
            size = int(m.group(2))
            if offset not in seen_offsets:
                seen_offsets.add(offset)
                fields.append({
                    "offset": offset,
                    "size": size,
                    "type_hint": f"blob[{size}]",
                    "signed": False,
                    "network_order": False,
                    "line": line[:120],
                })

    # Sort by offset
    fields.sort(key=lambda f: f["offset"])

    # Now scan for validation checks on the same lines
    validations = []
    for line in lines:
        m = comparison_re.search(line)
        if m:
            var_name = m.group(1)
            op = m.group(2)
            value = int(m.group(3))
            validations.append({"variable": var_name, "operator": op, "value": value, "line": line[:120]})

    # Attach validations to fields heuristically (if validation value matches a field offset or size)
    for field in fields:
        for v in validations:
            if v["value"] == field["size"] or v["value"] == field["offset"]:
                field.setdefault("validation", []).append(
                    f"{v['variable']} {v['operator']} {v['value']}"
                )

    return fields


def _analyze_handler_fields(func_ea):
    """Analyze a handler for field access patterns including TLV and length-prefixed fields.

    Returns dict with fields, relationships, and patterns detected.
    """
    result = {
        "fields": [],
        "relationships": [],
        "patterns": [],
        "decompiled_lines": [],
    }

    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return result
    except Exception:
        return result

    sv = cfunc.get_pseudocode()
    lines = []
    for i in range(sv.size()):
        lines.append(ida_lines.tag_remove(sv[i].line).strip())
    result["decompiled_lines"] = lines[:80]

    # Detect field accesses
    fields = _trace_buffer_accesses(func_ea)
    result["fields"] = fields

    # Detect TLV patterns: type-length-value with sequential small reads followed by variable read
    if len(fields) >= 2:
        for i in range(len(fields) - 1):
            f1 = fields[i]
            f2 = fields[i + 1]
            # TLV: small type field followed by small length field at adjacent offset
            if f1["size"] <= 2 and f2["size"] <= 2 and f2["offset"] == f1["offset"] + f1["size"]:
                result["patterns"].append({
                    "type": "possible_tlv",
                    "type_field_offset": f1["offset"],
                    "length_field_offset": f2["offset"],
                    "value_offset": f2["offset"] + f2["size"],
                    "confidence": "medium",
                })

    # Detect length-prefixed patterns: field A used as length for memcpy/read
    length_prefix_re = re.compile(
        r'(?:memcpy|memmove|read|recv)\s*\(\s*\w+\s*,\s*\w+(?:\s*\+\s*\d+)?\s*,\s*(\w+)\s*\)'
    )
    size_var_re = re.compile(
        r'(\w+)\s*=\s*\*\s*\(\s*(?:_?)?(?:u?int(?:16|32)_t|WORD|DWORD|unsigned\s+(?:short|int))\s*\*\s*\)'
        r'\s*\(\s*\w+\s*\+\s*(\d+)\s*\)'
    )

    # Find variables assigned from buffer reads
    size_vars = {}
    for line in lines:
        m = size_var_re.search(line)
        if m:
            var_name = m.group(1)
            offset = int(m.group(2))
            size_vars[var_name] = offset

    # Find those variables used as lengths
    for line in lines:
        m = length_prefix_re.search(line)
        if m:
            len_var = m.group(1)
            if len_var in size_vars:
                result["relationships"].append({
                    "type": "length_of",
                    "length_field_offset": size_vars[len_var],
                    "length_variable": len_var,
                    "usage": line[:120],
                })
                result["patterns"].append({
                    "type": "length_prefixed",
                    "length_field_offset": size_vars[len_var],
                    "confidence": "high",
                })

    # Detect nested sub-message patterns: a function call with buf+offset as argument
    nested_call_re = re.compile(r'(\w+)\s*\(\s*(?:\w+\s*\+\s*(\d+)|&\w+\[(\d+)\])')
    for line in lines:
        m = nested_call_re.search(line)
        if m:
            callee_name = m.group(1)
            offset = m.group(2) or m.group(3)
            # Filter out common non-parse functions
            if callee_name not in ("memcpy", "memmove", "memset", "memcmp", "printf",
                                   "sprintf", "snprintf", "strlen", "strcpy") and offset:
                result["patterns"].append({
                    "type": "nested_submessage",
                    "callee": callee_name,
                    "buffer_offset": int(offset),
                    "line": line[:120],
                    "confidence": "low",
                })

    # Detect loop-based repeated field parsing (while loops with incrementing offset)
    loop_offset_re = re.compile(r'(?:while|for)\s*\(.*?(\w+)\s*<\s*(\w+).*?\)')
    for line in lines:
        m = loop_offset_re.search(line)
        if m:
            result["patterns"].append({
                "type": "repeated_field",
                "iterator": m.group(1),
                "bound": m.group(2),
                "line": line[:120],
                "confidence": "medium",
            })

    return result


def _export_ksy(protocol_data):
    """Export protocol data as Kaitai Struct .ksy format (YAML).

    Args:
        protocol_data: dict with 'name', 'message_types' list

    Returns:
        String containing Kaitai .ksy YAML content.
    """
    name = protocol_data.get("name", "unknown_protocol")
    message_types = protocol_data.get("message_types", [])

    lines = [
        "meta:",
        f"  id: {name}",
        "  endian: be",
        "  file-extension: bin",
        "",
        "seq:",
    ]

    # If there's a dispatch field, add it as the first sequence element
    if message_types:
        lines.append("  - id: message_type")
        lines.append("    type: u1")
        lines.append("")
        lines.append("types:")

        for msg in message_types:
            msg_name = msg.get("name", f"msg_{msg.get('case_value', 0)}")
            msg_name = re.sub(r'[^a-zA-Z0-9_]', '_', msg_name).lower()
            fields = msg.get("fields", [])

            lines.append(f"  {msg_name}:")
            lines.append("    seq:")

            if not fields:
                lines.append("      - id: data")
                lines.append("        size-eos: true")
            else:
                for idx, field in enumerate(fields):
                    field_id = field.get("name", f"field_{idx}")
                    field_id = re.sub(r'[^a-zA-Z0-9_]', '_', field_id).lower()
                    size = field.get("size", 4)
                    field.get("type_hint", "")

                    # Map to Kaitai types
                    unsigned = not field.get("signed", False)
                    prefix = "u" if unsigned else "s"
                    if size == 1:
                        ksy_type = f"{prefix}1"
                    elif size == 2:
                        ksy_type = f"{prefix}2"
                    elif size == 4:
                        ksy_type = f"{prefix}4"
                    elif size == 8:
                        ksy_type = f"{prefix}8"
                    else:
                        # Blob/variable-length
                        ksy_type = None

                    lines.append(f"      - id: {field_id}")
                    if ksy_type:
                        lines.append(f"        type: {ksy_type}")
                    else:
                        lines.append(f"        size: {size}")

                    if field.get("network_order"):
                        lines.append("        # network byte order (big-endian)")

                    if field.get("validation"):
                        for v in field["validation"]:
                            lines.append(f"        # validation: {v}")
            lines.append("")

    return "\n".join(lines)


def _export_json_schema(protocol_data):
    """Export protocol data as JSON schema.

    Args:
        protocol_data: dict with 'name', 'message_types' list

    Returns:
        Dict containing JSON schema representation.
    """

    name = protocol_data.get("name", "unknown_protocol")
    message_types = protocol_data.get("message_types", [])

    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": name,
        "description": f"Reconstructed protocol schema for {name}",
        "type": "object",
        "properties": {
            "message_type": {
                "type": "integer",
                "description": "Protocol message type identifier",
            }
        },
        "oneOf": [],
    }

    for msg in message_types:
        case_value = msg.get("case_value", 0)
        msg_name = msg.get("name", f"message_type_{case_value}")
        fields = msg.get("fields", [])

        msg_schema = {
            "title": msg_name,
            "type": "object",
            "properties": {
                "message_type": {"const": case_value},
            },
            "required": ["message_type"],
        }

        for idx, field in enumerate(fields):
            field_name = field.get("name", f"field_{idx}")
            size = field.get("size", 4)
            signed = field.get("signed", False)

            field_schema = {"type": "integer"}
            if not signed:
                field_schema["minimum"] = 0
            if size == 1:
                field_schema["maximum"] = 255 if not signed else 127
            elif size == 2:
                field_schema["maximum"] = 65535 if not signed else 32767
            elif size == 4:
                field_schema["maximum"] = 4294967295 if not signed else 2147483647

            # For blobs, use string with content encoding
            if size > 8:
                field_schema = {
                    "type": "string",
                    "contentEncoding": "base64",
                    "description": f"Binary blob of {size} bytes",
                }

            if field.get("validation"):
                field_schema["description"] = f"Validated: {'; '.join(field['validation'])}"

            msg_schema["properties"][field_name] = field_schema
            msg_schema["required"].append(field_name)

        schema["oneOf"].append(msg_schema)

    return schema


def protocol(
    action: Annotated[Literal["detect", "parsers", "serializers", "handlers",
                               "endpoints", "tls_config", "socket_flow",
                               "packet_struct", "magic_numbers", "state_machine",
                               "reconstruct", "trace_handler", "export_spec"],
                      "Protocol analysis action"],
    addr: Annotated[Optional[str], "Address or function to analyze"] = None,
    limit: Annotated[int, "Max results"] = 50,
    query: Annotated[Optional[str], "Filter query (regex/glob/substring/semantic auto-detected)"] = None,
    include_items: Annotated[bool, "Include structured items array in response"] = False,
) -> dict:
    """
    Analyze network protocol structures, parsing code, and communication patterns.

    ACTIONS:
    detect - Detect network protocol usage via BehaviorClassifier + embedding fallback.
    parsers - Find protocol parsing functions (buffer reads with offset arithmetic).
    serializers - Find protocol serialization functions (structured buffer writes).
    handlers - Find message/command handler dispatch tables (large switch statements).
    endpoints - Find network endpoint strings (URLs, IPs, hostnames, ports).
    tls_config - Analyze TLS/SSL configuration (cipher suites, certificate handling).
    socket_flow - Trace socket lifecycle (create -> bind/connect -> send/recv -> close).
    packet_struct - Infer packet/message structure from parsing code.
    magic_numbers - Find protocol magic numbers and version identifiers.
    state_machine - Detect protocol state machine patterns.
    reconstruct - Full protocol reconstruction from a dispatch function (requires addr).
                  Traces each case/handler to map message types and field layouts.
    trace_handler - Deep trace of a single message handler (requires addr).
                    Analyzes buffer access, TLV patterns, length-prefixed fields,
                    nested sub-messages, and field relationships.
    export_spec - Export reconstructed protocol as Kaitai .ksy or JSON schema.
                  Pass query='ksy' or query='json' to select format.
                  Pass addr of the dispatch function to reconstruct and export.
    """
    try:
        query_matcher = compile_smart_pattern(query, case_sensitive=False) if query else None

        if action == "detect":
            protocols_detected = {}
            api_usage = {}
            string_evidence = {}
            classifier_results = []
            query_protocol_hints = []

            # --- BehaviorClassifier-based detection ---
            classifier = _get_protocol_classifier()
            if classifier is not None:
                # Gather representative text from binary
                all_strings = _get_all_strings(max_strings=5000)
                corpus = " ".join(s_val for _, s_val, _ in all_strings[:2000])
                # Also gather API names referenced
                for _api_cat, apis in _NETWORK_APIS.items():
                    for api in apis:
                        xrefs = _find_api_xrefs(api)
                        if xrefs:
                            corpus += " " + api
                            callers = [f"{hex(ea)} {name}" for ea, name in xrefs[:limit]]
                            api_usage[api] = callers

                try:
                    classifier_results = classifier.classify(corpus, threshold=0.0, top_k=5)
                    for r in classifier_results:
                        protocols_detected[r["behavior"]] = r["confidence"]
                except Exception:
                    classifier_results = []

                # Query-guided embedding hinting: map analyst intent into protocol candidates.
                if query:
                    try:
                        query_protocol_hints = classifier.classify(str(query)[:600], threshold=0.0, top_k=4)
                        for h in query_protocol_hints:
                            b = str(h.get("behavior") or "")
                            if not b:
                                continue
                            conf = float(h.get("confidence") or h.get("score") or 0.0)
                            existing = float(protocols_detected.get(b, 0.0))
                            protocols_detected[b] = max(existing, conf * 0.9)
                    except Exception:
                        query_protocol_hints = []

            # --- Fallback embedding aggregation when classifier unavailable or no results ---
            if not classifier_results:
                all_strings = _get_all_strings()
                if not api_usage:
                    for _api_cat, apis in _NETWORK_APIS.items():
                        for api in apis:
                            xrefs = _find_api_xrefs(api)
                            if xrefs:
                                callers = [f"{hex(ea)} {name}" for ea, name in xrefs[:limit]]
                                api_usage[api] = callers

                # Embedding-only fallback (no lexical protocol patterns).
                if BgeCodeEmbedder is not None:
                    try:
                        embedder = BgeCodeEmbedder()
                        anchor_map = {
                            "HTTP": _PROTOCOL_ANCHORS.get("http_protocol", ""),
                            "TLS": _PROTOCOL_ANCHORS.get("tls_ssl", ""),
                            "DNS": _PROTOCOL_ANCHORS.get("dns_protocol", ""),
                            "CustomBinary": _PROTOCOL_ANCHORS.get("custom_binary", ""),
                            "SMTP/FTP": _PROTOCOL_ANCHORS.get("smtp_ftp", ""),
                        }
                        anchor_vecs = {k: embedder.embed_vector(v) for k, v in anchor_map.items() if v}
                        anchor_vecs = {k: vec for k, vec in anchor_vecs.items() if vec is not None}
                        proto_scores = dict.fromkeys(anchor_vecs, 0.0)
                        proto_hits = {k: [] for k in anchor_vecs}
                        string_candidate_sims: List[float] = []
                        string_candidates: List[Tuple[str, float, str, str]] = []

                        # Score top strings against protocol anchors.
                        for s_ea, s_val, _ in all_strings[: min(4000, max(200, limit * 100))]:
                            text = str(s_val or "").strip()
                            if len(text) < 4:
                                continue
                            try:
                                sv = embedder.embed_vector(text[:200])
                                if sv is None:
                                    continue
                            except Exception:
                                continue
                            best_proto = None
                            best_sim = 0.0
                            for proto, av in anchor_vecs.items():
                                sim = float(BgeCodeEmbedder.cosine(sv, av))
                                if sim > best_sim:
                                    best_sim = sim
                                    best_proto = proto
                            if best_proto is not None:
                                string_candidate_sims.append(best_sim)
                                string_candidates.append((best_proto, best_sim, hex(s_ea), text[:80]))
                        if string_candidate_sims:
                            ss = sorted(string_candidate_sims)
                            q50 = ss[len(ss) // 2]
                            q75 = ss[min(len(ss) - 1, int(round((len(ss) - 1) * 0.75)))]
                            sgate = q50 + max(0.0, q75 - q50)
                            for proto, sim, ea_hex, preview in string_candidates:
                                if sim >= sgate:
                                    proto_scores[proto] += sim
                                    if len(proto_hits[proto]) < limit:
                                        proto_hits[proto].append(f"{ea_hex}  \"{preview}\"")

                        # Also fold API names into the same embedding vote.
                        api_candidate_sims: List[float] = []
                        api_candidates: List[Tuple[str, float]] = []
                        for api_name in list(api_usage.keys())[: min(400, limit * 20)]:
                            try:
                                av = embedder.embed_vector(str(api_name)[:80])
                                if av is None:
                                    continue
                            except Exception:
                                continue
                            best_proto = None
                            best_sim = 0.0
                            for proto, pv in anchor_vecs.items():
                                sim = float(BgeCodeEmbedder.cosine(av, pv))
                                if sim > best_sim:
                                    best_sim = sim
                                    best_proto = proto
                            if best_proto is not None:
                                api_candidate_sims.append(best_sim)
                                api_candidates.append((best_proto, best_sim))
                        if api_candidate_sims:
                            asv = sorted(api_candidate_sims)
                            aq50 = asv[len(asv) // 2]
                            aq75 = asv[min(len(asv) - 1, int(round((len(asv) - 1) * 0.75)))]
                            agate = aq50 + max(0.0, aq75 - aq50)
                            for proto, sim in api_candidates:
                                if sim >= agate:
                                    proto_scores[proto] += sim

                        ranked = sorted(proto_scores.items(), key=lambda kv: kv[1], reverse=True)
                        for proto, score in ranked:
                            if score <= 0:
                                continue
                            protocols_detected[proto] = round(score, 4)
                            if proto_hits.get(proto):
                                string_evidence[proto] = proto_hits[proto][:limit]
                    except Exception:
                        pass

            # Auto-write to blackboard
            if protocols_detected:
                _bb_write(
                    title=f"protocol:detect {list(protocols_detected.keys())[:5]}",
                    content=str(protocols_detected),
                    tags=["protocol", "detect"] + list(protocols_detected.keys())[:3],
                )

            result = {
                "ok": True,
                "protocols_detected": protocols_detected,
                "api_usage": api_usage,
                "string_evidence": string_evidence,
                "mode": "classifier+embedding" if classifier_results and protocols_detected else ("classifier" if classifier_results else "embedding_fallback"),
                "source": "behavior_classifier" if classifier_results else "embedding_fallback",
            }
            if classifier_results:
                result["classifier_hits"] = classifier_results
            if query_protocol_hints:
                result["query_protocol_hints"] = query_protocol_hints
            return result

        elif action == "parsers":
            parsers = []
            func_list = [validate_addr(addr, require_func=True)[0]] if addr else list(idautils.Functions())
            if addr and func_list[0] is None:
                return validate_addr(addr, require_func=True)[1]

            byte_order_apis = {"ntohs", "ntohl", "htons", "htonl",
                               "__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64"}

            for func_ea in func_list:
                if len(parsers) >= limit:
                    break
                fname = idc.get_func_name(func_ea)
                if not _match_query(fname, query_matcher):
                    continue
                callees = _get_func_callees(func_ea)
                callee_names = {_strip_api_suffix(c[1]).lower() for c in callees}
                has_byte_order = bool(callee_names & {a.lower() for a in byte_order_apis})
                has_memread = bool(callee_names & {"memcpy", "memmove", "recv", "recvfrom",
                                                   "read", "wsarecv", "ssl_read"})
                if has_byte_order or has_memread:
                    indicators = []
                    if has_byte_order:
                        indicators.append("byte_order")
                    if has_memread:
                        indicators.append("buffer_read")
                    parsers.append({"address": hex(func_ea), "name": fname,
                                    "indicators": indicators})

            return {"ok": True, "parsers": "\n".join(str(x) for x in parsers), "count": len(parsers)}

        elif action == "serializers":
            serializers = []
            func_list = [validate_addr(addr, require_func=True)[0]] if addr else list(idautils.Functions())
            if addr and func_list[0] is None:
                return validate_addr(addr, require_func=True)[1]

            write_apis = {"memcpy", "send", "sendto", "write", "wsasend", "ssl_write",
                          "winhttpsendrequest", "winhttpwritedata"}
            pack_apis = {"htons", "htonl", "sprintf", "snprintf", "memset",
                         "__builtin_bswap16", "__builtin_bswap32"}

            for func_ea in func_list:
                if len(serializers) >= limit:
                    break
                fname = idc.get_func_name(func_ea)
                if not _match_query(fname, query_matcher):
                    continue
                callees = _get_func_callees(func_ea)
                callee_names = {_strip_api_suffix(c[1]).lower() for c in callees}
                if bool(callee_names & write_apis) and bool(callee_names & pack_apis):
                    serializers.append({"address": hex(func_ea), "name": fname,
                                        "indicators": ["buffer_write", "data_packing"]})

            return {"ok": True, "serializers": "\n".join(str(x) for x in serializers), "count": len(serializers)}

        elif action == "handlers":
            handlers = []
            func_list = [validate_addr(addr, require_func=True)[0]] if addr else list(idautils.Functions())
            if addr and func_list[0] is None:
                return validate_addr(addr, require_func=True)[1]

            for func_ea in func_list:
                if len(handlers) >= limit:
                    break
                fname = idc.get_func_name(func_ea)
                if not _match_query(fname, query_matcher):
                    continue
                case_count = _count_switch_cases(func_ea)
                if case_count < 3:
                    continue
                callees = _get_func_callees(func_ea)
                callee_names = {_strip_api_suffix(c[1]).lower() for c in callees}
                is_network = bool(callee_names & _ALL_NETWORK_APIS)
                handlers.append({"address": hex(func_ea), "name": fname,
                                 "case_count": case_count, "network_related": is_network})

            return {"ok": True, "handlers": handlers[:limit], "count": len(handlers)}

        elif action == "endpoints":
            endpoints = {"urls": [], "ips": [], "hostnames": [], "ports": []}
            url_re = re.compile(r'https?://[^\s"\'<>]+')
            ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            host_re = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|dev|app|cloud)\b')
            port_re = re.compile(r'\b(?:port|PORT)[:\s=]+(\d{1,5})\b')

            for s_ea, s_val, _ in _get_all_strings():
                if not _match_query(s_val, query_matcher):
                    continue
                for m in url_re.finditer(s_val):
                    e = f"{hex(s_ea)}  \"{m.group()[:120]}\""
                    if e not in endpoints["urls"] and len(endpoints["urls"]) < limit:
                        endpoints["urls"].append(e)
                for m in ip_re.finditer(s_val):
                    parts = m.group().split(".")
                    if all(0 <= int(p) <= 255 for p in parts):
                        e = f"{hex(s_ea)}  {m.group()}"
                        if e not in endpoints["ips"] and len(endpoints["ips"]) < limit:
                            endpoints["ips"].append(e)
                for m in host_re.finditer(s_val):
                    e = f"{hex(s_ea)}  {m.group()}"
                    if e not in endpoints["hostnames"] and len(endpoints["hostnames"]) < limit:
                        endpoints["hostnames"].append(e)
                for m in port_re.finditer(s_val):
                    e = f"{hex(s_ea)}  port={m.group(1)}"
                    if e not in endpoints["ports"] and len(endpoints["ports"]) < limit:
                        endpoints["ports"].append(e)

            total = sum(len(v) for v in endpoints.values())
            endpoint_items = []
            for kind in ("urls", "ips", "hostnames", "ports"):
                for row in endpoints.get(kind, []):
                    endpoint_items.append({"kind": kind, "value": row})
            return {
                "ok": True,
                "endpoints": endpoints,
                "endpoint_items": endpoint_items,
                "counts": {k: len(v) for k, v in endpoints.items()},
                "total": total,
            }

        elif action == "tls_config":
            tls_apis = []
            cipher_strings = []
            cert_strings = []

            for api in _TLS_CONFIG_APIS:
                for caller_ea, caller_name in _find_api_xrefs(api):
                    if len(tls_apis) >= limit:
                        break
                    tls_apis.append({"api": api, "caller_address": hex(caller_ea),
                                     "caller_name": caller_name})

            search_pairs = []
            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                search_pairs = [(ea, s) for s in _get_func_strings(ea)]
            else:
                search_pairs = [(s_ea, s_val) for s_ea, s_val, _ in _get_all_strings()]

            cipher_kw = ["ecdhe", "rsa", "aes", "gcm", "cbc", "sha256", "chacha20", "tls_", "cipher"]
            cert_kw = ["cert", "certificate", "x509", "pem", "-----begin", ".pem", ".crt", ".key"]

            for s_ea, s_val in search_pairs:
                s_lower = s_val.lower() if isinstance(s_val, str) else s_val
                if any(kw in s_lower for kw in cipher_kw):
                    e = f"{hex(s_ea)}  \"{s_val[:100]}\""
                    if e not in cipher_strings and len(cipher_strings) < limit:
                        cipher_strings.append(e)
                if any(kw in s_lower for kw in cert_kw):
                    e = f"{hex(s_ea)}  \"{s_val[:100]}\""
                    if e not in cert_strings and len(cert_strings) < limit:
                        cert_strings.append(e)

            return {"ok": True, "tls_apis": tls_apis, "cipher_strings": cipher_strings,
                    "cert_strings": cert_strings}

        elif action == "socket_flow":
            flows = []
            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                func_list = [ea]
            else:
                func_set = set()
                for api in _SOCKET_LIFECYCLE["create"]:
                    for caller_ea, _ in _find_api_xrefs(api):
                        func_set.add(caller_ea)
                func_list = list(func_set)

            for func_ea in func_list:
                if len(flows) >= limit:
                    break
                fname = idc.get_func_name(func_ea)
                callees = _get_func_callees(func_ea)
                phases = {}
                for phase, apis in _SOCKET_LIFECYCLE.items():
                    matched = [c[1] for c in callees
                               if _strip_api_suffix(c[1]).lower() in {a.lower() for a in apis}]
                    if matched:
                        phases[phase] = matched
                if phases:
                    phase_order = [p for p in ["create", "configure", "connect", "listen", "io", "close"] if p in phases]
                    complete = "create" in phases and "close" in phases
                    flows.append(f"{hex(func_ea)}  {fname}  phases={','.join(phase_order)}  complete={complete}")

            return {"ok": True, "flows": "\n".join(flows), "count": len(flows)}

        elif action == "packet_struct":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for 'packet_struct' action")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            fname = idc.get_func_name(ea)
            fn = ida_funcs.get_func(ea)
            if not fn:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")

            callees = _get_func_callees(ea)
            byte_order_calls = [c[1] for c in callees
                                if _strip_api_suffix(c[1]).lower() in
                                {"ntohs", "ntohl", "htons", "htonl",
                                 "__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64"}]

            size_hints = []
            seen_imms = set()
            for head in idautils.Heads(fn.start_ea, fn.end_ea):
                if not ida_bytes.is_code(ida_bytes.get_flags(head)):
                    continue
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, head) <= 0:
                    continue
                for i in range(idaapi.UA_MAXOP):
                    op = insn.ops[i]
                    if op.type == idaapi.o_void:
                        break
                    if op.type == idaapi.o_imm and 1 <= op.value <= 65536 and op.value not in seen_imms:
                        seen_imms.add(op.value)
                        size_hints.append(f"{hex(head)}  value={op.value}  {hex(op.value)}")

            fields = []
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    sv = cfunc.get_pseudocode()
                    for i in range(sv.size()):
                        line = ida_lines.tag_remove(sv[i].line)
                        if any(p in line for p in ("[", "->", "offset", "buf +", "header")):
                            fields.append(line.strip())
            except Exception:
                pass

            return {"ok": True, "address": hex(ea), "name": fname,
                    "byte_order_calls": byte_order_calls,
                    "size_hints": size_hints[:limit], "fields": fields[:limit],
                    "strings": _get_func_strings(ea)[:20]}

        elif action == "magic_numbers":
            results = []
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if not seg:
                    continue
                ea_cursor = seg.start_ea
                while ea_cursor < seg.end_ea and len(results) < limit:
                    flags = ida_bytes.get_flags(ea_cursor)
                    if ida_bytes.is_dword(flags) or ida_bytes.has_value(flags):
                        val = ida_bytes.get_dword(ea_cursor)
                        if val in _KNOWN_MAGIC:
                            proto, desc = _KNOWN_MAGIC[val]
                            if _match_query(proto, query_matcher):
                                results.append(f"{hex(ea_cursor)}  {hex(val)}  {proto}  {desc}")
                    ea_cursor = ida_bytes.next_head(ea_cursor, seg.end_ea)
                    if ea_cursor == idaapi.BADADDR:
                        break

            version_re = re.compile(r'(?:v|version|ver)[:\s.=]*(\d+(?:\.\d+)+)', re.IGNORECASE)
            for s_ea, s_val, _ in _get_all_strings():
                if len(results) >= limit:
                    break
                for m in version_re.finditer(s_val):
                    if _match_query(s_val, query_matcher):
                        results.append(f"{hex(s_ea)}  {m.group()}  version_id  {s_val[:80]}")
                        break

            return {"ok": True, "magic_numbers": results, "count": len(results)}

        elif action == "state_machine":
            state_machines = []
            func_list = [validate_addr(addr, require_func=True)[0]] if addr else list(idautils.Functions())
            if addr and func_list[0] is None:
                return validate_addr(addr, require_func=True)[1]

            state_keywords = {"state", "status", "phase", "stage", "step", "mode", "fsm", "transition"}

            for func_ea in func_list:
                if len(state_machines) >= limit:
                    break
                fname = idc.get_func_name(func_ea)
                case_count = _count_switch_cases(func_ea)
                fn_strs = _get_func_strings(func_ea)
                has_state_name = any(kw in fname.lower() for kw in state_keywords)
                has_state_strings = any(any(kw in s.lower() for kw in state_keywords) for s in fn_strs)

                if case_count >= 3 and (has_state_name or has_state_strings):
                    state_machines.append({"address": hex(func_ea), "name": fname,
                                           "case_count": case_count,
                                           "state_name_match": has_state_name,
                                           "state_string_match": has_state_strings,
                                           "strings": fn_strs[:10]})
                elif case_count >= 5:
                    callees = _get_func_callees(func_ea)
                    callee_names = {_strip_api_suffix(c[1]).lower() for c in callees}
                    if bool(callee_names & _ALL_NETWORK_APIS):
                        state_machines.append({"address": hex(func_ea), "name": fname,
                                               "case_count": case_count,
                                               "network_related": True, "strings": fn_strs[:10]})

            return {"ok": True, "state_machines": state_machines[:limit], "count": len(state_machines)}

        elif action == "reconstruct":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for 'reconstruct' action")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            fname = idc.get_func_name(ea)
            fn = ida_funcs.get_func(ea)
            if not fn:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")

            # Step 1: Find switch/dispatch targets in the function
            switch_targets = _get_switch_targets(ea)

            # If no switch found, try to identify dispatch via call targets (indirect dispatch)
            if not switch_targets:
                # Fallback: look for comparison chains in decompiled output
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    if cfunc:
                        sv = cfunc.get_pseudocode()
                        case_re = re.compile(r'(?:==|case)\s*(\d+)')
                        call_re = re.compile(r'(\w+)\s*\(')
                        for i in range(sv.size()):
                            line = ida_lines.tag_remove(sv[i].line).strip()
                            cm = case_re.search(line)
                            if cm:
                                case_val = int(cm.group(1))
                                # Find the handler call on this or next line
                                handler_match = call_re.search(line)
                                if handler_match:
                                    handler_name = handler_match.group(1)
                                    handler_ea = ida_name.get_name_ea(idaapi.BADADDR, handler_name)
                                    if handler_ea != idaapi.BADADDR:
                                        switch_targets.append((case_val, handler_ea))
                except Exception:
                    pass

            # Step 2: For each case target, trace buffer accesses
            message_types = []
            for case_value, target_ea in switch_targets[:limit]:
                # Determine handler function
                handler_fn = ida_funcs.get_func(target_ea)
                if not handler_fn:
                    continue
                handler_name = idc.get_func_name(handler_fn.start_ea) or f"sub_{handler_fn.start_ea:X}"

                # Trace buffer accesses in the handler
                fields = _trace_buffer_accesses(handler_fn.start_ea)

                # Name fields sequentially
                for idx, field in enumerate(fields):
                    field["name"] = f"field_{idx}"

                msg_type = {
                    "case_value": case_value,
                    "handler_address": hex(handler_fn.start_ea),
                    "name": handler_name,
                    "fields": fields,
                    "field_count": len(fields),
                }

                # Add callees for context
                callees = _get_func_callees(handler_fn.start_ea, max_refs=20)
                msg_type["callees"] = [c[1] for c in callees[:10]]

                message_types.append(msg_type)

            # Calculate total protocol size estimate
            total_fields = sum(mt["field_count"] for mt in message_types)

            protocol_data = {
                "name": fname,
                "dispatch_address": hex(ea),
                "message_types": message_types,
            }

            # Auto-write to blackboard
            _bb_write(
                title=f"protocol:reconstruct {fname} ({len(message_types)} msg types)",
                content=str({
                    "dispatch": hex(ea),
                    "message_count": len(message_types),
                    "total_fields": total_fields,
                }),
                addr=hex(ea),
                tags=["protocol", "reconstruct", fname],
            )

            return {
                "ok": True,
                "dispatch_function": fname,
                "dispatch_address": hex(ea),
                "message_type_count": len(message_types),
                "total_fields": total_fields,
                "message_types": message_types,
                "protocol_data": protocol_data,
            }

        elif action == "trace_handler":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for 'trace_handler' action")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            fname = idc.get_func_name(ea)
            fn = ida_funcs.get_func(ea)
            if not fn:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")

            # Deep analysis of the handler
            analysis = _analyze_handler_fields(ea)

            # Enrich with callee context
            callees = _get_func_callees(ea, max_refs=50)
            callee_names = [c[1] for c in callees]

            # Check for byte-order conversions (indicates network protocol)
            byte_order_apis = {"ntohs", "ntohl", "htons", "htonl",
                               "__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64"}
            has_byteswap = bool({c.lower() for c in callee_names} & {a.lower() for a in byte_order_apis})

            # Compute total message size from fields
            total_size = 0
            if analysis["fields"]:
                last_field = analysis["fields"][-1]
                total_size = last_field["offset"] + last_field["size"]

            # Name fields based on patterns
            for idx, field in enumerate(analysis["fields"]):
                field["name"] = f"field_{idx}"
                # Heuristic naming
                if field["offset"] == 0 and field["size"] <= 2:
                    field["name"] = "msg_type"
                elif field["offset"] <= 2 and field["size"] == 2:
                    field["name"] = "msg_length"
                elif field["size"] > 16:
                    field["name"] = f"payload_{idx}"

            # Auto-write to blackboard
            _bb_write(
                title=f"protocol:trace_handler {fname} ({len(analysis['fields'])} fields)",
                content=str({
                    "handler": hex(ea),
                    "fields": len(analysis["fields"]),
                    "patterns": [p["type"] for p in analysis["patterns"]],
                    "relationships": len(analysis["relationships"]),
                }),
                addr=hex(ea),
                tags=["protocol", "trace_handler", fname],
            )

            return {
                "ok": True,
                "handler_address": hex(ea),
                "handler_name": fname,
                "fields": analysis["fields"],
                "field_count": len(analysis["fields"]),
                "estimated_message_size": total_size,
                "relationships": analysis["relationships"],
                "patterns": analysis["patterns"],
                "has_network_byte_order": has_byteswap,
                "callees": callee_names[:20],
                "decompiled_excerpt": analysis["decompiled_lines"][:40],
            }

        elif action == "export_spec":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for 'export_spec' action (dispatch function address)")

            # Determine output format from query param
            fmt = "ksy"
            if query and query.strip().lower() in ("json", "json_schema", "jsonschema"):
                fmt = "json"
            elif query and query.strip().lower() in ("ksy", "kaitai"):
                fmt = "ksy"

            # First reconstruct the protocol from the dispatch function
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err
            fname = idc.get_func_name(ea)
            fn = ida_funcs.get_func(ea)
            if not fn:
                return make_error(MCPError.FUNCTION_NOT_FOUND, f"No function at {hex(ea)}")

            # Reconstruct (reuse logic from 'reconstruct' action)
            switch_targets = _get_switch_targets(ea)
            if not switch_targets:
                try:
                    cfunc = ida_hexrays.decompile(ea)
                    if cfunc:
                        sv = cfunc.get_pseudocode()
                        case_re = re.compile(r'(?:==|case)\s*(\d+)')
                        call_re = re.compile(r'(\w+)\s*\(')
                        for i in range(sv.size()):
                            line = ida_lines.tag_remove(sv[i].line).strip()
                            cm = case_re.search(line)
                            if cm:
                                case_val = int(cm.group(1))
                                handler_match = call_re.search(line)
                                if handler_match:
                                    handler_name = handler_match.group(1)
                                    handler_ea = ida_name.get_name_ea(idaapi.BADADDR, handler_name)
                                    if handler_ea != idaapi.BADADDR:
                                        switch_targets.append((case_val, handler_ea))
                except Exception:
                    pass

            message_types = []
            for case_value, target_ea in switch_targets[:limit]:
                handler_fn = ida_funcs.get_func(target_ea)
                if not handler_fn:
                    continue
                handler_name = idc.get_func_name(handler_fn.start_ea) or f"sub_{handler_fn.start_ea:X}"
                fields = _trace_buffer_accesses(handler_fn.start_ea)
                for idx, field in enumerate(fields):
                    field["name"] = f"field_{idx}"
                message_types.append({
                    "case_value": case_value,
                    "name": handler_name,
                    "fields": fields,
                })

            protocol_data = {
                "name": fname,
                "dispatch_address": hex(ea),
                "message_types": message_types,
            }

            # Export in requested format
            if fmt == "ksy":
                spec_output = _export_ksy(protocol_data)
                return {
                    "ok": True,
                    "format": "ksy",
                    "dispatch_function": fname,
                    "dispatch_address": hex(ea),
                    "message_type_count": len(message_types),
                    "spec": spec_output,
                }
            else:
                spec_output = _export_json_schema(protocol_data)
                return {
                    "ok": True,
                    "format": "json_schema",
                    "dispatch_function": fname,
                    "dispatch_address": hex(ea),
                    "message_type_count": len(message_types),
                    "spec": spec_output,
                }

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
