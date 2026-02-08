
try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import re

# ============================================================================
# PROTOCOL - Network Protocol Structure Analysis for LLMs
# ============================================================================

# Known protocol signature strings
_PROTOCOL_STRINGS = {
    "HTTP": ["HTTP/1.", "HTTP/2", "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
             "Content-Type:", "Content-Length:", "Host:", "User-Agent:",
             "Accept:", "Authorization:", "Cookie:", "Set-Cookie:"],
    "DNS": ["dns", "DNS", "nameserver", "resolv", "AAAA", "CNAME", "MX ",
            "NS ", "SOA ", "PTR ", "SRV ", "TXT "],
    "TLS": ["TLS", "SSL", "TLSv1", "SSLv3", "certificate", "cipher",
            "handshake", "ECDHE", "RSA", "AES_256_GCM", "SHA256",
            "X509", "PEM", "-----BEGIN CERTIFICATE-----"],
    "MQTT": ["MQTT", "CONNECT", "PUBLISH", "SUBSCRIBE", "UNSUBSCRIBE",
             "PINGREQ", "PINGRESP", "CONNACK", "PUBACK", "SUBACK"],
    "FTP": ["USER ", "PASS ", "RETR ", "STOR ", "LIST ", "QUIT",
            "PORT ", "PASV", "TYPE ", "CWD ", "PWD", "MKD ", "RMD "],
    "SMTP": ["EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:", "DATA",
             "QUIT", "RSET", "VRFY", "NOOP"],
    "WebSocket": ["Upgrade: websocket", "Sec-WebSocket", "ws://", "wss://"],
    "gRPC": ["grpc", "application/grpc", "proto", "protobuf"],
}

# Network API patterns for protocol detection
_NETWORK_APIS = {
    "socket": ["socket", "WSASocket", "WSASocketA", "WSASocketW"],
    "connect": ["connect", "WSAConnect"],
    "bind": ["bind"],
    "listen": ["listen"],
    "accept": ["accept", "WSAAccept"],
    "send": ["send", "sendto", "WSASend", "WSASendTo"],
    "recv": ["recv", "recvfrom", "WSARecv", "WSARecvFrom"],
    "close": ["closesocket", "close", "shutdown"],
    "dns": ["getaddrinfo", "gethostbyname", "gethostbyaddr",
            "getservbyname", "getservbyport", "getnameinfo"],
    "http": ["InternetOpen", "InternetOpenA", "InternetOpenW",
             "InternetConnect", "InternetConnectA", "InternetConnectW",
             "HttpOpenRequest", "HttpOpenRequestA", "HttpOpenRequestW",
             "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
             "InternetReadFile", "URLDownloadToFile", "URLDownloadToFileA",
             "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
             "WinHttpSendRequest", "WinHttpReceiveResponse",
             "WinHttpReadData", "WinHttpWriteData",
             "curl_easy_init", "curl_easy_perform", "curl_easy_setopt",
             "curl_easy_cleanup"],
    "tls": ["SSL_new", "SSL_connect", "SSL_accept", "SSL_read", "SSL_write",
            "SSL_free", "SSL_CTX_new", "SSL_CTX_free",
            "SSL_CTX_set_cipher_list", "SSL_CTX_set_verify",
            "SSL_CTX_load_verify_locations", "SSL_CTX_use_certificate_file",
            "SSL_CTX_use_PrivateKey_file", "SSL_set_fd",
            "SSL_get_peer_certificate", "SSL_get_verify_result",
            "SSL_shutdown", "SSL_set_verify",
            "mbedtls_ssl_handshake", "mbedtls_ssl_read", "mbedtls_ssl_write"],
    "byte_order": ["ntohs", "ntohl", "htons", "htonl"],
    "init": ["WSAStartup", "WSACleanup"],
}

# Flat set of all network API names for fast lookup
_ALL_NETWORK_APIS = set()
for _apis in _NETWORK_APIS.values():
    _ALL_NETWORK_APIS.update(a.lower() for a in _apis)

# TLS-specific APIs for tls_config action
_TLS_CONFIG_APIS = [
    "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites",
    "SSL_CTX_set_verify", "SSL_set_verify",
    "SSL_CTX_load_verify_locations", "SSL_CTX_set_default_verify_paths",
    "SSL_CTX_use_certificate_file", "SSL_CTX_use_certificate_chain_file",
    "SSL_CTX_use_PrivateKey_file", "SSL_CTX_set_options",
    "SSL_CTX_set_min_proto_version", "SSL_CTX_set_max_proto_version",
    "SSL_CTX_set_mode", "SSL_CTX_set_session_cache_mode",
    "SSL_get_peer_certificate", "SSL_get_verify_result",
    "X509_verify_cert", "X509_check_host",
    "mbedtls_ssl_conf_authmode", "mbedtls_ssl_conf_ca_chain",
    "mbedtls_ssl_conf_own_cert", "mbedtls_ssl_conf_ciphersuites",
    "mbedtls_x509_crt_parse", "mbedtls_pk_parse_key",
    "SecureTransport", "SSLSetPeerDomainName",
    "SChannel", "AcquireCredentialsHandle",
]

# Socket lifecycle phases for socket_flow
_SOCKET_LIFECYCLE = {
    "create": ["socket", "WSASocket", "WSASocketA", "WSASocketW"],
    "configure": ["setsockopt", "getsockopt", "ioctlsocket", "fcntl",
                   "bind"],
    "connect": ["connect", "WSAConnect"],
    "listen": ["listen", "accept", "WSAAccept"],
    "io": ["send", "sendto", "recv", "recvfrom",
           "WSASend", "WSARecv", "WSASendTo", "WSARecvFrom",
           "read", "write", "select", "poll", "epoll_ctl",
           "SSL_read", "SSL_write"],
    "close": ["closesocket", "close", "shutdown", "SSL_shutdown", "SSL_free"],
}

# Common protocol magic numbers
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
    0xCAFEBABE: ("Java class / Mach-O fat", "Magic number"),
    0x7F454C46: ("ELF", "ELF header"),
    0x504B0304: ("ZIP/APK", "PK header"),
    0xFEEDFACE: ("Mach-O 32-bit", "Mach-O magic"),
    0xFEEDFACF: ("Mach-O 64-bit", "Mach-O magic"),
    0xD0CF11E0: ("OLE/MS Office", "OLE header"),
}


def _get_all_strings():
    """Collect all defined strings from the IDB."""
    results = []
    sc = idautils.Strings()
    for s in sc:
        val = str(s)
        if val:
            results.append((s.ea, val, s.length))
    return results


def _find_api_xrefs(api_name):
    """Find all xrefs to a named API. Returns list of (caller_ea, caller_name)."""
    results = []
    ea = ida_name.get_name_ea(idaapi.BADADDR, api_name)
    if ea == idaapi.BADADDR:
        # Try with common suffixes
        for suffix in ("A", "W", "@plt", "@PLT"):
            ea = ida_name.get_name_ea(idaapi.BADADDR, api_name + suffix)
            if ea != idaapi.BADADDR:
                break
    if ea == idaapi.BADADDR:
        return results
    for xref in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        if fn:
            fname = idc.get_func_name(fn.start_ea)
            results.append((fn.start_ea, fname))
    return results


def _get_func_callees(func_ea):
    """Return list of (callee_ea, callee_name) for the function."""
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return []
    callees = []
    seen = set()
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        for xref in idautils.CodeRefsFrom(head, 0):
            if xref not in seen:
                seen.add(xref)
                name = idc.get_func_name(xref)
                if not name:
                    name = ida_name.get_name(xref)
                if name:
                    callees.append((xref, name))
    return callees


def _get_func_strings(func_ea):
    """Get all string references from a function."""
    fn = ida_funcs.get_func(func_ea)
    if not fn:
        return []
    strings = []
    for head in idautils.Heads(fn.start_ea, fn.end_ea):
        for dref in idautils.DataRefsFrom(head):
            stype = idc.get_str_type(dref)
            if stype is not None and stype >= 0:
                s = idc.get_strlit_contents(dref, -1, stype)
                if s:
                    s = s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
                    if s not in strings:
                        strings.append(s)
    return strings


def _count_switch_cases(func_ea):
    """Count switch/case targets in a function (architecture-neutral)."""
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
    """Strip common API suffixes for matching."""
    for suffix in ("A", "W", "@plt", "@PLT"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def _match_query(text, query):
    """Check if text matches query filter (regex/substring auto-detected)."""
    if not query:
        return True
    import re
    try:
        return bool(re.search(query, text, re.IGNORECASE))
    except re.error:
        return query.lower() in text.lower()


@tool
@idaread
def protocol(
    action: Annotated[Literal["detect", "parsers", "serializers", "handlers",
                               "endpoints", "tls_config", "socket_flow",
                               "packet_struct", "magic_numbers", "state_machine"],
                      "Protocol analysis action"],
    addr: Annotated[Optional[str], "Address or function to analyze"] = None,
    limit: Annotated[int, "Max results"] = 50,
    query: Annotated[Optional[str], "Filter query (regex/glob/substring auto-detected)"] = None,
) -> dict:
    """
    Analyze network protocol structures, parsing code, and communication patterns.

    ACTIONS:

    detect - Detect network protocol usage by scanning strings and API patterns.
        Returns: {protocols_detected, api_usage, string_evidence}

    parsers - Find protocol parsing functions (buffer reads with offset arithmetic).
        Params: addr (optional, scope to one function), limit, query
        Returns: {parsers}

    serializers - Find protocol serialization functions (structured buffer writes).
        Params: addr (optional), limit, query
        Returns: {serializers}

    handlers - Find message/command handler dispatch tables (large switch statements).
        Params: addr (optional), limit, query
        Returns: {handlers}

    endpoints - Find network endpoint strings (URLs, IPs, hostnames, ports).
        Params: limit, query
        Returns: {endpoints}

    tls_config - Analyze TLS/SSL configuration (cipher suites, certificate handling).
        Params: addr (optional), limit
        Returns: {tls_apis, cipher_strings, cert_strings}

    socket_flow - Trace socket lifecycle (create -> bind/connect -> send/recv -> close).
        Params: addr (optional), limit
        Returns: {flows}

    packet_struct - Infer packet/message structure from parsing code.
        Params: addr (required)
        Returns: {fields, byte_order_calls, size_hints}

    magic_numbers - Find protocol magic numbers and version identifiers.
        Params: limit, query
        Returns: {magic_numbers}

    state_machine - Detect protocol state machine patterns.
        Params: addr (optional), limit
        Returns: {state_machines}
    """
    try:
        # ----------------------------------------------------------------
        # ACTION: detect
        # ----------------------------------------------------------------
        if action == "detect":
            protocols_detected = {}
            api_usage = {}
            string_evidence = {}

            # Scan strings for protocol signatures
            all_strings = _get_all_strings()
            for proto, patterns in _PROTOCOL_STRINGS.items():
                matches = []
                for s_ea, s_val, s_len in all_strings:
                    for pat in patterns:
                        if pat in s_val:
                            entry = f"{hex(s_ea)}  \"{s_val[:80]}\""
                            if entry not in matches:
                                matches.append(entry)
                            break
                if matches:
                    string_evidence[proto] = matches[:limit]
                    protocols_detected[proto] = len(matches)

            # Scan API usage
            for api_cat, apis in _NETWORK_APIS.items():
                for api in apis:
                    xrefs = _find_api_xrefs(api)
                    if xrefs:
                        callers = []
                        for caller_ea, caller_name in xrefs:
                            entry = f"{hex(caller_ea)}  {caller_name}"
                            if entry not in callers:
                                callers.append(entry)
                        api_usage[api] = callers[:limit]

            return {
                "ok": True,
                "protocols_detected": protocols_detected,
                "api_usage": api_usage,
                "string_evidence": string_evidence,
            }

        # ----------------------------------------------------------------
        # ACTION: parsers
        # ----------------------------------------------------------------
        elif action == "parsers":
            parsers = []

            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                func_list = [ea]
            else:
                func_list = list(idautils.Functions())

            byte_order_apis = {"ntohs", "ntohl", "htons", "htonl",
                               "__builtin_bswap16", "__builtin_bswap32",
                               "__builtin_bswap64", "_byteswap_ushort",
                               "_byteswap_ulong", "_byteswap_uint64"}

            for func_ea in func_list:
                if len(parsers) >= limit:
                    break
                fname = idc.get_func_name(func_ea)
                if not _match_query(fname, query):
                    continue
                callees = _get_func_callees(func_ea)
                callee_names = {_strip_api_suffix(c[1]).lower() for c in callees}

                # Heuristic: calls byte-order conversion or memcpy-style reads
                has_byte_order = bool(callee_names & {a.lower() for a in byte_order_apis})
                has_memread = bool(callee_names & {"memcpy", "memmove", "bcopy",
                                                   "recv", "recvfrom", "read",
                                                   "wsarecv", "ssl_read",
                                                   "internetreadfile"})

                if has_byte_order or has_memread:
                    indicators = []
                    if has_byte_order:
                        indicators.append("byte_order")
                    if has_memread:
                        indicators.append("buffer_read")
                    fn_strs = _get_func_strings(func_ea)
                    parsers.append({
                        "address": hex(func_ea),
                        "name": fname,
                        "indicators": indicators,
                        "relevant_callees": [c[1] for c in callees
                                             if _strip_api_suffix(c[1]).lower() in
                                             (byte_order_apis | {"memcpy", "memmove",
                                              "recv", "recvfrom", "read"})],
                        "strings": fn_strs[:10],
                    })

            return {"ok": True, "parsers": "\n".join(str(x) for x in parsers), "count": len(parsers)}

        # ----------------------------------------------------------------
        # ACTION: serializers
        # ----------------------------------------------------------------
        elif action == "serializers":
            serializers = []

            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                func_list = [ea]
            else:
                func_list = list(idautils.Functions())

            write_apis = {"memcpy", "memmove", "send", "sendto", "write",
                          "wsasend", "wsasendto", "ssl_write", "fwrite",
                          "httpsendrequesta", "httpsendrequestw",
                          "winhttpsendrequest", "winhttpwritedata",
                          "internetsendrequest"}
            pack_apis = {"htons", "htonl", "sprintf", "snprintf",
                         "sprint", "strcat", "strncat", "memset",
                         "__builtin_bswap16", "__builtin_bswap32"}

            for func_ea in func_list:
                if len(serializers) >= limit:
                    break
                fname = idc.get_func_name(func_ea)
                if not _match_query(fname, query):
                    continue
                callees = _get_func_callees(func_ea)
                callee_names = {_strip_api_suffix(c[1]).lower() for c in callees}

                has_write = bool(callee_names & write_apis)
                has_pack = bool(callee_names & {a.lower() for a in pack_apis})

                if has_write and has_pack:
                    indicators = []
                    if has_write:
                        indicators.append("buffer_write")
                    if has_pack:
                        indicators.append("data_packing")
                    serializers.append({
                        "address": hex(func_ea),
                        "name": fname,
                        "indicators": indicators,
                        "relevant_callees": [c[1] for c in callees
                                             if _strip_api_suffix(c[1]).lower() in
                                             (write_apis | {a.lower() for a in pack_apis})],
                    })

            return {"ok": True, "serializers": "\n".join(str(x) for x in serializers), "count": len(serializers)}

        # ----------------------------------------------------------------
        # ACTION: handlers
        # ----------------------------------------------------------------
        elif action == "handlers":
            handlers = []

            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                func_list = [ea]
            else:
                func_list = list(idautils.Functions())

            for func_ea in func_list:
                if len(handlers) >= limit:
                    break
                fname = idc.get_func_name(func_ea)
                if not _match_query(fname, query):
                    continue

                case_count = _count_switch_cases(func_ea)
                if case_count < 3:
                    continue

                # Check if function is related to network/message handling
                callees = _get_func_callees(func_ea)
                callee_names = {_strip_api_suffix(c[1]).lower() for c in callees}
                fn_strs = _get_func_strings(func_ea)
                is_network = bool(callee_names & _ALL_NETWORK_APIS)
                has_msg_strings = any(
                    kw in s.lower() for s in fn_strs
                    for kw in ("msg", "message", "command", "cmd", "opcode",
                               "type", "handler", "dispatch", "packet", "request")
                )

                handlers.append({
                    "address": hex(func_ea),
                    "name": fname,
                    "case_count": case_count,
                    "network_related": is_network,
                    "has_message_strings": has_msg_strings,
                    "strings": fn_strs[:10],
                })

            # Sort by case count descending
            # handlers are strings, already sorted by append order
            return {"ok": True, "handlers": handlers[:limit], "count": len(handlers)}

        # ----------------------------------------------------------------
        # ACTION: endpoints
        # ----------------------------------------------------------------
        elif action == "endpoints":
            endpoints = {
                "urls": [],
                "ips": [],
                "hostnames": [],
                "ports": [],
            }

            url_re = re.compile(r'https?://[^\s"\'<>]+')
            ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            host_re = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|int|info|biz|co|us|uk|de|fr|jp|cn|ru|br|in|au|dev|app|cloud)\b')
            port_re = re.compile(r'\b(?:port|PORT)[:\s=]+(\d{1,5})\b')

            all_strings = _get_all_strings()
            for s_ea, s_val, s_len in all_strings:
                if not _match_query(s_val, query):
                    continue

                # URLs
                for m in url_re.finditer(s_val):
                    entry = f"{hex(s_ea)}  \"{m.group()[:120]}\""
                    if entry not in endpoints["urls"] and len(endpoints["urls"]) < limit:
                        endpoints["urls"].append(entry)

                # IPs
                for m in ip_re.finditer(s_val):
                    ip = m.group()
                    # Filter out version-like patterns
                    parts = ip.split(".")
                    if all(0 <= int(p) <= 255 for p in parts):
                        entry = f"{hex(s_ea)}  {ip}"
                        if entry not in endpoints["ips"] and len(endpoints["ips"]) < limit:
                            endpoints["ips"].append(entry)

                # Hostnames
                for m in host_re.finditer(s_val):
                    entry = f"{hex(s_ea)}  {m.group()}"
                    if entry not in endpoints["hostnames"] and len(endpoints["hostnames"]) < limit:
                        endpoints["hostnames"].append(entry)

                # Ports
                for m in port_re.finditer(s_val):
                    entry = f"{hex(s_ea)}  port={m.group(1)}"
                    if entry not in endpoints["ports"] and len(endpoints["ports"]) < limit:
                        endpoints["ports"].append(entry)

            # Also check for well-known port constants used with htons
            htons_xrefs = _find_api_xrefs("htons")
            for caller_ea, caller_name in htons_xrefs:
                if len(endpoints["ports"]) >= limit:
                    break
                entry = f"{hex(caller_ea)}  {caller_name}  (htons caller)"
                if entry not in endpoints["ports"]:
                    endpoints["ports"].append(entry)

            total = sum(len(v) for v in endpoints.values())
            return {"ok": True, "endpoints": "\n".join(str(x) for x in endpoints), "total": total}

        # ----------------------------------------------------------------
        # ACTION: tls_config
        # ----------------------------------------------------------------
        elif action == "tls_config":
            tls_apis = []
            cipher_strings = []
            cert_strings = []

            # Find TLS API usage
            for api in _TLS_CONFIG_APIS:
                xrefs = _find_api_xrefs(api)
                for caller_ea, caller_name in xrefs:
                    if len(tls_apis) >= limit:
                        break
                    entry = {
                        "api": api,
                        "caller_address": hex(caller_ea),
                        "caller_name": caller_name,
                    }
                    tls_apis.append(entry)

            # Scope string search
            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                search_strings = _get_func_strings(ea)
                search_pairs = [(ea, s) for s in search_strings]
            else:
                all_strs = _get_all_strings()
                search_pairs = [(s_ea, s_val) for s_ea, s_val, _ in all_strs]

            cipher_keywords = ["ECDHE", "RSA", "AES", "GCM", "CBC", "SHA256",
                               "SHA384", "SHA1", "DHE", "CHACHA20", "POLY1305",
                               "TLS_", "SSL_", "cipher"]
            cert_keywords = ["cert", "certificate", "CA", "X509", "PEM",
                             "-----BEGIN", ".pem", ".crt", ".cer", ".key",
                             "verify", "trust"]

            for s_ea, s_val in search_pairs:
                s_lower = s_val.lower() if isinstance(s_val, str) else s_val
                for kw in cipher_keywords:
                    if kw.lower() in s_lower:
                        entry = f"{hex(s_ea)}  \"{s_val[:100]}\""
                        if entry not in cipher_strings and len(cipher_strings) < limit:
                            cipher_strings.append(entry)
                        break
                for kw in cert_keywords:
                    if kw.lower() in s_lower:
                        entry = f"{hex(s_ea)}  \"{s_val[:100]}\""
                        if entry not in cert_strings and len(cert_strings) < limit:
                            cert_strings.append(entry)
                        break

            return {
                "ok": True,
                "tls_apis": tls_apis,
                "cipher_strings": cipher_strings,
                "cert_strings": cert_strings,
            }

        # ----------------------------------------------------------------
        # ACTION: socket_flow
        # ----------------------------------------------------------------
        elif action == "socket_flow":
            flows = []

            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                func_list = [ea]
            else:
                # Start from functions that call socket creation APIs
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
                callee_names_lower = {_strip_api_suffix(c[1]).lower() for c in callees}

                phases = {}
                for phase, apis in _SOCKET_LIFECYCLE.items():
                    matched = [c[1] for c in callees
                               if _strip_api_suffix(c[1]).lower() in
                               {a.lower() for a in apis}]
                    if matched:
                        phases[phase] = matched

                if phases:
                    phase_order = ["create", "configure", "connect", "listen",
                                   "io", "close"]
                    ordered = [p for p in phase_order if p in phases]
                    complete = "create" in phases and "close" in phases
                    flows.append(f"{hex(func_ea)}  {fname}  phases={','.join(ordered)}  complete={complete}")

            return {"ok": True, "flows": "\n".join(str(x) for x in flows), "count": len(flows)}

        # ----------------------------------------------------------------
        # ACTION: packet_struct
        # ----------------------------------------------------------------
        elif action == "packet_struct":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for 'packet_struct' action")
            ea, err = validate_addr(addr, require_func=True)
            if err:
                return err

            fname = idc.get_func_name(ea)
            fn = ida_funcs.get_func(ea)
            if not fn:
                return make_error(MCPError.FUNC_NOT_FOUND, f"No function at {hex(ea)}")

            callees = _get_func_callees(ea)
            byte_order_calls = [c[1] for c in callees
                                if _strip_api_suffix(c[1]).lower() in
                                {"ntohs", "ntohl", "htons", "htonl",
                                 "__builtin_bswap16", "__builtin_bswap32",
                                 "__builtin_bswap64"}]
            fn_strs = _get_func_strings(ea)

            # Analyze immediate values used as sizes/offsets
            size_hints = []
            seen_imms = set()
            for head in idautils.Heads(fn.start_ea, fn.end_ea):
                flags = ida_bytes.get_flags(head)
                if not ida_bytes.is_code(flags):
                    continue
                insn = idaapi.insn_t()
                length = idaapi.decode_insn(insn, head)
                if length <= 0:
                    continue
                for i in range(idaapi.UA_MAXOP):
                    op = insn.ops[i]
                    if op.type == idaapi.o_void:
                        break
                    if op.type == idaapi.o_imm:
                        val = op.value
                        # Filter for plausible struct sizes/offsets
                        if 1 <= val <= 65536 and val not in seen_imms:
                            seen_imms.add(val)
                            size_hints.append(f"{hex(head)}  value={val}  {hex(val)}")

            # Try to get decompiled output for richer analysis
            fields = []
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    sv = cfunc.get_pseudocode()
                    for i in range(sv.size()):
                        line = ida_lines.tag_remove(sv[i].line)
                        # Look for array/pointer offset patterns
                        if any(p in line for p in ("[", "->", "offset", "buf +",
                                                    "ptr +", ".field", "header")):
                            fields.append(line.strip())
            except Exception:
                pass

            return {
                "ok": True,
                "address": hex(ea),
                "name": fname,
                "byte_order_calls": byte_order_calls,
                "size_hints": size_hints[:limit],
                "fields": fields[:limit],
                "strings": fn_strs[:20],
            }

        # ----------------------------------------------------------------
        # ACTION: magic_numbers
        # ----------------------------------------------------------------
        elif action == "magic_numbers":
            results = []

            # Search for known magic numbers in data segments
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if not seg:
                    continue
                seg_end = seg.end_ea
                ea_cursor = seg.start_ea
                while ea_cursor < seg_end and len(results) < limit:
                    flags = ida_bytes.get_flags(ea_cursor)
                    if ida_bytes.is_dword(flags) or ida_bytes.has_value(flags):
                        val = ida_bytes.get_dword(ea_cursor)
                        if val in _KNOWN_MAGIC:
                            proto, desc = _KNOWN_MAGIC[val]
                            if _match_query(proto, query):
                                results.append(f"{hex(ea_cursor)}  {hex(val)}  {proto}  {desc}")
                    ea_cursor = ida_bytes.next_head(ea_cursor, seg_end)
                    if ea_cursor == idaapi.BADADDR:
                        break

            # Also search strings for version identifiers
            version_re = re.compile(r'(?:v|version|ver)[:\s.=]*(\d+(?:\.\d+)+)', re.IGNORECASE)
            all_strings = _get_all_strings()
            for s_ea, s_val, _ in all_strings:
                if len(results) >= limit:
                    break
                for m in version_re.finditer(s_val):
                    if _match_query(s_val, query):
                        results.append(f"{hex(s_ea)}  {m.group()}  version_id  {s_val[:80]}")
                        break

            return {"ok": True, "magic_numbers": results, "count": len(results)}

        # ----------------------------------------------------------------
        # ACTION: state_machine
        # ----------------------------------------------------------------
        elif action == "state_machine":
            state_machines = []

            if addr:
                ea, err = validate_addr(addr, require_func=True)
                if err:
                    return err
                func_list = [ea]
            else:
                func_list = list(idautils.Functions())

            state_keywords = {"state", "status", "phase", "stage", "step",
                              "mode", "fsm", "transition"}

            for func_ea in func_list:
                if len(state_machines) >= limit:
                    break
                fname = idc.get_func_name(func_ea)

                case_count = _count_switch_cases(func_ea)
                fn_strs = _get_func_strings(func_ea)
                name_lower = fname.lower()

                # Check for state-related naming
                has_state_name = any(kw in name_lower for kw in state_keywords)
                has_state_strings = any(
                    any(kw in s.lower() for kw in state_keywords)
                    for s in fn_strs
                )

                # A state machine typically has a switch on state + transitions
                if case_count >= 3 and (has_state_name or has_state_strings):
                    # Check if function calls itself or functions in a cycle
                    callees = _get_func_callees(func_ea)
                    callee_names = [c[1] for c in callees]
                    is_recursive = fname in callee_names

                    state_machines.append({
                        "address": hex(func_ea),
                        "name": fname,
                        "case_count": case_count,
                        "state_name_match": has_state_name,
                        "state_string_match": has_state_strings,
                        "recursive": is_recursive,
                        "strings": fn_strs[:10],
                    })
                elif case_count >= 5:
                    # Large switch without state keywords - still might be a state machine
                    callees = _get_func_callees(func_ea)
                    callee_names_lower = {_strip_api_suffix(c[1]).lower() for c in callees}
                    is_network = bool(callee_names_lower & _ALL_NETWORK_APIS)
                    if is_network:
                        state_machines.append({
                            "address": hex(func_ea),
                            "name": fname,
                            "case_count": case_count,
                            "state_name_match": False,
                            "state_string_match": False,
                            "network_related": True,
                            "strings": fn_strs[:10],
                        })

            # Sort by case count descending
            # state_machines are strings, already sorted by append order
            return {"ok": True, "state_machines": state_machines[:limit],
                    "count": len(state_machines)}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
