# PROTOCOL Tool Manual

## What It Does
Performs protocol-focused reverse-engineering heuristics: protocol fingerprinting, parser/serializer discovery, endpoint extraction, TLS setup hints, packet-structure inference, and state-machine detection.

## Actions
- `detect`: Detect probable protocols from strings and network API usage.
- `parsers`: Find parser-like functions (byte-order + buffer-read heuristics).
- `serializers`: Find serializer-like functions (packing + write/send heuristics).
- `handlers`: Find command/message handler dispatch functions.
- `endpoints`: Extract URLs, IPs, hostnames, and ports.
- `tls_config`: Identify TLS API callsites and related cipher/cert strings.
- `socket_flow`: Map socket lifecycle phases in functions.
- `packet_struct`: Infer packet fields/size hints from one function.
- `magic_numbers`: Find known protocol/file magic constants and version IDs.
- `state_machine`: Find state-machine-like protocol control logic.

## Key Parameters
- `action`: One of `detect|parsers|serializers|handlers|endpoints|tls_config|socket_flow|packet_struct|magic_numbers|state_machine`.
- `addr`: Optional function scope for many actions; required for `packet_struct`.
- `limit`: Max returned findings per action.
- `query`: Optional regex/substring filter applied in several actions.

## Examples
```python
protocol(action="detect", limit=25)
protocol(action="parsers", query="packet", limit=20)
protocol(action="endpoints", query="api", limit=50)
protocol(action="tls_config", addr="0x401A20", limit=20)
protocol(action="packet_struct", addr="0x402100", limit=40)
protocol(action="state_machine", limit=20)
```

## Failure Modes
- Missing `addr` for `packet_struct`.
- Invalid `addr` when function scoping is requested.
- Heuristic output quality depends on symbol quality/import resolution.
- Decompiled field extraction in `packet_struct` can degrade if Hex-Rays is unavailable.
