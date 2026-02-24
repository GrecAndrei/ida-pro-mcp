# C2_DETECT Tool Manual

## What It Does
LLM-optimized C2/malware behavior detection for binary analysis.

## Actions
- `indicators`: Find all potential C2 indicators (URLs, IPs, domains, registry keys, mutexes)
- `persistence`: Find persistence mechanisms (registry run keys, services, scheduled tasks)
- `evasion`: Find evasion/anti-analysis techniques (anti-debug, anti-VM, sandbox detection)
- `injection`: Find process injection techniques (VirtualAllocEx, WriteProcessMemory, etc.)
- `exfiltration`: Find data exfiltration patterns (file reading + network sending)
- `lateral_movement`: Find lateral movement techniques (WMI, PSExec, SMB, RDP patterns)
- `privilege_escalation`: Find privilege escalation attempts (token manipulation)
- `capabilities`: Comprehensive capability assessment (what can this malware do?)
- `config_extract`: Find embedded configuration data (encrypted blocks, XOR'd data)
- `ioc_extract`: Extract all IOCs (indicators of compromise) in structured format

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `limit` (default `50`): Maximum result count.
- `include_context` (default `False`): Include nearby code/string context with findings.

## Examples (JSON call snippets)
```json
{
  "tool": "c2_detect",
  "args": {
    "action": "indicators",
    "limit": 100,
    "include_context": true
  }
}
```
```json
{
  "tool": "c2_detect",
  "args": {
    "action": "ioc_extract",
    "addr": "0x401000"
  }
}
```

## Failure Modes
- `INVALID_ARGS`: `Unknown action: {action}`
