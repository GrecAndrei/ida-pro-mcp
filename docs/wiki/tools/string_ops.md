# string_ops

Extracts, decodes, classifies, and scores strings for IOC discovery, C2 detection, and malware triage.

## Actions
- `decode_all` — Attempt decoding of obfuscated/encoded strings (XOR, base64, stack strings); params: `address`
- `find_urls` — Extract URL-like strings; params: `pattern`
- `find_paths` — Extract file system paths; params: `pattern`
- `find_registry` — Extract Windows registry key references; params: `pattern`
- `find_ips` — Extract IP addresses (IPv4/IPv6); params: `pattern`
- `find_emails` — Extract email addresses; params: `pattern`
- `find_commands` — Extract shell/command-line strings; params: `pattern`
- `encoding_stats` — Report encoding distribution across all strings (ASCII, UTF-8, wide, etc.)
- `multilingual` — Detect and classify multilingual/non-ASCII strings (CJK, Cyrillic, Arabic, etc.)
- `suspicious` — Flag strings with suspicious characteristics (high entropy, obfuscation markers)
- `find_xrefs` — Find cross-references to/from string addresses; params: `address`, `pattern`
- `find_stack_strings` — Detect strings constructed char-by-char on the stack (anti-static-analysis technique); params: `address`
- `find_base64` — Extract base64-encoded content and attempt decode; params: `pattern`
- `find_api_keys` — Detect API key patterns (AWS, GCP, generic high-entropy tokens); params: `pattern`
- `find_configs` — Extract configuration-like strings (key=value, JSON fragments, INI); params: `pattern`
- `find_c2` — Find strings matching known C2 framework patterns (Cobalt Strike, Metasploit, etc.); params: `pattern`
- `find_databases` — Extract database connection strings and SQL fragments; params: `pattern`
- `find_crypto_addrs` — Detect cryptocurrency wallet addresses (BTC, ETH, Monero); params: `pattern`
- `entropy_rank` — Rank all strings by Shannon entropy (high entropy = likely encrypted/encoded); params: `count`
- `score_c2` — ML-based scoring of strings for C2/beaconing risk; params: `threshold`
- `indicators` — Aggregate malware indicator strings (C2, crypto, credentials, anti-debug); params: `category`
- `persistence` — Find strings related to persistence mechanisms (registry run keys, services, scheduled tasks)
- `evasion` — Find strings related to evasion techniques (anti-VM, anti-debug, process injection)
- `ioc_extract` — Extract structured IOC list (IPs, domains, URLs, hashes, file paths) as machine-readable output

## Examples
```json
{"name": "string_ops", "arguments": {"action": "find_urls"}}
```
```json
{"name": "string_ops", "arguments": {"action": "score_c2", "threshold": 0.7}}
```
```json
{"name": "string_ops", "arguments": {"action": "find_stack_strings", "address": "0x401000"}}
```
```json
{"name": "string_ops", "arguments": {"action": "ioc_extract"}}
```
```json
{"name": "string_ops", "arguments": {"action": "indicators", "category": "c2"}}
```

## Notes
- `score_c2` uses a local ML model to score C2 likelihood — useful for quick malware triage before full `threat_hunt`.
- `ioc_extract` returns a structured list of IOCs suitable for feeding into SIEM/SOAR platforms.
- `find_stack_strings` detects char-by-char string construction that evades static string extraction.
- `indicators`, `persistence`, and `evasion` are malware-focused aggregators that combine multiple heuristics.
- All `find_*` actions support optional `pattern` for regex filtering of results.
- Pair with `crypto_id(action="encoding")` for deeper obfuscation analysis.
- Use `entropy_rank` to quickly surface encrypted/packed content for further investigation.
