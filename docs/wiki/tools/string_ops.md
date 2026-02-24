# STRING_OPS Tool Manual

## What It Does
Runs focused string intelligence queries (URLs, paths, registry keys, IPs, emails, command execution hints, encoding stats, multilingual text, and suspicious token patterns), with optional scope and query filtering.

## Actions
- `decode_all`: Decode non-ASCII strings using multiple encodings.
- `find_urls`: URL-like strings.
- `find_paths`: Windows/Unix path and executable-extension strings.
- `find_registry`: Registry-key patterns.
- `find_ips`: IPv4/IPv6 patterns.
- `find_emails`: Email addresses.
- `find_commands`: Command/shell execution indicators.
- `encoding_stats`: String-encoding distribution summary.
- `multilingual`: Non-ASCII multilingual strings.
- `suspicious`: Password/token/key/base64-like indicators.

## Key Parameters
- `action`: One of `decode_all|find_urls|find_paths|find_registry|find_ips|find_emails|find_commands|encoding_stats|multilingual|suspicious`.
- `addr`: Optional function scope filter.
- `limit`: Max result lines.
- `query`: Optional regex/substring filter applied before action matching.

## Examples
```python
string_ops(action="find_urls", limit=50)
string_ops(action="find_commands", addr="0x401900", limit=25)
string_ops(action="decode_all", query="config", limit=30)
string_ops(action="encoding_stats")
string_ops(action="suspicious", limit=100)
```

## Failure Modes
- Invalid `addr` may fail scope narrowing.
- Regex compilation failures in `query` fallback to substring matching.
- Results depend on currently defined IDA string items.
