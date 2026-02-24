# YARA_HUNT Tool Manual

## What It Does
Compiles and runs YARA signatures against either a specific memory range or all segments.

## Actions
- `scan`: Compile rules and scan range or full binary segments.
- `compile`: Validate YARA rule source text.
- `list_rules`: List `.yar`/`.yara` files under repo `rules/`.

## Key Parameters
- `action`: `scan|compile|list_rules`.
- `rules`: Required for `scan`/`compile`; either inline rule text or path to rule file.
- `addr`: Optional scan start address for `scan`.
- `size`: Range size for address-scoped `scan` (defaults to `0x1000` when `addr` is set).

## Examples
```json
{"name":"yara_hunt","arguments":{"action":"compile","rules":"rule Test { strings: $a = \"MZ\" condition: $a }"}}
```

```json
{"name":"yara_hunt","arguments":{"action":"scan","rules":"/tmp/rules/suspicious.yar","addr":"0x401000","size":8192}}
```

```json
{"name":"yara_hunt","arguments":{"action":"list_rules"}}
```

## Failure Modes
- `yara-python` missing in IDA environment returns not-implemented error.
- Rule compile errors return invalid-args with YARA parser message.
- Unsafe/invalid rule file paths are rejected.
- Invalid scan address/range can fail with address-invalid error.
- Full-binary mode caps returned matches to first 100 entries.
