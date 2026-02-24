# CRYPTO_ID Tool Manual

## What It Does
Identify cryptographic algorithms, constants, and patterns in the binary.

## Actions
- `identify`: Run broad crypto detection and scoring.
- `constants`: Find known crypto constants/signatures.
- `key_schedule`: Detect key schedule-like instruction patterns.
- `block_cipher`: Detect block-cipher style operations.
- `hash_detect`: Detect hashing-related patterns.
- `rng_detect`: Detect random-number generation patterns.
- `asymmetric`: Detect asymmetric-crypto indicators.
- `custom_crypto`: Flag custom/rolled cryptographic logic.
- `encoding`: Detect encoding/transform routines.
- `checksums`: Detect checksum/CRC style logic.

## Key Parameters
- `action` (required): Operation selector.
- `addr` (default `None`): Target address or function start (hex string).
- `limit` (default `50`): Maximum result count.
- `include_context` (default `False`): Include nearby code/string context with findings.

## Examples (JSON call snippets)
```json
{
  "tool": "crypto_id",
  "args": {
    "action": "identify",
    "addr": "0x401000",
    "include_context": true
  }
}
```
```json
{
  "tool": "crypto_id",
  "args": {
    "action": "constants",
    "limit": 80
  }
}
```

## Failure Modes
- `ADDRESS_INVALID`: `No function at address`
- `INVALID_ARGS`: `Unknown action: {action}`
