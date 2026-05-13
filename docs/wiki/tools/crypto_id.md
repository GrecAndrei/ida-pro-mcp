# crypto_id

Identifies cryptographic algorithms, constants, and encoding routines in binary code.

## Actions
- `identify` — Classify crypto usage via BehaviorClassifier on decompiled pseudocode + constant scanning; params: `address`
- `constants` — Scan for known crypto constants (S-boxes, IVs, magic values); params: `address`, `algorithm`
- `encoding` — Detect encoding/decoding routines (base64, XOR, RC4); params: `address`
- `checksums` — Find checksum/hash computation patterns (CRC, MD5, SHA); params: `address`
- `entropy_analysis` — Measure entropy to locate encrypted/compressed regions; params: `address`, `size`
- `aes_ni` — Detect AES-NI hardware instruction usage; params: `address`

## Examples
```json
{"name": "crypto_id", "arguments": {"action": "identify", "address": "0x401000"}}
```
```json
{"name": "crypto_id", "arguments": {"action": "constants"}}
```

## Notes
- `identify` combines behavioral classification with constant scanning for high-confidence results.
- Works on decompiled pseudocode when Hex-Rays is available; falls back to disassembly patterns.
- Pair with `entropy` tool for region-level packed/encrypted detection.
