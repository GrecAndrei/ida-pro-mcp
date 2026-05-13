# entropy

Computes entropy metrics to detect packed, encrypted, or compressed regions in the binary.

## Actions
- `section` — Compute entropy per section/segment; params: none
- `region` — Compute entropy for a specific address range; params: `address`, `size`
- `packed_detect` — Heuristic detection of packed/compressed sections; params: `threshold`
- `crypto_detect` — Identify high-entropy regions likely containing crypto material; params: `threshold`
- `compare` — Compare entropy profiles between two regions or binaries; params: `address_a`, `address_b`, `size`
- `window` — Sliding-window entropy computation; params: `address`, `size`, `window_size`
- `summary` — Overall binary entropy summary with anomaly flags

## Examples
```json
{"name": "entropy", "arguments": {"action": "section"}}
```
```json
{"name": "entropy", "arguments": {"action": "packed_detect", "threshold": 7.0}}
```

## Notes
- Entropy values range 0.0–8.0; values above ~7.0 suggest encryption or compression.
- Use `packed_detect` early in triage to identify UPX/custom packers.
- Combine with `crypto_id` for confirmation of cryptographic regions.
