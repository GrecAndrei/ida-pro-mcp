# ENTROPY Tool Manual

## What It Does
Computes entropy metrics across regions/segments and provides heuristics for packed data and crypto-related constants.

## Actions
- `region`: Entropy + null ratio + byte histogram for one range.
- `section`: Entropy and window stats per segment.
- `packed_detect`: Sliding-window high-entropy hit scan.
- `crypto_detect`: Constant pattern lookup (AES S-box, SHA-256 constants).
- `compare`: Entropy delta between two same-sized regions.
- `window`: Sliding-window entropy over explicit range.
- `summary`: Average entropy and per-segment entropy list.

## Key Parameters
- `action`: One of `section|region|packed_detect|crypto_detect|compare|window|summary`.
- `addr`: Start address for `region`, `compare`, `window`.
- `end_addr`: Required for `compare` and `window`.
- `size`: Region size for `region` and `compare` (default `4096`).
- `threshold`: High-entropy threshold (default `7.0`).
- `window`, `step`: Sliding scan settings.
- `limit`: Caps findings/windows returned.

## Examples
```python
entropy(action="region", addr="0x401000", size=8192)
entropy(action="section", threshold=7.2)
entropy(action="packed_detect", threshold=7.3, window=4096, step=512, limit=100)
entropy(action="crypto_detect")
entropy(action="compare", addr="0x401000", end_addr="0x501000", size=4096)
entropy(action="window", addr="0x401000", end_addr="0x404000", window=1024, step=256)
```

## Failure Modes
- Missing or invalid range arguments (`addr`, `end_addr`).
- Invalid address/range validation failures.
- Empty/unreadable data yields low-value outputs or IDA errors.
- Unknown `action` returns invalid-args error.
