# mbagcn

Mamba-based Graph Convolutional Network for CFG similarity encoding and comparison.

## Actions
- `encode` — encode a function's CFG as an embedding; params: `address`
- `similar` — find functions with similar CFG structure; params: `address`, `threshold`, `limit`
- `stats` — show index statistics

## Examples
```json
{"name": "mbagcn", "arguments": {"action": "similar", "address": "0x401000", "threshold": 0.85}}
```
```json
{"name": "mbagcn", "arguments": {"action": "encode", "address": "0x401000"}}
```

## Notes
- Uses FlowChart for correct basic block boundaries (not chunks).
- Local ML model, no external calls.
- Embeddings are cached for fast repeated queries.
