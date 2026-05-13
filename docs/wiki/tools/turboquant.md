# turboquant

4-bit PolarQuant quantization for fast embedding comparisons and similarity search.

## Actions
- `ingest` — quantize and store an embedding; params: `key`, `embedding`
- `query` — find nearest neighbors; params: `embedding`, `limit`
- `stats` — show quantization index statistics
- `delete` — remove an entry; params: `key`

## Examples
```json
{"name": "turboquant", "arguments": {"action": "query", "embedding": [0.1, -0.3, 0.5], "limit": 5}}
```
```json
{"name": "turboquant", "arguments": {"action": "stats"}}
```

## Notes
- 4-bit quantization trades precision for speed; suitable for approximate similarity.
- Used internally by Cartographer-mu for fast blackboard entry comparison.
- Embeddings are stored persistently in the session cache.
