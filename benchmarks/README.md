# Benchmarks

Benchmarks are run-time pipelines, not checked-in claims about one machine.
The canonical entry point is `python benchmarks/run.py`; it writes a JSON
report and a matching Markdown summary under `benchmark-results/` by default.

## Scopes

| Scope | Measures | Requirements |
| --- | --- | --- |
| `contract` | schema integrity, lint, generated-doc synchronization | Python + dev tools |
| `host` | host and IDA-side fake-test throughput | Python + pytest |
| `blackboard` | deterministic recall@1, recall@5, MRR, and query latency | Python only |
| `retrieval` | indexing time and gold-query recall for a supplied corpus/model | corpus, queries, configured backend |
| `ida` | the opt-in live operation surface | licensed IDA and target binary or fixture |

Examples:

```bash
python benchmarks/run.py --scope contract host blackboard
python benchmarks/run.py --scope retrieval \
  --corpus /path/to/functions.json --queries /path/to/queries.json \
  --backend native --out results/retrieval-native
python benchmarks/run.py --scope ida --ida-dir /path/to/ida --binary /path/to/sample
```

Retrieval corpus JSON must contain `functions`; each row needs `ea`, `name`,
and `pseudocode`. Query JSON is either an array or `{ "queries": [...] }`; each
row needs `query` and one of `target`, `targets`, `gold`, or `name`.

Every report records package version, commit, Python/platform metadata, input
hashes, command output, and skipped-scope reasons. Results are deliberately
ignored by Git. Do not add hardware-specific numbers to documentation; attach
the generated JSON report when comparing environments.
