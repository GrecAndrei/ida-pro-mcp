## What

<!-- One or two sentences: what this changes and why. -->

## Verification

<!-- How was this tested? Paste relevant test output. -->

- [ ] `ruff check .` clean
- [ ] `python scripts/check_schema_integrity.py` passes
- [ ] `pytest -q` passes locally (live-IDA tests may skip)
- [ ] Generated docs/skills up to date (`python scripts/generate_tool_skills.py`)
- [ ] Relevant benchmark scope passes (`python benchmarks/run.py --scope ...`)

## Notes for reviewers

<!-- Migration steps, env var changes, backend selection impact, or anything
that touches the native backend (libmcp_llama.so) or the operation surface. -->
