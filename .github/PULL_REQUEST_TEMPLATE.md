## What

<!-- One or two sentences: what this changes and why. -->

## Change class

<!-- Every commit subject must use exactly one matching prefix. See AGENTS.md. -->

- [ ] `[minor]`
- [ ] `[relevant]`
- [ ] `[major]`
- [ ] `[PR-work]`
- [ ] Every commit in this PR has a meaningful `CHANGELOG.md` entry

## Verification

<!-- How was this tested? Paste relevant test output. -->

- [ ] `ruff check .` clean
- [ ] `python scripts/check_schema_integrity.py` passes
- [ ] `pytest -q` passes locally (live-IDA tests may skip)
- [ ] Generated docs/skills up to date (`python scripts/generate_tool_skills.py`)
- [ ] Relevant benchmark scope passes (`python benchmarks/run.py --scope ...`)

## Safeguards

- [ ] Changelog entry is present for every commit class, including `[minor]` and `[PR-work]`
- [ ] Linked issue, or explanation why no issue is needed
- [ ] User, compatibility, and migration/rollback impact reviewed
- [ ] Relevant wiki and maintained documentation updated
- [ ] CodeQL, dependency review, vulnerability scan, and workflow-pin checks reviewed
- [ ] For `[major]`: release artifact dry run, checksums/provenance, changelog/version, and protected-publishing readiness reviewed

## Notes for reviewers

<!-- Migration steps, env var changes, backend selection impact, or anything
that touches the native backend (libmcp_llama.so) or the operation surface. -->
