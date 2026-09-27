# Contributing

Thanks for contributing to `ida-pro-mcp`.

## Before You Start

- Read `AGENTS.md` for repository-wide conventions and required checks.
- Read `README.md` for setup and runtime model.
- Read `docs/guide/architecture.md` for module boundaries and risky areas.
- Keep changes focused; avoid mixing refactors and behavior changes in one PR.

## Development Setup

```bash
python install.py
```

or for editable mode:

```bash
pip install -e .
```

## Running Tests

The suite is pytest-based. Most tests run without live IDA (host fakes,
`FakeIDB`-style stubs); only `tests/integration/` requires a real IDA
installation. Prefer `pytest --ignore=tests/integration` for the offline gate.
As of the 2026-09-27 EEST suite, offline `src/` coverage is **95.88%** (target
>=90% met); the Phase 0 64.27% baseline is historical — see `PROJECT.md` /
`AGENTS.md`. CI additionally gates *changed-line* coverage at 95% against the
merge base, so new and modified lines must be covered even when the repository
total moves little.
The runner writes scratch files under the pytest basetemp, and
the repo's temporary directory can fill — use a project-local scratch path
with `--basetemp=.pytest_tmp` when running large suites, and remove the
(gitignored) `.pytest_tmp` directory before re-running them: numbered
per-test directories accumulate across runs and slow down `tmp_path`
fixture setup until tests start timing out.

Targeted tests:

```bash
python -m pytest tests/test_docs_sync.py --basetemp=.pytest_tmp
python -m pytest tests/host/test_stale_docs.py --basetemp=.pytest_tmp
```

Per-directory layouts:

```bash
python -m pytest tests/ --basetemp=.pytest_tmp       # host + docs + contract tests
python -m pytest tests/host --basetemp=.pytest_tmp    # host-server fakes (no live IDA)
python -m pytest tests/ida_mcp --basetemp=.pytest_tmp # IDA-side tool logic (fakes)
```

Full suite:

```bash
python -m pytest --basetemp=.pytest_tmp
```

Surfaces hidden deprecation and future-removal debt. Run it before pushing
whenever you touch the test harness or any import path; a clean run emits no
warnings:

```bash
python -m pytest -q --ignore=tests/integration --basetemp=.pytest_tmp \
  -W error::DeprecationWarning
```

The standalone IDA-side modules are loaded by
`tests/_isolated_repo_loader.py` rather than imported normally, because they need
the IDA SDK. Use `load_standalone_package_module`, `load_tool_module`, or
`load_tool_submodule` from that module in new tests. Do not register a module
under a flat top-level `sys.modules` key and hand-pin `__package__`; that leaves
`__package__ != __spec__.parent`, which the import system reports as deprecated
and whose fallback is slated for removal.

Live-IDA integration lives in `tests/integration/`; run it explicitly and do
not count it as part of the fast suite.

## Benchmarks

Use the scope-based runner instead of creating one-off benchmark scripts or
checking in local measurements:

```bash
python benchmarks/run.py --scope contract host blackboard
python benchmarks/run.py --scope retrieval \
  --corpus /path/to/functions.json --queries /path/to/queries.json \
  --backend native
```

See `benchmarks/README.md` for corpus format, live-IDA scope requirements, and
report fields. Store generated reports outside the repository or under the
ignored `benchmark-results/` directory.

## Commit, pull request, and merge rules

This section is the authoritative, human-facing statement of the repository's
commit, pull request, and merge policy. `AGENTS.md` restates the same policy for
coding agents; if the two ever disagree, this file and `AGENTS.md` must be fixed
together in the same commit, and `tests/test_contributing_rules.py` fails when
they drift.

Everything below is enforced, not advisory. The enforcers are
`scripts/check_commit_policy.py` (commit classes and the changelog rule) and the
`policy` and `review` CI checks.

### The four commit classes

Every authored commit subject starts with **exactly one** of these prefixes,
followed by a space, followed by a summary. There are no other approved forms.

| Prefix | Use it for | Not for |
| --- | --- | --- |
| `[minor]` | Docs, tests, behavior-preserving refactors, and small maintenance with no product-visible behavior and no release or security impact. | Anything a user would notice. |
| `[relevant]` | User-visible but backward-compatible work: fixes, additive features or fields, contract changes, retrieval changes, and operational changes needing focused tests and docs. | Breaking changes, or work that needs a migration. |
| `[major]` | Breaking public or persistence changes, broad behavior changes, release/packaging changes, security-boundary changes, and anything needing migration, rollback, or substantial operational risk. | Routine work that merely touches many files. |
| `[PR-work]` | PR and branch mechanics only: review metadata, conflict resolution, and procedural CI/PR administration. | Any change to runtime, public contract, persistence, release, user guidance, or security posture. |

### Choosing a class

Work through these in order and stop at the first match:

1. Does this change runtime behavior, the public MCP contract, the persistence
   format, user-visible guidance, or the security posture? If no, it is
   `[minor]`, unless it touches release or packaging, which forces `[major]`.
2. Does it change behavior or security posture in any way, even if the change is
   framed as procedural? Then it is `[relevant]` or `[major]`.
3. Is it additive or backward compatible? Then `[relevant]`.
4. Does it break a public contract, change persistence, require a migration or
   rollback, or carry substantial operational risk? Then `[major]`.
5. Is it purely PR administration with no behavior change? Then `[PR-work]`.

**`[PR-work]` is not a safe default.** If a commit that was filed as `[PR-work]`
also changes behavior, it is misfiled. Never use `[PR-work]` to hide a product
change. When a procedural change turns out to also change behavior or security
posture, reclassify it to `[relevant]` or `[major]`.

When genuinely torn between `[relevant]` and `[major]`, choose `[major]`. The
asymmetry is deliberate: over-classifying costs extra review steps, while
under-classifying ships something risky without them.

### Commit subject format

```
[<class>] <imperative summary of what changed and why>
```

Good subjects name the effect, not the activity:

- `[relevant] Make Jev spend and budget headroom opt-in`
- `[relevant] Guard the symlink traversal check with one shared implementation`
- `[minor] Cover the layer switch and advisory fail-closed paths`

Subjects to avoid:

- `update stuff` — no class, no effect.
- `fix bug` — no class, and it does not say which bug.
- `[minor] Add feature X` when X is user-visible — misfiled; use `[relevant]`.
- `[PR-work] Bump config and change default timeouts` — hides a behavior change.

### Commit granularity

Keep commits sparse and coherent. Batch a behavior change together with its
focused tests and its generated documentation. Keep a schema migration together
with its regression test. Separate unrelated work.

Do not make one commit per file or per test, and do not split a single logical
fix just to create more commit subjects. Every commit still needs its own
`CHANGELOG.md` entry even when the change is documentation-only, test-only, or PR
administration.

Merge commits are ignored by the policy checker because the hosting service
owns their messages, but **every non-merge commit you author is checked**.

### The changelog rule

**Every** authored commit must update `CHANGELOG.md`, regardless of class. This
applies equally to `[minor]`, `[relevant]`, `[major]`, and `[PR-work]`. A
documentation-only change still gets an entry. A test-only change still gets an
entry. A PR-maintenance commit still gets an entry.

The entry must be meaningful and scoped to the commit, not a placeholder. A new
entry is added at the top of `CHANGELOG.md` under a dated heading. Entries for
multiple commits in one PR are cumulative and may be combined into one dated
section when they describe the same unit of work.

Verify locally before pushing:

```bash
python scripts/check_commit_policy.py --range origin/master..HEAD
```

This prints each commit's class, requires a `CHANGELOG.md` change in every one,
and reports the `highest_class` for the range. A range whose highest class is
`major` carries `[major]` safeguards (see below).

### Safeguards required before merge

`[relevant]` and `[major]` changes carry the same engineering and review
safeguards. The pull request must:

- name a linked issue, or explain why no issue is needed;
- identify the user impact and the compatibility impact;
- update the relevant maintained guide in `docs/guide/` **and** the matching
  hand-authored `docs/wiki/` page, or state why documentation does not apply;
- show the applicable results for the test suite, schema integrity, generated-doc
  checks, CodeQL, workflow-pin checks, dependency review, and vulnerability scan;
- not leave an existing security or blocking issue unowned: link it, fix it, or
  record an approved disposition and an owner.

`[major]` adds the release safeguards. Before merge or publication it also
requires:

- a linked issue and a PR description naming impact, owners, and acceptance;
- version, changelog, and release notes updated as applicable, with release notes
  authored under `docs/releases/<tag>.md` strictly following
  `docs/releases/TEMPLATE.md`;
- release artifacts (wheel, sdist, installers) built, inspected, and traceable to
  the reviewed commit before publishing;
- maintained guides, the release template, and relevant hand-authored wiki pages
  updated when the public surface changes;
- CodeQL results reviewed for Python and GitHub Actions, workflow permissions
  (including `attestations: write`) and action pin integrity checked explicitly;
- dependency and vulnerability scan results reviewed, including Dependabot's pip
  and GitHub Actions updates, with tool, date, findings, and disposition recorded;
- migration and rollback notes, compatibility tests, and backup/restore or
  downgrade steps for any schema, persistence, runtime, or installer change;
- an explicit review of every unresolved security alert or blocking issue with an
  owner and an approved disposition. Never silently merge or publish an
  unresolved blocker.

Publishing must go through the protected release environment. A coding agent must
not publish or retag a release as part of an ordinary change.

### Pull request mechanics

- Keep public tool contracts backward compatible where possible. Prefer additive
  fields over removing or renaming existing fields.
- Include tests for behavior changes.
- For schema changes, update docs and compatibility aliases as needed.
- Open a pull request as a **draft** while the work is in progress. Mark it
  **ready for review** only when the branch is genuinely mergeable: all routine
  checks pass locally and the commit history is coherent.
- Keep the PR description current. It should state the problem, the approach, the
  user and compatibility impact, the checks that were run, and anything a
  reviewer must decide. A PR body that describes an earlier state of the branch
  is worse than no body.
- Do not stack unrelated changes in one PR. If a reviewer asks for a split, use
  the split-to-PRs workflow.

### Merge mechanics

- **Merge with a merge commit.** Squash and rebase merges are not used for
  feature branches. The individual commits carry the class prefixes and the
  per-commit changelog entries that the policy checker validates, and squashing
  would destroy that reviewable history.
- Do not delete the feature branch as part of the merge unless asked; keeping it
  costs nothing and preserves the reference.
- Before merging, confirm the branch head equals what you tested: fetch, verify
  the working tree is clean, and confirm the last local commit is the head of the
  remote branch.
- Let CI settle on the head commit. A green run on the branch head is the
  evidence; a green run on an earlier commit is not.
- After merging, verify the merge commit itself is green, then fast-forward your
  local `master` and confirm the feature branch's commits are ancestors of
  `origin/master`.

## Code Style and Structure

- Keep host orchestration in `src/ida_pro_mcp/host/server/server_*.py` mixins.
- Keep IDA runtime tool logic in `src/ida_pro_mcp/ida_mcp/tools/*.py`.
- Keep durable investigation-memory changes in
  `src/ida_pro_mcp/host/stores/blackboard_store.py` with an idempotent schema
  migration and retrieval regression tests.
- Avoid introducing new giant handlers; extract helper functions early.
- Return structured errors with hints instead of raising opaque exceptions.

## Reporting Issues

When opening an issue, include:

- tool name and action,
- minimal reproducible call,
- expected vs actual result,
- environment notes (OS, IDA version, Python version),
- relevant logs/error payloads.
