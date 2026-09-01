# AGENTS.md

These instructions apply to the `ida-pro-mcp` repository. Keep changes
focused, preserve unrelated work, and report checks run, skipped scopes, and
unavailable external runtimes.

## Boundary and architecture

This is an MCP server for deterministic IDA Pro analysis. The host runs
outside IDA, validates and routes MCP calls, and communicates over a local
bridge with an IDA-side runtime that calls the IDA SDK. Embedding, reranking,
and Rizin are optional helpers; embedding/reranking are local unless the
explicit cloud backend is selected. There is no hidden LLM service in the
analysis path.

- `src/ida_pro_mcp/host/`: MCP server, schemas, policy, sessions, response
  handling, intelligence, and durable stores.
- `src/ida_pro_mcp/ida_mcp/`: bridge-side tools and compatibility dispatcher.
- `src/ida_pro_mcp/server_script.py`: IDA plugin/runtime loader.
- `src/ida_pro_mcp/installer/`: IDA discovery, runtime/client configuration,
  and skill installation.
- `src/ida_pro_mcp/native/`: optional in-process llama.cpp driver.
- `tests/`: host/contract tests, fake-IDA tests, and opt-in live tests.
- `docs/guide/`: maintained guidance; `docs/wiki/`: hand-authored pages
  loaded by the wiki tool; `docs/research/`: historical context.
- `benchmarks/run.py`: canonical benchmark entry point.

## Source of truth and safe edits

- `src/ida_pro_mcp/host/agent_operations.py` owns the exact public `ida_*`
  catalog: schemas, examples, descriptions, mappings, and generated help.
- `src/ida_pro_mcp/host/server/server_dispatch.py` owns host routing, policy,
  session checks, RPC handling, and response processing.
- `src/ida_pro_mcp/host/schemas_data.py` and
  `src/ida_pro_mcp/host/server/tool_registry.py` define the legacy catalog;
  `src/ida_pro_mcp/ida_mcp/tools/` contains its IDA-side implementations.
- `src/ida_pro_mcp/host/stores/blackboard_store.py` owns durable findings,
  migrations, anchors, conflicts, audit events, and embedding metadata.
- `src/ida_pro_mcp/_version.py` is the single package/MCP/CLI/benchmark version.

Prefer small behavior-focused changes, stable structured results, and
actionable errors. Use `Path`, environment variables, CLI arguments, or
temporary directories; never add personal paths, local models, IDBs, checked-in
machine output, or an implicit IDA installation. Test stable interfaces and
mock process/network boundaries, not private call counts or incidental order.

IDB mutations must retain the existing policy and explicit `risk_ack` flow.
Never weaken a guard or bypass the IDA read/write wrappers to make a test pass.
Blackboard schema changes require an idempotent migration and regression test;
preserve evidence, provenance, lifecycle state, conflicts, stale markers, and
audit events. Stored vectors must retain compatible model identity and
dimension; use the explicit lexical fallback when semantic retrieval is
unavailable.

## Public `ida_*` versus legacy

The default `IDA_MCP_TOOL_SURFACE=agent` exposes one strict-schema `ida_*`
operation per public capability. For a new operation:

1. Add an `AgentOperation` in `host/agent_operations.py` with a strict object
   schema, useful example, concise description, and existing backend mapping.
2. Implement/update the mapped IDA-side action.
3. Keep public names such as `address`, `query`, and `limit` distinct from
   legacy aliases unless compatibility requires both.
4. Add tests for schema admission, routing, policy tier/risk acknowledgement,
   meaningful output, and structured failure output.

Do not add a new broad `tool(action=...)` enum for an agent capability. The
legacy `tool(action=...)` backend is selected with
`IDA_MCP_TOOL_SURFACE=legacy` and exists for old clients. If it changes, keep
the action implementation, `_TOOL_ACTIONS`, descriptions/schemas, aliases,
exports/module maps, policy classification, dispatch, and compatibility tests
aligned. Do not remove a legacy action without checking callers and documenting
the impact. Prefer additive schema changes.

### Adding an operation

For a new public operation, update these surfaces together:

1. Add an `AgentOperation` in `host/agent_operations.py` with a strict schema,
   a valid example, one-sentence description, backend tool/action mapping, and
   any host-only `argument_map` entries. Public wire names such as `address`,
   `query`, and `limit` stay on the IDA wire. Risk is stamped from policy at
   import; do not hand-set a public risk tier in a test.
2. Add the IDA-side action to the tool's `Literal[...]` annotation and its
   dispatch table, accepting the public argument names beside legacy aliases
   where compatibility requires them.
3. Add schema, routing, acknowledgement, and policy-pair tests. Assert the
   result and error envelope rather than private handler calls.
4. Regenerate the tool reference and skill, update the README's operation
   count/summary, and update the relevant hand-authored wiki page.

The legacy catalog still needs matching entries in `_TOOL_ACTIONS`, `TOOLS`,
`TOOL_DESCRIPTIONS`, exports/module maps, and host-only dispatch branches where
applicable. Dynamic wrapper actions are not added to `_TOOL_ACTIONS`.

Keep these invariants true:

- every `TOOLS` entry has an `_TOOL_ACTIONS` entry and a description;
- every public operation has a strict schema and a validating example;
- generated references match `agent_operations.py`;
- no public operation is silently exposed through a different argument name.

## Generated docs and hand-authored docs

Never hand-edit generated operation references. After changing a public schema,
description, example, or operation list, run:

```bash
python scripts/check_schema_integrity.py
python scripts/generate_tool_skills.py
```

This regenerates `docs/TOOLS_REFERENCE.md` and
`.agents/skills/ida-pro-mcp/` from `agent_operations.py`; verify the generated
diff is clean and include it with the source change. Update the relevant
`docs/guide/` page and `docs/wiki/` page when user guidance or behavior
changes. Update `docs/index.md` when the documentation map changes. Change the
README operation summary only when the public summary/workflow changes. Do not
copy research-note claims, stale counts, paths, or benchmarks into maintained
docs without rechecking them.

## Installer and native constraints

When adding an environment variable, model, runtime, client setting, or binary,
update installer discovery/validation and generated client configuration,
document defaults and explicit paths, add missing-dependency behavior and
tests, and preserve atomic writes, backups, symlink/path checks, and rollback.

Native builds require a caller-supplied `LLAMA_CPP_SRC` for
`scripts/build_native_llama.sh` or `LLAMA_CPP_BUILD` for the CMake project.
The llama.cpp revision is pinned in the build script/workflow. Do not vendor a
checkout or assume a model/library exists. Run fake ABI tests and a real build
when the external checkout is available; otherwise report the skip.

## Tests, coverage, and live IDA

From the repository root, the normal development checks are:

```bash
python -m pip install --upgrade pip
python -m pip install -e . --group dev
ruff check .
python scripts/check_schema_integrity.py
python scripts/generate_tool_skills.py
python -m pytest -q --ignore=tests/integration --basetemp=.pytest_tmp
```

Run focused tests first, then the full non-live suite for host/runtime,
stores, bridge, installer, or contract changes. Cover valid and malformed
inputs, policy boundaries, compatibility behavior, and the meaningful result.
Retrieval changes need deterministic ranking/recall, lexical fallback, filters,
stale/conflict, and model-mismatch coverage. Native changes need fake ABI
coverage and, when possible, a configured build. Use the relevant
`benchmarks/run.py --scope ...`; keep reports outside source control.

The coverage hardening target is at least 90% of the measured project surface,
with offline and real-IDA live reports kept separate until merged. Do not
claim that target from catalog tests or fake IDA. Coverage is not yet a
repository-wide blocking threshold; until the gate is installed, every change
must report its measured result and uncovered external paths. Fake-IDA tests do
not prove live behavior. `tests/integration/` is opt-in and requires licensed IDA:

```bash
IDA_MCP_LIVE_TEST=1 IDA_MCP_LIVE_IDADIR=/path/to/ida \
  python -m pytest -q tests/integration -m live_ida
```

Use the documented idat/idalib runner or matrix, and record IDA version,
runtime, backend/model, and skipped suites. Do not make ordinary CI start IDA.
Use the documented optional tracer/`coverage.py` workflow for combined live
measurements.

## Investigating failures

Reproduce the smallest focused test and record `IDA_MCP_TOOL_SURFACE` plus
relevant `IDA_MCP_*` settings. Classify the failure as schema/dispatch,
host policy/session, bridge/IDA SDK, installer, optional backend, generated
drift, or environment. Inspect structured error codes and runtime logs;
distinguish an explicit unavailable backend from an incorrect success. For API
drift, check the compatibility layer and fake-IDB tests before claiming live
support. For hangs, use bounded RPC/test timeouts and isolate the IDA runtime
instead of increasing timeouts indefinitely.

## Commit subjects

Every authored commit subject must start with exactly one of these prefixes,
followed by a space, with exactly one class prefix:
`[minor]`, `[relevant]`, `[major]`, or `[PR-work]`.

- `[minor]`: docs, tests, behavior-preserving refactors, or small maintenance
  with no product-visible behavior or release/security impact.
- `[relevant]`: user-visible but backward-compatible fixes, additive features
  or fields, contract changes, retrieval changes, or operational changes that
  need focused tests/docs.
- `[major]`: breaking public/persistence changes, broad behavior changes,
  release/packaging changes, security-boundary changes, or work requiring
  migration, rollback, or substantial operational risk.
- `[PR-work]`: PR/branch mechanics only—review metadata, conflict resolution,
  or procedural CI/PR administration with no runtime, public-contract,
  persistence, release, user-guidance, or security-posture change.

Never use `[PR-work]` to hide product behavior changes. If a procedural change
also changes behavior or security posture, use `[relevant]` or `[major]`.
`python scripts/check_commit_policy.py --range <base>..<head>` checks prefix
syntax and requires every authored commit in the range to update
`CHANGELOG.md` when Git history is available. This changelog requirement
applies equally to `[minor]`, `[relevant]`, `[major]`, and `[PR-work]`; make the
entry meaningful and scoped to the commit.

Keep commits sparse and coherent: batch a behavior change with its focused
tests and generated documentation, keep migrations with their regression
tests, and separate unrelated work. Do not make one commit per file or test,
and do not split a single logical fix merely to create more commit subjects.
Every commit still needs its corresponding `CHANGELOG.md` entry, even when
the change is documentation-only, test-only, or PR administration.

## Safeguards by change class

`[relevant]` and `[major]` changes need the same engineering and review
safeguards. The PR must name a linked issue, or explain why no issue is needed;
identify the user and compatibility impact; update the relevant maintained
guide and `docs/wiki/` page, or state why documentation is not applicable; and
show the applicable test, schema, generated-doc, CodeQL, workflow-pin,
dependency-review, and vulnerability-scan results. Do not leave an existing
security or blocking issue unowned: link it, fix it, or record an approved
disposition and owner.

`[major]` adds release safeguards. Before merge or publication, also require
the version/changelog and migration or rollback notes, a clean release-artifact
dry run, artifact inspection and checksums, provenance, a review of the CodeQL
configuration and results, a review of GitHub Actions permissions and pins, and
an explicit check that no unresolved high-severity security or blocking issue is
being shipped. Publishing must use the protected release environment; a coding
agent must not publish or retag a release as part of an ordinary change.

### Extra safeguards for `[major]`

Before merge or release, `[major]` work must have:

- a linked issue and a PR description naming impact, owners, and acceptance;
- version/changelog/release notes updated as applicable; release artifacts
  (wheel/sdist/native or other published outputs) built, inspected, and
  traceable to the reviewed commit before publishing;
- maintained guides and relevant hand-authored wiki pages updated, plus
  generated docs/skills regenerated when the public surface changes;
- CodeQL results reviewed for Python and GitHub Actions; workflow permissions,
  action pin integrity, and untrusted-input handling explicitly checked;
- dependency and vulnerability scans reviewed, including Dependabot's pip and
  GitHub Actions updates, with tool/date/findings/disposition recorded;
- migration and rollback notes, compatibility tests, and backup/restore or
  downgrade steps for schema, persistence, runtime, or installer changes;
- an explicit review of every unresolved security alert or blocking issue,
  with owner and approved disposition. Do not silently merge or publish an
  unresolved blocker.

## Start-to-finish checklist

1. Read `README.md`, `CONTRIBUTING.md`, this file, and the relevant architecture,
   safety, versioning, or retrieval guide.
2. Run `git status --short` and inspect the existing diff. Preserve unrelated
   user work and do not stage `.pi/`, IDBs, local models, logs, or benchmark
   output.
3. Classify the change before editing: public operation, legacy compatibility,
   host/runtime, IDA-side, store/retrieval, installer, native, documentation,
   workflow, or release.
4. Make the smallest coherent change in the correct layer. Keep migration code
   with its regression test and generated docs with the source change.
5. Add stable-interface tests for valid behavior, failure behavior, policy
   boundaries, and compatibility effects. Use fake IDA offline and reserve
   real-IDA claims for `tests/integration/`.
6. If the public schema or description changed, run the schema check and
   generator and include the resulting generated files.
7. If installer, native, retrieval, or workflow behavior changed, run the
   corresponding focused checks and document unavailable external inputs.
8. Run the applicable routine checks:

   ```bash
   python -m pip install --upgrade pip
   ruff check .
   python scripts/check_schema_integrity.py
   python scripts/generate_tool_skills.py
   python -m pytest -q --ignore=tests/integration --basetemp=.pytest_tmp
   git diff --check
   ```

9. For `[relevant]` and `[major]`, review docs/wiki impact, CodeQL, immutable
   action pins, dependency/vulnerability results, and issue disposition. For
   `[major]`, run the release dry run and complete the extra safeguards above.
10. Review the final diff for secrets, personal paths, unsafe fallbacks,
    generated drift, machine output, and unrelated changes.
11. Commit a sparse, coherent unit with exactly one required prefix. Report
    checks run, checks skipped, external runtimes unavailable, docs/generated
    files changed, and compatibility/release implications.
