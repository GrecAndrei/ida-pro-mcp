# Repository instructions

These instructions apply to the whole `ida-pro-mcp` repository. Keep them
short, current, and operational: if a rule is not useful while changing the
tree, remove it.

## What this project is

`ida-pro-mcp` is an MCP server for deterministic IDA Pro analysis. The public
agent interface is the exact-schema `ida_*` catalog. The older
`tool(action=...)` interface remains as a compatibility backend and is not the
source of truth for new agent features.

The host runs outside IDA and talks to an IDA-side runtime over a local bridge.
The IDA-side code calls the IDA SDK. Optional local embedding and reranking are
machine-learning helpers; there is no hidden LLM service in the analysis path.

## Repository map

```text
src/ida_pro_mcp/
  host/                 MCP server, schemas, policy, sessions, intelligence
  ida_mcp/              IDA-side tools and compatibility dispatcher
  installer/            installer, runtime discovery, client configuration
  native/               optional in-process llama.cpp C++ driver
  _version.py           single package version identifier
docs/
  guide/                maintained architecture, safety, use-case, release docs
  wiki/                 hand-authored documentation read by the wiki tool
  reference/            background reference material
  research/             dated technical notes, not current product policy
benchmarks/run.py       canonical benchmark entry point
tests/                  host, contract, IDA-side fake, and opt-in live tests
.agents/skills/         generated agent skill and operation reference
```

Important source-of-truth files:

- `src/ida_pro_mcp/host/agent_operations.py` — public operation schemas,
  examples, mappings, descriptions, and generated help content.
- `src/ida_pro_mcp/host/schemas_data.py` and
  `src/ida_pro_mcp/host/server/tool_registry.py` — legacy backend catalog.
- `src/ida_pro_mcp/host/server/server_dispatch.py` — host routing, policy,
  session checks, and response handling.
- `src/ida_pro_mcp/ida_mcp/tools/` — deterministic IDA-side implementations.
- `src/ida_pro_mcp/host/stores/blackboard_store.py` — durable investigation
  memory, migrations, embedding metadata, and retrieval.

## Working rules

- Preserve unrelated user changes. Inspect the worktree before editing.
- Prefer small, behavior-focused changes and explicit errors with actionable
  hints.
- Keep public schemas stable where possible; make additive changes before
  removing fields or aliases.
- Do not add personal paths, local model paths, checked-in machine output, or
  implicit dependencies on a particular IDA installation.
- Use `Path`, environment variables, CLI arguments, or temporary directories
  for machine-specific resources. External build inputs must be explicit.
- Do not hand-edit generated operation references or skill files.
- Do not claim live-IDA behavior from fake tests. Mark live tests opt-in and
  report the IDA version, runtime, backend, and model when it matters.
- IDB mutations require the existing policy and risk-acknowledgement flow.
  Never weaken a guard to make a test or example pass.

## Normal development loop

From the repository root:

```bash
python -m pip install -e .
ruff check .
python scripts/check_schema_integrity.py
python scripts/generate_tool_skills.py
pytest -q --basetemp=.pytest_tmp
```

The `pythonpath = ["src"]` pytest setting makes the checkout win over an
unrelated installed copy. Live IDA tests are excluded by their opt-in marker;
run them separately only with a licensed installation.

The canonical benchmark runner has independent scopes:

```bash
python benchmarks/run.py --scope contract host blackboard
python benchmarks/run.py --scope retrieval \
  --corpus /path/to/functions.json --queries /path/to/queries.json \
  --backend native
python benchmarks/run.py --scope ida --ida-dir /path/to/ida \
  --binary /path/to/sample
```

Results belong outside source control. The runner records version, commit,
runtime, backend, and input hashes in its JSON report.

## Changing the public agent surface

1. Add or update an `AgentOperation` in
   `src/ida_pro_mcp/host/agent_operations.py`. Use a strict object schema, a
   valid example, a concise description, and an existing backend mapping.
2. Implement or update the mapped action in `src/ida_pro_mcp/ida_mcp/tools/`.
   Keep public names (`address`, `query`, `limit`) distinct from legacy aliases
   unless compatibility requires both.
3. Add behavior tests for schema admission, routing, policy tier, and the
   meaningful result. Test outputs and boundaries, not private call counts.
4. Regenerate the references:

   ```bash
   python scripts/generate_tool_skills.py
   ```

   This updates `docs/TOOLS_REFERENCE.md`,
   `.agents/skills/ida-pro-mcp/SKILL.md`, and its operations reference.
5. Update the README operation summary only when the public count or workflow
   changes. Update the relevant hand-authored wiki page if user guidance
   changes.
6. Run schema checks, generated-doc tests, and the affected test scope.

Do not create a new broad action enum for a new agent capability. The public
catalog is exact-operation based; the legacy action catalog exists for old
clients.

## Changing the legacy backend

Only change the legacy surface when compatibility requires it. Keep the
following aligned:

- action implementation in `src/ida_pro_mcp/ida_mcp/tools/`;
- `_TOOL_ACTIONS` in `host/server/tool_registry.py`;
- `TOOLS`, descriptions, and argument schemas in `host/schemas_data.py`;
- `ida_mcp/tools/__init__.py` exports and module map;
- policy classification and host dispatch where applicable; and
- focused tests plus generated references if the public catalog is affected.

The compatibility surface is selected with `IDA_MCP_TOOL_SURFACE=legacy`.
Never remove a legacy action without checking repository references and
documenting the compatibility impact.

## Blackboard and retrieval rules

- Blackboard schema changes require an idempotent migration and a regression
  test. Never rewrite or silently discard existing claims.
- A finding is durable evidence, not a cache. Preserve conflicts, lifecycle
  status, provenance, anchors, and audit events.
- Stored vectors must retain embedding identity and dimension. Never compare
  incompatible vector spaces; use the explicit lexical fallback when semantic
  retrieval is unavailable.
- Use query-purpose embeddings for queries and document-purpose embeddings for
  findings when the backend supports them.
- Retrieval changes need deterministic fixture coverage for recall/ranking,
  lexical fallback, filters, stale/conflicting claims, and model mismatch.
- Explain ranking decisions in returned metadata where practical; do not hide
  a backend downgrade behind a semantic-looking score.

## Installer, runtime, and native changes

When adding an environment variable, model, runtime, client setting, or binary:

- update discovery and validation in `src/ida_pro_mcp/installer/`;
- expose the setting in generated client configuration or installer output;
- document defaults and explicit paths without using personal directories;
- add graceful missing-dependency behavior and tests; and
- for native changes, run the relevant fake ABI tests and a real build when
  the external llama.cpp checkout is available.

Native builds require caller-supplied `LLAMA_CPP_SRC`/
`LLAMA_CPP_BUILD` paths. Do not vendor a checkout or assume a model exists.

## Documentation and versioning

- Maintained guides live in `docs/guide/`; the documentation map is
  `docs/index.md`.
- The wiki is runtime-loaded and must remain under `docs/wiki/` unless the
  loader is changed in the same change.
- Generated operation docs come from `agent_operations.py`; run the generator
  after schema or description changes.
- The package, MCP handshake, CLI, and benchmark version come from
  `src/ida_pro_mcp/_version.py`. Follow `docs/guide/versioning.md` and update
  `CHANGELOG.md` for release-facing changes.
- Research notes are historical context. Do not use them as current behavior
  or copy their old counts, paths, benchmarks, or compatibility claims into
  active documentation.

## Test design

Test through stable interfaces. Mock at process/network boundaries such as
`subprocess.Popen` and `urllib.request.urlopen`; avoid asserting private
implementation names or incidental call order. For IDA-side logic, use the
existing fake SDK harness. For real IDA behavior, use `tests/integration/` and
the documented opt-in live runner.

Required checks depend on the change:

- schemas/operations/docs: generator, schema integrity, docs sync;
- host/runtime/stores: focused host tests plus the full non-live suite;
- IDA-side tools: focused fake-IDB tests plus the full non-live suite;
- retrieval: blackboard benchmark and, when available, corpus retrieval scope;
- native: fake ABI tests and a caller-configured native build;
- live behavior: explicit live integration scope with environment metadata.

Before handoff, report what ran, what was skipped, and any external runtime
that was unavailable. Do not include generated benchmark reports in commits.
