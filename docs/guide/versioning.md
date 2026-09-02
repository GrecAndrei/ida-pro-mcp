# Versioning and releases

`ida-pro-mcp` uses one PEP 440 version identifier from
`src/ida_pro_mcp/_version.py`.

## Scheme

- `MAJOR.MINOR.PATCH` is a stable release.
- `MAJOR.MINOR.PATCHaN` is an alpha release for active development.
- `MAJOR.MINOR.PATCHbN` is a beta release for feature-complete testing.
- `MAJOR.MINOR.PATCHrcN` is a release candidate.

Major releases may change the public MCP contract or persistence format. Minor
releases add backwards-compatible operations or supported runtimes. Patch
releases contain compatible fixes, documentation, and maintenance.

The current checkout is `1.0.0a1`. It is an alpha: the exact-schema `ida_*`
surface and workspace format may still change before `1.0.0`.

## Release checklist

1. Update `__version__` in `_version.py`.
2. Add a dated entry to `CHANGELOG.md`.
3. Run Ruff, schema validation, and the full non-live test suite.
4. Regenerate `docs/TOOLS_REFERENCE.md` and the portable agent skill.
5. Build and inspect the wheel/sdist, then tag the exact commit with the same
   version, such as `v1.0.0a1`.
6. Author the release artifact description under `docs/releases/<tag>.md` adhering
   strictly to the mandatory release template (`docs/releases/TEMPLATE.md`).

## Mandatory release description template

Every GitHub release must use the standardized format defined in
[`docs/releases/TEMPLATE.md`](../releases/TEMPLATE.md). Loose or unformatted
release descriptions are prohibited. The template requires:
- **Title & Overview**: Version header and one-sentence core value proposition.
- **Highlights**: 3 to 6 high-impact capability summaries with bold headings.
- **🚀 Instant Auto-Installation**: Direct, copy-pasteable platform instructions
  (`curl ... | bash` for Linux/macOS, double-clickable `install.bat` for Windows,
  and native standalone binaries).
- **Manual / Offline Setup**: Extraction instructions for air-gapped environments.
- **Integrity & Provenance**: `sha256sum` and `gh attestation verify` commands.
- **Canonical Links**: Direct references to the Wiki, Tools Reference, and Safety model.

## GitHub alpha artifacts

The `Alpha Release Artifacts` workflow is manual and accepts only an existing
alpha tag whose name matches `_version.py`. Run it once with `publish=false`
to build the wheel, source distribution, source bundle, manifest, and
checksums. Inspect the uploaded artifact, then rerun the workflow with
`publish=true`; the protected `release` environment is the approval boundary.
The workflow automatically reads `docs/releases/${RELEASE_TAG}.md` to populate
the release notes.

The published auto-installers (`install.sh`, `install.bat`, and standalone binary)
provide zero-friction automated installation across all supported AI coding agents.
The workflow never creates a tag from the default branch and does not include IDA,
proprietary files, native model weights, or credentials.

Benchmark output records the package version, commit, runtime, and inputs at
run time; benchmark results do not carry hand-maintained version numbers.

## Commit changelog rule

Every authored commit must use exactly one approved subject prefix—`[minor]`,
`[relevant]`, `[major]`, or `[PR-work]`—and must update `CHANGELOG.md`. This
also applies to documentation, tests, and PR-maintenance commits. The project
guardrail checks both requirements for every authored commit after the policy
baseline.
