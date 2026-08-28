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

Benchmark output records the package version, commit, runtime, and inputs at
run time; benchmark results do not carry hand-maintained version numbers.
