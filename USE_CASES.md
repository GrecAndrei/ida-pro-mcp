# Use Cases

`ida-pro-mcp` is designed for defensive, educational, interoperability, preservation, and maintainer-oriented reverse-engineering workflows. It exposes deterministic IDA Pro capabilities through the Model Context Protocol (MCP) so agents can assist with structured analysis instead of scraping UI output.

This project is not intended for cheating, piracy, DRM circumvention, unauthorized multiplayer tampering, or analysis of systems without permission.

Workflows below are written against the action-specific `ida_*` operation
catalog (see `host.agent_operations` and `docs/ROADMAP.md`). Every operation
named here is part of the current surface; call `ida_help(topic='...')` for
the exact schema of any of them.

## 1. Open source software (OSS) supply-chain binary auditing

Maintainers often depend on native extensions, shared libraries, release artifacts, wheels, vendor SDKs, CI outputs, or prebuilt binaries they did not fully author.

`ida-pro-mcp` can help inspect these artifacts for unexpected imports, embedded paths, debug strings, risky APIs, suspicious sections, compiler metadata, symbol drift, or mismatches between source code and shipped binaries.

Example workflows:

- `ida_open_binary(binary_path=...)` then `ida_overview()` to establish architecture and entry points
- `ida_list_imports()` and `ida_list_strings()` to surface unexpected dependencies and embedded paths
- `ida_find(query=...)` to locate risky parser, crypto, filesystem, network, or process-control APIs
- `ida_list_functions()` and `ida_function_families()` to spot symbol drift between builds
- `ida_export_findings(path=...)` to document binary behavior in structured notes before filing an advisory or patch

## 2. Vulnerability triage and patch validation

Security maintainers can use structured IDA workflows to understand crash reports, reproduce affected paths, inspect decompiled functions, trace references to vulnerable routines, and compare patched versus unpatched builds.

This is useful when source-level symptoms do not fully explain the shipped binary behavior.

Example workflows:

- `ida_find(query=...)` to map a crash address back to a function and call chain
- `ida_decompile(address=...)` / `ida_disassemble(address=...)` for the affected function body
- `ida_xrefs_to(address=...)`, `ida_callers(address=...)`, `ida_callees(address=...)` to trace calls into unsafe parsing or bounds-sensitive code
- `ida_calc_offset(address=..., target=...)` to compare patched and vulnerable binaries for expected changes
- `ida_write_finding(...)` with `ida_update_finding(...)` to build an audit trail for advisories and regression tests

## 3. Release verification

Projects that publish binaries can verify that release artifacts match expectations before distribution.

`ida-pro-mcp` can help compare imports, exports, sections, strings, compiler/linker metadata, function counts, and other binary-level signals across builds.

Example workflows:

- `ida_overview()` and `ida_list_strings()` to detect accidentally embedded local paths or debug strings
- `ida_list_imports()` to verify that unexpected dependencies were not introduced
- `ida_list_functions()` and `ida_list_segments()` to compare release candidates against previous known-good builds
- `ida_export_findings(format='markdown', path=...)` to document binary metadata for reproducible-release review

## 4. Firmware and embedded systems maintenance

Embedded and firmware projects often involve vendor blobs, board support packages, bootloaders, drivers, memory maps, and partially documented hardware interfaces.

`ida-pro-mcp` can help maintainers map memory regions, identify MMIO patterns, recover function boundaries, annotate protocols, and build repeatable knowledge bases for firmware analysis.

Example workflows:

- `ida_fw_detect_vector_table(start=..., end=...)` to identify reset handlers and interrupt tables
- `ida_fw_detect_mmio(...)` / `ida_fw_detect_load_base(...)` to locate hardware register access and infer load bases
- `ida_add_segment(start=..., end=..., name=...)` and `ida_set_segment_attrs(...)` to annotate MMIO regions and peripheral usage
- `ida_find(query=...)` and `ida_xrefs_to(address=...)` to find protocol handlers and parsing paths
- `ida_write_finding(...)` to document vendor-supplied components used by OSS firmware projects

## 5. Game modding, preservation, and compatibility research

Game modding communities often reverse engineer file formats, asset pipelines, scripting interfaces, save data, rendering behavior, engine quirks, and compatibility issues.

`ida-pro-mcp` can support structured, permission-respecting analysis for mods, preservation, accessibility improvements, bug fixes, translation patches, compatibility layers, and documentation of old engines.

Example workflows:

- `ida_search_data_value(value=...)` and `ida_create_data(address=..., type='array', ...)` to understand asset loaders, archive formats, or save-file structures
- `ida_disassemble(address=...)` / `ida_decompile(address=...)` to document scripting VM behavior or engine callbacks
- `ida_callees(address=...)` and `ida_calc_chain(address=..., offsets=[...])` to inspect crashy code paths that affect compatibility patches
- `ida_rename(address=..., name=...)`, `ida_comment(address=..., comment=...)` to recover names and notes for community documentation
- `ida_import_annotations()` and `ida_publish_findings(risk_ack=true)` to carry notes between sessions and back into the IDB
- `ida_calc_offset(address=..., target=...)` to compare different regional or patched game builds

## 6. Malware and abuse artifact triage for defenders

Defenders may need to analyze binaries that target their users, projects, or infrastructure.

`ida-pro-mcp` can assist with defensive triage by extracting imports, strings, xrefs, persistence indicators, protocol clues, crypto usage, and capability summaries into structured notes.

Example workflows:

- `ida_list_imports()` and `ida_find(query=...)` to identify suspicious imports and persistence mechanisms
- `ida_search_data_value(value=...)` to locate C2 strings, protocol handlers, or configuration parsers
- `ida_mark_dangerous(address=..., risk_ack=true)` to flag dangerous API call sites
- `ida_write_finding(...)` and `ida_export_findings(path=...)` to summarize defensive indicators for incident response
- `ida_save_idb(risk_ack=true)` so the annotated triage survives IDA restarts

## 7. Legacy binary documentation

OSS ecosystems sometimes depend on old helper binaries, native plugins, abandoned tools, or closed-source components whose behavior is poorly documented.

`ida-pro-mcp` can help maintainers document these binaries so they can be replaced, wrapped, sandboxed, or migrated away from.

Example workflows:

- `ida_rename(address=..., name=...)` and `ida_comment(address=..., comment=...)` to recover function names and high-level behavior
- `ida_create_function(address=...)` and `ida_change_function(address=..., end=...)` to fix function boundaries
- `ida_list_imports()` and `ida_xrefs_to(address=...)` to map dependencies and runtime assumptions
- `ida_til_export(path=...)` / `ida_til_import(path=...)` to carry recovered types across sessions
- `ida_export_findings(format='markdown', path=...)` to produce structured notes for replacement implementations

## 8. Agent-assisted reverse-engineering notes

The `ida_write_finding`, `ida_mark_examined`, `ida_list_findings`,
`ida_search_findings`, `ida_publish_findings`, and `ida_import_annotations`
workflows convert ad hoc reverse-engineering discoveries into structured,
repeatable analysis trails.

Example workflows:

- `ida_write_finding(...)` to save hypotheses, findings, and unresolved questions
- `ida_mark_examined(address=..., verdict=...)` to record functions read and dismissed
- `ida_next_target(strategy='coverage')` / `ida_analysis_brief()` to summarize analysis progress across long sessions
- `ida_export_findings(path=...)` to preserve context for future maintainers or contributors

## 9. Headerless raw blobs, firmware carving, and RISC-V

An opaque raw blob (a firmware dump, boot ROM, or vector-table image with no
ELF/PE header) has no symbols and no IDA-created cross-references, so the
xref- and name-based discovery flows above apply only after the blob has been
shaped. The raw path is:

- Open the blob as raw bytes: `ida_open_binary(binary_path=..., input_format='bin')`
  (or `ida_open_background(...)` for large blobs).
- `ida_r2_bininfo(binary_path=...)` / `ida_r2_load_hints(...)` to get
  architecture, bits, entry, and suggested load-base hypotheses before an IDB
  exists — the r2 sidecar engine is default-off and runs as a subprocess.
- `ida_fw_detect_vector_table(start=..., end=...)` to find a Cortex-M
  reset/ISR vector table, `ida_fw_detect_load_base(...)` to infer the load
  address, and `ida_fw_detect_mmio(...)` / `ida_fw_rtos_scan(...)` for
  peripherals and RTOS kernels.
- `ida_fw_carve(start=..., end=..., risk_ack=true)` to extract a bounded
  code/data region into an analyzable range.
- `ida_search_data_value(value=..., endian=..., size=...)` to locate raw
  pointer-word or string values across the mapped bytes when IDA xrefs do not
  exist yet; `ida_r2_vxrefs(value=...)` does the same pre-IDA.
- `ida_create_data(address=..., type='dword', count=...)` /
  `ida_create_strlit(address=..., size=...)` to lay down data items so the
  blob becomes analyzable without redeclaring types.
- `ida_sreg_set(start=..., reg='gp', value=..., risk_ack=true)` /
  `ida_sreg_get(start=..., reg='gp')` to fix the RISC-V GP register so
  GP-relative xrefs resolve (x86-16 `cs`/`ds` segmented mode works the same
  way through `ida_sreg_set` / `ida_sreg_list`).
- `ida_undo_begin(risk_ack=true)` / `ida_undo_end(risk_ack=true)` and
  `ida_idb_snapshot(risk_ack=true)` / `ida_idb_restore_snapshot(risk_ack=true)`
  to keep shaping experiments reversible.

## Guiding principle

The goal is to make binary analysis more reproducible, reviewable, and useful for maintainers. The project is strongest when used to understand, document, verify, and defend software systems with permission.
