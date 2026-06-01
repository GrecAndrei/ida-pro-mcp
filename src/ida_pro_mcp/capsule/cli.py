from __future__ import annotations

import argparse
import json
from pathlib import Path

from .errors import CapsuleError
from .store import CapsuleStore


def _print_human_inspect(summary: dict) -> None:
    print(f"Capsule: {summary['path']}")
    print(f"Format: {summary['format']}")
    print(f"Schema: {summary['schema_version']}")
    print(f"Project: {summary['project_name']}")
    print(f"Backends: {', '.join(summary['backends']) if summary['backends'] else '(none)'}")
    print(f"Trust: {summary['trust_state']}")
    print(f"Executable payloads: {str(summary['contains_executable_payloads']).lower()}")
    print(f"Sessions: {summary['sessions']}")
    print(f"Audit events: {summary['audit_events']}")
    print(f"Objects: {summary['objects']}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Sideband capsule utility")
    sub = p.add_subparsers(dest="command", required=True)

    init_p = sub.add_parser("init", help="initialize a capsule file")
    init_p.add_argument("capsule")
    init_p.add_argument("--project-name", required=True)
    init_p.add_argument("--created-by", default="ida-pro-mcp")
    init_p.add_argument("--force", action="store_true")

    inspect_p = sub.add_parser("inspect", help="inspect capsule summary")
    inspect_p.add_argument("capsule")
    inspect_p.add_argument("--json", action="store_true", dest="as_json")

    verify_p = sub.add_parser("verify", help="verify capsule integrity")
    verify_p.add_argument("capsule")
    verify_p.add_argument("--json", action="store_true", dest="as_json")

    report_p = sub.add_parser("add-report", help="import install report json")
    report_p.add_argument("capsule")
    report_p.add_argument("report")

    note_p = sub.add_parser("add-note", help="add note entry")
    note_p.add_argument("capsule")
    note_p.add_argument("--kind", required=True)
    note_p.add_argument("--title", required=True)
    note_p.add_argument("--body", required=True)

    export_p = sub.add_parser("export-manifest", help="print manifest json")
    export_p.add_argument("capsule")

    sem_sum_p = sub.add_parser("semantic-summary", help="show semantic table counts")
    sem_sum_p.add_argument("capsule")
    sem_sum_p.add_argument("--json", action="store_true", dest="as_json")

    sem_idx_p = sub.add_parser("list-indexes", help="list semantic indexes")
    sem_idx_p.add_argument("capsule")
    sem_idx_p.add_argument("--json", action="store_true", dest="as_json")

    sem_manifest_p = sub.add_parser("export-semantic-manifest", help="export semantic summary+index manifest")
    sem_manifest_p.add_argument("capsule")

    evidence_p = sub.add_parser("list-evidence", help="list evidence cards")
    evidence_p.add_argument("capsule")
    evidence_p.add_argument("--json", action="store_true", dest="as_json")
    evidence_p.add_argument("--limit", type=int, default=100)
    evidence_p.add_argument("--claim-type", default="")

    import_idx_p = sub.add_parser("import-function-index", help="import a .embeddings.db into capsule semantic tables")
    import_idx_p.add_argument("capsule")
    import_idx_p.add_argument("index_db")
    import_idx_p.add_argument("--mode", choices=["metadata-only", "with-vectors"], default="metadata-only")
    import_idx_p.add_argument("--index-id", default="")
    import_idx_p.add_argument("--max-items", type=int, default=100000)

    export_idx_p = sub.add_parser("export-function-index", help="export function semantic index to .embeddings.db")
    export_idx_p.add_argument("capsule")
    export_idx_p.add_argument("--index-id", required=True)
    export_idx_p.add_argument("--out", required=True)
    export_idx_p.add_argument("--mode", choices=["metadata-only", "with-vectors"], default="metadata-only")

    export_analysis_p = sub.add_parser("export-analysis", help="export analysis-only capsule without raw blobs")
    export_analysis_p.add_argument("capsule")
    export_analysis_p.add_argument("--out", required=True)
    export_analysis_p.add_argument("--metadata-only", action="store_true", help="export metadata only (equivalent to no vectors)")
    export_analysis_p.add_argument("--include-vectors", action="store_true", help="include semantic vectors")
    export_analysis_p.add_argument("--include-notes", action="store_true", help="include notes in export")
    export_analysis_p.add_argument("--include-audit", action="store_true", help="include audit events in export")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            cap_path = Path(args.capsule)
            if cap_path.exists() and not args.force:
                print(f"Error: capsule already exists: {cap_path}")
                return 1
            with CapsuleStore.open(cap_path) as c:
                c.init(project_name=args.project_name, created_by=args.created_by, force=args.force)
            print(f"Initialized capsule: {cap_path}")
            return 0

        if args.command == "inspect":
            with CapsuleStore.open(Path(args.capsule)) as c:
                summary = c.inspect_summary()
            if args.as_json:
                print(json.dumps(summary, indent=2))
            else:
                _print_human_inspect(summary)
            return 0

        if args.command == "verify":
            with CapsuleStore.open(Path(args.capsule)) as c:
                result = c.verify()
            if args.as_json:
                print(json.dumps(result, indent=2))
            else:
                print("Verification: ok")
            return 0

        if args.command == "add-report":
            report_data = json.loads(Path(args.report).read_text(encoding="utf-8"))
            with CapsuleStore.open(Path(args.capsule)) as c:
                rid = c.add_install_report(report_data)
            print(rid)
            return 0

        if args.command == "add-note":
            with CapsuleStore.open(Path(args.capsule)) as c:
                nid = c.add_note(kind=args.kind, title=args.title, body=args.body)
            print(nid)
            return 0

        if args.command == "export-manifest":
            with CapsuleStore.open(Path(args.capsule)) as c:
                manifest = c.get_manifest()
            print(json.dumps(manifest, indent=2))
            return 0

        if args.command == "semantic-summary":
            with CapsuleStore.open(Path(args.capsule)) as c:
                summary = c.semantic_summary()
            if args.as_json:
                print(json.dumps(summary, indent=2))
            else:
                for key in ("semantic_indexes", "semantic_items", "semantic_vectors", "behavior_hits", "evidence_cards"):
                    print(f"{key}: {summary.get(key, 0)}")
            return 0

        if args.command == "list-indexes":
            with CapsuleStore.open(Path(args.capsule)) as c:
                rows = c.list_semantic_indexes()
            if args.as_json:
                print(json.dumps(rows, indent=2))
            else:
                if not rows:
                    print("(no semantic indexes)")
                for row in rows:
                    print(f"{row.get('id')} {row.get('kind')} {row.get('backend')} dim={row.get('dim')}")
            return 0

        if args.command == "export-semantic-manifest":
            with CapsuleStore.open(Path(args.capsule)) as c:
                payload = {
                    "semantic_summary": c.semantic_summary(),
                    "semantic_indexes": c.list_semantic_indexes(),
                }
            print(json.dumps(payload, indent=2))
            return 0

        if args.command == "list-evidence":
            with CapsuleStore.open(Path(args.capsule)) as c:
                rows = c.list_evidence_cards(limit=int(args.limit), claim_type=str(args.claim_type or ""))
            if args.as_json:
                print(json.dumps(rows, indent=2))
            else:
                if not rows:
                    print("(no evidence cards)")
                for row in rows:
                    print(f"{row.get('id')} {row.get('claim_type')} conf={row.get('confidence')} claim={row.get('claim')}")
            return 0

        if args.command == "import-function-index":
            with CapsuleStore.open(Path(args.capsule)) as c:
                payload = c.import_function_embedding_index(
                    Path(args.index_db),
                    mode=args.mode,
                    index_id=(args.index_id or None),
                    max_items=int(args.max_items),
                )
            print(json.dumps(payload, indent=2))
            return 0

        if args.command == "export-function-index":
            with CapsuleStore.open(Path(args.capsule)) as c:
                payload = c.export_function_embedding_index(
                    index_id=args.index_id,
                    out_path=Path(args.out),
                    mode=args.mode,
                )
            print(json.dumps(payload, indent=2))
            return 0

        if args.command == "export-analysis":
            include_vectors = bool(args.include_vectors)
            if args.metadata_only:
                include_vectors = False
            with CapsuleStore.open(Path(args.capsule)) as c:
                payload = c.export_analysis_capsule(
                    out_path=Path(args.out),
                    include_vectors=include_vectors,
                    include_notes=bool(args.include_notes),
                    include_audit=bool(args.include_audit),
                )
            print(json.dumps(payload, indent=2))
            return 0

        parser.print_help()
        return 1
    except (CapsuleError, json.JSONDecodeError, OSError) as exc:
        print(f"Error: {exc}")
        return 1
