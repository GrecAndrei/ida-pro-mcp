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

        parser.print_help()
        return 1
    except (CapsuleError, json.JSONDecodeError, OSError) as exc:
        print(f"Error: {exc}")
        return 1
