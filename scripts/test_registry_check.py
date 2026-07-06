#!/usr/bin/env python3
"""
Test Binding Registry Checker

Enforces bidirectional binding between tests and code entities.
Every test file must declare what it interacts with via @@TEST_REGISTRY@@.
When source code changes, the checker detects which tests need updating.

Usage:
    python scripts/test_registry_check.py              # Check current state
    python scripts/test_registry_check.py --discover   # Auto-detect bindings
    python scripts/test_registry_check.py --validate   # Validate registry integrity
    python scripts/test_registry_check.py --strict     # Exit non-zero on violations
    python scripts/test_registry_check.py --mark-fp TEST --entities "tool:search" --reason "..."
    python scripts/test_registry_check.py --update-hashes  # Accept current state
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_FILE = REPO_ROOT / ".test-registry.json"
SRC_DIR = REPO_ROOT / "src" / "ida_pro_mcp"
TESTS_DIR = REPO_ROOT / "tests"
TOOL_REGISTRY_FILE = REPO_ROOT / "src" / "ida_pro_mcp" / "host" / "server" / "tool_registry.py"
SCHEMAS_FILE = REPO_ROOT / "src" / "ida_pro_mcp" / "host" / "schemas_data.py"
DISPATCH_FILE = REPO_ROOT / "src" / "ida_pro_mcp" / "host" / "server" / "server_dispatch.py"

REGISTRY_HEADER_RE = re.compile(r"@@TEST_REGISTRY@@")
REGISTRY_BLOCK_RE = re.compile(
    r"@@TEST_REGISTRY@@\s*\n(.*?)(?=\n(?:@@|\"\"\"|'''|\n\n)|\Z)",
    re.DOTALL,
)


@dataclass
class RegistryEntry:
    interacts: list[str]
    format: str
    description: str
    created: str
    false_positives: list[str] = field(default_factory=list)
    fp_reason: str = ""
    fp_author: str = ""
    fp_date: str = ""
    requires_format: str = ""
    requires_format_reason: str = ""


@dataclass
class CodeEntity:
    entity_id: str
    file: str
    entity_type: str
    name: str
    hash: str = ""
    actions: list[str] = field(default_factory=list)


@dataclass
class Violation:
    test_id: str
    entity_id: str
    violation_type: str  # "stale_binding", "missing_binding", "format_mismatch"
    message: str
    fix_hint: str


def _file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    if not path.exists():
        return ""
    content = path.read_bytes()
    return hashlib.sha256(content).hexdigest()[:16]


def _func_hash(source: str, func_name: str) -> str:
    """Extract a function's source and hash it."""
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                segment = ast.get_source_segment(source, node) or ""
                return hashlib.sha256(segment.encode()).hexdigest()[:16]
    except SyntaxError:
        pass
    return ""


def discover_code_entities() -> list[CodeEntity]:
    """Scan source code to discover all trackable entities."""
    entities: list[CodeEntity] = []

    # 1. Tool modules (both .py files and packages with __init__.py)
    tools_dir = SRC_DIR / "ida_mcp" / "tools"
    if tools_dir.exists():
        for entry in sorted(tools_dir.iterdir()):
            if entry.name.startswith("_"):
                continue
            if entry.is_file() and entry.suffix == ".py":
                tool_name = entry.stem
                rel_path = str(entry.relative_to(REPO_ROOT))
                entities.append(CodeEntity(
                    entity_id=f"tool:{tool_name}",
                    file=rel_path,
                    entity_type="tool",
                    name=tool_name,
                    hash=_file_hash(entry),
                ))
            elif entry.is_dir():
                init_file = entry / "__init__.py"
                if init_file.exists():
                    tool_name = entry.name
                    rel_path = str(init_file.relative_to(REPO_ROOT))
                    entities.append(CodeEntity(
                        entity_id=f"tool:{tool_name}",
                        file=rel_path,
                        entity_type="tool",
                        name=tool_name,
                        hash=_file_hash(init_file),
                    ))

    # 2. Tool actions from registry (_TOOL_ACTIONS, one entity per tool)
    if TOOL_REGISTRY_FILE.exists():
        tr_source = TOOL_REGISTRY_FILE.read_text(encoding="utf-8")
        try:
            tree = ast.parse(tr_source)
            for node in tree.body:
                # Handle both Assign and AnnAssign
                target_name = None
                if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    target_name = node.target.id
                    value = node.value
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            target_name = target.id
                            value = node.value
                            break
                else:
                    continue

                if target_name == "_TOOL_ACTIONS" and isinstance(value, ast.Dict):
                    for key, val in zip(value.keys, value.values):
                        if isinstance(key, ast.Constant) and isinstance(val, ast.List):
                            tool_name = key.value
                            actions = [
                                elt.value for elt in val.elts
                                if isinstance(elt, ast.Constant)
                            ]
                            entities.append(CodeEntity(
                                entity_id=f"tool_actions:{tool_name}",
                                file=str(TOOL_REGISTRY_FILE.relative_to(REPO_ROOT)),
                                entity_type="tool_actions",
                                name=tool_name,
                                hash=hashlib.sha256(
                                    json.dumps(actions).encode()
                                ).hexdigest()[:16],
                                actions=actions,
                            ))
        except SyntaxError:
            pass

    # 2b. TOOL_ACTIONS from schemas_data (the flat dict)
    if SCHEMAS_FILE.exists():
        schemas_source = SCHEMAS_FILE.read_text(encoding="utf-8")
        match = re.search(r'^TOOL_ACTIONS\s*=\s*_tool_actions_from_registry\(\)', schemas_source, re.MULTILINE)
        if match:
            entities.append(CodeEntity(
                entity_id="schema:TOOL_ACTIONS",
                file=str(SCHEMAS_FILE.relative_to(REPO_ROOT)),
                entity_type="schema",
                name="TOOL_ACTIONS",
                hash=hashlib.sha256(schemas_source.encode()).hexdigest()[:16],
            ))

    # 2c. Per-tool action entities (tool_actions:X) for all tools in TOOLS
    if SCHEMAS_FILE.exists():
        schemas_source = SCHEMAS_FILE.read_text(encoding="utf-8")
        m = re.search(r'^TOOLS\s*[=:]\s*\[', schemas_source, re.MULTILINE)
        if m:
            start = m.start()
            depth = 0
            end = start
            for i, ch in enumerate(schemas_source[start:], start):
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            tools_segment = schemas_source[start:end]
            for tm in re.finditer(r'"(\w+)"', tools_segment):
                tool_name = tm.group(1)
                entity_id = f"tool_actions:{tool_name}"
                if not any(e.entity_id == entity_id for e in entities):
                    entities.append(CodeEntity(
                        entity_id=entity_id,
                        file=str(SCHEMAS_FILE.relative_to(REPO_ROOT)),
                        entity_type="tool_actions",
                        name=tool_name,
                        hash=hashlib.sha256(tool_name.encode()).hexdigest()[:16],
                    ))

    # 4b. Per-tool dispatch entities for all tools in TOOLS
    if SCHEMAS_FILE.exists() and DISPATCH_FILE.exists():
        schemas_source = SCHEMAS_FILE.read_text(encoding="utf-8")
        dispatch_source = DISPATCH_FILE.read_text(encoding="utf-8")
        m = re.search(r'^TOOLS\s*[=:]\s*\[', schemas_source, re.MULTILINE)
        if m:
            start = m.start()
            depth = 0
            end = start
            for i, ch in enumerate(schemas_source[start:], start):
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            tools_segment = schemas_source[start:end]
            for tm in re.finditer(r'"(\w+)"', tools_segment):
                tool_name = tm.group(1)
                entity_id = f"dispatch:{tool_name}"
                if not any(e.entity_id == entity_id for e in entities):
                    entities.append(CodeEntity(
                        entity_id=entity_id,
                        file=str(DISPATCH_FILE.relative_to(REPO_ROOT)),
                        entity_type="dispatch",
                        name=tool_name,
                        hash=hashlib.sha256(
                            dispatch_source[:1000].encode()
                        ).hexdigest()[:16],
                    ))

    # 3. Schema structures (TOOLS, ADVERTISED_TOOLS)
    if SCHEMAS_FILE.exists():
        schemas_source = SCHEMAS_FILE.read_text(encoding="utf-8")
        for name in ["TOOLS", "ADVERTISED_TOOLS"]:
            # Find start of the list literal
            m = re.search(rf'^{name}\s*[=:]\s*\[', schemas_source, re.MULTILINE)
            if m:
                start = m.start()
                depth = 0
                end = start
                for i, ch in enumerate(schemas_source[start:], start):
                    if ch == "[":
                        depth += 1
                    elif ch == "]":
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break
                segment = schemas_source[start:end]
                entities.append(CodeEntity(
                    entity_id=f"schema:{name}",
                    file=str(SCHEMAS_FILE.relative_to(REPO_ROOT)),
                    entity_type="schema",
                    name=name,
                    hash=hashlib.sha256(segment.encode()).hexdigest()[:16],
                ))

    # 4. Dispatch handlers and routes
    if DISPATCH_FILE.exists():
        dispatch_source = DISPATCH_FILE.read_text(encoding="utf-8")
        try:
            tree = ast.parse(dispatch_source)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name.startswith("_handle_"):
                    tool_name = node.name[len("_handle_"):]
                    segment = ast.get_source_segment(dispatch_source, node) or ""
                    entities.append(CodeEntity(
                        entity_id=f"dispatch:{tool_name}",
                        file=str(DISPATCH_FILE.relative_to(REPO_ROOT)),
                        entity_type="dispatch",
                        name=tool_name,
                        hash=hashlib.sha256(segment.encode()).hexdigest()[:16],
                    ))
            # Also add dispatch routes (tool_name == "X" patterns)
            for m in re.finditer(r'tool_name\s*==\s*"(\w+)"', dispatch_source):
                tool_name = m.group(1)
                entity_id = f"dispatch:{tool_name}"
                if not any(e.entity_id == entity_id for e in entities):
                    entities.append(CodeEntity(
                        entity_id=entity_id,
                        file=str(DISPATCH_FILE.relative_to(REPO_ROOT)),
                        entity_type="dispatch",
                        name=tool_name,
                        hash=hashlib.sha256(
                            dispatch_source[m.start():m.end()].encode()
                        ).hexdigest()[:16],
                    ))
        except SyntaxError:
            pass

    return entities


def parse_registry_header(text: str) -> dict[str, Any] | None:
    """Parse @@TEST_REGISTRY@@ header from a test file."""
    match = REGISTRY_BLOCK_RE.search(text)
    if not match:
        return None

    block = match.group(1).strip()
    result: dict[str, Any] = {
        "interacts": [],
        "format": "v1",
        "description": "",
        "created": "",
        "false_positives": [],
        "fp_reason": "",
        "fp_author": "",
        "fp_date": "",
        "requires_format": "",
        "requires_format_reason": "",
    }

    current_key = None
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Key: value
        if ":" in stripped and not stripped.startswith("-"):
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            current_key = key

            if key == "interacts":
                if val:
                    result["interacts"] = [v.strip() for v in val.split(",")]
                else:
                    result["interacts"] = []
            elif key == "format":
                result["format"] = val
            elif key == "description":
                result["description"] = val
            elif key == "created":
                result["created"] = val
            elif key == "false_positives":
                if val:
                    result["false_positives"] = [v.strip() for v in val.split(",")]
            elif key == "fp_reason":
                result["fp_reason"] = val
            elif key == "fp_author":
                result["fp_author"] = val
            elif key == "fp_date":
                result["fp_date"] = val
            elif key == "requires_format":
                result["requires_format"] = val
            elif key == "requires_format_reason":
                result["requires_format_reason"] = val
        elif stripped.startswith("-") and current_key == "interacts":
            item = stripped.lstrip("- ").strip()
            if item:
                result["interacts"].append(item)
        elif stripped.startswith("-") and current_key == "false_positives":
            item = stripped.lstrip("- ").strip()
            if item:
                result["false_positives"].append(item)

    return result


def scan_test_files() -> dict[str, dict[str, Any]]:
    """Scan all test files for registry headers."""
    results: dict[str, dict[str, Any]] = {}

    if not TESTS_DIR.exists():
        return results

    for test_file in sorted(TESTS_DIR.rglob("*.py")):
        if "__pycache__" in str(test_file):
            continue
        if test_file.name == "conftest.py":
            continue

        rel_path = str(test_file.relative_to(REPO_ROOT))
        text = test_file.read_text(encoding="utf-8")

        header = parse_registry_header(text)
        if header:
            results[rel_path] = header

    return results


def auto_discover_bindings(test_file: Path) -> list[str]:
    """Auto-detect what a test file interacts with by scanning imports and references."""
    bindings: set[str] = set()
    text = test_file.read_text(encoding="utf-8")

    # Detect tool imports and references
    tool_names_found: set[str] = set()
    tool_patterns = [
        re.compile(r'from\s+ida_mcp\.tools\.(\w+)\s+import'),
        re.compile(r'from\s+ida_mcp\.tools\s+import\s+(\w+)'),
        re.compile(r'import\s+ida_mcp\.tools\.(\w+)'),
        re.compile(r'"(\w+)",\s*\{\s*"action":'),  # tool call patterns
        re.compile(r'tool_name\s*==\s*"(\w+)"'),
        re.compile(r'_handle_(\w+)\b'),
        re.compile(r'_execute_tool\("(\w+)"'),
        re.compile(r'self\.server\._execute_tool\("(\w+)"'),
    ]

    for pattern in tool_patterns:
        for match in pattern.finditer(text):
            tool_name = match.group(1)
            if tool_name.startswith("_") or tool_name in ("pycache__", "conftest", "self"):
                continue
            tool_names_found.add(tool_name)

    # Map to entity IDs
    for tool_name in sorted(tool_names_found):
        bindings.add(f"tool:{tool_name}")
        bindings.add(f"tool_actions:{tool_name}")
        bindings.add(f"dispatch:{tool_name}")

    # Detect schema references
    schema_patterns = [
        re.compile(r'schemas_data\.(TOOLS|ADVERTISED_TOOLS|TOOL_ACTIONS|TOOL_DESCRIPTIONS)'),
        re.compile(r'schemas\.(TOOLS|ADVERTISED_TOOLS)'),
        re.compile(r'TOOL_ACTIONS\["(\w+)"\]'),
    ]
    for pattern in schema_patterns:
        for match in pattern.finditer(text):
            name = match.group(1) if match.lastindex else match.group(0)
            bindings.add(f"schema:{name}")

    # Detect dispatch references
    dispatch_patterns = [
        re.compile(r'server_dispatch\.py'),
        re.compile(r'from.*server_dispatch\s+import'),
    ]
    for pattern in dispatch_patterns:
        if pattern.search(text):
            bindings.add("dispatch:all")
    # Also detect specific tool_name checks
    for m in re.finditer(r'tool_name\s*==\s*"(\w+)"', text):
        bindings.add(f"dispatch:{m.group(1)}")

    return sorted(bindings)


def load_registry() -> dict[str, Any]:
    """Load the registry file."""
    if REGISTRY_FILE.exists():
        return json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
    return {"version": 1, "entities": {}, "tests": {}, "changes": {}}


def save_registry(registry: dict[str, Any]) -> None:
    """Save the registry file."""
    REGISTRY_FILE.write_text(
        json.dumps(registry, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def check_violations(
    registry: dict[str, Any],
    current_entities: list[CodeEntity],
    test_headers: dict[str, dict[str, Any]],
    test_files_mtime: dict[str, float],
) -> list[Violation]:
    """Check for binding violations."""
    violations: list[Violation] = []

    # Build entity lookup
    entity_map: dict[str, CodeEntity] = {e.entity_id: e for e in current_entities}

    # Check each test in registry
    for test_id, test_entry in registry.get("tests", {}).items():
        interacts = test_entry.get("interacts", [])
        false_positives = test_entry.get("false_positives", [])

        for entity_id in interacts:
            # Skip if marked as false positive
            if entity_id in false_positives:
                continue

            # Check if entity still exists
            if entity_id not in entity_map:
                violations.append(Violation(
                    test_id=test_id,
                    entity_id=entity_id,
                    violation_type="stale_binding",
                    message=f"Test '{test_id}' binds to entity '{entity_id}' which no longer exists",
                    fix_hint=f"Remove '{entity_id}' from test's interacts list or update to new entity",
                ))
                continue

            entity = entity_map[entity_id]

            # Check if entity changed since last verification
            changes = registry.get("changes", {})
            entity_change = changes.get(entity.file, {})
            last_hash = entity_change.get("hash", "")
            current_hash = entity.hash

            if last_hash and current_hash != last_hash:
                # Entity changed. Check if test file also changed.
                test_mtime = test_files_mtime.get(test_id, 0)
                entity_file = REPO_ROOT / entity.file
                entity_mtime = entity_file.stat().st_mtime if entity_file.exists() else 0

                # If entity changed AFTER test was last modified, it's a violation
                if entity_mtime > test_mtime:
                    violations.append(Violation(
                        test_id=test_id,
                        entity_id=entity_id,
                        violation_type="stale_binding",
                        message=f"Entity '{entity_id}' changed (hash {last_hash} -> {current_hash}) but test '{test_id}' not updated",
                        fix_hint=f"Update test '{test_id}' to reflect changes in '{entity_id}', or mark as false positive",
                    ))

    # Check for tests with headers but not in registry
    for test_id, header in test_headers.items():
        if test_id not in registry.get("tests", {}):
            violations.append(Violation(
                test_id=test_id,
                entity_id="",
                violation_type="missing_binding",
                message=f"Test '{test_id}' has @@TEST_REGISTRY@@ header but is not in registry",
                fix_hint=f"Run --discover to add to registry, or run --update-hashes",
            ))

    return violations


def cmd_check(args: argparse.Namespace) -> int:
    """Run the binding check."""
    registry = load_registry()
    current_entities = discover_code_entities()
    test_headers = scan_test_files()

    # Get test file mtimes
    test_mtimes: dict[str, float] = {}
    if TESTS_DIR.exists():
        for f in TESTS_DIR.rglob("*.py"):
            if "__cache__" not in str(f):
                rel = str(f.relative_to(REPO_ROOT))
                test_mtimes[rel] = f.stat().st_mtime

    violations = check_violations(registry, current_entities, test_headers, test_mtimes)

    if not violations:
        print("✓ All test bindings are up to date.")
        return 0

    # Group by violation type
    by_type: dict[str, list[Violation]] = {}
    for v in violations:
        by_type.setdefault(v.violation_type, []).append(v)

    print(f"✗ {len(violations)} binding violation(s) found:\n")

    for vtype, vlist in by_type.items():
        print(f"  [{vtype}] ({len(vlist)})")
        for v in vlist:
            print(f"    • {v.message}")
            print(f"      Fix: {v.fix_hint}")
        print()

    if args.strict:
        return 1
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    """Auto-discover test bindings and update registry."""
    registry = load_registry()
    current_entities = discover_code_entities()

    # Ensure entities section exists
    if "entities" not in registry:
        registry["entities"] = {}

    # Update entities from current code
    for entity in current_entities:
        registry["entities"][entity.entity_id] = {
            "file": entity.file,
            "type": entity.entity_type,
            "name": entity.name,
            "hash": entity.hash,
        }

    # Scan test files
    if not TESTS_DIR.exists():
        print("No tests/ directory found.")
        return 0

    test_count = 0
    for test_file in sorted(TESTS_DIR.rglob("*.py")):
        if "__pycache__" in str(test_file):
            continue
        if test_file.name == "conftest.py":
            continue

        rel_path = str(test_file.relative_to(REPO_ROOT))
        text = test_file.read_text(encoding="utf-8")

        # Check for existing header
        header = parse_registry_header(text)
        if header:
            entry = header
        else:
            # Auto-discover
            bindings = auto_discover_bindings(test_file)
            entry = {
                "interacts": bindings,
                "format": "v1",
                "description": "",
                "created": date.today().isoformat(),
                "false_positives": [],
            }

        registry["tests"][rel_path] = entry
        test_count += 1

    # Update hashes
    if "changes" not in registry:
        registry["changes"] = {}
    for entity in current_entities:
        registry["changes"][entity.file] = {
            "hash": entity.hash,
            "last_verified": date.today().isoformat(),
        }

    save_registry(registry)
    print(f"✓ Discovered {test_count} test files.")
    print(f"✓ Tracked {len(current_entities)} code entities.")
    print(f"✓ Registry saved to {REGISTRY_FILE}")
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate registry integrity."""
    registry = load_registry()
    errors: list[str] = []

    # Check required fields
    if "version" not in registry:
        errors.append("Missing 'version' field")
    if "entities" not in registry:
        errors.append("Missing 'entities' section")
    if "tests" not in registry:
        errors.append("Missing 'tests' section")

    # Check each test entry
    for test_id, entry in registry.get("tests", {}).items():
        if "interacts" not in entry:
            errors.append(f"Test '{test_id}' missing 'interacts' field")
        if "format" not in entry:
            errors.append(f"Test '{test_id}' missing 'format' field")

        # Check entity references exist
        for entity_id in entry.get("interacts", []):
            if entity_id not in registry.get("entities", {}):
                errors.append(f"Test '{test_id}' references unknown entity '{entity_id}'")

    # Check entity files exist
    for entity_id, entity_data in registry.get("entities", {}).items():
        file_path = REPO_ROOT / entity_data.get("file", "")
        if not file_path.exists():
            errors.append(f"Entity '{entity_id}' file not found: {entity_data.get('file')}")

    if errors:
        print(f"✗ {len(errors)} validation error(s):")
        for e in errors:
            print(f"  • {e}")
        return 1

    print("✓ Registry is valid.")
    return 0


def cmd_mark_fp(args: argparse.Namespace) -> int:
    """Mark a test as false positive for specific entities."""
    registry = load_registry()

    test_id = args.test
    entities = [e.strip() for e in args.entities.split(",")]
    reason = args.reason or ""

    if test_id not in registry.get("tests", {}):
        print(f"✗ Test '{test_id}' not found in registry.")
        print(f"  Run --discover first.")
        return 1

    entry = registry["tests"][test_id]
    fps = entry.get("false_positives", [])
    for entity_id in entities:
        if entity_id not in fps:
            fps.append(entity_id)
    entry["false_positives"] = fps
    entry["fp_reason"] = reason
    entry["fp_author"] = args.author or os.environ.get("USER", "unknown")
    entry["fp_date"] = date.today().isoformat()

    save_registry(registry)
    print(f"✓ Marked {len(entities)} false positive(s) for '{test_id}'.")
    return 0


def cmd_update_hashes(args: argparse.Namespace) -> int:
    """Update all hashes to current state (accept changes)."""
    registry = load_registry()
    current_entities = discover_code_entities()

    if "changes" not in registry:
        registry["changes"] = {}

    for entity in current_entities:
        registry["changes"][entity.file] = {
            "hash": entity.hash,
            "last_verified": date.today().isoformat(),
        }

    # Also update entity definitions
    if "entities" not in registry:
        registry["entities"] = {}
    for entity in current_entities:
        registry["entities"][entity.entity_id] = {
            "file": entity.file,
            "type": entity.entity_type,
            "name": entity.name,
            "hash": entity.hash,
        }

    save_registry(registry)
    print(f"✓ Updated {len(current_entities)} entity hashes.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Test Binding Registry Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Check current state
  %(prog)s --discover               Auto-detect all bindings
  %(prog)s --validate               Validate registry integrity
  %(prog)s --strict                 Exit non-zero on violations
  %(prog)s --mark-fp "tests/foo.py" --entities "tool:search" --reason "..."
  %(prog)s --update-hashes          Accept current state
        """,
    )

    parser.add_argument("--discover", action="store_true", help="Auto-detect bindings")
    parser.add_argument("--validate", action="store_true", help="Validate registry")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero on violations")
    parser.add_argument("--mark-fp", dest="test", help="Test file to mark as false positive")
    parser.add_argument("--entities", default="", help="Comma-separated entity IDs for FP mark")
    parser.add_argument("--reason", default="", help="Reason for false positive mark")
    parser.add_argument("--author", default="", help="Author of the FP mark")
    parser.add_argument("--update-hashes", action="store_true", help="Update all hashes")

    args = parser.parse_args()

    if args.discover:
        return cmd_discover(args)
    if args.validate:
        return cmd_validate(args)
    if args.test:
        return cmd_mark_fp(args)
    if args.update_hashes:
        return cmd_update_hashes(args)

    return cmd_check(args)


if __name__ == "__main__":
    sys.exit(main())
