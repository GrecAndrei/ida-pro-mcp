"""Small deterministic coverage cases for schema normalization helpers."""

from __future__ import annotations

import builtins

from ida_pro_mcp.host import schemas


def test_schema_alias_helpers_handle_empty_and_wrapped_values():
    assert schemas._snake_variants("") == set()
    assert schemas._camel_variants("single") == set()
    assert schemas._strip_balanced_wrappers("") == ""
    assert schemas._strip_balanced_wrappers("  `['action: run']`  ") == "action: run"
    assert schemas._noisy_alias_variants("") == set()
    assert schemas._normalize_alias_lookup_key("  ACTION = run  ") == "run"
    assert schemas._resolve_tool_alias(42) == 42
    assert schemas._resolve_tool_alias("   ") == "   "


def test_augment_arg_schemas_returns_original_on_catalog_import_failure(monkeypatch):
    original_import = builtins.__import__

    def fail_catalog(name, *args, **kwargs):
        if name.endswith("agent_operations"):
            raise ImportError("catalog unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_catalog)
    source = {"tool": {"value": {"type": "string"}}}
    assert schemas._augment_arg_schemas(source) == source


def test_schema_builders_cover_action_only_and_unknown_tools(monkeypatch):
    monkeypatch.setattr(schemas, "TOOL_ARG_SCHEMAS", {})
    monkeypatch.setattr(schemas, "TOOL_ACTIONS", {"synthetic": ["run"]})
    monkeypatch.setattr(schemas, "ADVERTISED_ACTIONS", {})
    full = schemas.build_input_schema("synthetic")
    lean = schemas.build_input_schema_lean("synthetic")
    assert full["required"] == ["action"]
    assert lean["properties"]["action"]["enum"] == ["run"]
    unknown = schemas.build_input_schema("unknown")
    assert unknown["required"] == []
    assert "idb" in unknown["properties"]


def test_lean_property_schema_covers_fallback_shapes():
    assert schemas._lean_prop_schema("x", None) == {"type": "string"}
    assert schemas._lean_prop_schema("x", {"type": ["unsupported"]}) == {"type": "string"}
    assert schemas._lean_prop_schema("action", {"type": "string"}) == {"type": "string"}
    assert schemas._lean_prop_schema("x", {"type": None}) == {"type": "string"}


def test_ultra_and_description_builders_cover_fallbacks(monkeypatch):
    monkeypatch.setattr(schemas, "TOOL_ACTIONS", {"synthetic": ["run"]})
    monkeypatch.setattr(schemas, "ADVERTISED_ACTIONS", {})
    ultra = schemas.build_input_schema_ultra("synthetic")
    assert ultra["required"] == ["action"]
    assert schemas.build_input_schema_ultra("unknown")["properties"] == {"idb": {
        "type": "string",
        "description": "Optional. session_id, SID_* id, binary path, or full IDB path.",
    }}

    monkeypatch.setattr(schemas, "TOOL_DESCRIPTIONS", {
        "empty": "",
        "long": "x" * 350,
        "actions": "Summary. Actions: " + ", ".join("run" for _ in range(80)),
        "note": "A NOTE:",
    })
    assert schemas.build_tool_description_ultra("empty").startswith("Use wiki")
    assert len(schemas.build_tool_description_ultra("long")) == 161
    assert "Actions:" in schemas.build_tool_description_ultra("actions")
    assert schemas.build_tool_description_lean("empty") == ""
    assert schemas.build_tool_description_lean("note") == "A."
    assert schemas.build_tool_description_lean("long").endswith("...")


def test_classification_and_vertex_sanitization_cover_all_fallbacks(monkeypatch):
    assert schemas.classify_tool_category("deobfuscate") == "security"
    monkeypatch.setattr(schemas, "_TOOL_CATEGORY_COMPAT", {"compat-tool"})
    assert schemas.classify_tool_category("compat-tool") == "compat"
    assert schemas.classify_tool_category("not-a-tool") == "other"

    assert schemas.sanitize_schema_for_vertex("scalar") == "scalar"
    sanitized = schemas.sanitize_schema_for_vertex({
        "type": ["unknown"],
        "required": [],
        "properties": {},
        "nested": [{"type": ["array"]}, {"type": "object", "items": {"x": 1}}],
    })
    assert sanitized["type"] == "string"
    assert sanitized["nested"][0] == {"type": "array", "items": {"type": "string"}}
    assert sanitized["nested"][1] == {"type": "object"}
    assert schemas.sanitize_schema_for_vertex({"type": "array"})["items"] == {"type": "string"}
