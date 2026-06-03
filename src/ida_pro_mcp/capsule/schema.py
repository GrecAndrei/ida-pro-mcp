from __future__ import annotations

FORMAT_NAME = "sideband-capsule"
FORMAT_VERSION = 0
SCHEMA_VERSION = 3

REQUIRED_META_KEYS = {
    "format_name",
    "format_version",
    "schema_version",
    "created_at",
    "updated_at",
    "created_by",
    "project_name",
}

TRUST_STATES = {
    "untrusted",
    "inspected",
    "trusted-local",
    "trusted-signed",
    "quarantined",
}
