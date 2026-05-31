from __future__ import annotations

from .schema import FORMAT_NAME, FORMAT_VERSION, SCHEMA_VERSION


def default_manifest(project_name: str, created_by: str) -> dict:
    return {
        "format": FORMAT_NAME,
        "format_version": FORMAT_VERSION,
        "schema_version": SCHEMA_VERSION,
        "project_name": project_name,
        "created_by": created_by,
        "backends": {
            "ida": {
                "status": "primary",
                "adapter": "ida_pro_mcp",
            }
        },
        "trust": {
            "state": "trusted-local",
            "contains_executable_payloads": False,
            "last_verified_at": None,
        },
        "policy": {
            "mode": "assist",
            "allowed_purposes": [
                "oss_audit",
                "release_verification",
                "vulnerability_triage",
                "firmware_analysis",
                "game_modding",
                "preservation",
                "malware_triage_defensive",
                "legacy_documentation",
                "education",
                "general_research",
            ],
            "disallowed_purposes": [
                "cheating",
                "piracy",
                "drm_circumvention",
                "unauthorized_multiplayer_tampering",
                "unauthorized_access",
                "credential_theft",
                "exploit_development",
            ],
            "requires_ack": [
                "write_idb",
                "destructive",
                "filesystem_write",
                "local_code_exec",
                "debugger",
                "unknown",
            ],
        },
    }
