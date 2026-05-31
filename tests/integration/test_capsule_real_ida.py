#!/usr/bin/env python3
"""Real IDA integration tests for capsule workflows.

These tests require a licensed IDA installation and use the integration
`ida_runner` fixture to execute IDAPython snippets against a real binary.
"""

from __future__ import annotations

import json

from ida_pro_mcp.capsule import CapsuleStore


def test_capsule_records_real_ida_probe(tmp_path, ida_runner):
    result = ida_runner.run_script(
        """
func_count = sum(1 for _ in idautils.Functions())
entry_count = sum(1 for _ in idautils.Entries())
imagebase = int(idc.get_inf_attr(idc.INF_MIN_EA))
with open(RESULT_PATH, "w") as f:
    json.dump(
        {
            "ok": True,
            "func_count": func_count,
            "entry_count": entry_count,
            "imagebase": imagebase,
        },
        f,
    )
"""
    )

    capsule_path = tmp_path / "real-ida.sideband"
    with CapsuleStore.open(capsule_path) as capsule:
        capsule.init(project_name="real-ida-integration", created_by="pytest-integration")
        capsule.add_audit_event("ida_probe", result)
        capsule.add_note(
            kind="integration",
            title="Real IDA probe",
            body=f"functions={result.get('func_count', 0)} entries={result.get('entry_count', 0)}",
            metadata={"imagebase": result.get("imagebase")},
        )
        verify = capsule.verify()
        summary = capsule.inspect_summary()

    assert result.get("ok") is True
    assert result.get("func_count", 0) >= 0
    assert verify["ok"] is True
    assert summary["audit_events"] == 1


def test_capsule_blob_roundtrip_from_real_ida_output(tmp_path, ida_runner):
    result = ida_runner.run_script(
        """
func_sample = []
for idx, ea in enumerate(idautils.Functions()):
    if idx >= 8:
        break
    func_sample.append(int(ea))
with open(RESULT_PATH, "w") as f:
    json.dump({"ok": True, "sample_functions": func_sample}, f)
"""
    )

    payload = json.dumps(result, sort_keys=True).encode("utf-8")
    capsule_path = tmp_path / "real-ida-blob.sideband"
    with CapsuleStore.open(capsule_path) as capsule:
        capsule.init(project_name="real-ida-blob", created_by="pytest-integration")
        sha = capsule.store_blob(payload, kind="ida_probe_json", media_type="application/json")
        restored = capsule.get_blob(sha)
        verify = capsule.verify()

    assert result.get("ok") is True
    assert restored == payload
    assert verify["ok"] is True
