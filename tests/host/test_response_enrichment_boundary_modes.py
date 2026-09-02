"""Composed response-digest coverage for all enrichment categories."""

from __future__ import annotations

from ida_pro_mcp.host.response_enrichment import digest_decompiled, patch_addresses


def test_digest_decompiled_combines_schema_and_text_evidence():
    pseudo = """\
for (i = 0; i < n; i++) { state ^= key; }
if (ready) { GetProcAddress(h, name); LoadLibrary(lib); }
VirtualAlloc(p, size, PAGE_EXECUTE); WriteProcessMemory(p, src, n);
CreateRemoteThread(p); IsDebuggerPresent(); cpuid; int 3;
socket(AF_INET); connect(s); CreateFile(path); CryptEncrypt(buf);
RegOpenKey(root); RegCreateKey(root); CreateService(name); push offset aCommand;
"""
    digest = digest_decompiled(
        pseudo,
        schema_attrs={
            "apis": ["socket", "VirtualAlloc", "CryptEncrypt", "IsDebuggerPresent", "CreateService"],
            "has_loops": True,
            "cyclomatic_complexity": 7,
            "entropy": 6.12345,
            "xref_count": 4,
            "has_crypto_constants": True,
        },
    )
    assert {"memory", "process", "network", "file", "crypto", "registry", "injection", "evasion", "persistence"} <= set(digest["api_categories"])
    assert {"network", "crypto", "allocator", "process_injection", "anti_analysis", "persistence", "file_io"} <= set(digest["behavior_tags"])
    assert digest["complexity"]["has_loops"] is True
    assert digest["complexity"]["cyclomatic_complexity"] == 7
    assert digest["complexity"]["entropy"] == 6.123
    assert digest["complexity"]["xref_count"] == 4
    assert any(item.startswith("Dynamic API resolution") for item in digest["patterns"])
    assert any(item.startswith("Shellcode staging") for item in digest["patterns"])
    assert "Anti-debug check" in digest["patterns"]
    assert "Anti-VM/anti-sandbox check" in digest["patterns"]
    assert digest["string_refs"] == ["push offset aCommand"]


def test_patch_addresses_is_additive_and_tolerates_invalid_inputs():
    assert patch_addresses(None) is None
    assert patch_addresses(3) == 3
    text = "lea rax, [rbp+oops]\nmov rax, [rip-0x10]\npush rsp"
    output = patch_addresses(text, {"rbp": 0x1000, "rip": 0x400000})
    assert "rip-0x10 -> 0x3ffff0" in output
    assert "push rsp" in output
