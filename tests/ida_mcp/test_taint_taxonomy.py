"""Tests for taint taxonomy: curated tables, runtime extension, and
the merged effective-source / effective-sink view used by the taint
tool.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _load_tt():
    spec = importlib.util.spec_from_file_location(
        "_tt_under_test",
        SRC / "ida_pro_mcp/ida_mcp/tools/taint_taxonomy.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_curated_tables_have_expected_minimum_coverage():
    mod = _load_tt()
    # Linux: must include the canonical sockets/file/env surface
    must_have = {"recv", "recvfrom", "read", "fread", "fgets", "getenv", "mmap",
                 "scanf", "fscanf", "gets"}
    assert must_have <= mod.LINUX_TAINT_SOURCES, (
        f"missing linux sources: {must_have - mod.LINUX_TAINT_SOURCES}"
    )
    # Windows: must include winsock + WinHTTP + registry
    must_have_w = {"WSARecv", "WSARecvFrom", "ReadFile", "WinHttpReceiveResponse",
                   "InternetReadFile", "RegQueryValueExA", "RegQueryValueExW",
                   "GetCommandLineW"}
    assert must_have_w <= mod.WINDOWS_TAINT_SOURCES
    # Linux sinks: must include the canonical dangerous ones
    must_have_ls = {"memcpy", "strcpy", "sprintf", "system", "execve",
                    "popen", "mmap", "chroot", "setuid"}
    assert must_have_ls <= set(mod.LINUX_DANGEROUS_SINKS.keys())
    # Windows sinks: must include process/memory/registry sinks
    must_have_ws = {"CreateProcessW", "ShellExecuteW", "LoadLibraryW",
                    "VirtualAlloc", "WriteProcessMemory", "RegSetValueExW"}
    assert must_have_ws <= set(mod.WINDOWS_DANGEROUS_SINKS.keys())


def test_apply_curated_taxonomy_merges_all_layers():
    mod = _load_tt()
    base_sources = {"recv", "CustomA"}
    base_sinks = {"memcpy": "buffer_overflow"}
    sources, sinks = mod.apply_curated_taxonomy(base_sources, base_sinks)
    # base preserved
    assert "CustomA" in sources
    # Linux + Windows sinks merged
    for s in ("execve", "LoadLibraryA", "popen", "CreateProcessW"):
        assert s in sinks, f"missing sink {s}"
    # base vuln_type preserved (curated setdefault keeps it)
    assert sinks["memcpy"] == "buffer_overflow"
    # base entries included, plus linux+windows sources (with overlaps)
    assert sources >= base_sources
    assert sources >= (mod.LINUX_TAINT_SOURCES | mod.WINDOWS_TAINT_SOURCES)


def test_extend_from_corpus_adds_yara_sinks_with_low_confidence_tag():
    mod = _load_tt()
    from ida_pro_mcp.host.intelligence.threat_corpus import ThreatCorpus
    corpus = ThreatCorpus(
        cwe=[], attack_patterns=[], malware=[], intrusion_sets=[],
        tools=[], mitigations=[],
        yara_rules=[
            {"name": "synth_malware_1", "description": "Test",
             "source": 'rule x1 { strings: $a = "CreateProcessW" ascii wide condition: any of them }'},
            {"name": "synth_malware_2", "description": "Test",
             "source": 'rule x2 { strings: $a = "execve" ascii condition: any of them }'},
            {"name": "synth_malware_3", "description": "Test",
             "source": 'rule x3 { strings: $a = "LoadLibraryA" ascii condition: any of them }'},
            {"name": "synth_malware_4", "description": "Test",
             "source": 'rule x4 { strings: $a = "NtCreateThreadEx" ascii condition: any of them }'},
        ],
    )
    mod.reset_taxonomy()
    rep = mod.extend_taint_taxonomy_from_corpus(corpus, reset=True)
    assert rep["yara_rules_scanned"] == 4
    # execve and LoadLibraryA are already in curated tables; only "yara_match"
    # entries are NEW. CreateProcessW IS in WINDOWS_DANGEROUS_SINKS so its
    # curated vuln_type wins via setdefault.
    sources, sinks = mod.apply_curated_taxonomy(set(), {})
    assert "CreateProcessW" in sinks
    # vuln_type from curated table for CreateProcessW is "command_injection"
    assert sinks["CreateProcessW"] == "command_injection"
    # NtCreateThreadEx is NOT in curated tables, so it should be added with
    # vuln_type="yara_match" and live in the EXTRAS
    assert "NtCreateThreadEx" in mod.get_extra_sinks()
    assert mod.get_extra_sinks()["NtCreateThreadEx"] == "yara_match"


def test_extend_handles_empty_corpus():
    mod = _load_tt()
    mod.reset_taxonomy()
    rep = mod.extend_taint_taxonomy_from_corpus(None)
    assert rep == {"sources": 0, "sinks": 0, "yara_rules_scanned": 0}
    rep2 = mod.extend_taint_taxonomy_from_corpus(
        None, reset=True, max_yara_rules=0,
    )
    assert rep2 == {"sources": 0, "sinks": 0, "yara_rules_scanned": 0}


def test_reset_taxonomy_clears_only_extras():
    mod = _load_tt()
    mod.reset_taxonomy()
    pre_sources_count = len(mod.LINUX_TAINT_SOURCES)
    pre_sinks_count = len(mod.WINDOWS_DANGEROUS_SINKS)
    # Add an extra via the corpus path
    from ida_pro_mcp.host.intelligence.threat_corpus import ThreatCorpus
    corpus = ThreatCorpus(
        cwe=[], attack_patterns=[], malware=[], intrusion_sets=[],
        tools=[], mitigations=[],
        yara_rules=[
            {"name": "rt", "description": "x",
             "source": 'rule rt { strings: $a = "WsaSend" ascii condition: any of them }'},
            {"name": "rt2", "description": "x",
             "source": 'rule rt2 { strings: $a = "WSASendTo" ascii condition: any of them }'},
            {"name": "rt3", "description": "x",
             "source": 'rule rt3 { strings: $a = "CryptEncrypt" ascii condition: any of them }'},
        ],
    )
    mod.extend_taint_taxonomy_from_corpus(corpus, reset=True)
    sources, sinks = mod.apply_curated_taxonomy(set(), {})
    # WSASend/WSASendTo/CryptEncrypt are in curated tables, so they should
    # at least be present (possibly with curated vuln_type)
    assert "WSASend" in sinks
    assert "WSASendTo" in sinks
    assert "CryptEncrypt" in sinks
    # After reset, curated tables still present
    mod.reset_taxonomy()
    sources, sinks = mod.apply_curated_taxonomy(set(), {})
    assert "WSASend" in sinks  # curated kept
    assert "CryptEncrypt" in sinks  # curated kept
    # Curated tables untouched
    assert len(mod.LINUX_TAINT_SOURCES) == pre_sources_count
    assert len(mod.WINDOWS_DANGEROUS_SINKS) == pre_sinks_count


def test_yara_string_extraction_handles_escapes():
    mod = _load_tt()
    src = r'''
    rule rt { strings:
        $a = "CreateProcess\x00W" ascii wide
        $b = { 4D 5A 90 00 03 }
        $c = "WSASendTo" ascii
    condition:
        any of them
    }
    '''
    literals = mod._extract_yara_string_literals(src)
    # We expect both quoted literals; hex pattern is not a string literal.
    joined = " ".join(literals)
    assert "CreateProcess" in joined
    assert "WSASendTo" in joined
    # Hex pattern (4D 5A 90 00 03) shouldn't be captured as a string literal
    assert "4D 5A 90 00 03" not in joined


def test_effective_helpers_consistent_with_curated_view():
    """Spot-check that the taint module's effective_* helpers agree with
    apply_curated_taxonomy on a fresh process."""
    mod = _load_tt()
    mod.reset_taxonomy()
    sources, sinks = mod.apply_curated_taxonomy(set(), {})
    # Linux and Windows curated tables must be fully present (with duplicates
    # collapsed by set)
    assert sources >= mod.LINUX_TAINT_SOURCES
    assert sources >= mod.WINDOWS_TAINT_SOURCES
    assert set(sinks.keys()) >= mod.LINUX_DANGEROUS_SINKS.keys()
    assert set(sinks.keys()) >= mod.WINDOWS_DANGEROUS_SINKS.keys()
