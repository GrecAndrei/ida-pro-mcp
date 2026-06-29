"""Tests that BgeCodeEmbedder wires its TF-IDF fallback through
derive_synonyms_from_corpus at construction time.

We mock the threat-corpus load to return a fixture corpus with known
keys, then assert the embedder's fallback embedder has those keys
materialized in effective_synonyms.
"""

from __future__ import annotations

import pathlib
import sys
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeThreatCorpus:
    """Drop-in replacement for ThreatCorpus with the attributes the
    derive function consumes (no YARA/IO setup needed)."""

    def __init__(self) -> None:
        self.cwe = [
            {
                "id": "CWE-119",
                "name": "buffer overflow",
                "description": "classic stack smashing copy without bounds check, "
                               "exploits memcpy length-mismatch",
            },
        ]
        self.malware = [
            {
                "id": "M001",
                "name": "WannaCry",
                "description": "ransomware payload",
                "aliases": ["WCry", "WannaCrypt"],
            },
        ]
        self.attack_patterns = []
        self.intrusion_sets = []
        self.tools = []
        self.mitigations = []
        self.yara_rules = []


def _monkey_patch_corpus(monkeypatch):
    """Make threat_corpus.load_corpus return our fake."""
    from ida_pro_mcp.host.intelligence import core as core_mod, threat_corpus as tc_mod

    monkeypatch.setattr(tc_mod, "load_corpus", lambda path=None: _FakeThreatCorpus())


def test_bge_embedder_loads_corpus_synonyms_into_fallback(monkeypatch):
    """BgeCodeEmbedder.__init__ should call derive_synonyms_from_corpus
    on the threat corpus and apply the result to its TF-IDF fallback."""
    from ida_pro_mcp.host.intelligence import core as core_mod

    # Stub out the parts of __init__ that hit the filesystem/network.
    monkeypatch.setattr(core_mod, "_find_llama_server", lambda: "")
    monkeypatch.setattr(core_mod, "_find_model", lambda: "")

    _monkey_patch_corpus(monkeypatch)

    emb = core_mod.BgeCodeEmbedder()

    eff = emb._fallback.effective_synonyms
    # Base synonyms remain.
    assert "aes" in eff
    assert "uaf" in eff
    # Malware aliases cross-linked.
    assert "wannacry" in eff
    assert "wcry" in eff
    assert "wannacrypt" in eff
    # CWE name → description words.
    assert "buffer overflow" in eff
    overflow_vals = eff["buffer overflow"]
    assert any("exploits" in v for v in overflow_vals)
