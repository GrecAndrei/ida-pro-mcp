"""Tests for the TF-IDF synonym extension surface and
``derive_synonyms_from_corpus``.
"""
from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ida_pro_mcp.host.intelligence.core import (
    _TFIDFEmbedder,
    derive_synonyms_from_corpus,
)
from ida_pro_mcp.host.intelligence.threat_corpus import ThreatCorpus


def test_base_synonyms_preserved_by_default():
    tfidf = _TFIDFEmbedder()
    effective = tfidf.effective_synonyms
    for key in ("aes", "cipher", "http", "recv", "send", "socket",
                "debugger", "sandbox", "overflow", "uaf"):
        assert key in effective, f"base synonym key {key} missing"


def test_extra_synonyms_layered_on_top_of_base():
    tfidf = _TFIDFEmbedder()
    rep = tfidf.extend_synonyms(
        {"exploit": ("vulnerability", "leverage"), "shellcode": ("payload", "code")},
        reset=True,
    )
    assert rep["added_keys"] == 2
    assert rep["added_vals"] == 4
    effective = tfidf.effective_synonyms
    # Base still there
    assert "aes" in effective
    # Extras are there
    assert effective["exploit"] == ("vulnerability", "leverage")
    assert effective["shellcode"] == ("payload", "code")


def test_extra_synonyms_merge_with_base_per_key():
    """Adding a key that already exists in BASE_SYNONYMS extends it."""
    tfidf = _TFIDFEmbedder()
    rep = tfidf.extend_synonyms({"aes": ("block", "rijndael")}, reset=True)
    assert rep["added_vals"] == 2
    eff = tfidf.effective_synonyms["aes"]
    assert "block" in eff
    assert "rijndael" in eff
    # Original base still present
    for v in ("crypto", "cipher", "encrypt", "decrypt"):
        assert v in eff


def test_reset_clears_only_extras():
    tfidf = _TFIDFEmbedder()
    tfidf.extend_synonyms({"foo": ("bar",)}, reset=True)
    assert "foo" in tfidf.effective_synonyms
    tfidf.extend_synonyms({}, reset=True)
    assert "foo" not in tfidf.effective_synonyms
    # Base still there
    assert "aes" in tfidf.effective_synonyms


def test_max_keys_and_max_vals_per_key_caps():
    tfidf = _TFIDFEmbedder()
    mapping = {
        f"k{i}": tuple(f"v{i}_{j}" for j in range(20))
        for i in range(50)
    }
    rep = tfidf.extend_synonyms(mapping, reset=True, max_keys=10, max_vals_per_key=3)
    assert rep["added_keys"] == 10
    eff = tfidf.effective_synonyms
    # 10 extras + 10 base
    assert len(eff) == 10 + len(_TFIDFEmbedder.BASE_SYNONYMS)
    # Each extra capped at 3
    for k in (f"k{i}" for i in range(10)):
        assert len(eff[k]) <= 3


def test_short_long_and_self_synonyms_filtered():
    tfidf = _TFIDFEmbedder()
    rep = tfidf.extend_synonyms(
        {"good": ("ok", "a", "b"), "noop": ("x",), "y": ("",)},
        reset=True,
    )
    # Only "good" should be added (1-char values filtered; "noop" has no
    # valid value; "y" is empty key)
    assert rep["added_keys"] == 1
    assert rep["added_vals"] == 1  # only "ok" survives
    eff = tfidf.effective_synonyms
    assert "good" in eff
    assert eff["good"] == ("ok",)
    # 'noop' shouldn't be added because no value >1 char
    assert "noop" not in eff


def test_derive_synonyms_returns_dict_of_tuples():
    corpus = ThreatCorpus(
        cwe=[
            {"id": "CWE-120", "name": "Buffer Overflow",
             "description": "classic buffer copy without bounds check leads to overflow"},
            {"id": "CWE-787", "name": "Out-of-bounds Write",
             "description": "writing outside buffer bounds"},
        ],
        attack_patterns=[], malware=[], intrusion_sets=[],
        tools=[], mitigations=[], yara_rules=[],
    )
    out = derive_synonyms_from_corpus(corpus, max_per_source=10)
    assert isinstance(out, dict)
    assert all(isinstance(v, tuple) for v in out.values())
    # No empty values
    for k, v in out.items():
        assert k
        assert v


def test_derive_handles_malware_with_aliases():
    corpus = ThreatCorpus(
        cwe=[], attack_patterns=[], malware=[
            {"id": "M001", "name": "WannaCry",
             "description": "ransomware worm",
             "aliases": ["WCry", "WannaCrypt"]},
        ],
        intrusion_sets=[], tools=[], mitigations=[], yara_rules=[],
    )
    out = derive_synonyms_from_corpus(corpus)
    # Aliases are cross-linked
    for tok in ("wcry", "wannacry", "wannacrypt"):
        assert tok in out, f"alias token {tok} not derived"


def test_derive_handles_empty_corpus():
    corpus = ThreatCorpus(
        cwe=[], attack_patterns=[], malware=[],
        intrusion_sets=[], tools=[], mitigations=[], yara_rules=[],
    )
    out = derive_synonyms_from_corpus(corpus)
    assert out == {}


def test_derive_handles_none():
    out = derive_synonyms_from_corpus(None)
    assert out == {}
