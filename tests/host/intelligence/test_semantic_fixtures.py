from __future__ import annotations

from pathlib import Path

from ida_pro_mcp.host.intelligence.core import BehaviorClassifier, _extract_signature


FIX_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "semantic"


class _TokenEmbedder:
    backend = "fake-token"
    dim = 8

    _TOKENS = {
        "crypto": 0,
        "aes": 0,
        "round": 0,
        "key": 0,
        "http": 1,
        "network": 1,
        "recv": 1,
        "overflow": 2,
        "memcpy": 2,
        "decrypt": 3,
        "xor": 3,
        "file": 4,
        "fopen": 4,
        "write": 4,
    }

    def _norm(self, v):
        s = sum(x * x for x in v) ** 0.5 or 1.0
        return [x / s for x in v]

    def embed(self, text: str):
        v = [0.0] * self.dim
        low = (text or "").lower()
        for token, idx in self._TOKENS.items():
            if token in low:
                v[idx] += 1.0
        return self._norm(v)


def _fixture(name: str) -> str:
    return (FIX_DIR / name).read_text(encoding="utf-8")


def test_signature_extractor_removes_noise_tokens():
    pseudo = "int parse_user_input(char *buf, int len) { memcpy(buf, src, len); return 0; }"
    sig = _extract_signature(pseudo)
    assert "parse" in sig
    assert "user" in sig
    assert "input" in sig
    assert "memcpy" not in sig
    assert "int" not in sig


def test_signature_extractor_splits_camelcase_identifiers():
    sig = _extract_signature("void AESDecryptRoundKeySchedule() { MixColumns(state); }")
    low = sig.lower().split()
    assert "decrypt" in low
    assert "round" in low
    assert "key" in low
    assert "mix" in low
    assert "columns" in low

