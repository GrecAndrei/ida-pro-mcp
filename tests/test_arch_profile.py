import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.host.arch_profile import normalize_arch_options, infer_binary_arch_profile


def test_normalize_arch_options_aliases():
    out, meta = normalize_arch_options(
        {
            "processor": "x86_64",
            "endian": "LE",
            "loader_options": {"k": "v"},
        }
    )
    assert out["processor"] == "metapc"
    assert out["bitness"] == 64
    assert out["endian"] == "little"
    assert out["value"] == {"k": "v"}
    assert meta.get("normalizations")


def test_infer_binary_arch_profile_raw_cortex_m():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        # SP in RAM, reset vector thumb bit set -> Cortex-M heuristic.
        tf.write((0x20001000).to_bytes(4, "little"))
        tf.write((0x08000101).to_bytes(4, "little"))
        tf.write(b"\x00" * 64)
        path = tf.name
    try:
        inf = infer_binary_arch_profile(path)
        assert inf["file_kind"] == "raw"
        assert inf["processor"] == "arm"
        assert inf["bitness"] == 32
        assert inf["endian"] == "little"
        assert float(inf["confidence"]) >= 0.9
    finally:
        os.unlink(path)


def test_infer_binary_arch_profile_raw_ambiguous_does_not_force_processor():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        # Weak x86-ish signal: enough for candidates, below auto-apply threshold.
        tf.write((b"\xe8" + (b"\x00" * 63)) * 8)
        path = tf.name
    try:
        inf = infer_binary_arch_profile(path)
        assert inf["file_kind"] == "raw"
        # Ambiguous raw blobs should not be hard-forced into one processor.
        assert inf.get("processor") in (None, "",)
        assert isinstance(inf.get("candidates"), list)
        assert len(inf.get("candidates") or []) >= 1
        assert inf.get("reason")
    finally:
        os.unlink(path)
