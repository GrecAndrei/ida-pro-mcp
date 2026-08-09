import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(__file__))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ida_pro_mcp.host.analysis.arch_profile import (
    prepare_profile_from_inference,
    prepared_profile,
)
from ida_pro_mcp.services import (
    infer_binary_arch_profile,
    normalize_arch_options,
)


def test_normalize_arch_options_riscv_aliases():
    # IDA's RISC-V processor module is canonically "riscv"; the suffixed
    # forms resolve to it with the bitness carried through.
    for raw, canon, bits in (("riscv64", "riscv", 64), ("rv64", "riscv", 64),
                             ("riscv32", "riscv", 32), ("rv32", "riscv", 32),
                             ("riscv", "riscv", None)):
        out, meta = normalize_arch_options({"processor": raw})
        assert out["processor"] == canon, raw
        assert out.get("bitness") == bits, raw
        if raw == "riscv":
            # Already canonical: no normalization is expected.
            assert out["processor"] == "riscv"
        else:
            assert meta.get("normalizations"), raw


def test_normalize_arch_options_riscv_alias_with_explicit_bitness():
    # Explicit bitness wins; alias still normalizes the processor name.
    out, meta = normalize_arch_options({"processor": "riscv64", "bitness": 32})
    assert out["processor"] == "riscv"
    assert out["bitness"] == 32


def test_prepared_profile_builds_openable_options():
    inf = {"processor": "riscv", "bitness": 32, "endian": "little",
           "loader": "bin", "load_base": 0x10000000,
           "confidence": 0.8, "warning": "raw blob; arch unverified"}
    prof = prepared_profile(inf)
    assert prof["processor"] == "riscv"
    assert prof["bitness"] == 32
    assert prof["endian"] == "little"
    assert prof["loader"] == "bin"
    assert prof["load_base"] == 0x10000000
    assert prof["confidence"] == 0.8
    assert "warning" in prof


def test_prepared_profile_explicit_options_win():
    inf = {"processor": "riscv", "bitness": None, "load_base": 0x10000000}
    prof = prepared_profile(inf, {"processor": "arm", "baseaddr": "0x40000000"})
    assert prof["processor"] == "arm"
    assert prof["load_base"] == 0x40000000


def test_prepared_profile_from_inference_roundtrip():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write((0x20001000).to_bytes(4, "little"))
        tf.write((0x08000101).to_bytes(4, "little"))
        tf.write(b"\x00" * 64)
        path = tf.name
    try:
        prof = prepare_profile_from_inference(path)
        assert prof["processor"] == "arm"
        assert prof["bitness"] == 32
        assert prof["load_base"] == 0x08000100
        assert prof["file_kind"] == "raw"
    finally:
        os.unlink(path)


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
        # Zero-followed vector table validates at high confidence.
        assert inf.get("load_base") == 0x08000100
        assert inf.get("warning") is None
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
        # Honest surfaces: a mostly-zero weak blob is not code, is flagged as
        # unverified, and its absolute confidence stays low (no relative
        # best-of-N inflation).
        assert inf.get("looks_like_code") is False
        assert inf.get("warning")
        assert float(inf.get("confidence") or 1) < 0.1
    finally:
        os.unlink(path)


def test_infer_binary_arch_profile_cortex_arch_only():
    # The Cortex-M vector-table heuristic survives as pure arch detection:
    # it still sets processor/bitness/endian but emits no chip-family fields.
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write((0x20002000).to_bytes(4, "little"))
        tf.write((0x08000101).to_bytes(4, "little"))
        tf.write(b"\x00" * 64)
        path = tf.name
    try:
        inf = infer_binary_arch_profile(path)
        assert inf["file_kind"] == "raw"
        assert inf["processor"] == "arm"
        assert inf["bitness"] == 32
        assert inf["endian"] == "little"
        assert inf.get("chip_family") is None
        # The reset vector is a load-base candidate now: 0x08000101 & ~1.
        assert inf.get("load_base") == 0x08000100
    finally:
        os.unlink(path)


def test_infer_binary_arch_profile_packed_idb_magic():
    """IDA2 magic → packed_idb detection with no processor override."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".i64") as tf:
        # IDA2 magic (0x49444132) identifies a packed IDA database.
        tf.write(b"IDA2")
        tf.write(b"\x00" * 256)
        path = tf.name
    try:
        inf = infer_binary_arch_profile(path)
        assert inf["file_kind"] == "packed_idb"
        assert float(inf["confidence"]) == 1.0
        # Must NOT set processor/bitness — let IDA load the DB as-is.
        assert inf.get("processor") is None
        assert inf.get("bitness") is None
    finally:
        os.unlink(path)
