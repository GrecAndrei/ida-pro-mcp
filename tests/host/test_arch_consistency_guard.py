import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools"


def _iter_tool_files():
    for p in TOOLS_DIR.rglob("*.py"):
        rel = p.relative_to(TOOLS_DIR).as_posix()
        if rel in {"_common.py", "arch_utils.py"}:
            continue
        yield p


def test_arch_metadata_uses_shared_helpers():
    """
    Guardrail: architecture/filetype metadata probes should go through _common helpers.
    This prevents per-tool drift that breaks raw-binary handling consistency.
    """
    forbidden = [
        re.compile(r"idc\.get_inf_attr\(\s*idc\.INF_PROCNAME\s*\)"),
        re.compile(r"idc\.get_inf_attr\(\s*idc\.INF_FILETYPE\s*\)"),
        re.compile(r"\binfo\.procname\b"),
        re.compile(r"\binfo\.filetype\b"),
    ]
    violations = []
    for path in _iter_tool_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        for idx, line in enumerate(text.splitlines(), start=1):
            for pat in forbidden:
                if pat.search(line):
                    violations.append(f"{path}:{idx}: {line.strip()}")
    assert not violations, "Use _inf_procname/_inf_filetype_id/_filetype_name/_inf_bitness helpers:\n" + "\n".join(violations[:50])

