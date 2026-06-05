from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SURVEY_STORE_PATH = ROOT / "src" / "ida_pro_mcp" / "host" / "survey_store.py"
SERVER_DISPATCH_PATH = ROOT / "src" / "ida_pro_mcp" / "host" / "server_dispatch.py"
SURVEY_TOOL_PATH = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "survey.py"
CODE_TOOL_PATH = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "code.py"


def _load_survey_store_module():
    spec = importlib.util.spec_from_file_location("_survey_store_scope_test", SURVEY_STORE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_survey_store_scopes_surveys_and_visits_per_idb(tmp_path):
    mod = _load_survey_store_module()
    db_file = os.path.join(tmp_path, "survey_scope.db")

    with patch.object(mod, "_resolve_survey_db_path", return_value=db_file):
        alpha = mod.SurveyStore(context_key="/tmp/alpha.idb")
        beta = mod.SurveyStore(context_key="/tmp/beta.idb")

        alpha.save_survey(
            addr="0x401000",
            status="ACTIVE",
            variables=["v1"],
            dependencies=["0x402000"],
            deferred_until=[],
            reason="alpha only",
        )
        alpha.add_visited_address("0x402000")

        beta.save_survey(
            addr="0x501000",
            status="DORMANT",
            variables=["v9"],
            dependencies=[],
            deferred_until=[],
            reason="beta only",
        )
        beta.add_visited_address("0x503000")

        assert [s["addr"] for s in alpha.list_surveys()] == ["0x401000"]
        assert [s["addr"] for s in beta.list_surveys()] == ["0x501000"]
        assert alpha.get_survey("0x501000") is None
        assert beta.get_survey("0x401000") is None
        assert alpha.get_visited_addresses() == ["0x402000"]
        assert beta.get_visited_addresses() == ["0x503000"]


def test_survey_call_sites_are_context_scoped():
    dispatch_text = SERVER_DISPATCH_PATH.read_text(encoding="utf-8")
    survey_tool_text = SURVEY_TOOL_PATH.read_text(encoding="utf-8")
    code_tool_text = CODE_TOOL_PATH.read_text(encoding="utf-8")

    assert "def _survey_context_key(self) -> Optional[str]:" in dispatch_text
    assert "return SurveyStore(db_path=db_path, context_key=self._survey_context_key())" in dispatch_text
    assert "store = self._get_survey_store()" in dispatch_text
    assert "SurveyStore()" not in dispatch_text
    assert 'SurveyStore(context_key=idc.get_idb_path() or "")' in survey_tool_text
    assert 'SurveyStore(context_key=idc.get_idb_path() or "")' in code_tool_text
