#!/usr/bin/env python3
"""
AST-level regression tests for llm_helpers actions.
Tests that implemented actions are present in the Literal declaration.
"""

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LLM_HELPERS_PATH = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "llm_helpers.py"
HOST_PATH = ROOT / "src" / "ida_pro_mcp" / "host" / "schemas.py"


# Actions that must be present and implemented
REQUIRED_ACTIONS = {
    "context_window", "function_digest", "binary_digest", "explain_address",
    "suggest_next", "progress_report", "focus_area", "question_answer",
    "guided_analysis", "cheatsheet", "compact", "enrich",
    "intent_tool_compiler", "adaptive_query_planner", "question_type_router",
    "behavioral_signature_search", "cross_artifact_correlation_search",
    "function_role_classifier", "dangerous_pattern_explainer",
    "api_contract_extractor", "global_state_influence_mapper",
    "interprocedural_data_lineage_graph", "semantic_diff_explainer",
    "decompile_disasm_consistency_search", "argument_semantics_search",
    "path_constrained_search",
}

NEW_ACTIONS = REQUIRED_ACTIONS


def _find_fn(module, name):
    return next((n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == name), None)


class TestLLMHelpersExpansionAst(unittest.TestCase):
    def setUp(self):
        self.source = LLM_HELPERS_PATH.read_text(encoding="utf-8")
        self.module = ast.parse(self.source)

    def test_llm_helpers_action_literal_includes_all_expansion_actions(self):
        fn = _find_fn(self.module, "llm_helpers")
        self.assertIsNotNone(fn)
        action_arg = next((a for a in fn.args.args if a.arg == "action"), None)
        self.assertIsNotNone(action_arg)
        ann = action_arg.annotation
        self.assertIsInstance(ann, ast.Subscript)
        literal = ann.slice.elts[0]
        values = {
            e.value
            for e in literal.slice.elts
            if isinstance(e, ast.Constant) and isinstance(e.value, str)
        }
        for action in REQUIRED_ACTIONS:
            self.assertIn(action, values, f"Action '{action}' missing from Literal")

    def test_dispatcher_source_mentions_all_expansion_actions(self):
        for action in REQUIRED_ACTIONS:
            self.assertIn(f'"{action}"', self.source, f'Action "{action}" not mentioned in source')


class TestHostRegistrationExpansionAst(unittest.TestCase):
    def test_tool_actions_llm_helpers_contains_core_actions(self):
        source = HOST_PATH.read_text(encoding="utf-8")
        module = ast.parse(source)
        tool_actions = None
        for node in module.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "TOOL_ACTIONS":
                        tool_actions = node.value
                        break
                if tool_actions is not None:
                    break
        self.assertIsNotNone(tool_actions)
        from ida_pro_mcp.services import TOOL_ACTIONS

        action_values = set(TOOL_ACTIONS.get("llm_helpers", []))
        for action in {"context_window", "function_digest", "binary_digest",
                       "behavioral_signature_search", "function_role_classifier",
                       "dangerous_pattern_explainer", "api_contract_extractor"}:
            self.assertIn(action, action_values)


if __name__ == "__main__":
    unittest.main()
