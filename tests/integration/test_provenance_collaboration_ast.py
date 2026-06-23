#!/usr/bin/env python3
"""
AST-level regression tests for project provenance/collaboration intelligence actions.
"""

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROJECT_PATH = ROOT / "src" / "ida_pro_mcp" / "ida_mcp" / "tools" / "project.py"
HOST_PATH = ROOT / "src" / "ida_pro_mcp" / "host" / "schemas.py"


def _find_fn(module, name):
    return next((n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == name), None)


NEW_ACTIONS = {
    "evidence_graph",
    "knowledge_merge",
    "confidence_model",
    "replay_pipeline",
    "hypothesis_tracker",
    "temporal_reasoning",
    "semantic_artifact_diff",
    "ai_governance",
    "knowledge_debt",
    "casefile_export",
}


class TestProjectProvenanceAst(unittest.TestCase):
    def setUp(self):
        self.source = PROJECT_PATH.read_text(encoding="utf-8")
        self.module = ast.parse(self.source)

    def test_project_action_literal_includes_provenance_actions(self):
        fn = _find_fn(self.module, "project")
        self.assertIsNotNone(fn)
        action_arg = next((a for a in fn.args.args if a.arg == "action"), None)
        self.assertIsNotNone(action_arg)
        ann = action_arg.annotation
        self.assertIsInstance(ann, ast.Subscript)
        literal = ann.slice.elts[0]
        values = [e.value for e in literal.slice.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        for action in NEW_ACTIONS:
            self.assertIn(action, values)

    def test_project_has_explicit_action_branches(self):
        for action in NEW_ACTIONS:
            self.assertIn(f'elif action == "{action}":', self.source)


class TestHostToolActionsProjectProvenance(unittest.TestCase):
    def test_tool_actions_project_contains_provenance_actions(self):
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

        action_values = set(TOOL_ACTIONS.get("project", []))
        for action in NEW_ACTIONS:
            self.assertIn(action, action_values)


if __name__ == "__main__":
    unittest.main()
