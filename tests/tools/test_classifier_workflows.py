"""BehaviorClassifier and ContextAssembler integration tests."""
from __future__ import annotations

import pytest

from ida_pro_mcp.host.intelligence.core import BehaviorClassifier
from ida_pro_mcp.host.intelligence.context import ContextAssembler


class TestBehaviorClassifier:
    """BehaviorClassifier core functionality."""

    def test_classifier_exists(self) -> None:
        assert BehaviorClassifier is not None

    def test_classifier_has_classify(self) -> None:
        assert hasattr(BehaviorClassifier, "classify")

    def test_classifier_has_anchors(self) -> None:
        anchors = BehaviorClassifier.ANCHORS
        assert isinstance(anchors, dict)
        assert len(anchors) > 0

    def test_classifier_instance_with_embedder(self) -> None:
        from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder
        embedder = BgeCodeEmbedder()
        instance = BehaviorClassifier.instance(embedder)
        assert instance is not None


class TestContextAssembler:
    """ContextAssembler core functionality."""

    def test_assembler_exists(self) -> None:
        assert ContextAssembler is not None

    def test_assembler_has_assemble(self) -> None:
        assert hasattr(ContextAssembler, "assemble")
