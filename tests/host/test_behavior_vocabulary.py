"""The coarse and fine behavior vocabularies must stay one system.

``CANONICAL_TAGS`` (routing/indexing/search filters) and ``BEHAVIOR_LABELS``
(advisory answer choices) used to be unrelated lists defined in different
layers, so a label could be added to one and forgotten in the other. They now
live together in ``ida_pro_mcp.behavior_tags`` with a declared mapping. These
tests assert that mapping is total and internally consistent.
"""

from __future__ import annotations

import pytest

from ida_pro_mcp.behavior_tags import (
    BEHAVIOR_LABELS,
    CANONICAL_TAGS,
    COARSE_TO_FINE,
    UNRESOLVED_BEHAVIOR_LABEL,
)
from ida_pro_mcp.host.intelligence.advisory import BEHAVIOR_LABELS as ADVISORY_LABELS
from ida_pro_mcp.host.stores.insight_index import CANONICAL_TAGS as STORE_TAGS
from tests._isolated_repo_loader import load_tool_submodule  # needs the loader's sys.path setup


def test_advisory_reexports_the_canonical_fine_vocabulary():
    assert ADVISORY_LABELS == BEHAVIOR_LABELS
    assert tuple(BEHAVIOR_LABELS) == BEHAVIOR_LABELS


def test_every_layer_shares_one_coarse_vocabulary():
    assert STORE_TAGS == CANONICAL_TAGS
    # The IDA-side search module is loaded standalone, as the flat plugin layout
    # requires, so its copy of the vocabulary is checked through that same path.
    search_core = load_tool_submodule("search.core")
    assert search_core._CANONICAL_TAGS == CANONICAL_TAGS


def test_fine_labels_are_unique_and_lowercase():
    assert len(set(BEHAVIOR_LABELS)) == len(BEHAVIOR_LABELS)
    assert all(label == label.lower() for label in BEHAVIOR_LABELS)
    assert all(label.strip() == label and label for label in BEHAVIOR_LABELS)


def test_coarse_tags_are_unique_and_lowercase():
    assert all(tag == tag.lower() for tag in CANONICAL_TAGS)
    assert all(tag.strip() == tag and tag for tag in CANONICAL_TAGS)


def test_mapping_covers_every_fine_label_except_the_unresolved_one():
    # "unknown" is the explicit no-evidence answer and deliberately maps to no tag.
    assert set(COARSE_TO_FINE) | {UNRESOLVED_BEHAVIOR_LABEL} == set(BEHAVIOR_LABELS)
    assert UNRESOLVED_BEHAVIOR_LABEL not in COARSE_TO_FINE


def test_every_mapped_coarse_tag_is_real():
    unknown_targets = set(COARSE_TO_FINE.values()) - CANONICAL_TAGS
    assert not unknown_targets, f"mapping points at non-existent coarse tags: {unknown_targets}"


@pytest.mark.parametrize("fine_label", sorted(COARSE_TO_FINE))
def test_each_fine_label_resolves_to_exactly_one_coarse_tag(fine_label):
    assert fine_label in BEHAVIOR_LABELS
    coarse = COARSE_TO_FINE[fine_label]
    assert coarse in CANONICAL_TAGS
