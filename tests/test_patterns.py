"""Tests for the pattern registry — validates structure and consistency."""

import re

from classifinder_engine.patterns.registry import PATTERN_REGISTRY


def test_all_patterns_registered():
    assert len(PATTERN_REGISTRY) >= 101


def test_pattern_ids_are_unique():
    ids = [p.id for p in PATTERN_REGISTRY]
    assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"


def test_all_patterns_have_required_fields():
    for p in PATTERN_REGISTRY:
        assert p.id, f"Pattern missing id: {p}"
        assert p.name, f"Pattern {p.id} missing name"
        assert p.regex, f"Pattern {p.id} missing regex"
        assert p.severity, f"Pattern {p.id} missing severity"
        assert p.confidence_base > 0, f"Pattern {p.id} has zero confidence_base"


def test_severity_values_are_valid():
    valid = {"critical", "high", "medium", "low"}
    for p in PATTERN_REGISTRY:
        assert p.severity in valid, f"Pattern {p.id} has invalid severity: {p.severity}"


def test_all_regexes_have_secret_named_group():
    for p in PATTERN_REGISTRY:
        compiled = re.compile(p.regex)
        assert "secret" in compiled.groupindex, (
            f"Pattern {p.id} regex is missing (?P<secret>...) named group"
        )


def test_confidence_base_in_valid_range():
    for p in PATTERN_REGISTRY:
        assert 0.0 < p.confidence_base <= 1.0, (
            f"Pattern {p.id} has confidence_base={p.confidence_base} outside (0, 1]"
        )
