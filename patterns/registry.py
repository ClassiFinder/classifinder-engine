"""
ClassiFinder — Pattern Registry

Central registry for all secret detection patterns. Each pattern is a dataclass
containing the regex, metadata, and scoring parameters needed to detect and
classify a specific secret type.

Usage:
    from app.engine.patterns.registry import PATTERN_REGISTRY

    for pattern in PATTERN_REGISTRY:
        for match in pattern.regex.finditer(text):
            # process match
"""

import re
from dataclasses import dataclass, field


@dataclass
class SecretPattern:
    """A single secret detection rule."""

    id: str  # Machine-readable ID, e.g. "aws_access_key"
    name: str  # Human-readable name, e.g. "AWS Access Key ID"
    description: str  # What this is and how to recognize it
    provider: str  # Service provider: "aws", "stripe", "github", "generic"
    severity: str  # "critical" | "high" | "medium" | "low"
    regex: re.Pattern  # Compiled regex with named capture groups
    confidence_base: float  # Starting confidence before context adjustment (0.0-1.0)
    entropy_threshold: float = 0.0  # Min Shannon entropy to pass (0.0 = skip entropy check)
    context_keywords: list[str] = field(default_factory=list)
    known_test_values: set[str] = field(default_factory=set)
    recommendation: str = ""
    tags: list[str] = field(default_factory=list)


# -----------------------------------------------
# Master registry -- all pattern modules append here
# -----------------------------------------------
PATTERN_REGISTRY: list[SecretPattern] = []


def register(*patterns: SecretPattern) -> None:
    """Add patterns to the global registry."""
    PATTERN_REGISTRY.extend(patterns)
