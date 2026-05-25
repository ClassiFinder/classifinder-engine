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
    # Opt-in length+entropy bonus. When set to (min_len, min_entropy),
    # matches whose secret_value has BOTH length ≥ min_len AND Shannon entropy
    # ≥ min_entropy receive +0.15 confidence. Designed to promote real-looking
    # generic findings (where prefix anchoring isn't available) to high-band
    # without distorting prefix-anchored patterns. See
    # classifinder-knowledge/tasks/Finished Tasks/
    # 2026-05-20-add-length-entropy-bonus-for-generic-patterns.md.
    length_entropy_bonus_threshold: tuple[int, float] | None = None
    context_keywords: list[str] = field(default_factory=list)
    known_test_values: set[str] = field(default_factory=set)
    recommendation: str = ""
    tags: list[str] = field(default_factory=list)
    safe_mcp_ids: list[str] = field(default_factory=list)  # SAFE-MCP technique IDs this pattern detects (e.g., ["SAFE-T1001", "SAFE-T1102"])


# -----------------------------------------------
# Master registry -- all pattern modules append here
# -----------------------------------------------
PATTERN_REGISTRY: list[SecretPattern] = []


def register(*patterns: SecretPattern) -> None:
    """Add patterns to the global registry."""
    PATTERN_REGISTRY.extend(patterns)


# -----------------------------------------------
# Eager pattern-module import — populate the registry at registry-module
# load time, not as a side effect of importing scanner.py.
#
# Imports are placed at the BOTTOM of the file (not the top) to break the
# circular dependency: each pattern module needs SecretPattern + register
# from this file, and those must be defined before pattern modules load.
#
# Before this change: `from registry import PATTERN_REGISTRY` returned an
# empty list unless something else had already imported a pattern module
# (typically via scanner.py). That was a footgun for tooling, standalone
# scripts, and test isolation. See:
# classifinder-knowledge/tasks/Finished Tasks/2026-05-19-promote-pattern-registry-to-eager-registration.md
from . import (  # noqa: E402, F401
    ai,
    cloud,
    comms,
    data,
    database,
    devops,
    generic,
    identity,
    payment,
    prompt_injection,
    vcs,
)
