"""
ClassiFinder — Core Scanner Engine

Pure function: text in -> findings out. No I/O, no side effects, no state.

This module is the heart of the product. It:
1. Runs all registered patterns against the input text
2. Calculates entropy for matches that require it
3. Scores confidence using pattern base + context + entropy + test value checks
4. Deduplicates overlapping findings (keeps highest confidence)
5. Returns structured findings sorted by position

The scanner is designed to be called from both /scan and /redact endpoints.
The redactor is a separate module that takes scanner output and produces
sanitized text.
"""

from dataclasses import dataclass

from .entropy import shannon_entropy

# Import all pattern modules to trigger registration
from .patterns import (
    ai,  # noqa: F401 -- side effect: registers AI provider patterns
    cloud,  # noqa: F401 -- side effect: registers patterns
    comms,  # noqa: F401
    database,  # noqa: F401
    generic,  # noqa: F401
    payment,  # noqa: F401
    registry,
    vcs,  # noqa: F401
)
from .patterns.payment import _luhn_check


@dataclass
class Finding:
    """A single detected secret."""

    id: str
    type: str
    type_name: str
    provider: str
    severity: str
    confidence: float
    value_preview: str
    span_start: int
    span_end: int
    context: str | None
    is_likely_test_value: bool
    recommendation: str
    matched_pattern: str


def _mask_value(value: str) -> str:
    """
    Create a masked preview of a secret value.
    Shows first 4 and last 4 characters, masks the middle.
    Never returns the full value.
    """
    if len(value) <= 12:
        # Too short to preview safely -- show first 4 + mask
        return value[:4] + "****"
    return value[:4] + "****" + value[-4:]


def _extract_context(text: str, start: int, end: int, window: int = 40) -> str:
    """
    Extract a short snippet of text around a finding, with the
    secret itself masked. Used for human review.
    """
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)

    before = text[ctx_start:start]
    secret = text[start:end]
    after = text[end:ctx_end]

    masked = _mask_value(secret)

    prefix = "..." if ctx_start > 0 else ""
    suffix = "..." if ctx_end < len(text) else ""

    return f"{prefix}{before}{masked}{after}{suffix}"


def _context_boost(text: str, start: int, end: int, keywords: list[str]) -> float:
    """
    Check for context keywords within 50 characters of the match.
    Each keyword found adds +0.02 to confidence, max +0.10.
    """
    window_start = max(0, start - 50)
    window_end = min(len(text), end + 50)
    nearby_text = text[window_start:window_end].lower()

    boost = 0.0
    for keyword in keywords:
        if keyword.lower() in nearby_text:
            boost += 0.02

    return min(boost, 0.10)


def scan(
    text: str,
    types: list[str] | None = None,
    min_confidence: float = 0.5,
    include_context: bool = True,
) -> list[Finding]:
    """
    Scan text for secrets. Returns a list of findings sorted by span position.

    Args:
        text: The text to scan.
        types: Optional list of pattern IDs to filter to. None = all patterns.
        min_confidence: Minimum confidence threshold. Findings below this are excluded.
        include_context: Whether to include context snippets in findings.

    Returns:
        List of Finding objects, sorted by span_start.
    """
    if not text or not text.strip():
        return []

    raw_findings: list[Finding] = []
    finding_counter = 0

    for pattern in registry.PATTERN_REGISTRY:
        # Filter by type if specified
        if types and "all" not in types and pattern.id not in types:
            continue

        for match in pattern.regex.finditer(text):
            # Extract the secret value from the named group
            try:
                secret_value = match.group("secret")
            except IndexError:
                secret_value = match.group(0)

            span_start = match.start("secret") if "secret" in match.groupdict() else match.start()
            span_end = match.end("secret") if "secret" in match.groupdict() else match.end()

            # -- Confidence calculation --
            confidence = pattern.confidence_base

            # Context boost
            confidence += _context_boost(text, span_start, span_end, pattern.context_keywords)

            # Entropy penalty (generic patterns only)
            is_test = False
            if pattern.entropy_threshold > 0:
                entropy = shannon_entropy(secret_value)
                if entropy < pattern.entropy_threshold:
                    confidence -= 0.50  # heavy penalty for low entropy

            # Luhn validation (credit card patterns)
            if pattern.id == "credit_card_number":
                digits_only = "".join(ch for ch in secret_value if ch.isdigit())
                if not _luhn_check(digits_only):
                    confidence = 0.15  # fails checksum -- likely not a real card

            # Test value penalty
            if secret_value in pattern.known_test_values:
                confidence = 0.15
                is_test = True

            # Clamp
            confidence = max(0.05, min(0.99, round(confidence, 2)))

            # Skip if below threshold
            if confidence < min_confidence:
                continue

            finding_counter += 1
            finding = Finding(
                id=f"f_{finding_counter:03d}",
                type=pattern.id,
                type_name=pattern.name,
                provider=pattern.provider,
                severity=pattern.severity,
                confidence=confidence,
                value_preview=_mask_value(secret_value),
                span_start=span_start,
                span_end=span_end,
                context=(_extract_context(text, span_start, span_end) if include_context else None),
                is_likely_test_value=is_test,
                recommendation=pattern.recommendation,
                matched_pattern=f"{pattern.id}_v1",
            )
            raw_findings.append(finding)

    # -- Deduplication: overlapping spans --
    # Sort by confidence descending, then resolve overlaps
    raw_findings.sort(key=lambda f: (-f.confidence, f.span_start))

    final_findings: list[Finding] = []
    occupied_ranges: list[tuple] = []

    for finding in raw_findings:
        # Check if this finding overlaps with any already-accepted finding
        overlaps = False
        for occ_start, occ_end in occupied_ranges:
            if finding.span_start < occ_end and finding.span_end > occ_start:
                overlaps = True
                break

        if not overlaps:
            final_findings.append(finding)
            occupied_ranges.append((finding.span_start, finding.span_end))

    # Sort final results by position in text
    final_findings.sort(key=lambda f: f.span_start)

    # Re-number IDs sequentially after dedup
    for i, f in enumerate(final_findings, 1):
        f.id = f"f_{i:03d}"

    return final_findings
