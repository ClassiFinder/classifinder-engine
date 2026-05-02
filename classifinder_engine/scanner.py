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

import bisect
from dataclasses import dataclass

from .decoders import decode_base64_segments
from .entropy import shannon_entropy
from .false_positives import is_known_false_positive

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
    encoding: str | None = None


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
    _depth: int = 0,
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

    # Decode base64 segments only at the top level. The recursive call below
    # passes _depth=1 and skips this — enforcing the "single-pass only"
    # contract documented in decoders.py and preventing exponential blow-up
    # on nested base64 inputs.
    decoded_segments = decode_base64_segments(text) if _depth == 0 else []

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

            # False positive wordlist penalty (only for lower-confidence patterns)
            if confidence < 0.85:
                fp_match, _fp_reason = is_known_false_positive(secret_value)
                if fp_match:
                    confidence -= 0.40

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

    # -- Scan decoded base64 segments for secrets (single-pass: _depth=1) --
    for decoded_text, orig_start, orig_end in decoded_segments:
        decoded_findings = scan(
            decoded_text, types=types,
            min_confidence=min_confidence, include_context=False,
            _depth=_depth + 1,
        )
        for df in decoded_findings:
            finding_counter += 1
            raw_findings.append(Finding(
                id=f"f_{finding_counter:03d}",
                type=df.type,
                type_name=df.type_name,
                provider=df.provider,
                severity=df.severity,
                confidence=df.confidence,
                value_preview=df.value_preview,
                span_start=orig_start,
                span_end=orig_end,
                context=(_extract_context(text, orig_start, orig_end) if include_context else None),
                is_likely_test_value=df.is_likely_test_value,
                recommendation=df.recommendation,
                matched_pattern=df.matched_pattern,
                encoding="base64",
            ))

    final_findings = _dedup_overlapping_findings(raw_findings)

    # Re-number IDs sequentially after dedup
    for i, f in enumerate(final_findings, 1):
        f.id = f"f_{i:03d}"

    return final_findings


def _dedup_overlapping_findings(raw_findings: list[Finding]) -> list[Finding]:
    """Greedy-by-confidence dedup: highest-confidence finding wins each overlap.

    Walks findings in (-confidence, span_start) order so the most reliable
    finding gets first claim on its span. For each candidate, checks for overlap
    against the already-accepted set in O(log F) via bisect on a span-sorted list
    of (start, end) tuples — only the immediate neighbors (predecessor and
    successor by span_start) can possibly overlap, since accepted intervals are
    non-overlapping by construction. Returns findings sorted ascending by
    span_start for downstream consumers (redactor, response serializer).

    Replaces an O(F^2) Python-level overlap loop. F can hit hundreds to
    thousands on long documents.
    """
    if not raw_findings:
        return []

    # Highest confidence wins; span_start is a stable tie-breaker.
    raw_findings.sort(key=lambda f: (-f.confidence, f.span_start))

    accepted_intervals: list[tuple[int, int]] = []  # (start, end), sorted by start, non-overlapping
    final_findings: list[Finding] = []

    for finding in raw_findings:
        s, e = finding.span_start, finding.span_end
        # Position where (s, ...) would slot in. Comparing against (s,) places us
        # before any interval whose start equals s, so we still detect overlap there.
        i = bisect.bisect_left(accepted_intervals, (s,))

        # Successor at i (start >= s): overlaps iff its start < e.
        if i < len(accepted_intervals) and accepted_intervals[i][0] < e:
            continue
        # Predecessor at i-1 (start < s): overlaps iff its end > s.
        if i > 0 and accepted_intervals[i - 1][1] > s:
            continue

        accepted_intervals.insert(i, (s, e))
        final_findings.append(finding)

    final_findings.sort(key=lambda f: f.span_start)
    return final_findings
