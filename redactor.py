"""
ClassiFinder — Text Redactor

Takes scanner findings and produces a sanitized version of the input text
with all detected secrets replaced. Supports three redaction styles:

- "label":  [AWS_ACCESS_KEY_REDACTED]
- "mask":   AKIA**************
- "hash":   [REDACTED:sha256:a1b2c3d4]  (first 8 chars of hash, for dedup)

The redactor works backwards through the text (highest span first) so that
replacing one secret doesn't shift the character offsets of earlier secrets.
"""

import hashlib

from .scanner import Finding


def _mask_value_for_redaction(original_text: str, start: int, end: int) -> str:
    """
    Create a masked version preserving first 4 chars and replacing rest with *.
    """
    value = original_text[start:end]
    if len(value) <= 4:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 4)


def _hash_value(original_text: str, start: int, end: int) -> str:
    """
    Create a hash-based redaction label for deduplication across scans.
    """
    value = original_text[start:end]
    h = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"[REDACTED:sha256:{h}]"


def _label_for_type(secret_type: str) -> str:
    """
    Generate a human-readable redaction label from the secret type ID.
    e.g., "aws_access_key" -> "[AWS_ACCESS_KEY_REDACTED]"
    """
    return f"[{secret_type.upper()}_REDACTED]"


def redact(
    text: str,
    findings: list[Finding],
    style: str = "label",
) -> tuple[str, list[dict[str, str]]]:
    """
    Produce a redacted version of the input text.

    Args:
        text: Original text.
        findings: List of findings from the scanner.
        style: "label", "mask", or "hash".

    Returns:
        Tuple of (redacted_text, redaction_map) where redaction_map
        is a list of dicts with finding_id and redacted_as fields.
    """
    if not findings:
        return text, []

    # Sort findings by span_start descending so we replace from end to start
    sorted_findings = sorted(findings, key=lambda f: f.span_start, reverse=True)

    redacted = text
    redaction_map = []

    for finding in sorted_findings:
        start = finding.span_start
        end = finding.span_end

        if style == "mask":
            replacement = _mask_value_for_redaction(text, start, end)
        elif style == "hash":
            replacement = _hash_value(text, start, end)
        else:  # "label" (default)
            replacement = _label_for_type(finding.type)

        redacted = redacted[:start] + replacement + redacted[end:]

        redaction_map.append(
            {
                "finding_id": finding.id,
                "redacted_as": replacement,
            }
        )

    # Reverse the map so it's in text-order (we built it backwards)
    redaction_map.reverse()

    return redacted, redaction_map
