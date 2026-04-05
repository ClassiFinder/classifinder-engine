"""
ClassiFinder — Pre-scan Decoders for Encoded Secrets

Decodes base64-encoded substrings before scanning. Secrets commonly appear
base64-encoded in Kubernetes secrets, CI/CD configs, Docker .env files,
and Terraform state files.

Single-pass only (no chaining). This catches the vast majority of real-world
encoded secrets without the complexity of recursive decoding.
"""

import base64
import re


# Match base64 strings of 20+ chars (real secrets are rarely shorter when encoded)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/\-_]{20,}={0,3}")


def decode_base64_segments(text: str) -> list[tuple[str, int, int]]:
    """Find and decode base64 segments in text.

    Returns list of (decoded_text, original_start, original_end).
    Only returns segments that:
    - Successfully decode with standard or URL-safe base64
    - Produce printable ASCII output
    - Are at least 10 chars decoded (avoids noise)
    """
    results: list[tuple[str, int, int]] = []
    for match in _BASE64_RE.finditer(text):
        candidate = match.group()
        decoded = _try_decode(candidate)
        if decoded is not None:
            results.append((decoded, match.start(), match.end()))
    return results


def _try_decode(candidate: str) -> str | None:
    """Attempt base64 decode with standard and URL-safe variants."""
    padded = candidate + "=" * (-len(candidate) % 4)

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded_bytes = decoder(padded)
            decoded_str = decoded_bytes.decode("ascii")
            if len(decoded_str) >= 10 and decoded_str.isprintable():
                return decoded_str
        except Exception:
            continue
    return None
