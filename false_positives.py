"""
ClassiFinder — False Positive Detection

Checks raw secret values against known false positive patterns: a hardcoded
default list of common junk strings plus an external wordlist of programming
terms, placeholder names, and documentation patterns.

Used by the scanner as a post-match confidence penalty for findings that
contain known false positive terms.

Provenance: independently authored. The wordlist (data/fp_wordlist.txt) and
the DEFAULT_FALSE_POSITIVES set below were curated by hand. The lookup
implementation is a plain substring scan, not Aho-Corasick. Audited
2026-04-07 against TruffleHog's wordlists; overlap was limited to universal
English/programming keywords. See ATTRIBUTION.md.
"""

from functools import lru_cache
from pathlib import Path

# Common junk strings that appear in example code, docs, and placeholder configs.
# Checked via substring match against the lowercased raw value.
DEFAULT_FALSE_POSITIVES: frozenset[str] = frozenset({
    "example",
    "xxxxxx",
    "aaaaaa",
    "000000",
    "sample",
    "*****",
    "changeme",
    "redacted",
    "placeholder",
    "foobar",
    "your_api_key",
    "insert_key_here",
    "replace_me",
})


@lru_cache(maxsize=1)
def _load_wordlist() -> frozenset[str]:
    """Load fp_wordlist.txt from the data/ directory next to this module."""
    wordlist_path = Path(__file__).parent / "data" / "fp_wordlist.txt"
    if not wordlist_path.exists():
        return frozenset()
    words: set[str] = set()
    for line in wordlist_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip().lower()
        if stripped and not stripped.startswith("#"):
            words.add(stripped)
    return frozenset(words)


def is_known_false_positive(raw_value: str) -> tuple[bool, str]:
    """Check if a raw secret value is a known false positive.

    Returns a (is_fp, reason) tuple. The caller should apply a confidence
    penalty when is_fp is True.

    Only intended for findings with confidence < 0.85 — prefix-anchored
    patterns are trustworthy enough to skip this check.
    """
    # Reject non-UTF-8
    try:
        raw_value.encode("utf-8")
    except UnicodeEncodeError:
        return True, "invalid utf-8"

    lower = raw_value.lower()

    # Check default list (substring match)
    for fp in DEFAULT_FALSE_POSITIVES:
        if fp in lower:
            return True, f"contains '{fp}'"

    # Check wordlist (substring match)
    for word in _load_wordlist():
        if word in lower:
            return True, f"contains wordlist term '{word}'"

    return False, ""
