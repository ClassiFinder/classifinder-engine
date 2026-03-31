"""
SecretSweep — Shannon Entropy Calculator

Calculates Shannon entropy of a string to help distinguish real secrets
(high entropy, random-looking) from false positives (low entropy,
repetitive or patterned strings).

Shannon entropy for a string of base64/hex characters:
- Random 40-char hex string:   ~3.9 to 4.0 bits
- Random 40-char base64:       ~5.0 to 5.5 bits
- "aaaaaaaaaaaaaaaaaaaaaa":    0.0 bits
- "abcabcabcabcabcabcabc":    ~1.58 bits
- "password1234567890123":     ~3.7 bits (borderline)

Typical thresholds used in our patterns:
- 0.0 = skip entropy check (prefix-anchored patterns don't need it)
- 1.5 = very permissive (catches most non-trivial strings)
- 3.0 = moderate (filters obvious patterns and repetition)
- 3.5 = strict (most real secrets pass, most false positives don't)
- 4.0 = very strict (only high-quality random strings)
"""

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string in bits.

    Returns 0.0 for empty strings or single-character strings.
    Maximum theoretical entropy for a string of length N with
    K distinct characters is log2(K).
    """
    if len(s) <= 1:
        return 0.0

    counts = Counter(s)
    length = len(s)

    entropy = 0.0
    for count in counts.values():
        if count == 0:
            continue
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)
