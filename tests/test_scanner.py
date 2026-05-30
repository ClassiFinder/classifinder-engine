"""Tests for the core scan() function."""

from classifinder_engine.scanner import Finding, scan

# ── Empty / no-match inputs ──────────────────────────────────────────────


def test_empty_string_returns_empty():
    assert scan("") == []


def test_whitespace_only_returns_empty():
    assert scan("   \n\t  ") == []


def test_no_secrets_returns_empty():
    assert scan("Hello world, no secrets here. Just a regular sentence.") == []


# ── Detection ────────────────────────────────────────────────────────────


def test_detects_aws_access_key():
    # Use a non-test-value key (test values get confidence overridden to 0.15).
    # Body is clearly-synthetic alphabet (16 letters) to satisfy AKIA[A-Z0-9]{16}
    # without tripping GitHub's secret scanner.
    findings = scan("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP")
    types = [f.type for f in findings]
    assert "aws_access_key" in types


def test_detects_github_pat_classic():
    findings = scan("GITHUB_TOKEN=ghp_ABCDEFghijklMNOP1234567890abcdefghij")
    types = [f.type for f in findings]
    assert "github_pat_classic" in types


def test_detects_stripe_live_key():
    # Build key at runtime to avoid GitHub push protection false positive
    prefix = "sk_live_"
    findings = scan(f"STRIPE_KEY={prefix}{'0' * 32}")
    types = [f.type for f in findings]
    assert "stripe_live_secret_key" in types


def test_square_access_token_high_conf_with_context():
    """Square token in code (with SQUARE_ACCESS_TOKEN variable name or
    'square'/'access_token' nearby) should reach high confidence (>=0.80)."""
    text = 'SQUARE_ACCESS_TOKEN = "EAAAEABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-abcdefghi"'
    findings = scan(text, min_confidence=0.1)
    square = [f for f in findings if f.type == "square_access_token"]
    assert len(square) == 1
    assert square[0].confidence >= 0.80


def test_square_access_token_demoted_without_context():
    """Bare EAA-prefixed base64 (common in notebook image/data payloads) must
    NOT be high-confidence — needs context to be promoted. Locks in the fix
    documented in benchmark-results-2026-05-19.md (4560 notebook FPs)."""
    text = '"output_data": "EAAxA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6a7b8c9d0e1f2g3h4"'
    findings = scan(text, min_confidence=0.1)
    square = [f for f in findings if f.type == "square_access_token"]
    assert len(square) == 1
    assert square[0].confidence < 0.80


def test_generic_api_key_env_low_entropy_drops_below_default():
    """Low-entropy values in API_KEY= assignments (template/test strings) must
    drop below the default 0.5 threshold. Locks in the entropy threshold raise
    from 3.0 → 4.0 (benchmark-results-2026-05-19.md showed 81% of mid-band
    findings had entropy <4.0 — overwhelmingly fake/test content)."""
    # Entropy ~3.91 — currently passes 3.0 threshold; after threshold raises to
    # 4.0 the -0.50 penalty drops it from ~0.67 to ~0.17.
    text = "ACCESS_TOKEN=abc_def_ghi_jkl123"
    findings = scan(text, min_confidence=0.01)
    gk = [f for f in findings if f.type == "generic_api_key_env"]
    assert len(gk) == 1
    assert gk[0].confidence < 0.50


def test_generic_api_key_env_high_entropy_stays_visible():
    """Real-looking high-entropy values (≥4.5) must remain visible at the
    default 0.5 threshold — no recall regression from the entropy tuning."""
    text = "API_KEY=aB3xKp9LqVnT5mFw8zRy7sCdEhJ2gNiMbOvUyXr1Q4tHcW"
    findings = scan(text, min_confidence=0.01)
    gk = [f for f in findings if f.type == "generic_api_key_env"]
    assert len(gk) == 1
    assert gk[0].confidence >= 0.50


def test_generic_api_key_env_long_high_entropy_promoted_to_high_band():
    """Long (≥32 chars) AND high-entropy (≥4.5) values must reach high-band
    confidence (≥0.80) so they surface to strict-threshold users (min_conf=0.8).
    Closes the recall gap from
    classifinder-knowledge/tasks/Finished Tasks/
    2026-05-20-add-length-entropy-bonus-for-generic-patterns.md
    where 208 baseline findings sat at 0.65-0.79 despite looking real."""
    # 46 chars, entropy ~5.48 — squarely in the "real-looking key" zone
    text = "API_KEY=aB3xKp9LqVnT5mFw8zRy7sCdEhJ2gNiMbOvUyXr1Q4tHcW"
    findings = scan(text, min_confidence=0.01)
    gk = [f for f in findings if f.type == "generic_api_key_env"]
    assert len(gk) == 1
    assert gk[0].confidence >= 0.80, (
        f"Long+high-entropy generic finding should reach high-band, "
        f"got {gk[0].confidence}"
    )


def test_generic_api_key_env_short_high_entropy_stays_midband():
    """Short (<32 chars) high-entropy values must stay mid-band — the bonus
    is a two-axis gate (length AND entropy), neither alone is sufficient."""
    # 22 chars, entropy ~4.46 — high entropy but short
    text = "API_KEY=aB3xKp9LqVnT5mFw8zRy7s"
    findings = scan(text, min_confidence=0.01)
    gk = [f for f in findings if f.type == "generic_api_key_env"]
    assert len(gk) == 1
    assert gk[0].confidence < 0.80, (
        f"Short high-entropy generic finding must NOT receive the length "
        f"bonus, got {gk[0].confidence}"
    )
    assert gk[0].confidence >= 0.50, (
        f"Short high-entropy generic finding should still be mid-band-visible, "
        f"got {gk[0].confidence}"
    )


def test_generic_api_key_env_doc_band_entropy_stays_midband():
    """Long values with mid-band entropy (4.5 ≤ H < 5.0) — the canonical
    doc-example shape — must NOT be promoted to high-band. The 2026-05-29
    benchmark spot-check (benchmark-results-2026-05-19.md §"Post-batch
    spot-check") found that 4 of 7 findings in this entropy band were docs
    (.md / .txt / .ipynb README placeholders). Raising the bonus floor from
    4.5 → 5.0 demotes them while preserving the ≥5.0 cohort that contains
    the more random-looking real-key candidates.

    See classifinder-knowledge/tasks/Finished Tasks/
    2026-05-29-doc-context-tuning-for-generic-api-key-env.md."""
    # 40 chars, entropy ~4.82: 20 letters (a-t, each 1x) + 10 digits (each 2x).
    # Representative of README-style synthetic placeholder tokens.
    text = "API_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
    findings = scan(text, min_confidence=0.01)
    gk = [f for f in findings if f.type == "generic_api_key_env"]
    assert len(gk) == 1
    assert gk[0].confidence < 0.80, (
        f"Doc-band-entropy generic finding (length≥32, 4.5≤H<5.0) must NOT "
        f"receive the length+entropy bonus, got {gk[0].confidence}"
    )
    assert gk[0].confidence >= 0.50, (
        f"Doc-band-entropy finding should still be mid-band-visible to default "
        f"min_confidence=0.5 users, got {gk[0].confidence}"
    )


def test_length_entropy_bonus_is_opt_in_per_pattern():
    """Patterns that don't set length_entropy_bonus_threshold must not receive
    the bonus, even on long+high-entropy matches. Confirms the bonus is
    strictly opt-in and doesn't leak to prefix-anchored patterns that already
    work well at their authored confidence."""
    # AWS access key is prefix-anchored at 0.95 base, doesn't opt in
    text = "AKIAIOSFODNN7EXAMPLE"  # in aws_access_key.known_test_values → 0.15
    findings = scan(text, min_confidence=0.01)
    # is_test path overrides — confirm it still gets the 0.15 test-value cap,
    # not bumped by any bonus.
    aws = [f for f in findings if f.type == "aws_access_key"]
    assert len(aws) == 1
    assert aws[0].confidence <= 0.20, (
        f"Test-value cap (0.15) must still hold for non-opting-in patterns, "
        f"got {aws[0].confidence}"
    )


def test_specific_pattern_beats_generic_at_overlapping_span():
    """When a specific provider pattern (e.g., cohere_api_key) and the
    catch-all generic_api_key_env both match the same span, the specific
    reading must win regardless of confidence. The length+entropy bonus can
    push generic above some specific patterns' post-context confidence; the
    dedup tweak enforces 'specific over generic' to preserve attribution
    accuracy. See
    classifinder-knowledge/tasks/Finished Tasks/
    2026-05-20-add-length-entropy-bonus-for-generic-patterns.md."""
    text = "COHERE_API_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
    findings = scan(text)
    cohere = [f for f in findings if f.type == "cohere_api_key"]
    generic = [f for f in findings if f.type == "generic_api_key_env"]
    assert len(cohere) == 1, (
        f"cohere_api_key must win the overlapping span; got types: "
        f"{[f.type for f in findings]}"
    )
    assert len(generic) == 0, (
        "generic_api_key_env must be suppressed when a specific provider "
        "pattern matches the same span"
    )


def test_detects_generic_jwt():
    # Standard example JWT — use types filter since generic_high_entropy can win dedup
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    findings = scan(f"token={jwt}", types=["jwt_token"], min_confidence=0.0)
    assert len(findings) >= 1
    assert findings[0].type == "jwt_token"


# ── Finding structure ────────────────────────────────────────────────────


def test_finding_has_correct_fields():
    findings = scan("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP")
    assert len(findings) >= 1
    f = next(f for f in findings if f.type == "aws_access_key")
    assert isinstance(f, Finding)
    assert isinstance(f.id, str)
    assert isinstance(f.confidence, float)
    assert isinstance(f.span_start, int)
    assert isinstance(f.span_end, int)
    assert f.severity in {"critical", "high", "medium", "low"}
    assert "****" in f.value_preview  # masked


# ── Filters ──────────────────────────────────────────────────────────────


def test_type_filter():
    text = (
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE "
        "GITHUB_TOKEN=ghp_ABCDEFghijklMNOP1234567890abcdefghij"
    )
    findings = scan(text, types=["aws_access_key"])
    assert all(f.type == "aws_access_key" for f in findings)


def test_min_confidence_filter():
    # Known test value gets confidence overridden to 0.15
    findings = scan("AKIAIOSFODNN7EXAMPLE", min_confidence=0.5)
    # This is a known test value — should be filtered out at 0.5 threshold
    aws = [f for f in findings if f.type == "aws_access_key"]
    assert len(aws) == 0


# ── Context ──────────────────────────────────────────────────────────────


def test_context_included_by_default():
    findings = scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", min_confidence=0.0)
    aws = [f for f in findings if f.type == "aws_access_key"]
    assert len(aws) == 1
    assert aws[0].context is not None


def test_context_excluded_when_disabled():
    findings = scan(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        include_context=False,
        min_confidence=0.0,
    )
    aws = [f for f in findings if f.type == "aws_access_key"]
    assert len(aws) == 1
    assert aws[0].context is None


# ── Dedup & ordering ────────────────────────────────────────────────────


def test_findings_sorted_by_position():
    text = "end=ghp_ABCDEFghijklMNOP1234567890abcdefghij start=AKIAIOSFODNN7EXAMPLE"
    findings = scan(text, min_confidence=0.0)
    positions = [f.span_start for f in findings]
    assert positions == sorted(positions)


def test_known_test_value_gets_low_confidence():
    # AKIAIOSFODNN7EXAMPLE is a known test value
    findings = scan("AKIAIOSFODNN7EXAMPLE", min_confidence=0.0)
    aws = [f for f in findings if f.type == "aws_access_key"]
    assert len(aws) == 1
    assert aws[0].confidence <= 0.20
    assert aws[0].is_likely_test_value is True
