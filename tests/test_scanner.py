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
    # Use a non-test-value key (test values get confidence overridden to 0.15)
    findings = scan("AWS_ACCESS_KEY_ID=AKIAZ3MHQWRSDHOF7EPN")
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
    findings = scan("AWS_ACCESS_KEY_ID=AKIAZ3MHQWRSDHOF7EPN")
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
