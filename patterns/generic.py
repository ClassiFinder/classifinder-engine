"""
ClassiFinder — Generic & Auth Token Patterns

Catch-all patterns for JWT tokens, Bearer auth headers, generic API keys
in .env files, and high-entropy strings that look like secrets but don't
match a specific provider pattern.

Pattern design notes:
- Generic patterns have LOWER base confidence because they're format-based
  rather than prefix-based. Context boosting and entropy analysis matter
  more here than in provider-specific patterns.
- The generic high-entropy pattern is the most false-positive-prone rule
  in the entire library. It should always be the last resort -- if a
  provider-specific pattern already matched the same span, the generic
  match should be dropped by the deduplicator.
- JWT detection is reliable because the eyJ prefix is the base64 encoding
  of {"  which begins every JWT header.
"""

import re

from .registry import SecretPattern, register

# ===================================================
# JWT
# ===================================================

JWT_TOKEN = SecretPattern(
    id="jwt_token",
    name="JSON Web Token (JWT)",
    description=(
        "JWT token identified by the eyJ prefix (base64-encoded JSON header)"
        " and three dot-separated segments."
    ),
    provider="generic",
    severity="high",
    regex=re.compile(
        r"(?P<secret>"
        r"eyJ[A-Za-z0-9_-]{10,500}"  # header (base64url)
        r"\."
        r"[A-Za-z0-9_-]{10,1000}"  # payload (base64url)
        r"\."
        r"[A-Za-z0-9_-]{10,500}"  # signature (base64url)
        r")"
        r"(?![A-Za-z0-9_\-.])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,  # structural match
    context_keywords=[
        "jwt",
        "token",
        "bearer",
        "authorization",
        "auth",
        "session",
    ],
    known_test_values={
        # Standard JWT example from jwt.io
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    },
    recommendation=(
        "JWTs may contain sensitive claims (user ID, roles, permissions)."
        " If this token is still valid, revoke it or invalidate the"
        " signing key. Check the exp claim for expiration."
    ),
    tags=["auth", "jwt", "token"],
)


# ===================================================
# BEARER TOKEN IN HEADER
# ===================================================

BEARER_TOKEN = SecretPattern(
    id="bearer_token",
    name="Bearer Token in Authorization Header",
    description=(
        "Bearer token found in an Authorization header pattern."
        " The token itself could be any format (JWT, opaque, API key)."
    ),
    provider="generic",
    severity="high",
    regex=re.compile(
        r"(?:Authorization|authorization|AUTHORIZATION)"
        r"[\s]*[:=][\s]*"
        r"[\"']?"
        r"Bearer\s+"
        r"(?P<secret>[A-Za-z0-9_\-.]{20,500})"
        r"[\"']?",
        re.ASCII,
    ),
    confidence_base=0.88,
    entropy_threshold=2.5,
    context_keywords=[
        "authorization",
        "bearer",
        "header",
        "auth",
        "token",
    ],
    known_test_values=set(),
    recommendation=(
        "Rotate the token used in this Authorization header."
        " If it's an OAuth token, revoke it at the issuing provider."
    ),
    tags=["auth", "bearer", "header"],
)


# ===================================================
# BASIC AUTH
# ===================================================

BASIC_AUTH_HEADER = SecretPattern(
    id="basic_auth_header",
    name="Basic Auth Credentials in Header",
    description=("Base64-encoded username:password in a Basic authorization header."),
    provider="generic",
    severity="high",
    regex=re.compile(
        r"(?:Authorization|authorization|AUTHORIZATION)"
        r"[\s]*[:=][\s]*"
        r"[\"']?"
        r"Basic\s+"
        r"(?P<secret>[A-Za-z0-9+/]{8,256}={0,2})"
        r"[\"']?",
        re.ASCII,
    ),
    confidence_base=0.85,
    entropy_threshold=2.0,
    context_keywords=[
        "authorization",
        "basic",
        "header",
        "auth",
        "credentials",
    ],
    known_test_values={
        "dXNlcjpwYXNzd29yZA==",  # base64("user:password")
        "YWRtaW46YWRtaW4=",  # base64("admin:admin")
    },
    recommendation=(
        "Rotate the credentials encoded in this Basic auth header."
        " Switch to token-based authentication if possible."
    ),
    tags=["auth", "basic", "header"],
)


# ===================================================
# GENERIC ENV API KEYS
# ===================================================

GENERIC_API_KEY_ENV = SecretPattern(
    id="generic_api_key_env",
    name="Generic API Key in Environment Variable",
    description=(
        "API key, secret key, or access token assigned in an"
        " environment variable. Catches patterns like API_KEY=...,"
        " SECRET_KEY=..., ACCESS_TOKEN=... that don't match"
        " a specific provider."
    ),
    provider="generic",
    severity="medium",
    regex=re.compile(
        r"(?P<context_key>"
        r"(?:API_KEY|API_SECRET|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN"
        r"|APP_SECRET|APP_KEY|PRIVATE_KEY|CLIENT_SECRET|ENCRYPTION_KEY"
        r"|SIGNING_KEY|WEBHOOK_SECRET)"
        r")"
        r"[\s]*[=][\s]*[\"']?"
        r"(?P<secret>[A-Za-z0-9_\-/+=.]{16,256})"  # min 16 chars to reduce noise
        r"[\"']?",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.65,  # generic -- many false positives possible
    entropy_threshold=3.0,  # must have reasonable entropy
    context_keywords=[
        "api",
        "key",
        "secret",
        "token",
        "credential",
        "auth",
    ],
    known_test_values={
        "your-api-key-here",
        "your_api_key_here",
        "REPLACE_ME",
        "changeme",
        "xxxxxxxxxxxxxxxx",
        "test_key_do_not_use",
        "INSERT_YOUR_KEY_HERE",
        "TODO_REPLACE",
        "sk-xxxxxxxxxxxxxxxx",
    },
    recommendation=(
        "Identify the service this key belongs to and rotate it."
        " Use a secrets manager to inject API keys at runtime."
    ),
    tags=["auth", "env", "generic"],
)


# ===================================================
# GENERIC HIGH-ENTROPY STRING
# ===================================================

GENERIC_HIGH_ENTROPY = SecretPattern(
    id="generic_high_entropy",
    name="Generic High-Entropy String (possible secret)",
    description=(
        "A long, high-entropy alphanumeric string near context keywords"
        " suggesting it may be a secret."
        " This is the lowest-confidence catch-all pattern."
    ),
    provider="generic",
    severity="low",
    regex=re.compile(
        # Only match if preceded by a keyword suggesting this is a secret
        r"(?:"
        r"(?:key|token|secret|password|credential|api_key|apikey|auth)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9_\-/+=]{32,256})"
        r"(?![A-Za-z0-9_\-/+=])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.45,  # very low -- entropy check does the heavy lifting
    entropy_threshold=4.5,  # must be high entropy to survive
    context_keywords=[
        "key",
        "token",
        "secret",
        "password",
        "credential",
        "auth",
    ],
    known_test_values={
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "0000000000000000000000000000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "1234567890123456789012345678901234567890",
        "abcdefghijklmnopqrstuvwxyzabcdef",
        "testkeytestkeytestkeytestkeytestkey",
    },
    recommendation=(
        "This may be a secret or credential."
        " Identify what service it belongs to and verify"
        " whether it needs rotation."
    ),
    tags=["generic", "entropy"],
)


register(
    JWT_TOKEN,
    BEARER_TOKEN,
    BASIC_AUTH_HEADER,
    GENERIC_API_KEY_ENV,
    GENERIC_HIGH_ENTROPY,
)
