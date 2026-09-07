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
    # Format per RFC 7519 (JSON Web Token).
    #   https://datatracker.ietf.org/doc/html/rfc7519
    # eyJ is the base64url encoding of '{"', the start of every JWT header.
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
    # Format per RFC 6750 (OAuth 2.0 Authorization Framework: Bearer Token Usage).
    #   https://datatracker.ietf.org/doc/html/rfc6750#section-2.1
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
    # Format per RFC 7617 (HTTP Basic Authentication Scheme).
    #   https://datatracker.ietf.org/doc/html/rfc7617
    # The encoded portion is base64(username:password).
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
    # Independently authored — common environment-variable naming conventions
    # for opaque API credentials. Variable names compiled from the most popular
    # public SDK quickstart docs (no single canonical source).
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
    # Tuned 2026-05-20 from 3.0 → 4.0 per benchmark-results-2026-05-19.md.
    # Baseline run surfaced 2168 mid-band findings (0.65-0.79 confidence);
    # 81% had entropy <4.0 — overwhelmingly fake/test/template values that
    # the existing -0.50 penalty now demotes below the default 0.5 threshold.
    # Parallels the April 2026 win on generic_high_entropy (3.0 → 4.5 there;
    # leaving this slightly more permissive at 4.0 since the env-var assignment
    # is a stronger structural signal than the keyword-context anchor).
    # See tasks/Finished Tasks/2026-05-20-tune-generic-api-key-env-entropy-threshold.md.
    entropy_threshold=4.0,  # must have reasonable entropy
    # Promote real-looking findings: length ≥32 AND entropy ≥5.0 adds +0.15,
    # pushing 0.69 → 0.84 so strict-threshold users (min_confidence=0.8)
    # surface them. Closes the recall gap surfaced in
    # benchmark-results-2026-05-19.md (208 long+high-entropy matches sat at
    # 0.65-0.79 despite looking like real keys). See
    # classifinder-knowledge/tasks/Finished Tasks/
    # 2026-05-20-add-length-entropy-bonus-for-generic-patterns.md.
    #
    # Tuned 2026-05-29 from (32, 4.5) → (32, 5.0). The original 4.5 floor
    # over-promoted documentation placeholders: the 2026-05-29 benchmark
    # spot-check found 17 newly-high-conf findings, of which 11 were in
    # docs (.md/.txt/.ipynb) and 7 sat in the 4.5–5.0 entropy band —
    # the canonical README quickstart shape (32-50 chars, 25-30 distinct
    # alphanumerics, entropy ~4.7-4.9). Real random base64/alnum keys
    # cluster at entropy ≥5.5, so the ≥5.0 floor preserves the promotion
    # of genuinely high-entropy candidates while demoting the doc cohort.
    # See classifinder-knowledge/tasks/Finished Tasks/
    # 2026-05-29-doc-context-tuning-for-generic-api-key-env.md and
    # benchmark-results-2026-05-19.md §"Post-batch spot-check ... 2026-05-29".
    length_entropy_bonus_threshold=(32, 5.0),
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
    # Independently authored — catch-all keyword-anchored high-entropy probe.
    # No external source: this is the lowest-confidence rule, gated by entropy
    # and context keywords to suppress prose / hashes / IDs.
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


# ===================================================
# BCRYPT PASSWORD HASH (2026-09-07)
# ===================================================

# THIS IS A HASH, NOT A LIVE CREDENTIAL, AND THE WHOLE ENTRY IS BUILT AROUND
# THAT. A bcrypt digest grants nothing when presented to anything: it is a
# verifier, not a bearer token. Its value to an attacker is entirely offline —
# and its value to the person reading the finding is as a SIGNAL: a bcrypt hash
# in source, in a fixture, in a config file or in a pasted log means either a
# leaked password table or a hardcoded administrative credential, and both are
# worth knowing about. Severity is therefore medium, deliberately, and the
# description and recommendation are written so neither implies an immediate
# compromise. Overstating this would be worse than missing it.
#
# Registered in the GENERIC module rather than a new one. The generic module is
# where the registry keeps the provider-agnostic structural formats — JWT,
# Basic auth headers — which is exactly what a bcrypt hash is: a credential
# shape with no vendor behind it. A dedicated 'hash' module would mean a new
# registry import and a new corpus category for a single member; the 'hash' tag
# carries that grouping instead, and a second hash format can join it here.
#
# The format is fully fixed and therefore highly precise on its own: '$2' + one
# of the four minor-version letters + '$' + a two-digit cost + '$' + a 22-
# character base64 salt and a 31-character digest in bcrypt's own './A-Za-z0-9'
# alphabet, 53 together, 60 characters in total, always. There is no length
# range and no entropy gate because there is no variation to accommodate.
#
# The canonical published sample (the one in passlib's documentation, which is
# reproduced across the entire ecosystem) is pinned as a known test value: at
# confidence_base 0.95 the FP wordlist never runs, so without the pin it would
# be a permanent high-confidence finding in every tutorial that quotes it.

BCRYPT_PASSWORD_HASH = SecretPattern(
    id="bcrypt_password_hash",
    name="bcrypt Password Hash",
    description=(
        "A bcrypt password hash — '$2a$', '$2b$', '$2x$' or '$2y$', a two-digit"
        " cost factor, then a 22-character salt and 31-character digest, 60"
        " characters in total. This is a one-way hash, not a usable"
        " credential: it authenticates nothing on its own. It matters as a"
        " signal — a bcrypt hash in source, in a fixture or in a pasted log"
        " usually means a leaked password table or a hardcoded administrative"
        " password, and a low-cost hash of a weak password is crackable"
        " offline."
    ),
    provider="generic",
    severity="medium",
    # Format per the bcrypt modular-crypt specification as documented by
    # passlib: '$2[abxy]$' + a two-digit cost + '$' + 22 characters of salt and
    # 31 of digest in bcrypt's './A-Za-z0-9' alphabet, 60 characters in total.
    # Guards, confidence and known_test_values are ClassiFinder's own.
    # Source: https://passlib.readthedocs.io/en/stable/lib/passlib.hash.bcrypt.html
    regex=re.compile(
        r"(?<![./A-Za-z0-9$])"
        r"(?P<secret>\$2[abxy]\$[0-9]{2}\$[./A-Za-z0-9]{53})"
        r"(?![./A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # the format is fully fixed; there is nothing to gate
    context_keywords=[
        "bcrypt",
        "password",
        "password_hash",
        "hashed_password",
        "htpasswd",
        "users",
        "credentials",
    ],
    known_test_values={
        # The canonical published bcrypt sample. It appears verbatim in
        # passlib's documentation and is reproduced across the ecosystem, so
        # without this pin it would be a permanent high-confidence finding in
        # tutorials. Assembled by concatenation, per repository convention.
        "$2b$12$" + "R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
        # The same salt and digest also circulate under the older '$2a$'
        # identifier — that form is the one reproduced in most tutorials, so
        # pin it too or the commoner of the two stays a high-confidence hit.
        "$2a$12$" + "R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
        # All-same-character digests, the usual redaction masks.
        "$2a$10$" + "x" * 53,
        "$2y$10$" + "0" * 53,
    },
    recommendation=(
        "This is a hash, so nothing is directly usable with it — do not treat"
        " it as an active credential. Do treat it as an exposure: work out"
        " whose password it is, force a reset for that account, and remove the"
        " hash from source control and from any log or fixture that carries"
        " it. If it came from a database dump, handle it as a password-table"
        " leak and reset every affected account. Check the cost factor: a hash"
        " below about cost 10 is meaningfully cheaper to crack offline, and a"
        " '$2a$' or '$2x$' prefix indicates an old implementation worth"
        " re-hashing at a higher cost."
    ),
    tags=["generic", "hash", "password", "bcrypt"],
)


register(
    JWT_TOKEN,
    BEARER_TOKEN,
    BASIC_AUTH_HEADER,
    GENERIC_API_KEY_ENV,
    GENERIC_HIGH_ENTROPY,
    # 2026-09-07 — bcrypt password hash. A verifier, not a bearer
    # credential: severity medium, and the first 'hash'-tagged pattern.
    BCRYPT_PASSWORD_HASH,
)
