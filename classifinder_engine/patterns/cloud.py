"""
ClassiFinder — Cloud Provider Patterns

Patterns for AWS, GCP, Azure, DigitalOcean, Heroku, and Cloudflare credentials.
These are the highest-severity detections -- leaked cloud keys can result in
immediate financial damage (crypto mining, data exfiltration, service abuse).

Pattern design notes:
- AWS Access Key IDs always start with AKIA (active keys) or ASIA (STS temp keys).
  Older prefixes like AIDA, AROA are for internal identifiers, not access keys.
- AWS Secret Keys are 40-char base64 strings. No prefix, so we rely on context
  (nearby AKIA match or env var names like AWS_SECRET_ACCESS_KEY).
- GCP API keys start with AIza, always 39 chars.
- GCP service account keys are JSON blocks with a "private_key" field containing
  a PEM-encoded RSA key. We detect the JSON fragment pattern.
"""

import re

from .registry import SecretPattern, register

# ===================================================
# AWS
# ===================================================

AWS_ACCESS_KEY = SecretPattern(
    id="aws_access_key",
    name="AWS Access Key ID",
    description=(
        "AWS IAM access key, 20 characters starting with AKIA (permanent) or ASIA (temporary STS)."
    ),
    provider="aws",
    severity="critical",
    # Vendor-published format — AKIA/ASIA prefix is AWS-documented IAM key format
    regex=re.compile(
        r"(?P<secret>(?:AKIA|ASIA)[0-9A-Z]{16,20})"
        r"(?![0-9A-Za-z])",  # negative lookahead: must not be followed by more alnum
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # prefix-anchored, no entropy check needed
    context_keywords=[
        "aws",
        "access_key",
        "access-key",
        "AWS_ACCESS_KEY_ID",
        "credential",
        "iam",
    ],
    known_test_values={
        "AKIAIOSFODNN7EXAMPLE",
        "AKIAI44QH8DHBEXAMPLE",
        "ASIAJEXAMPLEXEG2JICEA",
    },
    recommendation=(
        "Rotate this key immediately in the AWS IAM console."
        " Audit its usage via CloudTrail."
        " If paired with a secret key, rotate both."
    ),
    tags=["cloud", "aws", "iam"],
)


AWS_SECRET_KEY = SecretPattern(
    id="aws_secret_key",
    name="AWS Secret Access Key",
    description=(
        "AWS IAM secret access key, 40-character base64 string."
        " Usually paired with an access key ID."
    ),
    provider="aws",
    severity="critical",
    # Vendor-published format — context-gated 40-char base64; AWS-documented credential
    regex=re.compile(
        # Match when preceded by common env var names or config keys
        r"(?:"
        r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey|secret_access_key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9/+=]{40})"
        r"(?![A-Za-z0-9/+=])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=3.5,  # real keys have high entropy; filter out padding strings
    context_keywords=["aws", "secret", "access_key", "credential", "iam"],
    known_test_values={
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
    },
    recommendation=(
        "Rotate this secret key immediately in AWS IAM."
        " If the corresponding access key ID is also exposed, rotate both."
    ),
    tags=["cloud", "aws", "iam"],
)


AWS_STS_SESSION_TOKEN = SecretPattern(
    id="aws_sts_session_token",
    name="AWS STS Session Token",
    description=(
        "AWS STS temporary session token — the third component of a temporary"
        " credential triple, alongside an ASIA access key ID and a 40-character"
        " secret access key. A base64 blob whose leading bytes are a fixed"
        " binary header, which is what makes the base64 prefix deterministic."
    ),
    provider="aws",
    severity="critical",
    # The header literals decode to fixed protobuf bytes, so this is
    # prefix-anchored rather than format-only:
    #   IQoJb3JpZ2luX2Vj  -> 21 0a 09 'origin_ec'  (v2, current, dominant)
    #   FwoGZXIvYXdz      -> 17 0a 06 'er/aws'     (v1, legacy)
    #   FQoGZXIvYXdz      -> 15 0a 06 'er/aws'     (v1, legacy)
    #   AQoDYXdz          -> 01 0a 03 'aws'        (legacy; AWS's own sample)
    # All four are byte-aligned (16/12/12/8 base64 chars = 12/9/9/6 bytes), so
    # there is no partial-byte bleed and the prefixes cannot drift. No entropy
    # gate for the same reason the AKIA/ASIA pattern has none. The upper bound
    # is deliberately open: AWS states the token size "is not fixed" and that
    # callers should "make no assumptions about the maximum size". The charset
    # excludes newlines because AWS's own XML and JSON samples hard-wrap tokens.
    # Vendor-published format — SessionToken in the AWS STS AssumeRole API Reference
    regex=re.compile(
        r"(?<![A-Za-z0-9+/])"
        r"(?P<secret>"
        r"(?:IQoJb3JpZ2luX2Vj|F[wQ]oGZXIvYXdz|AQoDYXdz)"
        r"[A-Za-z0-9+/]{100,}"
        r"={0,2}"
        r")"
        r"(?![A-Za-z0-9+/=])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # prefix-anchored, no entropy check needed
    context_keywords=[
        "aws",
        "sts",
        "session_token",
        "AWS_SESSION_TOKEN",
        "SessionToken",
        "security_token",
        "assume-role",
        "credential",
    ],
    known_test_values={
        # AWS's own AssumeRole sample response, joined from the five wrapped
        # lines the API Reference prints. Assembled by concatenation so no
        # scannable AWS-credential literal exists in source.
        "AQoD"
        + "YXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW"
        + "LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd"
        + "QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU"
        + "9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz"
        + "+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==",
    },
    recommendation=(
        "This is a temporary credential and cannot be rotated. Revoke the role"
        " session immediately: attach an inline Deny policy scoped to"
        " aws:TokenIssueTime (the AWSRevokeOlderSessions action in the IAM"
        " console does this for you). Then audit the session's activity in"
        " CloudTrail and rotate the long-lived credentials or identity"
        " provider secret that was used to obtain it -- whoever holds those"
        " can simply mint a replacement token."
    ),
    tags=["cloud", "aws", "iam", "sts", "temporary-credentials"],
)


# ===================================================
# GCP
# ===================================================

GCP_API_KEY = SecretPattern(
    id="gcp_api_key",
    name="GCP API Key",
    description=(
        "Google Cloud Platform API key, 39 characters starting with AIza."
        " As of 2025-2026, GCP API keys also grant access to Google Gemini AI models."
    ),
    provider="gcp",
    severity="critical",
    # Vendor-published format — AIza prefix is Google-published GCP API key format
    regex=re.compile(
        r"(?P<secret>AIza[0-9A-Za-z\-_]{35})"
        r"(?![0-9A-Za-z\-_])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "google",
        "gcp",
        "api_key",
        "api-key",
        "GOOGLE_API_KEY",
        "firebase",
        "gemini",
        "generativelanguage",
    ],
    known_test_values={
        "AIzaSyA-FAKE-KEY-FOR-TESTING-1234567",
    },
    recommendation=(
        "Restrict or delete this key in the Google Cloud Console."
        " Check for unauthorized usage in the API dashboard."
        " As of 2025-2026, GCP API keys may grant Gemini access"
        " -- audit billing immediately."
    ),
    tags=["cloud", "gcp", "google"],
)


GCP_SERVICE_ACCOUNT_KEY = SecretPattern(
    id="gcp_service_account_key",
    name="GCP Service Account Key (JSON fragment)",
    description=(
        "Fragment of a Google Cloud service account JSON key file,"
        " identified by the private_key field containing an RSA key."
    ),
    provider="gcp",
    severity="critical",
    # Vendor-published format — PEM key within JSON service account file (RFC 7468 + Google docs)
    regex=re.compile(
        r"(?P<secret>"
        r"\"private_key\"\s*:\s*\"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----"
        r"[^\"]{50,2048}"  # capture enough of the key to confirm, but cap it
        r"-----END\s(?:RSA\s)?PRIVATE\sKEY-----\\n\""
        r")",
        re.DOTALL,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "service_account",
        "client_email",
        "project_id",
        "type",
        "google",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this service account key in the GCP IAM console immediately."
        " Generate a new key if still needed."
        " Prefer Workload Identity Federation over exported keys."
    ),
    tags=["cloud", "gcp", "google", "service_account"],
)


# ===================================================
# AZURE
# ===================================================

AZURE_STORAGE_KEY = SecretPattern(
    id="azure_storage_key",
    name="Azure Storage Account Key",
    description=("Azure Storage account access key, 88-character base64 string ending with ==."),
    provider="azure",
    severity="critical",
    # Independently authored — context-gated 86-char base64 + == suffix; Azure-documented format
    regex=re.compile(
        r"(?:"
        r"(?:AccountKey|account_key|AZURE_STORAGE_KEY|azure_storage_key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9+/]{86}==)",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=4.0,
    context_keywords=[
        "azure",
        "storage",
        "account_key",
        "AccountKey",
        "blob",
        "DefaultEndpointsProtocol",
    ],
    known_test_values={
        "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
    },
    recommendation=(
        "Rotate this storage account key in the Azure Portal."
        " Use Azure AD authentication or managed identities instead"
        " of shared keys where possible."
    ),
    tags=["cloud", "azure", "storage"],
)


AZURE_STORAGE_SAS_TOKEN = SecretPattern(
    id="azure_storage_sas_token",
    name="Azure Storage SAS Token",
    description=(
        "Azure Storage shared access signature (SAS) token: a delegated,"
        " time-limited query-string credential. Anchored on the mandatory"
        " 'sv=' signed-version date literal co-occurring with an 'sig='"
        " signature — a URL-encoded base64 HMAC-SHA256, 43 characters plus"
        " one pad — in the same query string. A lone 'sig=' is never matched."
    ),
    provider="azure",
    severity="high",
    # Two mandatory fields are required TOGETHER inside one bounded, unbroken
    # query string; neither alone is enough. 'sv' is the signed storage-service
    # version and is always a date literal (20YY-MM-DD); 'sig' is the credential
    # itself — base64 of a 32-byte HMAC-SHA256, hence exactly 43 data characters
    # plus one '=' pad, in either the raw ('+', '/', '=') or the percent-encoded
    # ('%2B', '%2F', '%3D') spelling. Both orders are accepted: branch 1 reads
    # sv-then-sig (what every first-party generator emits, since the signature
    # is appended after the fields it signs), branch 2 reads sig-then-sv through
    # a non-consuming lookahead, because Azure does not mandate parameter order
    # and a single named group cannot span both directions.
    # Format per https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas
    regex=re.compile(
        r"(?:"
        r"(?<![0-9A-Za-z_-])sv=20\d{2}-\d{2}-\d{2}"
        r"[^\s" '"' r"'<>]{0,400}?"
        r"(?<![0-9A-Za-z_-])sig="
        r"|"
        r"(?<![0-9A-Za-z_-])sig="
        r"(?=(?:[0-9A-Za-z+/]|%2[BbFf]){43}(?:=|%3[Dd])"
        r"[^\s" '"' r"'<>]{0,400}?(?<![0-9A-Za-z_-])sv=20\d{2}-\d{2}-\d{2})"
        r")"
        r"(?P<secret>(?:[0-9A-Za-z+/]|%2[BbFf]){43}(?:=|%3[Dd]))"
        r"(?![0-9A-Za-z+/=]|%2[BbFf]|%3[Dd])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=[
        "blob.core.windows.net",
        "file.core.windows.net",
        "queue.core.windows.net",
        "table.core.windows.net",
        "dfs.core.windows.net",
        "SharedAccessSignature",
        "azure",
        "sas",
        "srt=",
        "ss=",
        "sr=",
        "sp=",
        "se=",
    ],
    known_test_values={
        "A" * 43 + "=",
        "A" * 43 + "%3D",
        "a" * 43 + "=",
        "a" * 43 + "%3D",
        "X" * 43 + "=",
        "X" * 43 + "%3D",
        "x" * 43 + "=",
        "x" * 43 + "%3D",
        "0" * 43 + "=",
        "0" * 43 + "%3D",
    },
    recommendation=(
        "A SAS token cannot be revoked individually. If it was signed with the"
        " account key, rotate that key in the Azure Portal; if it was signed"
        " through a stored access policy, delete or expire the policy; if it is"
        " a user delegation SAS, revoke the delegation key. Prefer short"
        " expiries and user delegation SAS over account-key-signed tokens."
    ),
    tags=["cloud", "azure", "storage", "sas", "delegated"],
)


AZURE_AD_CLIENT_SECRET = SecretPattern(
    id="azure_ad_client_secret",
    name="Azure AD Client Secret",
    description=(
        "Azure Active Directory application client secret."
        " Variable format but typically 34-44 characters with mixed case,"
        " digits, and special chars."
    ),
    provider="azure",
    severity="high",
    # Independently authored — context-gated 34-44 char secret; Azure-documented credential
    regex=re.compile(
        r"(?:"
        r"(?:AZURE_CLIENT_SECRET|client_secret|clientSecret)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9~_.]{34,44})"
        r"(?![A-Za-z0-9~_.])",
        re.ASCII,
    ),
    confidence_base=0.75,  # lower base -- format is less distinctive
    entropy_threshold=3.5,
    context_keywords=[
        "azure",
        "client_secret",
        "tenant",
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "active_directory",
    ],
    known_test_values=set(),
    recommendation=(
        "Rotate this client secret in Azure AD app registrations."
        " Use certificate-based authentication or managed identities"
        " where possible."
    ),
    tags=["cloud", "azure", "auth"],
)


# ===================================================
# DIGITALOCEAN
# ===================================================

DIGITALOCEAN_TOKEN = SecretPattern(
    id="digitalocean_token",
    name="DigitalOcean Personal Access Token",
    description=("DigitalOcean API token with dop_v1_ prefix, 64 hex characters."),
    provider="digitalocean",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:738) — dop_v1_ vendor prefix
    regex=re.compile(
        r"(?P<secret>dop_v1_[a-f0-9]{64})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["digitalocean", "do_token", "DIGITALOCEAN_TOKEN"],
    known_test_values=set(),
    recommendation=("Revoke this token in the DigitalOcean control panel under API > Tokens."),
    tags=["cloud", "digitalocean"],
)


# ===================================================
# HEROKU
# ===================================================

HEROKU_API_KEY = SecretPattern(
    id="heroku_api_key",
    name="Heroku API Key",
    description=("Heroku API key, a UUID-format string (36 chars including hyphens)."),
    provider="heroku",
    severity="high",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:3220) — context-gated UUID
    regex=re.compile(
        r"(?:"
        r"(?:HEROKU_API_KEY|heroku_api_key|heroku.*api.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,  # UUID format is common, context-dependent
    entropy_threshold=0.0,
    context_keywords=["heroku", "api_key", "HEROKU_API_KEY"],
    known_test_values=set(),
    recommendation=(
        "Regenerate your Heroku API key via `heroku authorizations:create` or the Heroku dashboard."
    ),
    tags=["cloud", "heroku"],
)


# ===================================================
# CLOUDFLARE
# ===================================================

CLOUDFLARE_API_TOKEN = SecretPattern(
    id="cloudflare_api_token",
    name="Cloudflare API Token",
    description=(
        "Cloudflare API token, 40-character alphanumeric string with underscores and hyphens."
    ),
    provider="cloudflare",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:509) — context-gated 40-char
    regex=re.compile(
        r"(?:"
        r"(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN|cloudflare.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9_\-]{40})"
        r"(?![A-Za-z0-9_\-])",
        re.ASCII,
    ),
    confidence_base=0.80,
    entropy_threshold=3.5,
    context_keywords=["cloudflare", "cf_", "api_token", "CF_API_TOKEN"],
    known_test_values=set(),
    recommendation=("Revoke this token in the Cloudflare dashboard under My Profile > API Tokens."),
    tags=["cloud", "cloudflare"],
)


# ---------------------------------------------------
# BATCH 4 Part 1.6 — Cloudflare additions (2026-05-21)
# ---------------------------------------------------
# Body shapes from Betterleaks MIT cmd/generate/config/rules/cloudflare.go.
# Global API Key is the nuclear option for Cloudflare accounts — grants
# unrestricted access to all zones and services; rotation is a major incident.

CLOUDFLARE_GLOBAL_API_KEY = SecretPattern(
    id="cloudflare_global_api_key",
    name="Cloudflare Global API Key",
    description=(
        "Cloudflare Global API Key (37 lowercase hex chars, context-gated)."
        " The original Cloudflare API auth method, with UNRESTRICTED access to all"
        " account zones and services. Treat any leak as a major incident."
    ),
    provider="cloudflare",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/cloudflare.go) — context-gated 37 hex.
    # Context-gated because raw 37-hex strings are not distinctive (might match SHA hashes, etc).
    # Only fires when "cloudflare" keyword is present in the line/assignment.
    regex=re.compile(
        r"(?:"
        r"(?:CLOUDFLARE_GLOBAL_API_KEY|cloudflare.*global.*api.*key|cloudflare.*api.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{37})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=["cloudflare", "global_api_key", "X-Auth-Key"],
    known_test_values=set(),
    recommendation=(
        "Immediately rotate this Global API Key in the Cloudflare dashboard."
        " Critical — Global API Keys grant unrestricted access. Migrate to scoped API tokens."
    ),
    tags=["cloud", "cloudflare", "global"],
)


CLOUDFLARE_ORIGIN_CA_KEY = SecretPattern(
    id="cloudflare_origin_ca_key",
    name="Cloudflare Origin CA Key",
    description=(
        "Cloudflare Origin CA key with v1.0- prefix (24-hex + - + 146-hex structure)."
        " Used to manage Cloudflare-issued origin TLS certificates."
    ),
    provider="cloudflare",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/cloudflare.go) — v1.0- prefix.
    regex=re.compile(
        r"(?P<secret>v1\.0-[a-f0-9]{24}-[a-f0-9]{146})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["cloudflare", "origin", "ca", "X-Auth-User-Service-Key"],
    known_test_values=set(),
    recommendation=(
        "Rotate this Origin CA key in the Cloudflare dashboard."
        " Compromised keys allow attackers to issue/revoke origin certificates."
    ),
    tags=["cloud", "cloudflare", "ca", "tls"],
)


# ===================================================
# DOPPLER
# ===================================================

DOPPLER_TOKEN = SecretPattern(
    id="doppler_token",
    name="Doppler Service Token",
    description=(
        "Doppler service token with dp.pt. prefix. Grants access to secrets stored in Doppler."
    ),
    provider="doppler",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:786) — dp.pt. vendor prefix
    regex=re.compile(
        r"(?P<secret>dp\.pt\.[A-Za-z0-9]{40,44})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["doppler", "DOPPLER_TOKEN", "dp_token"],
    known_test_values=set(),
    recommendation=("Revoke this token in the Doppler dashboard under Access > Service Tokens."),
    tags=["cloud", "doppler", "secrets"],
)

# ---------------------------------------------------------------------------
# 2026-08-03 — the remaining five Doppler auth-token families.
#
# Doppler publishes every one of its token formats, with an explicit regex per
# family, on a single reference page. `dp.pt.` (personal token) already shipped
# above; the five below complete the set. Each family carries a distinct literal
# segment after `dp.`, so none of them can double-match another — including the
# `dp.said.` Service Account *Identity* token, which is deliberately NOT
# registered here and must not be absorbed by `dp.sa.`.
#
# Bodies are 40-44 characters of [A-Za-z0-9] in every family. The service token
# is the sole exception in structure: it may carry an optional lowercase config
# segment between the prefix and the body (`dp.st.dev.<body>`), and it is also
# emitted in the bare `dp.st.<body>` form. Both must match — making the segment
# mandatory silently misses every bare service token.
# ---------------------------------------------------------------------------

DOPPLER_CLI_TOKEN = SecretPattern(
    id="doppler_cli_token",
    name="Doppler CLI Token",
    description=(
        "Doppler CLI token with dp.ct. prefix, minted by `doppler login` and stored in the"
        " local CLI config. Carries the full authority of the developer who logged in —"
        " read access to every project and config that user can reach."
    ),
    provider="doppler",
    severity="critical",
    # Doppler documents one regex per token family; the CLI token is
    # `dp.ct.` followed by 40-44 alphanumerics.
    # Source: https://docs.doppler.com/reference/auth-token-formats
    regex=re.compile(
        r"(?<![A-Za-z0-9._\-])"
        r"(?P<secret>dp\.ct\.[0-9A-Za-z]{40,44})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["doppler", "DOPPLER_TOKEN", "dp.ct", "cli"],
    known_test_values={"dp.ct." + "0" * 43},
    recommendation=(
        "Revoke this CLI token in the Doppler dashboard under Account > Tokens,"
        " then run `doppler logout` and re-authenticate on the affected machine."
    ),
    tags=["cloud", "doppler", "secrets", "cli"],
)


DOPPLER_SERVICE_TOKEN = SecretPattern(
    id="doppler_service_token",
    name="Doppler Service Token",
    description=(
        "Doppler service token with dp.st. prefix, optionally carrying a config segment"
        " (dp.st.<config>.<body>). Scoped read (or read/write) access to one config's"
        " secrets — the token type deployed into CI and production runtimes."
    ),
    provider="doppler",
    severity="critical",
    # Doppler's published service-token regex allows an optional lowercase
    # config segment before the body; the bare `dp.st.<body>` form is equally
    # valid and is what the dashboard emits by default.
    # Source: https://docs.doppler.com/reference/auth-token-formats
    regex=re.compile(
        r"(?<![A-Za-z0-9._\-])"
        r"(?P<secret>dp\.st\.(?:[0-9a-z\-_]{2,35}\.)?[0-9A-Za-z]{40,44})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["doppler", "DOPPLER_TOKEN", "dp.st", "service_token"],
    known_test_values={"dp.st." + "0" * 43, "dp.st." + "dev." + "0" * 43},
    recommendation=(
        "Revoke this service token in the Doppler dashboard under the affected config's"
        " Access tab, then issue a replacement and redeploy the workloads that used it."
    ),
    tags=["cloud", "doppler", "secrets", "service-token"],
)


DOPPLER_SERVICE_ACCOUNT_TOKEN = SecretPattern(
    id="doppler_service_account_token",
    name="Doppler Service Account Token",
    description=(
        "Doppler service account token with dp.sa. prefix. Machine credential scoped to a"
        " service account, typically granting workplace-wide programmatic access to"
        " projects and configs. Distinct from the dp.said. service account IDENTITY token."
    ),
    provider="doppler",
    severity="critical",
    # Anchored on the literal `dp.sa.` so the separately-documented
    # `dp.said.` service account identity token cannot be absorbed here —
    # `dp.said.` has no dot immediately after `sa`, so the anchor rejects it.
    # Source: https://docs.doppler.com/reference/auth-token-formats
    regex=re.compile(
        r"(?<![A-Za-z0-9._\-])"
        r"(?P<secret>dp\.sa\.[0-9A-Za-z]{40,44})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["doppler", "DOPPLER_TOKEN", "dp.sa", "service_account"],
    known_test_values={"dp.sa." + "0" * 43},
    recommendation=(
        "Revoke this service account token in the Doppler dashboard under"
        " Team > Service Accounts, and audit that account's recent API activity."
    ),
    tags=["cloud", "doppler", "secrets", "service-account"],
)


DOPPLER_AUDIT_TOKEN = SecretPattern(
    id="doppler_audit_token",
    name="Doppler Audit Token",
    description=(
        "Doppler audit token with dp.audit. prefix. Read-only access to the workplace audit"
        " log — it cannot read secrets, so impact is disclosure of activity metadata"
        " (who accessed what, when) rather than credential compromise."
    ),
    provider="doppler",
    severity="medium",
    # Source: https://docs.doppler.com/reference/auth-token-formats
    regex=re.compile(
        r"(?<![A-Za-z0-9._\-])"
        r"(?P<secret>dp\.audit\.[0-9A-Za-z]{40,44})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["doppler", "DOPPLER_TOKEN", "dp.audit", "audit"],
    known_test_values={"dp.audit." + "0" * 43},
    recommendation=(
        "Revoke this audit token in the Doppler dashboard under Team > Audit."
        " It exposes workplace activity metadata but not secret values."
    ),
    tags=["cloud", "doppler", "audit"],
)


DOPPLER_SCIM_TOKEN = SecretPattern(
    id="doppler_scim_token",
    name="Doppler SCIM Token",
    description=(
        "Doppler SCIM token with dp.scim. prefix. Used by an identity provider to provision"
        " and de-provision Doppler users. It cannot read secrets, but it can create, modify"
        " and remove workplace members — an account-takeover primitive."
    ),
    provider="doppler",
    severity="high",
    # Source: https://docs.doppler.com/reference/auth-token-formats
    regex=re.compile(
        r"(?<![A-Za-z0-9._\-])"
        r"(?P<secret>dp\.scim\.[0-9A-Za-z]{40,44})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["doppler", "DOPPLER_TOKEN", "dp.scim", "scim", "provisioning"],
    known_test_values={"dp.scim." + "0" * 43},
    recommendation=(
        "Revoke this SCIM token in the Doppler dashboard under Team > SCIM and reissue it"
        " in your identity provider. Audit recent user provisioning changes."
    ),
    tags=["cloud", "doppler", "scim", "provisioning"],
)


# ===================================================
# GOOGLE CLOUD STORAGE — HMAC KEYS
# ===================================================

GCS_HMAC_ACCESS_KEY_ID = SecretPattern(
    id="gcs_hmac_access_key_id",
    name="Google Cloud Storage HMAC Access Key ID",
    description=(
        "Google Cloud Storage HMAC access key ID, used with the S3-compatible XML API."
        " Service-account keys are 61 characters, user-account keys 24 — both begin GOOG"
        " and use uppercase alphanumerics only."
    ),
    provider="gcp",
    severity="critical",
    # Scope decision: the access key ID is flagged, its paired secret is NOT.
    # The paired secret is a bare, unanchored 40-character base64 string with no
    # prefix or structure to key on — registering it would be a generic-base64
    # false-positive cannon. Flagging the ID alone mirrors how this engine
    # already handles AWS AKIA access key IDs, whose secret is likewise omitted.
    # Both documented lengths are pinned: 61 chars (service account) and 24
    # chars (user account). The prefix is plain GOOG per Google's own example —
    # the widely-circulated GOOG1E variant is not a Google-published anchor.
    # Source: https://docs.cloud.google.com/storage/docs/authentication/hmackeys
    regex=re.compile(
        r"(?<![0-9A-Z])"
        r"(?P<secret>GOOG(?:[0-9A-Z]{57}|[0-9A-Z]{20}))"
        r"(?![0-9A-Z])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "gcs",
        "hmac",
        "google",
        "storage",
        "access_id",
        "GOOG",
        "s3",
    ],
    known_test_values={"GOOG" + "0" * 57, "GOOG" + "0" * 20},
    recommendation=(
        "Delete this HMAC key in the Google Cloud console under Cloud Storage > Settings >"
        " Interoperability, and rotate the paired secret. Audit the owning service"
        " account's Cloud Storage access logs."
    ),
    tags=["cloud", "gcp", "gcs", "hmac", "storage"],
)


# ===================================================
# TERRAFORM CLOUD
# ===================================================

TERRAFORM_CLOUD_TOKEN = SecretPattern(
    id="terraform_cloud_token",
    name="Terraform Cloud / Enterprise API Token",
    description=(
        "Terraform Cloud or Enterprise API token with .atlasv1. segment."
        " Grants access to manage infrastructure-as-code workspaces."
    ),
    provider="terraform",
    severity="critical",
    # Format derived from HashiCorp-published example tokens:
    #   https://developer.hashicorp.com/terraform/cloud-docs/api-docs/user-tokens
    #   https://developer.hashicorp.com/terraform/cloud-docs/api-docs/agent-tokens
    # Structure: 14 alphanumeric . "atlasv1" . 67 alphanumeric.
    # Independently derived from vendor documentation.
    regex=re.compile(
        r"(?P<secret>[0-9A-Za-z]{14}\.atlasv1\.[0-9A-Za-z]{67})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "terraform",
        "TF_TOKEN",
        "TFE_TOKEN",
        "atlas",
        "terraform_cloud",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in Terraform Cloud under User Settings > Tokens."
        " An attacker with this token can modify your infrastructure."
    ),
    tags=["cloud", "terraform", "iac"],
)


# ===================================================
# HASHICORP VAULT
# ===================================================

VAULT_TOKEN = SecretPattern(
    id="vault_token",
    name="HashiCorp Vault Token",
    description=(
        "HashiCorp Vault service token with hvs. prefix. Grants access to secrets stored in Vault."
    ),
    provider="vault",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4731) — hvs. vendor prefix
    regex=re.compile(
        r"(?P<secret>hvs\.[A-Za-z0-9]{24,})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "vault",
        "VAULT_TOKEN",
        "hashicorp",
        "hvs",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token using `vault token revoke`."
        " Audit the token's policies and recent access logs."
    ),
    tags=["cloud", "vault", "secrets"],
)


# ===================================================
# HASHICORP VAULT — BATCH TOKENS (2026-08-24)
# ===================================================

# Vault's token prefix is the whole discriminator between its token classes:
# 'hvs.' service tokens (above), 'hvb.' batch tokens (here) and 'hvr.' recovery
# tokens (registered below as vault_recovery_token, 2026-09-07 — this comment
# named it as a gap until then). Batch tokens are encrypted blobs rather than
# storage entries — they
# are not renewable, carry no accessor, cannot be listed and cannot create
# child tokens — which is why this is severity high where vault_token is
# critical. It is still a bearer credential that authenticates every request it
# is attached to for as long as its TTL runs.
#
# The {24,} floor is the vendor's own wording rather than a measured width:
# HashiCorp documents the prefix as being followed by "at least 24 randomly-
# generated characters", and a batch token's body varies with the size of the
# encrypted payload it carries, so pinning an exact width would be inventing a
# format. The trailing (?![A-Za-z0-9]) guard is what makes the greedy run take
# the whole token instead of a 24-character prefix of it, and it also stops the
# pattern from reporting the leading slice of a longer alphanumeric run.
#
# 'hvb.' does not overlap the existing vault_token regex (hvs\.[A-Za-z0-9]{24,}):
# the two prefixes differ in the third character, so an hvs. token still
# resolves to vault_token. A test pins that.

VAULT_BATCH_TOKEN = SecretPattern(
    id="vault_batch_token",
    name="HashiCorp Vault Batch Token",
    description=(
        "HashiCorp Vault batch token — the 'hvb.' prefix followed by at least 24"
        " randomly-generated characters. Batch tokens are lightweight, encrypted,"
        " non-persisted tokens: not renewable, no accessor, not listable, and"
        " unable to create child tokens. A leaked batch token still authenticates"
        " every Vault request it is presented on, with the policies it was"
        " issued with, until its TTL expires."
    ),
    provider="vault",
    severity="high",
    # Prefix and the "at least 24 randomly-generated characters" body floor are
    # HashiCorp's own, from its token concepts page. The boundary guard, the
    # confidence and the known_test_values are ClassiFinder's own.
    # Source: https://developer.hashicorp.com/vault/docs/concepts/tokens
    regex=re.compile(
        r"(?P<secret>hvb\.[A-Za-z0-9]{24,})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    # Prefix-anchored tier. Deliberately kept at/above 0.85 so the FP-wordlist
    # penalty (-0.40, scanner.py) can never silently sink a real batch token
    # that happens to sit next to the word "test" or "demo" — Vault batch tokens
    # are minted per-environment and routinely appear in staging config.
    confidence_base=0.95,
    # 0.0 on purpose: the body is a fixed-charset random run, so any entropy
    # floor a masked placeholder failed would also sink short real tokens. The
    # literal 'hvb.' prefix carries the precision instead.
    entropy_threshold=0.0,
    context_keywords=[
        "vault",
        "VAULT_TOKEN",
        "hashicorp",
        "batch",
        "hvb",
    ],
    known_test_values={
        # The masked shape that dominates Vault tutorials and issue reports.
        # Assembled by concatenation so no contiguous token-shaped literal
        # exists in this repository. Down-scores to ~0.15.
        "hvb." + "X" * 28,
    },
    recommendation=(
        "Batch tokens cannot be revoked individually — they are not stored in"
        " Vault, so `vault token revoke` has nothing to revoke. Contain the leak"
        " by revoking the parent lease or the auth-method role that minted it,"
        " or by rotating the underlying auth credentials, and shorten the role's"
        " token_ttl so the exposure window closes. Then stop the leak at source:"
        " batch tokens are meant to be requested per-operation, never written to"
        " config, CI variables or logs. Audit Vault's audit device for requests"
        " carrying this token."
    ),
    tags=["cloud", "vault", "secrets", "batch-token"],
)


# ===================================================
# PULUMI
# ===================================================

PULUMI_ACCESS_TOKEN = SecretPattern(
    id="pulumi_access_token",
    name="Pulumi Access Token",
    description=(
        "Pulumi Cloud access token with pul- prefix."
        " Grants access to manage Pulumi stacks and state."
    ),
    provider="pulumi",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4129) — pul- vendor prefix
    regex=re.compile(
        r"(?P<secret>pul-[a-f0-9]{40})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "pulumi",
        "PULUMI_ACCESS_TOKEN",
        "pulumi_token",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token at app.pulumi.com/account/tokens."
        " An attacker can modify your infrastructure stacks."
    ),
    tags=["cloud", "pulumi", "iac"],
)


# ===================================================
# FLY.IO
# ===================================================

FLY_API_TOKEN = SecretPattern(
    id="fly_api_token",
    name="Fly.io API Token",
    description=(
        "Fly.io deploy token with fo1_ prefix."
        " Grants access to manage Fly.io applications and machines."
    ),
    provider="fly",
    severity="critical",
    # Independently authored — fo1_ vendor prefix per Fly.io access token documentation
    regex=re.compile(
        r"(?P<secret>fo1_[A-Za-z0-9]{39})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "fly",
        "FLY_API_TOKEN",
        "fly_token",
        "flyctl",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token at fly.io/dashboard under Tokens."
        " Generate a new deploy token with minimal scope."
    ),
    tags=["cloud", "fly", "deploy"],
)


# 2026-09-09 — Fly.io's MACAROON access token, the 'fm2_' form. This is a
# SIBLING of FLY_API_TOKEN above, not a replacement: 'fo1_' is the older
# opaque deploy token, while 'fm2_' is the macaroon flyctl and the Fly.io
# GraphQL API carry today. Fly joins SEVERAL macaroons with commas into one
# 'Authorization: FlyV1 …' header, so each segment has to be matched on its
# own rather than as a single anchored value.
FLY_MACAROON_ACCESS_TOKEN = SecretPattern(
    id="fly_macaroon_access_token",
    name="Fly.io Macaroon Access Token",
    description=(
        "Fly.io macaroon access token — the vendor-published 'fm2_' prefix"
        " followed by the base64 of a MsgPack-encoded macaroon. It is the"
        " credential flyctl and the Fly.io GraphQL API authenticate with"
        " today, and an org-scoped one can deploy, restart and destroy every"
        " app and machine in the organisation, read its secrets through the"
        " platform API and attach to a running machine. Several macaroons are"
        " comma-joined inside a single 'Authorization: FlyV1 …' header, so"
        " one leaked header can carry more than one credential."
    ),
    provider="fly",
    severity="critical",
    # FORMAT, FIRST-PARTY. Fly.io's own macaroon repository states the
    # encoding verbatim in macaroon-thought.md: each macaroon "is
    # MsgPack-encoded, then base64'd, then has `fm2_` prepended so it's easy
    # to grep for them, then joined with commas". So the prefix is a literal
    # Fly DESIGNED to be greppable, and the body is STANDARD base64 — the
    # '+/' alphabet, not base64url — with the usual '=' padding. The same
    # page prints the carrier, 'Authorization: FlyV1 fm2_…,fm2_…', and
    # annotates its own examples "(Except way longer)", i.e. the toy bodies
    # in the docs are deliberately not real widths. Fly's token docs
    # (fly.io/docs/security/tokens/) reference the prefix independently in a
    # '-t <existing token starting with fm2_>' CLI example.
    #
    # THE 100-CHARACTER FLOOR IS A FLOOR, NOT A MEASUREMENT. Fly publishes no
    # length anywhere, so nothing here pretends to a fixed width: a macaroon
    # carries a location, a nonce, a key id and an arbitrary list of caveats,
    # and it GROWS as it is attenuated. The lower bound is corroborated by
    # gitleaks (MIT), whose flyio-access-token rule uses the same
    # '{100,}' body floor. Because 'fm2_' is a distinctive vendor literal
    # rather than a generic shape, a loose bound costs nothing in precision
    # while a tight one could only cause misses.
    #
    # PADDING IS {0,2} AND THE RIGHT GUARD DELIBERATELY EXCLUDES '='.
    # Standard base64 emits zero, one or two pad characters and never three,
    # so {0,2} is the correct width; but putting '=' in the trailing lookahead
    # would turn a malformed over-padded value into a total MISS rather than a
    # slightly short span, and a miss is the worse failure for a scanner. The
    # guard therefore carries the body charset only. The body quantifier is
    # greedy and unbounded, so a long macaroon can never be clipped to its
    # first 100 characters and half-redacted.
    #
    # THE LEFT GUARD OMITS '=' ON PURPOSE. 'FLY_API_TOKEN=fm2_…' is the single
    # most common carrier there is, so '=' must not block a match — while
    # '+' and '/' ARE excluded, because '_' is outside the standard base64
    # alphabet but inside base64url, and that is exactly how 'fm2_' could
    # otherwise be carved out of the middle of somebody else's base64url blob.
    # Source: https://github.com/superfly/macaroon/blob/main/macaroon-thought.md
    regex=re.compile(
        r"(?<![0-9A-Za-z+/_-])"
        r"(?P<secret>fm2_[A-Za-z0-9+/]{100,}={0,2})"
        r"(?![0-9A-Za-z+/])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,  # the vendor literal carries the precision
    context_keywords=[
        "fly",
        "flyctl",
        "FlyV1",
        "FLY_API_TOKEN",
        "fly_token",
        "macaroon",
    ],
    known_test_values={
        # Single-character masks at the minimum width — how a redacted
        # 'Authorization' header or a docs placeholder renders this value.
        # These are load-bearing rather than cosmetic: confidence_base 0.97
        # sits ABOVE the 0.85 FP-wordlist gate (scanner.py:197), so the
        # wordlist never gets a chance to price a masked token down, and
        # without an explicit pin every such placeholder would be a permanent
        # 0.99 finding. Fly's own 'fm2_Zm9vCg==' / 'fm2_YmFyCg==' examples
        # need no entry: at eight body characters they are structurally
        # unmatchable, and a test pins that.
        "fm2" + "_" + "A" * 100,
        "fm2" + "_" + "a" * 100,
        "fm2" + "_" + "0" * 100,
        "fm2" + "_" + "x" * 100,
    },
    recommendation=(
        "Revoke the token at fly.io/dashboard under Tokens, or with"
        " 'fly tokens revoke', and issue a replacement narrowed with"
        " 'fly tokens create deploy --app <app>' rather than an org-wide one."
        " Revoke EVERY macaroon in the carrier, not just the first: a"
        " 'FlyV1' header comma-joins several, and each is a separate"
        " credential. Then treat the organisation's app secrets as disclosed"
        " — the holder could read and rewrite them through the platform API —"
        " so rotate those too, and review recent deploys, machine starts and"
        " SSH/console sessions for activity you do not recognise."
    ),
    tags=["cloud", "fly", "deploy", "macaroon"],
)


# ===================================================
# ALIBABA CLOUD
# ===================================================

ALIBABA_ACCESS_KEY = SecretPattern(
    id="alibaba_access_key",
    name="Alibaba Cloud Access Key ID",
    description=(
        "Alibaba Cloud access key ID starting with LTAI prefix."
        " Grants access to Alibaba Cloud services."
    ),
    provider="alibaba",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:177) — LTAI vendor prefix
    regex=re.compile(
        r"(?P<secret>LTAI[A-Za-z0-9]{17,21})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "alibaba",
        "aliyun",
        "ALIBABA_ACCESS_KEY",
        "alicloud",
    ],
    known_test_values=set(),
    recommendation=(
        "Rotate this key in the Alibaba Cloud RAM console. Audit AccessKey usage via ActionTrail."
    ),
    tags=["cloud", "alibaba", "iam"],
)


# ===================================================
# VERCEL
# ===================================================

# ---------------------------------------------------
# VERCEL — 5-prefix taxonomy reconciled 2026-05-21
# ---------------------------------------------------
# Vercel's official changelog (2026-02-09) at
#   https://vercel.com/changelog/new-token-formats-and-secret-scanning
# lists exactly five prefixed token types:
#   vcp_ — Personal Access Token
#   vci_ — Integration Token
#   vca_ — App Access Token (OAuth)
#   vcr_ — App Refresh Token (OAuth)
#   vck_ — AI Gateway API Key
# The vendor changelog confirms PREFIXES only; body length and charset
# are not vendor-documented. Body length 56 + charset [A-Za-z0-9_-]
# (URL-safe base64) come from Betterleaks' empirical observation, verified
# 2026-05-21 by reading betterleaks/cmd/generate/config/rules/vercel.go
# (which contains verbatim 56-char synthetic test tokens for all five
# prefixes). Cross-checked against Grok + Gemini independent research.
# Vercel's single published example (vca_BQuu9...340sjz on the
# sign-in-with-vercel/tokens docs page) is 56 alphanumeric chars and
# fits within [A-Za-z0-9_-].
#
# The (?P<secret>...{56})(?![A-Za-z0-9_-]) shape uses a trailing
# negative lookahead in place of \b because the body charset includes
# _ and -, which are not word boundaries in Python re.
#
# A 6th GitHub-catalog type (vercel_support_access_token) is omitted —
# its prefix is not publicly disclosed. Tracked as a P3 follow-up.

VERCEL_ACCESS_TOKEN = SecretPattern(
    id="vercel_access_token",
    name="Vercel OAuth App Access Token",
    description=(
        "Vercel OAuth app access token with vca_ prefix."
        " Grants access to Vercel deployments and project management on behalf of a user."
    ),
    provider="vercel",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/vercel.go) — vca_ prefix
    # Vendor-confirmed prefix per Vercel changelog 2026-02-09 + sign-in-with-vercel/tokens docs.
    # Example token from Vercel docs: vca_BQuu9ChDu3n6Pfh6YQnCshpoYkWDSFKogLqmBtQ0tC8NAA5rXt340sjz (56 chars).
    regex=re.compile(
        r"(?P<secret>vca_[A-Za-z0-9_-]{56})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "vercel",
        "VERCEL_TOKEN",
        "vercel_token",
    ],
    known_test_values=set(),
    recommendation=("Revoke this token in the Vercel dashboard under Account Settings > Tokens."),
    tags=["cloud", "vercel", "deploy", "oauth"],
)


VERCEL_REFRESH_TOKEN = SecretPattern(
    id="vercel_refresh_token",
    name="Vercel OAuth App Refresh Token",
    description=(
        "Vercel OAuth app refresh token with vcr_ prefix."
        " Can be exchanged for new access tokens — treat as critical."
    ),
    provider="vercel",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/vercel.go) — vcr_ prefix
    # Vendor-confirmed prefix per Vercel changelog 2026-02-09 + sign-in-with-vercel/tokens docs.
    regex=re.compile(
        r"(?P<secret>vcr_[A-Za-z0-9_-]{56})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "vercel",
        "VERCEL_REFRESH_TOKEN",
        "refresh",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in the Vercel dashboard."
        " Refresh tokens allow persistent access — treat as critical."
    ),
    tags=["cloud", "vercel", "oauth"],
)


VERCEL_PERSONAL_ACCESS_TOKEN = SecretPattern(
    id="vercel_personal_access_token",
    name="Vercel Personal Access Token",
    description=(
        "Vercel personal access token (PAT) with vcp_ prefix."
        " Grants full account-level access to a user's Vercel resources — treat as critical."
    ),
    provider="vercel",
    severity="critical",
    # Vendor-confirmed vcp_ prefix per Vercel changelog 2026-02-09. Body length
    # = 56 chars [A-Za-z0-9_-] confirmed via three independent paths 2026-05-21:
    #   1. Betterleaks source cmd/generate/config/rules/vercel.go (synthetic test tokens)
    #   2. Grok + Gemini independent research (both converge on 56)
    #   3. Empirical: real PAT minted from a Vercel account matched at exactly 56 chars
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/vercel.go)
    regex=re.compile(
        r"(?P<secret>vcp_[A-Za-z0-9_-]{56})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "vercel",
        "VERCEL_PAT",
        "vercel_pat",
        "personal access",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this personal access token in the Vercel dashboard under"
        " Account Settings > Tokens. PATs grant full account-level access."
    ),
    tags=["cloud", "vercel", "pat"],
)


VERCEL_INTEGRATION_TOKEN = SecretPattern(
    id="vercel_integration_token",
    name="Vercel Integration Token",
    description=(
        "Vercel integration token with vci_ prefix."
        " Used by Vercel marketplace integrations to act on a user's behalf."
    ),
    provider="vercel",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/vercel.go) — vci_ prefix.
    # Vendor-confirmed prefix per Vercel changelog 2026-02-09. Body 56 chars +
    # [A-Za-z0-9_-] charset per Betterleaks empirical observation.
    regex=re.compile(
        r"(?P<secret>vci_[A-Za-z0-9_-]{56})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "vercel",
        "VERCEL_INTEGRATION",
        "vercel_integration",
        "integration",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this integration token in the Vercel dashboard under the integration's settings."
    ),
    tags=["cloud", "vercel", "integration"],
)


# vck_ (Vercel AI Gateway API Key) — already defined in patterns/ai.py
# (existing pattern uses [A-Za-z0-9_\-]{56}, the same shape as the four
# above; consolidating here would be a churn refactor for no benefit).


# ===================================================
# NETLIFY
# ===================================================

NETLIFY_TOKEN = SecretPattern(
    id="netlify_token",
    name="Netlify Personal Access Token",
    description=(
        "Netlify personal access token with nfp_ prefix."
        " Grants access to Netlify sites, deploys, and account management."
    ),
    provider="netlify",
    severity="critical",
    # Format per Netlify official announcement of token format change:
    #   https://answers.netlify.com/t/change-to-the-netlify-authentication-token-format/106146
    # Per Netlify staff: "nfp" prefix = Personal Access Token; total token length 40 chars.
    # Independently derived from vendor documentation.
    regex=re.compile(
        r"(?P<secret>nfp_[0-9A-Za-z_]{36})"
        r"(?![0-9A-Za-z_])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "netlify",
        "NETLIFY_AUTH_TOKEN",
        "netlify_token",
    ],
    known_test_values=set(),
    recommendation=("Revoke this token at app.netlify.com under User Settings > Applications."),
    tags=["cloud", "netlify", "deploy"],
)


# ===================================================
# DROPBOX (Batch 4 Part 1.4, 2026-05-21)
# ===================================================
# Vendor docs (developers.dropbox.com) confirm token TYPES (short-lived,
# long-lived) but withhold format details. Body shapes from Betterleaks MIT
# cmd/generate/config/rules/dropbox.go.
#
# The generic dropbox-api-token rule in Betterleaks (15-char alphanumeric
# near "dropbox" keyword) is deliberately omitted — its FP risk is
# unfavorable in ClassiFinder's scoring model, where a 15-char alphanumeric
# string near "dropbox" matches countless variable names, UUIDs, and hash
# fragments inside Dropbox SDK code.

DROPBOX_SHORT_LIVED_API_TOKEN = SecretPattern(
    id="dropbox_short_lived_api_token",
    name="Dropbox Short-Lived API Token",
    description=(
        "Dropbox short-lived OAuth2 access token with sl. prefix (135-char body)."
        " Returned by /oauth2/token; typically expires within hours."
    ),
    provider="dropbox",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/dropbox.go) — sl. prefix.
    # Vendor-confirmed type per developers.dropbox.com/oauth-guide (short-lived access tokens).
    regex=re.compile(
        r"(?P<secret>sl\.[a-z0-9\-=_]{135})"
        r"(?![a-z0-9\-=_])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["dropbox", "DROPBOX_TOKEN", "DROPBOX_ACCESS_TOKEN"],
    known_test_values=set(),
    recommendation=(
        "Short-lived tokens auto-expire, but revoke any associated refresh tokens"
        " in the Dropbox App Console if a long-lived secret was leaked together."
    ),
    tags=["cloud", "dropbox", "oauth"],
)


# ===================================================
# JFROG / ARTIFACTORY (Batch 4 Part 1.5, 2026-05-21)
# ===================================================
# Supply-chain critical — JFrog Artifactory is the canonical package
# repository for many enterprises. Compromised tokens can poison releases.
# Body shapes from Betterleaks MIT cmd/generate/config/rules/artifactory.go.
# The cmVmd prefix is the base64 encoding of "ref" + first byte of "tkn"
# (reference token), distinctive enough to anchor reliably.
#
# Spec proposed jfrog_identity_token (JWT-shaped) but Betterleaks doesn't
# carry it, and our existing jwt_token pattern catches JWTs. Skipped here;
# file a follow-up if JFrog-specific JWT identity tokens need detection.

JFROG_API_KEY = SecretPattern(
    id="jfrog_api_key",
    name="JFrog Artifactory API Key",
    description=(
        "JFrog/Artifactory API key with AKCp prefix (73 chars total)."
        " Authenticates against JFrog Artifactory package repositories."
        " Supply-chain critical — compromised keys can poison releases."
    ),
    provider="jfrog",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/artifactory.go) — AKCp prefix.
    # Vendor-published format — JFrog documents AKCp as the API key prefix.
    regex=re.compile(
        r"(?P<secret>AKCp[A-Za-z0-9]{69})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["jfrog", "artifactory", "bintray", "xray", "JFROG_API_KEY"],
    known_test_values=set(),
    recommendation=(
        "Revoke this JFrog/Artifactory API key in the JFrog platform."
        " Audit recent package publishes and downloads — supply-chain compromise risk."
    ),
    tags=["cloud", "jfrog", "artifactory", "supply-chain"],
)


ARTIFACTORY_REFERENCE_TOKEN = SecretPattern(
    id="artifactory_reference_token",
    name="Artifactory Reference Token",
    description=(
        "JFrog Artifactory reference token with cmVmd prefix (64 chars total)."
        " The cmVmd prefix is the base64 encoding of 'ref' + first byte of 'tkn'."
        " Used by Artifactory clients to authenticate package operations."
    ),
    provider="jfrog",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/artifactory.go) — cmVmd prefix.
    regex=re.compile(
        r"(?P<secret>cmVmd[A-Za-z0-9]{59})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["jfrog", "artifactory", "reference", "ref_token"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Artifactory reference token in the JFrog platform."
        " Audit package operations performed with this token — supply-chain risk."
    ),
    tags=["cloud", "jfrog", "artifactory", "supply-chain"],
)


DROPBOX_LONG_LIVED_API_TOKEN = SecretPattern(
    id="dropbox_long_lived_api_token",
    name="Dropbox Long-Lived API Token",
    description=(
        "Dropbox legacy long-lived API token with 64-char structural format."
        " 11 alphanumeric + literal 'AAAAAAAAAA' middle marker + 43 alphanumeric-with-special."
        " Treat as critical — these tokens have no expiry."
    ),
    provider="dropbox",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/dropbox.go) — long-lived shape.
    # No prefix; the literal AAAAAAAAAA mid-token sequence is the structural anchor.
    # Distinctive enough that random alphanumeric won't accidentally contain that exact run.
    regex=re.compile(
        r"(?P<secret>[a-z0-9]{11}AAAAAAAAAA[a-z0-9\-_=]{43})"
        r"(?![a-z0-9\-_=])",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=["dropbox", "DROPBOX_TOKEN", "DROPBOX_ACCESS_TOKEN"],
    known_test_values=set(),
    recommendation=(
        "Rotate this Dropbox long-lived token in the App Console immediately."
        " Long-lived tokens have no expiry — if leaked, an attacker has persistent access."
        " Migrate to short-lived tokens with refresh-token rotation when possible."
    ),
    tags=["cloud", "dropbox", "legacy"],
)


# Register all cloud patterns
# ===================================================
# IBM CLOUD
# ===================================================

IBM_CLOUD_API_KEY = SecretPattern(
    id="ibm_cloud_api_key",
    name="IBM Cloud API Key",
    description=(
        "IBM Cloud IAM API key, a 44-character alphanumeric string."
        " Detected when preceded by IBM-specific context keywords."
    ),
    provider="ibm",
    severity="high",
    # Pattern attribution: secrets-patterns-db CC-BY-4.0 (rules-stable.yml:~1740) — context-gated 44-char
    regex=re.compile(
        r"(?:"
        r"(?:IBM_API_KEY|IBM_CLOUD_API_KEY|ibm.*api.*key|ibm.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9_\-]{44})"
        r"(?![A-Za-z0-9_\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.5,
    context_keywords=[
        "ibm",
        "IBM_API_KEY",
        "IBM_CLOUD_API_KEY",
        "ibm_cloud",
        "bluemix",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the IBM Cloud console under Manage > Access (IAM) > API Keys."
        " Generate a new key with minimal permissions."
    ),
    tags=["cloud", "ibm"],
)


# ===================================================
# OKTA
# ===================================================

OKTA_API_TOKEN = SecretPattern(
    id="okta_api_token",
    name="Okta API Token",
    description=(
        "Okta API token starting with 00 prefix followed by 40 alphanumeric characters."
        " Detected when preceded by Okta-specific context keywords."
    ),
    provider="okta",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:3821) — context-gated 00-prefix
    regex=re.compile(
        r"(?:"
        r"(?:OKTA_API_TOKEN|OKTA_TOKEN|okta.*token|okta.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>00[A-Za-z0-9_\-]{40})"
        r"(?![A-Za-z0-9_\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=3.0,
    context_keywords=["okta", "OKTA_API_TOKEN", "okta_token", "sso"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in Okta Admin Console under Security > API > Tokens."
    ),
    tags=["cloud", "okta", "identity"],
)


# ===================================================
# BUILDKITE
# ===================================================

BUILDKITE_TOKEN = SecretPattern(
    id="buildkite_token",
    name="Buildkite API Token",
    description="Buildkite API token with bkua_ prefix followed by 40 alphanumeric characters.",
    provider="buildkite",
    severity="high",
    # Format per Buildkite official docs:
    #   https://buildkite.com/docs/apis/managing-api-tokens
    #   https://buildkite.com/docs/platform/security/tokens
    # "bkua_" = Buildkite User Access token, followed by 40 alphanumerics.
    # Independently derived from vendor documentation.
    regex=re.compile(
        r"(?P<secret>bkua_[0-9A-Za-z]{40})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["buildkite", "BUILDKITE_TOKEN", "buildkite_agent"],
    known_test_values=set(),
    recommendation="Revoke this token in Buildkite under Personal Settings > API Access Tokens.",
    tags=["ci", "buildkite"],
)


# ===================================================
# RAILWAY
# ===================================================

RAILWAY_TOKEN = SecretPattern(
    id="railway_token",
    name="Railway Deploy Token",
    description=(
        "Railway deploy token, a UUID-format string."
        " Detected when preceded by Railway-specific context keywords."
    ),
    provider="railway",
    severity="high",
    # Independently authored — context-gated UUID; Railway-documented deploy token format
    regex=re.compile(
        r"(?:"
        r"(?:RAILWAY_TOKEN|railway.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9\-]{36})"
        r"(?![a-f0-9\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=0.0,
    context_keywords=["railway", "RAILWAY_TOKEN"],
    known_test_values=set(),
    recommendation="Revoke this token in the Railway dashboard under Project Settings > Tokens.",
    tags=["cloud", "railway", "deploy"],
)


# ===================================================
# GOOGLE OAUTH (Batch 8 — 2026-06-22)
# ===================================================

GOOGLE_OAUTH_ACCESS_TOKEN = SecretPattern(
    id="google_oauth_access_token",
    name="Google OAuth 2.0 Access Token",
    description=(
        "Google OAuth 2.0 access token with the documented 'ya29.' prefix."
        " Grants delegated access to Google APIs on behalf of a user or"
        " service account until expiry."
    ),
    provider="google",
    severity="high",
    # Vendor-published format — ya29. is Google's documented OAuth 2.0 access-token prefix
    # Source: https://cloud.google.com/docs/authentication/token-types#access
    regex=re.compile(
        r"(?P<secret>ya29\.[0-9A-Za-z._\-]{50,})"
        r"(?![0-9A-Za-z._\-])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["google", "oauth", "access_token", "ya29", "googleapis"],
    known_test_values={
        "ya29.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOp",
    },
    recommendation=(
        "Revoke this access token via the Google OAuth token revocation endpoint"
        " (https://oauth2.googleapis.com/revoke) and rotate the refresh token or"
        " service-account key that minted it."
    ),
    tags=["cloud", "google", "oauth"],
)


# ===================================================
# TENCENT CLOUD (Batch 8 — 2026-06-22)
# ===================================================

TENCENT_CLOUD_SECRET_ID = SecretPattern(
    id="tencent_cloud_secret_id",
    name="Tencent Cloud Secret ID",
    description=(
        "Tencent Cloud API SecretId with the 'AKID' prefix followed by 32"
        " alphanumeric characters. The SecretId is an identifier paired with a"
        " SecretKey — medium severity because it is not sufficient alone."
    ),
    provider="tencent",
    severity="medium",
    # Vendor-published format — AKID prefix is Tencent Cloud's documented SecretId format
    # Source: https://www.tencentcloud.com/document/product/845/32207
    regex=re.compile(
        r"(?P<secret>AKID[A-Za-z0-9]{32})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=["tencent", "tencentcloud", "secret_id", "AKID", "qcloud"],
    known_test_values={
        "AKID" + "0" * 32,  # synthetic; concatenated so no scannable AKID secret literal exists in source
    },
    recommendation=(
        "Rotate this SecretId together with its paired SecretKey in the Tencent"
        " Cloud console under Access Management > API Keys."
    ),
    tags=["cloud", "tencent"],
)


# ===================================================
# YANDEX CLOUD (Batch 10 — 2026-07-06)
# ===================================================

YANDEX_CLOUD_IAM_TOKEN = SecretPattern(
    id="yandex_cloud_iam_token",
    name="Yandex Cloud IAM Token",
    description=(
        "Yandex Cloud IAM token — a 't1.' prefix, a base64url middle segment,"
        " and a fixed 86-char base64url signature tail. These are short-lived"
        " bearer tokens (roughly a 12-hour TTL), so severity is medium: a leaked"
        " token grants Yandex Cloud API access only until it expires, but that is"
        " still ample time for abuse."
    ),
    provider="yandex_cloud",
    severity="medium",
    # Format per https://yandex.cloud/en/docs/security/standard/authentication :
    # IAM tokens are 't1.' + base64url payload + '.' + a fixed 86-char base64url
    # signature. Prefix + fixed-length tail make this structural. Only the
    # signature tail is captured as the secret. Regex independently authored.
    # Format per https://yandex.cloud/en/docs/security/standard/authentication
    regex=re.compile(
        r"t1\.[A-Za-z0-9_-]+={0,2}\."
        r"(?P<secret>[A-Za-z0-9_-]{86}={0,2})",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["yandex", "yandexcloud", "iam_token", "IAM-Token", "yc"],
    known_test_values={
        # The captured secret is the 86-char signature tail only.
        # Synthetic; concatenated so no scannable token literal exists in source.
        "B" * 86,
    },
    recommendation=(
        "IAM tokens are ephemeral (~12h TTL) but still exploitable while valid."
        " Stop logging tokens; issue fresh ones per request via the yc CLI or"
        " metadata service rather than storing them."
    ),
    tags=["cloud", "yandex_cloud"],
)


# ===================================================
# YANDEX PASSPORT OAUTH TOKEN (2026-08-24)
# ===================================================

# Distinct credential from yandex_cloud_iam_token above, and far more dangerous.
# An IAM token ('t1.' prefix) is a ~12-hour derived credential; a Yandex
# Passport OAuth token is the LONG-LIVED user credential you exchange FOR IAM
# tokens, so a leak grants renewable access for the life of the token rather
# than until the next expiry. Hence critical, where the IAM token is medium.
#
# Yandex documents the anchor exactly: "The token always starts with a `y`, a
# random number in the `0-3` range, and an underscore (`_`)." The digit class is
# deliberately NOT widened past [0-3] — that is the vendor's documented range,
# and widening it would be inventing format.
#
# A three-character prefix is a weak anchor on its own, so two things carry the
# precision instead:
#   - The exact 55-character body width, measured on the vendor's own published
#     token. Both boundary guards are (?<![A-Za-z0-9_-]) / (?![A-Za-z0-9_-]),
#     which means the pattern can never fire INSIDE a longer base64url run — in
#     a JWT payload or a base64 blob every neighbouring character is in the key
#     charset, so the left guard fails and there is no match. The residual FP
#     surface is a standalone 58-character token that happens to open with
#     y[0-3]_.
#   - The mixed-case lookaheads, which are the placeholder defence and cost
#     essentially nothing: a random 55-character base64url body contains no
#     lowercase (or no uppercase) with probability ~1e-13, while every plausible
#     mask — 55 'x's, 55 'X's, a lowercase hex run, an all-digit run — fails one
#     of them. This matters because confidence_base 0.90 sits ABOVE the 0.85
#     FP-wordlist gate, so the wordlist never gets a chance to price masks down.

YANDEX_PASSPORT_OAUTH_TOKEN = SecretPattern(
    id="yandex_passport_oauth_token",
    name="Yandex Passport OAuth Token",
    description=(
        "Yandex Passport OAuth token — 'y', a digit in the 0-3 range, an"
        " underscore, then 55 base64url characters. This is the long-lived user"
        " credential that Yandex Cloud API clients exchange for short-lived IAM"
        " tokens, so unlike an IAM token it does not expire out of usefulness:"
        " whoever holds it can keep minting fresh IAM tokens and acting as the"
        " account across Yandex Cloud and Yandex services."
    ),
    provider="yandex",
    severity="critical",
    # Prefix shape (a 'y', a digit 0-3, an underscore) is stated verbatim in
    # Yandex Cloud's OAuth token documentation, and the 55-character body width
    # was measured on the token the same page publishes. The boundary guards,
    # the mixed-case lookaheads, the confidence and the known_test_values are
    # ClassiFinder's own.
    # Source: https://yandex.cloud/en/docs/iam/concepts/authorization/oauth-token
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>y[0-3]_"
        r"(?=[A-Za-z0-9_-]{0,54}[a-z])"
        r"(?=[A-Za-z0-9_-]{0,54}[A-Z])"
        r"[A-Za-z0-9_-]{55})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    # 0.90 — the structural tier rather than the 0.95 prefix-anchored tier,
    # because a three-character prefix is a weak anchor and the width plus the
    # guards are doing most of the work. It is also a floor: below 0.85 the
    # FP-wordlist penalty (-0.40) would sink real tokens sitting in a *test* or
    # *demo* context.
    confidence_base=0.90,
    # 0.0 on purpose: the body is a fixed-width random base64url value, so any
    # entropy floor a placeholder failed would also fail real tokens. The
    # mixed-case lookaheads do the placeholder filtering instead.
    entropy_threshold=0.0,
    context_keywords=[
        "yandex",
        "oauth",
        "OAUTH_TOKEN",
        "passport",
        "yandex_passport",
        "iam",
    ],
    known_test_values={
        # Alphabet-sequence fixture shape — the placeholder convention used
        # throughout this repository, and mixed-case so it still satisfies the
        # lookaheads. Assembled by concatenation so no contiguous token-shaped
        # literal exists here. Down-scores to ~0.15.
        "y0_" + ("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" * 2)[:55],
    },
    recommendation=(
        "Revoke the OAuth token by removing the application's access under the"
        " Yandex ID account page (Security > App passwords and tokens), which"
        " invalidates every token issued to that client, then re-authorise and"
        " store the new token in a secret manager rather than in source or CI"
        " config. Rotate any IAM tokens, service-account keys or resources the"
        " token could have provisioned while it was exposed, and review the"
        " account's Yandex Cloud audit trails for API calls you did not make."
    ),
    tags=["cloud", "yandex", "oauth", "passport"],
)


# ===================================================
# ELASTIC CLOUD (Batch 12 — 2026-07-13; prefix-anchored)
# ===================================================

ELASTIC_CLOUD_API_KEY = SecretPattern(
    id="elastic_cloud_api_key",
    name="Elastic Cloud API Key",
    description=(
        "Elastic Cloud (serverless) API key — the literal 'essu_' prefix followed"
        " by a base64 body (variable length, roughly 100 characters, optionally"
        " padded with '='). Grants API access to the Elastic Cloud project."
        " Prefix-anchored on 'essu_'."
    ),
    provider="elastic",
    severity="critical",
    # Source: https://www.elastic.co/guide/en/serverless/current/api-keys.html
    # (Elastic Cloud serverless API keys carry the 'essu_' prefix followed by a
    # base64-encoded body). Independently authored — anchored on 'essu_' with a
    # base64 charset and a min-length floor rather than a hardcoded length.
    regex=re.compile(
        r"(?P<secret>essu_[A-Za-z0-9+/=]{50,})(?![A-Za-z0-9+/=])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["elastic", "essu_", "elasticsearch", "ELASTIC_API_KEY", "elastic.co"],
    known_test_values={
        # Synthetic — clearly-fake all-'A' base64 body, concatenated. ~0.15.
        "essu_" + "A" * 90,
    },
    recommendation=(
        "Revoke this key in the Elastic Cloud console under Project > API keys"
        " (or via the API-key management API) and issue a replacement."
    ),
    tags=["cloud", "elastic", "search"],
)


# ===================================================
# RENDER (2026-07-16)
# ===================================================
# Render (render.com) API keys carry the distinctive 'rnd_' prefix. The prefix
# is the citable anchor: Render's official API docs (render.com/docs/api,
# api-docs.render.com) reference the rnd_-prefixed key, and OpenAI's curated
# render-deploy skill shows `export RENDER_API_KEY="rnd_xxxxx"`. The vendor
# publishes only a `rnd_xxxxx` placeholder (no full literal, as expected for a
# live secret), so this pattern is deliberately PREFIX-ANCHORED on the public
# 'rnd_' spec with a generous URL-unsafe-free body range rather than a hardcoded
# length. Exact body length is community-corroborated ({20,} / {32}); {20,}
# chosen conservatively.

RENDER_API_KEY = SecretPattern(
    id="render_api_key",
    name="Render API Key",
    description=(
        "Render (render.com) API key, anchored on the public 'rnd_' prefix"
        " followed by an alphanumeric token body. Grants API access to the"
        " Render account (services, deploys, environment variables, custom"
        " domains). The prefix is vendor-confirmed via Render's official API"
        " docs and OpenAI's curated render-deploy skill."
    ),
    provider="render",
    severity="high",
    # Source: https://github.com/openai/skills/blob/main/skills/.curated/render-deploy/SKILL.md
    #   (OpenAI curated render-deploy skill: `export RENDER_API_KEY="rnd_xxxxx"`)
    #   cross-referenced with Render's official API docs (render.com/docs/api,
    #   api-docs.render.com), which reference the rnd_-prefixed key.
    # Independently authored — prefix-anchored on the vendor-published 'rnd_'
    # spec; body is a bounded alphanumeric charset, not a copied fixed length.
    regex=re.compile(
        r"(?P<secret>rnd_[0-9A-Za-z]{20,100})(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["render", "render.com", "RENDER_API_KEY", "rnd_"],
    known_test_values={
        # Synthetic — clearly-fake all-'A' body, kept out of git as a real token
        # shape. Registered so the documented example down-scores to ~0.15.
        "rnd_" + "A" * 32,
    },
    recommendation=(
        "Revoke this key in the Render dashboard (Account Settings → API Keys)"
        " and issue a replacement. Store it in Render's secret/env management"
        " rather than in code or logs."
    ),
    tags=["cloud", "render"],
)
# ===================================================
# AMAZON MWS (2026-07-22)
# ===================================================
# Amazon MWS (Marketplace Web Service) auth tokens carry the fixed literal
# 'amzn.mws.' prefix followed by a canonical UUID (8-4-4-4-12 lowercase hex
# with hyphens). The prefix is a public, structurally rigid anchor, so this is
# a high-precision pattern that needs no entropy gate. MWS is a legacy/deprecated
# Amazon seller API, but auth tokens still appear in older configs and leaks.

AMAZON_MWS_AUTH_TOKEN = SecretPattern(
    id="amazon_mws_auth_token",
    name="Amazon MWS Auth Token",
    description=(
        "Amazon Marketplace Web Service (MWS) auth token, anchored on the public"
        " 'amzn.mws.' prefix followed by a canonical UUID. Grants API access to a"
        " seller's Amazon MWS account (orders, inventory, reports, fulfillment)."
    ),
    provider="amazon",
    severity="high",
    # Prefix-anchored on the public 'amzn.mws.' literal + canonical UUID
    # (8-4-4-4-12 lowercase hex). Fixed prefix and rigid UUID shape — no entropy
    # gate needed. Format re-derived from the public spec below.
    # Pattern attribution: secrets-patterns-db CC-BY-4.0 (datasets/high-confidence.yml,
    #   "Amazon MWS Auth Token") — https://github.com/mazen160/secrets-patterns-db ; see ATTRIBUTION.md
    regex=re.compile(
        r"(?P<secret>amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        r"(?![0-9a-fA-F-])",  # negative lookahead: no trailing hex/hyphen
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # prefix-anchored + rigid UUID shape, no entropy check
    context_keywords=[
        "amzn.mws",
        "mws",
        "MWSAuthToken",
        "mws_auth_token",
        "amazon",
        "marketplace",
    ],
    known_test_values={
        # Synthetic all-zero UUID — clearly fake, kept out of git as a real token
        # shape. Registered so the documented example down-scores to ~0.15.
        "amzn.mws.00000000-0000-0000-0000-000000000000",
    },
    recommendation=(
        "Revoke this MWS auth token in Amazon Seller Central (or the Amazon"
        " developer console) and issue a replacement. Store it in a secret"
        " manager rather than in code, configs, or logs."
    ),
    tags=["cloud", "amazon", "mws"],
)


# ===================================================
# INFISICAL (2026-07-30)
# ===================================================
# Infisical is open source, so this format is read off the vendor's own key
# generator rather than inferred from a published example.
#
#   backend/src/services/service-token/service-token-service.ts
#       const secret = crypto.randomBytes(16).toString("hex");
#       const token  = `st.${serviceToken.id.toString()}.${secret}`;
#
# 16 bytes hex-encoded is exactly 32 lowercase characters, which pins the third
# segment. The middle segment is the service-token row id, and the table DDL in
# backend/src/db/migrations/20231225072545_service-token.ts declares
#
#       t.string("id", 36).primary().defaultTo(knex.fn.uuid());
#
# — a 36-character column defaulting to a generated UUID, i.e. canonical
# 8-4-4-4-12 lowercase hex. The vendor's own Go test fixture builds tokens as
# "st." + uuid.New().String() + "." + <secret>, agreeing with the DDL.
#
# 'st.' alone would be a far too weak anchor; what makes this low-FP is the
# fixed UUID plus fixed 32-hex structure, so neither segment is relaxed to a
# generic charset. No entropy threshold either: both variable segments are pure
# lowercase hex, whose maximum Shannon entropy is 4.0 bits per character, so any
# meaningful gate would make the pattern unmatchable in practice. Confidence
# comes from the structure, not from entropy.
#
# docs/internals/service-tokens.mdx documents the full user-facing token as
# "st.abc.def.ghi": "st.abc.def" is what applications send as the Bearer
# credential, and the trailing hex segment decrypts the project key. The
# server-side parser uses token.split(".", 3) and ignores that 4th segment, so
# pasted tokens occur in both shapes — hence the optional trailing hex group.
#
# Scope is service tokens only. backend-go/internal/services/auth/apiauth/
# classify.go returns AuthModeServiceToken for the 'st.' prefix and routes every
# other three-part dotted token to AuthModeJWT, so the literal anchor already
# excludes JWT bearer tokens and Infisical's other credential families.

INFISICAL_SERVICE_TOKEN = SecretPattern(
    id="infisical_service_token",
    name="Infisical Service Token",
    description=(
        "Infisical service token — the literal 'st.' prefix, the service-token"
        " id (a canonical lowercase UUID), and a 32-character lowercase hex"
        " secret, with an optional trailing hex segment carrying the"
        " project-key decryption material. Applications send the first three"
        " segments as a Bearer credential; the token reads every secret in the"
        " project environment it is scoped to."
    ),
    provider="infisical",
    severity="critical",
    # Format read off the vendor's own generator rather than an example:
    # crypto.randomBytes(16).toString("hex") fixes the secret segment at exactly
    # 32 lowercase hex characters, and the service-token id column is
    # t.string("id", 36) defaulting to knex.fn.uuid(), i.e. a canonical UUID.
    # The optional 4th segment is the project-key decryption material documented
    # in docs/internals/service-tokens.mdx and ignored by the server's
    # token.split(".", 3). Independently authored from those vendor sources; no
    # third-party detector was consulted. No entropy threshold — both variable
    # segments are lowercase hex (max 4.0 bits/char), so a gate would only add
    # false negatives; the UUID + fixed-32-hex structure carries the signal.
    # Source: https://github.com/Infisical/infisical/blob/main/backend/src/services/service-token/service-token-service.ts
    regex=re.compile(
        r"(?<![A-Za-z0-9._-])"
        r"(?P<secret>st\."
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        r"\.[0-9a-f]{32}(?:\.[0-9a-f]+)?)"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,  # prefix-anchored + fixed UUID and 32-hex structure
    entropy_threshold=0.0,
    context_keywords=[
        "infisical",
        "INFISICAL_TOKEN",
        "service token",
        "serviceToken",
        "INFISICAL_API_URL",
    ],
    known_test_values={
        # All-zero UUID with an all-zero secret — the canonical placeholder
        # shape for this token and definitionally not a live credential. Built
        # by concatenation so no scannable token literal exists in source.
        "st." + "00000000-0000-0000-0000-000000000000" + "." + "0" * 32,
    },
    recommendation=(
        "Revoke this service token in the Infisical dashboard under the"
        " project's Access Control > Service Tokens, then issue a replacement"
        " and update it everywhere it is configured — CI, deploy targets, and"
        " local .env files. Because the token reads every secret in the"
        " environment it is scoped to, treat every secret in that environment"
        " as exposed and rotate them too."
    ),
    tags=["cloud", "infisical", "secrets"],
)

# ===================================================
# AZURE / MICROSOFT IDENTIFIABLE ("annotated") KEYS
# ===================================================
#
# Microsoft stamps a fixed 4-character signature into its generated keys at a
# fixed byte offset, so the credential announces its own provider and service
# without a leading prefix. `microsoft/security-utilities` (MIT) publishes the
# signature, the offset and the total length for each service in
# GeneratedRegexPatterns/HighConfidenceSecurityModels.json; those three facts
# are what the nine patterns below are derived from. See ATTRIBUTION.md.
#
# Every one of them is signature-anchored at a fixed offset rather than
# prefix-anchored, which is an equally strong signal: the probability that an
# arbitrary base64 blob carries e.g. `ACDb` at exactly offset 76 AND terminates
# with a base64-legal `[AQgw]==` is negligible. That is why none of them carries
# an entropy gate. What they do carry are left/right boundary guards, so a
# signature sitting inside a longer blob cannot be carved out into a finding.
# The left guard deliberately does NOT exclude `=`, so `AccountKey=<key>` and
# `?code=<key>` still match while a mid-blob match does not.
#
# Microsoft publishes no real literals — its own tests call
# GenerateTruePositiveExamples() — so there is no vendor-published dummy to
# register as a known_test_value for any of these. Registering the test fixtures
# instead would force them to 0.15 and break the tests that use them.


AZURE_COSMOS_DB_KEY = SecretPattern(
    id="azure_cosmos_db_key",
    name="Azure Cosmos DB Account Key",
    description=(
        "Azure Cosmos DB account key — 88 base64 characters carrying the literal"
        " signature 'ACDb' at offset 76. Grants full read/write access to every"
        " container in the account. May be either the primary or the secondary"
        " key, and either the read-write or the read-only variant; Microsoft"
        " ships the same format for all four, so they are indistinguishable."
    ),
    provider="azure",
    severity="critical",
    # Confidence 0.95 is load-bearing, not cosmetic. This shape is a strict
    # subset of `azure_storage_key` (86 base64 characters + '=='), and real
    # Cosmos connection strings genuinely use `AccountKey=` — so before this
    # pattern existed the engine reported a leaked Cosmos key as
    # `azure_storage_key` at 0.92. Dedup picks the highest-confidence finding on
    # an overlapping span, so 0.95 is what makes the specific reading win and
    # fixes that mislabel. A non-collision test asserts it in both directions.
    # Source: microsoft/security-utilities (MIT), rule SEC101/160
    #   https://github.com/microsoft/security-utilities/blob/main/GeneratedRegexPatterns/HighConfidenceSecurityModels.json
    regex=re.compile(
        r"(?<![A-Za-z0-9+/_-])"
        r"(?P<secret>[A-Za-z0-9+/]{76}ACDb[A-Za-z0-9+/]{5}[AQgw]==)"
        r"(?![A-Za-z0-9+/=_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # signature-anchored at a fixed offset
    context_keywords=[
        "cosmos",
        "AccountKey",
        "documents.azure.com",
        "azure",
        "COSMOS_KEY",
        "AccountEndpoint",
    ],
    known_test_values=set(),
    recommendation=(
        "Regenerate this account key in the Azure Portal (Cosmos DB account ->"
        " Keys) and roll the secondary key first so callers can cut over."
        " Prefer Entra ID role-based access or a managed identity over account"
        " keys, which cannot be scoped below the account."
    ),
    tags=["cloud", "azure", "cosmos", "database"],
)


AZURE_FUNCTIONS_KEY = SecretPattern(
    id="azure_functions_key",
    name="Azure Functions Access Key",
    description=(
        "Azure Functions access key — 56 base64url characters carrying the"
        " literal signature 'AzFu' at offset 44. Authorizes invocation of a"
        " function app's HTTP-triggered endpoints, usually via the '?code='"
        " query parameter or the 'x-functions-key' header. May be a function,"
        " host or master key; the format does not distinguish them."
    ),
    provider="azure",
    severity="high",
    # Base64URL, not standard base64: the charset is [A-Za-z0-9_-], with '_'
    # and '-' replacing '+' and '/'. Using the standard alphabet here would miss
    # every real key that happens to contain either substituted character.
    # Source: microsoft/security-utilities (MIT), rule SEC101/158
    #   https://github.com/microsoft/security-utilities/blob/main/GeneratedRegexPatterns/HighConfidenceSecurityModels.json
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>[A-Za-z0-9_-]{44}AzFu[A-Za-z0-9_-]{5}[AQgw]==)"
        r"(?![A-Za-z0-9=_-])",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,  # signature-anchored at a fixed offset
    context_keywords=[
        "azurewebsites.net",
        "functions",
        "x-functions-key",
        "code",
        "azure",
        "FUNCTION_KEY",
    ],
    known_test_values=set(),
    recommendation=(
        "Renew this key in the Azure Portal (Function App -> App keys, or the"
        " individual function's Function keys). If it is the master key, treat"
        " the whole function app as compromised — the master key also unlocks"
        " the admin API. Prefer Entra ID authentication over access keys."
    ),
    tags=["cloud", "azure", "functions", "serverless"],
)


AZURE_SEARCH_KEY = SecretPattern(
    id="azure_search_key",
    name="Azure AI Search Service Key",
    description=(
        "Azure AI Search (formerly Cognitive Search) service key — 52"
        " alphanumeric characters carrying the literal signature 'AzSe' at"
        " offset 42. May be an ADMIN key, which grants full control of indexes"
        " and data, or a QUERY key, which is read-only and is designed to be"
        " embedded in client-side code. Microsoft ships a byte-identical format"
        " for both, so a finding cannot tell them apart — treat it as an admin"
        " key until you have confirmed otherwise, and expect legitimate query"
        " keys to surface in public JavaScript bundles."
    ),
    provider="azure",
    severity="high",
    # Deliberate, documented false-positive risk. Query keys are public by
    # design and are legitimately shipped in browser bundles, so this pattern
    # will fire on values their owners intended to publish. It ships anyway
    # because the alternative — missing admin keys entirely, since the two are
    # byte-identical — is the worse failure. confidence_base is set one notch
    # below the rest of this family to reflect that, while staying above the
    # 0.85 FP-wordlist pricing floor.
    # Source: microsoft/security-utilities (MIT), rules SEC101/166 and SEC101/167
    #   https://github.com/microsoft/security-utilities/blob/main/GeneratedRegexPatterns/HighConfidenceSecurityModels.json
    regex=re.compile(
        r"(?<![A-Za-z0-9+/_-])"
        r"(?P<secret>[A-Za-z0-9]{42}AzSe[A-D][A-Za-z0-9]{5})"
        r"(?![A-Za-z0-9+/=_-])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,  # signature-anchored at a fixed offset
    context_keywords=[
        "search.windows.net",
        "api-key",
        "azure",
        "search",
        "SEARCH_API_KEY",
        "cognitive",
    ],
    known_test_values=set(),
    recommendation=(
        "Regenerate the key in the Azure Portal (Search service -> Keys)."
        " Confirm first whether this is an admin or a query key: an admin key"
        " can create, delete and read every index, while a query key is"
        " read-only and may have been published deliberately."
    ),
    tags=["cloud", "azure", "search", "ai"],
)


AZURE_EVENT_HUB_KEY = SecretPattern(
    id="azure_event_hub_key",
    name="Azure Event Hubs Shared Access Key",
    description=(
        "Azure Event Hubs shared access key — 44 base64 characters carrying the"
        " literal signature '+AEh' at offset 33. The 'SharedAccessKey' half of"
        " an Event Hubs connection string; grants whatever the paired SAS policy"
        " allows (send, listen or manage) over the namespace or entity."
    ),
    provider="azure",
    severity="high",
    # The '+' in '+AEh' is a literal base64 character, not a quantifier, and is
    # escaped accordingly. Same for the Service Bus and Container Registry
    # siblings below.
    # Source: microsoft/security-utilities (MIT), rule SEC101/172
    #   https://github.com/microsoft/security-utilities/blob/main/GeneratedRegexPatterns/HighConfidenceSecurityModels.json
    regex=re.compile(
        r"(?<![A-Za-z0-9+/_-])"
        r"(?P<secret>[A-Za-z0-9+/]{33}\+AEh[A-P][A-Za-z0-9+/]{5}=)"
        r"(?![A-Za-z0-9+/=_-])",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,  # signature-anchored at a fixed offset
    context_keywords=[
        "servicebus.windows.net",
        "SharedAccessKey",
        "eventhub",
        "Endpoint",
        "azure",
        "EVENTHUB_CONNECTION_STRING",
    ],
    known_test_values=set(),
    recommendation=(
        "Regenerate the shared access policy's key in the Azure Portal"
        " (Event Hubs namespace or entity -> Shared access policies)."
        " Prefer Entra ID role-based access over SAS keys, and scope any"
        " remaining policy to the single entity and the single right it needs."
    ),
    tags=["cloud", "azure", "eventhub", "messaging"],
)


AZURE_SERVICE_BUS_KEY = SecretPattern(
    id="azure_service_bus_key",
    name="Azure Service Bus Shared Access Key",
    description=(
        "Azure Service Bus shared access key — 44 base64 characters carrying the"
        " literal signature '+ASb' at offset 33. The 'SharedAccessKey' half of a"
        " Service Bus connection string; grants whatever the paired SAS policy"
        " allows (send, listen or manage) over the namespace, queue or topic."
    ),
    provider="azure",
    severity="high",
    # Structurally identical to the Event Hubs key apart from the signature —
    # both services sit on the same *.servicebus.windows.net endpoint, which is
    # why the signature rather than the hostname is what separates them.
    # Source: microsoft/security-utilities (MIT), rule SEC101/171
    #   https://github.com/microsoft/security-utilities/blob/main/GeneratedRegexPatterns/HighConfidenceSecurityModels.json
    regex=re.compile(
        r"(?<![A-Za-z0-9+/_-])"
        r"(?P<secret>[A-Za-z0-9+/]{33}\+ASb[A-P][A-Za-z0-9+/]{5}=)"
        r"(?![A-Za-z0-9+/=_-])",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,  # signature-anchored at a fixed offset
    context_keywords=[
        "servicebus.windows.net",
        "SharedAccessKey",
        "servicebus",
        "Endpoint",
        "azure",
        "SERVICEBUS_CONNECTION_STRING",
    ],
    known_test_values=set(),
    recommendation=(
        "Regenerate the shared access policy's key in the Azure Portal"
        " (Service Bus namespace, queue or topic -> Shared access policies)."
        " Prefer Entra ID role-based access over SAS keys, and scope any"
        " remaining policy to the single entity and the single right it needs."
    ),
    tags=["cloud", "azure", "servicebus", "messaging"],
)


AZURE_IOT_KEY = SecretPattern(
    id="azure_iot_key",
    name="Azure IoT Key",
    description=(
        "Azure IoT shared access key — 44 base64 characters carrying the literal"
        " signature 'AIoT' at offset 33. Microsoft ships a byte-identical format"
        " for the IoT Hub service key, the per-device symmetric key and the"
        " Device Provisioning Service key, so a finding cannot tell which of the"
        " three it is. Assume the broadest: an IoT Hub or DPS key can enrol,"
        " impersonate and control every device in the hub."
    ),
    provider="azure",
    severity="critical",
    # Named generically on purpose. SEC101/178 (IoT Hub), SEC101/179 (Device
    # Provisioning) and SEC101/180 (Device) are three separate Microsoft rules
    # with one identical regex; calling this "IoT Hub Key" would overclaim on
    # two thirds of its matches.
    # Source: microsoft/security-utilities (MIT), rules SEC101/178, 179 and 180
    #   https://github.com/microsoft/security-utilities/blob/main/GeneratedRegexPatterns/HighConfidenceSecurityModels.json
    regex=re.compile(
        r"(?<![A-Za-z0-9+/_-])"
        r"(?P<secret>[A-Za-z0-9+/]{33}AIoT[A-P][A-Za-z0-9+/]{5}=)"
        r"(?![A-Za-z0-9+/=_-])",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,  # signature-anchored at a fixed offset
    context_keywords=[
        "azure-devices.net",
        "SharedAccessKey",
        "iothub",
        "DeviceId",
        "HostName",
        "azure",
    ],
    known_test_values=set(),
    recommendation=(
        "Determine which key this is before rotating: an IoT Hub shared access"
        " policy key and a DPS enrolment key are regenerated in the Azure"
        " Portal, while a device symmetric key is regenerated per device."
        " If it is a hub or DPS key, audit device registrations for"
        " unrecognised enrolments — it can mint device identities."
    ),
    tags=["cloud", "azure", "iot"],
)


AZURE_CONTAINER_REGISTRY_KEY = SecretPattern(
    id="azure_container_registry_key",
    name="Azure Container Registry Access Key",
    description=(
        "Azure Container Registry admin access key — 52 base64 characters"
        " carrying the literal signature '+ACR' at offset 42. Paired with the"
        " registry name as the username, it grants push and pull rights over"
        " every repository in the registry."
    ),
    provider="azure",
    severity="critical",
    # Push access to a container registry is a supply-chain foothold: an
    # attacker who can push a tag can have it pulled and executed by whatever
    # deploys from it. Hence critical rather than high.
    # Source: microsoft/security-utilities (MIT), rule SEC101/176
    #   https://github.com/microsoft/security-utilities/blob/main/GeneratedRegexPatterns/HighConfidenceSecurityModels.json
    regex=re.compile(
        r"(?<![A-Za-z0-9+/_-])"
        r"(?P<secret>[A-Za-z0-9+/]{42}\+ACR[A-D][A-Za-z0-9+/]{5})"
        r"(?![A-Za-z0-9+/=_-])",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,  # signature-anchored at a fixed offset
    context_keywords=[
        "azurecr.io",
        "registry",
        "docker login",
        "acr",
        "azure",
        "REGISTRY_PASSWORD",
    ],
    known_test_values=set(),
    recommendation=(
        "Regenerate the admin credential in the Azure Portal (Container"
        " Registry -> Access keys), then audit the registry's push history for"
        " unexpected tags. Better: disable the admin account entirely and use"
        " Entra ID tokens or a scoped repository token instead."
    ),
    tags=["cloud", "azure", "registry", "containers"],
)


AZURE_APIM_KEY = SecretPattern(
    id="azure_apim_key",
    name="Azure API Management Key",
    description=(
        "Azure API Management key — 88 base64 characters carrying the literal"
        " signature 'APIM' at offset 76. Microsoft ships a byte-identical format"
        " for the direct-management, subscription, gateway and repository keys,"
        " so a finding cannot tell which of the four it is. Assume the"
        " broadest: a direct-management key is a control-plane credential for"
        " the whole APIM instance."
    ),
    provider="azure",
    severity="high",
    # Named generically on purpose — SEC101/181 through SEC101/184 are four
    # Microsoft rules sharing one regex, so "Subscription Key" would overclaim.
    # Like the Cosmos key this shares the 86-base64 + '==' shape with
    # `azure_storage_key`; confidence_base is set above that pattern's
    # post-context score so the specific reading wins dedup. The practical
    # likelihood of an APIM key sitting behind an `AccountKey=` label is low,
    # but the non-collision is asserted rather than assumed.
    # Source: microsoft/security-utilities (MIT), rules SEC101/181 through 184
    #   https://github.com/microsoft/security-utilities/blob/main/GeneratedRegexPatterns/HighConfidenceSecurityModels.json
    regex=re.compile(
        r"(?<![A-Za-z0-9+/_-])"
        r"(?P<secret>[A-Za-z0-9+/]{76}APIM[A-Za-z0-9+/]{5}[AQgw]==)"
        r"(?![A-Za-z0-9+/=_-])",
        re.ASCII,
    ),
    confidence_base=0.93,
    entropy_threshold=0.0,  # signature-anchored at a fixed offset
    context_keywords=[
        "azure-api.net",
        "Ocp-Apim-Subscription-Key",
        "apim",
        "management",
        "azure",
        "subscription",
    ],
    known_test_values=set(),
    recommendation=(
        "Regenerate the key in the Azure Portal (API Management -> the relevant"
        " Subscriptions, Gateways or Repository page). If it is the direct"
        " management key, disable direct management access entirely and use the"
        " ARM control plane, which honours Entra ID and RBAC."
    ),
    tags=["cloud", "azure", "apim", "api-gateway"],
)


MICROSOFT_CASK_KEY = SecretPattern(
    id="microsoft_cask_key",
    name="Microsoft Common Annotated Security Key",
    description=(
        "Microsoft Common Annotated Security Key (CASK) — the successor format"
        " to the per-service 'identifiable' keys, carrying the literal signature"
        " 'JQQJ' at offset 52 followed by a version character and a fixed"
        " metadata layout. 84 characters, or 88 with the optional base64 tail."
        " The provider signature that would name the issuing service is not"
        " part of the shape this pattern matches, so the credential is reported"
        " unclassified: it may belong to any Microsoft or Azure service."
    ),
    provider="microsoft",
    severity="high",
    # The optional '(?:[A-Za-z0-9]{2}==)?' tail is Microsoft's own: a CASK key
    # is published as either 84 or 88 characters. The group is greedy, so an
    # 88-character key is matched in full rather than truncated to its first 84.
    # Source: microsoft/security-utilities (MIT), rule SEC101/200
    #   https://github.com/microsoft/security-utilities/blob/main/GeneratedRegexPatterns/HighConfidenceSecurityModels.json
    regex=re.compile(
        r"(?<![A-Za-z0-9])"
        r"(?P<secret>[A-Za-z0-9]{52}JQQJ9[9DH][A-Za-z0-9][A-L][A-Za-z0-9]{16}"
        r"[A-Za-z][A-Za-z0-9]{7}(?:[A-Za-z0-9]{2}==)?)"
        r"(?![A-Za-z0-9=])",
        re.ASCII,
    ),
    confidence_base=0.93,
    entropy_threshold=0.0,  # signature-anchored at a fixed offset
    context_keywords=[
        "azure",
        "microsoft",
        "api_key",
        "apikey",
        "key",
        "secret",
    ],
    known_test_values=set(),
    recommendation=(
        "Identify the issuing service from where the key is used, then"
        " regenerate it there. CASK keys are self-describing by design, so"
        " Microsoft's own tooling can classify the value; treat it as a live"
        " credential for whatever service it belongs to until proven otherwise."
    ),
    tags=["cloud", "azure", "microsoft"],
)


# ===================================================
# OPENSHIFT (2026-08-24)
# ===================================================

# An OpenShift OAuth access token is the bearer credential `oc login --token=`
# takes and the value of the `Authorization: Bearer ...` header against the
# cluster API. The whole 'sha256~<43>' string is the credential, so the whole
# string is captured — the prefix is not a decoration to be stripped.
#
# The 43-character body is a DERIVED constant, not a width measured off one
# sample. OpenShift's OAuth API types state that a token's stored name is the
# token sha256-hashed and then URL-safe unpadded-base64-encoded per RFC 4648;
# 43 is the unique unpadded-base64url length for a 32-byte SHA-256 digest
# (31 bytes -> 42 characters, 33 -> 44). So {43} is a property of the digest
# size and cannot drift.
#
# 'sha256~' appears in no other registered pattern. The 43-character body is
# also matchable by the generic catch-alls, but provider != "generic" wins every
# overlapping span in _dedup_overlapping_findings regardless of confidence, so
# this pattern is the sole claimant; a test pins that.
#
# The '~' is the reason the left guard can be cheap: it is not in the token
# charset, so a 'sha256~' occurring inside a longer identifier is already
# impossible. The guards exist to stop the body being the leading or trailing
# slice of a longer base64url run.

OPENSHIFT_OAUTH_ACCESS_TOKEN = SecretPattern(
    id="openshift_oauth_access_token",
    name="OpenShift OAuth Access Token",
    description=(
        "OpenShift / OKD OAuth access token — the literal 'sha256~' prefix"
        " followed by 43 URL-safe unpadded base64 characters. This is the bearer"
        " token `oc login --token=` accepts and that clients send as"
        " 'Authorization: Bearer'. It carries the full RBAC of the user or"
        " service account it was issued to, so on a cluster-admin account it is"
        " effectively root on the whole cluster."
    ),
    provider="openshift",
    severity="high",
    # Structure per OpenShift's own OAuth API type definitions, which state that
    # the token name is the token sha256-hashed and URL-safe unpadded-base64
    # encoded (RFC 4648); the 43-character width is derived from that 32-byte
    # digest, not transcribed. Guards, confidence and known_test_values are
    # ClassiFinder's own.
    # Source: https://github.com/openshift/api/blob/master/oauth/v1/types.go
    regex=re.compile(
        r"(?<![A-Za-z0-9_~-])"
        r"(?P<secret>sha256~[A-Za-z0-9_-]{43})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    # Prefix-anchored tier: 'sha256~' plus a derived fixed width is about as
    # unambiguous as a detector gets. Also comfortably above the 0.85
    # FP-wordlist gate, so a token pasted next to the word "test" is not sunk.
    confidence_base=0.95,
    # 0.0 on purpose: the body is a fixed-width digest, so an entropy floor
    # could only ever sink legitimate tokens.
    entropy_threshold=0.0,
    context_keywords=[
        "openshift",
        "oc login",
        "okd",
        "kubeconfig",
        "Bearer",
        "OCP_TOKEN",
    ],
    known_test_values={
        # The masked shape that dominates OpenShift docs, blog posts and
        # bug reports. Assembled by concatenation. Down-scores to ~0.15.
        "sha256~" + "A" * 43,
    },
    recommendation=(
        "Delete the token object on the cluster — `oc delete oauthaccesstoken"
        " sha256~<...>`, or `oc logout` from the session that minted it — which"
        " revokes it immediately; OpenShift access tokens are otherwise valid"
        " for their full 24-hour default lifetime. If the token belonged to a"
        " service account, rotate the account's credentials. Then review the"
        " cluster audit log for API activity attributed to that user while the"
        " token was exposed, and stop embedding `oc login --token=` in CI"
        " scripts, kubeconfigs committed to source, or shell history."
    ),
    tags=["cloud", "openshift", "kubernetes", "oauth"],
)


# ===================================================
# SCALINGO (2026-08-24)
# ===================================================

# Scalingo API tokens carry a region in the prefix — 'tk-us-' is the token shape
# Scalingo's own token documentation publishes, and it is the only variant
# shipped here. Widening the region segment to an open [a-z]{2} would be
# inventing format for regions whose prefixes have not been observed.
#
# Severity is critical rather than high on the vendor's own wording: Scalingo
# API tokens have an INFINITE lifetime unless explicitly revoked, and they
# authenticate the full platform API — deploying, scaling, reading environment
# variables (which is to say, every other secret the app holds), and opening
# database tunnels.
#
# The 48-character body is measured, not assumed: both concrete tokens Scalingo
# renders in its own documentation are exactly 48 characters after the prefix.
# The charset includes '-' and '_' as well as alphanumerics, which is why the
# left guard has to carry '-' too: without it, the trailing part of a longer
# hyphenated identifier could present as a 'tk-us-' prefix.

SCALINGO_API_TOKEN = SecretPattern(
    id="scalingo_api_token",
    name="Scalingo API Token",
    description=(
        "Scalingo API token — the 'tk-us-' region-qualified prefix followed by"
        " 48 base64url characters. Scalingo API tokens have no expiry unless"
        " revoked, and they authenticate the whole platform API: deploying and"
        " restarting apps, scaling containers, reading and writing environment"
        " variables (so every other credential the app holds), and opening"
        " database tunnels."
    ),
    provider="scalingo",
    severity="critical",
    # Prefix and the 48-character body are Scalingo's own: both concrete tokens
    # rendered on its token documentation measure identically. Guards,
    # confidence and known_test_values are ClassiFinder's own.
    # Source: https://developers.scalingo.com/tokens
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>tk-us-[A-Za-z0-9_-]{48})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    # Prefix-anchored tier, and above the 0.85 FP-wordlist gate so a token in a
    # *test* or *staging* context is not silently priced down — Scalingo tokens
    # are commonly issued per-environment.
    confidence_base=0.95,
    # 0.0 on purpose: fixed-width random body; an entropy floor could only sink
    # legitimate tokens.
    entropy_threshold=0.0,
    context_keywords=[
        "scalingo",
        "SCALINGO_API_TOKEN",
        "scalingo login",
        "api_token",
    ],
    known_test_values={
        # The token Scalingo publishes in its own documentation — the most
        # copy-pasted value of this shape. Assembled by concatenation so no
        # contiguous token-shaped literal exists here. Down-scores to ~0.15.
        "tk-us-" + "BQ3LRmLGc35pMjdgwjX6kI1IWh7MAYk2uqquYwLDxCd4fhSm",
        # Masked placeholder shape.
        "tk-us-" + "X" * 48,
    },
    recommendation=(
        "Revoke this token immediately in the Scalingo dashboard under Account >"
        " Tokens — it does not expire on its own — and issue a replacement"
        " scoped to a single automation. Because the token can read every app's"
        " environment variables, treat every other credential in those apps as"
        " exposed too and rotate them. Review the app's deployment and"
        " operations history for activity you did not initiate."
    ),
    tags=["cloud", "scalingo", "paas"],
)


# ===================================================
# GOOGLE OAUTH CLIENT SECRET
# ===================================================

GOOGLE_OAUTH_CLIENT_SECRET = SecretPattern(
    id="google_oauth_client_secret",
    name="Google OAuth Client Secret",
    description=(
        "Google OAuth 2.0 client secret — the literal 'GOCSPX-' prefix"
        " followed by 28 base64url characters, 35 characters in total. Issued"
        " alongside a '<numeric>-<hash>.apps.googleusercontent.com' client ID"
        " in the Google Cloud console and presented on the token endpoint to"
        " exchange authorization codes for access and refresh tokens. Holding"
        " it together with a leaked authorization code or refresh token is"
        " enough to mint access tokens for the end users who consented to the"
        " app, for every scope the app requested."
    ),
    provider="google",
    severity="high",
    # The 'GOCSPX-' prefix and the 28-character base64url body are the format
    # Google has issued since the 2021 console change; the older secrets it
    # replaced were prefixless and are deliberately not matched, because an
    # unanchored 24-character base64url run is any random string.
    #
    # No entropy gate: the body is a fixed-width random run, so any floor a
    # placeholder failed would also sink real secrets. The boundary guards are
    # ClassiFinder's own — 'GOCSPX-' is a strong literal, but the left guard
    # keeps it from starting mid-identifier and the right guard carries the
    # body charset so a 28-character head of a longer base64url run is never
    # claimed as a whole secret.
    # Source: https://github.com/praetorian-inc/noseyparker/blob/main/crates/noseyparker/data/default/builtin/rules/google.yml
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"(?P<secret>GOCSPX-[0-9A-Za-z_-]{28})"
        r"(?![0-9A-Za-z_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # fixed-width random body; a floor could only sink real secrets
    context_keywords=[
        "google",
        "oauth",
        "client_secret",
        "GOOGLE_CLIENT_SECRET",
        "googleusercontent",
    ],
    known_test_values={
        # Single-character masks — how documentation and redacted console
        # screenshots render this secret. confidence_base 0.95 sits above the
        # 0.85 FP-wordlist gate (scanner.py:197), so the wordlist never gets a
        # chance to price these down; they are pinned here instead and land at
        # ~0.15. Assembled by concatenation so no scannable literal exists in
        # source — GitHub's partner scanner recognises this prefix.
        "GOCSPX-" + "x" * 28,
        "GOCSPX-" + "X" * 28,
        "GOCSPX-" + "0" * 28,
        "GOCSPX-" + "a" * 28,
    },
    recommendation=(
        "Reset this secret in the Google Cloud console under APIs & Services >"
        " Credentials > OAuth 2.0 Client IDs, then redeploy every service that"
        " presents it. Google supports having two secrets live at once, so"
        " create the replacement first and disable the old one after the"
        " rollout rather than taking an outage. Treat any refresh tokens the"
        " app holds as exposed — with the client secret they can be exchanged"
        " for user access tokens — and review the project's OAuth consent and"
        " token activity for the exposure window."
    ),
    tags=["cloud", "google", "oauth", "auth"],
)


# ===================================================
# DIGITALOCEAN OAUTH TOKENS
# ===================================================

DIGITALOCEAN_OAUTH_ACCESS_TOKEN = SecretPattern(
    id="digitalocean_oauth_access_token",
    name="DigitalOcean OAuth Access Token",
    description=(
        "DigitalOcean OAuth access token — the literal 'doo_v1_' prefix"
        " followed by 64 lowercase hex characters. Minted by the OAuth"
        " authorization-code exchange rather than by hand, and presented as a"
        " bearer token against the DigitalOcean API with the scopes the"
        " resource owner granted: read or write across Droplets, Kubernetes"
        " clusters, Spaces, databases and the account's billing data. The"
        " sibling personal access token uses 'dop_v1_' and the refresh token"
        " 'dor_v1_'; all three share the 64-hex body and differ only in the"
        " prefix character that names the token's role."
    ),
    provider="digitalocean",
    severity="critical",
    # The three-way 'dop_' / 'doo_' / 'dor_' prefix family and the 64-hex body
    # are the format DigitalOcean has issued since the v1 token migration.
    # 64 lowercase hex is a 32-byte random value; the width is exact, not a
    # measured range, so the regex pins it rather than bounding it.
    #
    # No entropy gate: a fixed-width random hex run is capped at Shannon
    # entropy 4.0 by its 16-symbol alphabet, so any floor a placeholder failed
    # would also sink real tokens.
    # Source: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"(?P<secret>doo_v1_[a-f0-9]{64})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,  # fixed-width random hex; a floor could only sink real tokens
    context_keywords=[
        "digitalocean",
        "do_token",
        "DIGITALOCEAN_TOKEN",
        "oauth",
        "access_token",
    ],
    known_test_values={
        # Single-character masks — the redaction shape documentation and logs
        # use. confidence_base 0.97 is above the 0.85 FP-wordlist gate, so
        # they are pinned here rather than priced down by the wordlist.
        "doo_v1_" + "0" * 64,
        "doo_v1_" + "a" * 64,
        "doo_v1_" + "f" * 64,
    },
    recommendation=(
        "Revoke the granting OAuth application's authorization in the"
        " DigitalOcean control panel under Settings > Applications & API >"
        " Authorized OAuth Apps, which invalidates this access token and its"
        " paired refresh token together. Then re-run the authorization flow"
        " for the integration that needs it. Audit the team's resources for"
        " the exposure window by the scopes the app was granted — a 'write'"
        " token can create Droplets and Kubernetes clusters that bill to the"
        " account, and can read every Spaces key and database credential the"
        " API exposes."
    ),
    tags=["cloud", "digitalocean", "oauth"],
)


DIGITALOCEAN_OAUTH_REFRESH_TOKEN = SecretPattern(
    id="digitalocean_oauth_refresh_token",
    name="DigitalOcean OAuth Refresh Token",
    description=(
        "DigitalOcean OAuth refresh token — the literal 'dor_v1_' prefix"
        " followed by 64 lowercase hex characters. Returned beside the"
        " 'doo_v1_' access token by the authorization-code exchange and used"
        " to mint fresh access tokens without the resource owner present."
        " Severity is critical for the same reason it is on any refresh"
        " token: it does not expire on the access token's schedule, so a"
        " leaked one is durable access to the granted scopes until the"
        " authorization itself is revoked."
    ),
    provider="digitalocean",
    severity="critical",
    # Same generator family as the 'doo_v1_' access token and the 'dop_v1_'
    # personal access token: a shared 64-hex (32-byte random) body behind a
    # role-naming prefix. Registered as its own pattern rather than folded
    # into a prefix alternation so the finding names the token's role — a
    # leaked refresh token is a longer-lived exposure than an access token
    # and the recommendation differs.
    #
    # No entropy gate, for the same reason as its sibling: a fixed-width hex
    # run is capped at Shannon entropy 4.0 by its alphabet.
    # Source: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"(?P<secret>dor_v1_[a-f0-9]{64})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,  # fixed-width random hex; a floor could only sink real tokens
    context_keywords=[
        "digitalocean",
        "do_token",
        "DIGITALOCEAN_TOKEN",
        "oauth",
        "refresh_token",
    ],
    known_test_values={
        "dor_v1_" + "0" * 64,
        "dor_v1_" + "a" * 64,
        "dor_v1_" + "f" * 64,
    },
    recommendation=(
        "Revoke the granting OAuth application's authorization in the"
        " DigitalOcean control panel under Settings > Applications & API >"
        " Authorized OAuth Apps — that invalidates the refresh token and every"
        " access token minted from it — then re-run the authorization flow."
        " Do not rely on the access token expiring: a refresh token is durable"
        " access to the granted scopes until the authorization is withdrawn."
        " Audit the team's Droplets, Kubernetes clusters and billing activity"
        " for the exposure window."
    ),
    tags=["cloud", "digitalocean", "oauth"],
)



AZURE_APP_CONFIGURATION_CONNECTION_STRING = SecretPattern(
    id="azure_app_configuration_connection_string",
    name="Azure App Configuration Connection String",
    description=(
        "Azure App Configuration access key, in the connection-string form the"
        " Azure Portal and 'az appconfig credential list' emit. Three segments"
        " must co-occur unbroken and in order: the '.azconfig.io' store"
        " endpoint, ';Id=' with the 4-2-2:body key identifier, and ';Secret='"
        " with the base64 access key. The captured span is the secret alone, so"
        " a redacted string keeps its store name and key Id intact."
    ),
    provider="azure",
    severity="critical",
    # THE CO-OCCURRENCE IS THE PATTERN. No segment here detects on its own: a
    # bare base64 run behind 'Secret=' is a generic-catch-all shape, and an
    # '.azconfig.io' hostname is a public endpoint rather than a credential.
    # Detection requires the endpoint host literal, the ';Id=' identifier and
    # the ';Secret=' body together in one unbroken string, which is why no
    # entropy gate is needed and confidence sits in the 0.95 tier.
    #
    # THE Id SEGMENTS KEEP '+' AND '/'. Real identifiers are not alphanumeric:
    # the catalog's own leaked-in-the-wild example is 'Id=+8zC-l4-s0:+CqeGMSCw'
    # '1jwHIR/eOuC'. Narrowing the Id charset to [A-Za-z0-9] would silently miss
    # every identifier carrying a base64 sign character.
    #
    # THE VENDOR'S 'Endpoint=' PREFIX IS DELIBERATELY NOT MATCHED. Microsoft's
    # template spells the whole string 'Endpoint=https://<host>.azconfig.io;'
    # 'Id=<Id>;Secret=<Secret>', but the prefix is absent from real-world
    # fragments, so it cannot be required. Making it an optional leading group
    # would be a pure no-op — the alternative branch already begins at
    # 'https://' — so it is simply omitted; the '=' before 'https' satisfies
    # the left guard and both spellings detect. A test pins both.
    #
    # Source: https://github.com/praetorian-inc/noseyparker/blob/main/crates/noseyparker/data/default/builtin/rules/azure.yml
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"https://[A-Za-z0-9-]{1,50}\.azconfig\.io;"
        r"Id=[A-Za-z0-9+/]{4}-[A-Za-z0-9+/]{2}-[A-Za-z0-9+/]{2}:[A-Za-z0-9+/]{18,22};"
        r"Secret=(?P<secret>[A-Za-z0-9+/]{36,50}=)"
        r"(?![0-9A-Za-z+/=])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # three-segment structural anchor; a floor could only sink real keys
    context_keywords=[
        "azconfig.io",
        "appconfig",
        "app_configuration",
        "AppConfigurationClient",
        "APP_CONFIGURATION_CONNECTION_STRING",
        "azure",
        "connection_string",
    ],
    known_test_values={
        # Built by concatenation on purpose: a contiguous literal of this shape
        # trips GitHub Push Protection on the public engine repository.
        "A" * 43 + "=",
        "a" * 43 + "=",
        "X" * 43 + "=",
        "x" * 43 + "=",
        "0" * 43 + "=",
    },
    recommendation=(
        "Regenerate the App Configuration access key immediately:"
        " 'az appconfig credential regenerate --name <store> --id <key-id>',"
        " or Access settings > Regenerate in the Azure Portal. Read-only and"
        " read-write keys are format-identical, so treat the leak as read-write"
        " until you have matched the Id against the store's credential list."
        " An App Configuration store routinely holds the downstream connection"
        " strings and feature flags for an entire application, so audit every"
        " secret it serves and rotate anything it referenced, and prefer Entra"
        " ID (Azure AD) role-based access over access keys going forward."
    ),
    tags=["cloud", "azure", "appconfig", "configuration"],
)

# ===================================================
# HEROKU 'HRKU-' PLATFORM API KEY (2026-09-07)
# ===================================================

# Heroku's SECOND API-key format, and a materially different credential shape
# from HEROKU_API_KEY above. That one is a bare RFC4122 UUID which only becomes
# detectable when a 'heroku…api…key' context word sits next to it, so a key
# pasted into a CI log, a curl invocation or a config dump without that word is
# invisible to it. The 'HRKU-' key carries its own five-character vendor
# literal, so it is self-anchoring and needs no context at all.
#
# THE PREFIX IS 'HRKU-' AND THE BODY IS 60 CHARACTERS — NOT 'HRKU-AA' + 58.
# Heroku's own changelog item announcing the format states the key is 65
# characters and publishes a worked example verbatim; 65 - len("HRKU-") = 60.
# Third-party catalogues that hard-code 'HRKU-AA' are encoding an issuance
# cohort rather than a format: Heroku documents no 'AA' constant anywhere, and
# baking it in would silently miss every key minted outside that cohort. The
# two leading characters buy nothing anyway — five fixed characters plus an
# exact 60-character body is already a strong anchor.
#
# No entropy gate: a 60-character urlsafe-base64 body behind a vendor literal
# leaves no placeholder an entropy floor would catch that the prefix does not
# already exclude. confidence_base 0.95 is the prefix-anchored tier and also a
# floor — below 0.85 the FP-wordlist penalty (-0.40, scanner.py) would sink a
# real key that happens to sit in a *test* or *staging* file.

HEROKU_API_KEY_V2 = SecretPattern(
    id="heroku_api_key_v2",
    name="Heroku API Key (HRKU-)",
    description=(
        "Heroku platform API key in the 'HRKU-' format — the literal 'HRKU-'"
        " prefix followed by a 60-character urlsafe-base64 body, 65 characters"
        " in total. Unlike the older UUID-shaped Heroku key, this one is"
        " self-identifying and needs no surrounding context. It authenticates"
        " the whole Heroku Platform API for the account or authorization that"
        " minted it: apps, dynos, config vars, add-ons, Postgres credentials"
        " and team membership."
    ),
    provider="heroku",
    severity="critical",
    # 65 total characters, per Heroku's own changelog item, whose worked
    # example is 'HRKU-' plus exactly 60 urlsafe-base64 characters. The
    # boundary guards, confidence and known_test_values are ClassiFinder's own.
    # Source: https://devcenter.heroku.com/changelog-items/3175
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"(?P<secret>HRKU-[0-9A-Za-z_-]{60})"
        r"(?![0-9A-Za-z_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # the vendor literal carries the precision
    context_keywords=[
        "heroku",
        "HEROKU_API_KEY",
        "heroku_api_key",
        "HRKU",
        "authorization",
        "platform",
    ],
    known_test_values={
        # Single-character masks — how Heroku tutorials, blog posts and
        # redacted CI configs render this key. confidence_base 0.95 sits above
        # the 0.85 FP-wordlist gate (scanner.py), so the wordlist never gets a
        # chance to price a mask down; they are pinned here and land at ~0.15.
        # Assembled by concatenation so no contiguous key-shaped literal is
        # committed to source.
        "HRKU" + "-" + "x" * 60,
        "HRKU" + "-" + "X" * 60,
        "HRKU" + "-" + "0" * 60,
    },
    recommendation=(
        "Revoke this key immediately. If it came from `heroku authorizations`,"
        " run `heroku authorizations:revoke <id>`; if it is the account's"
        " global key, run `heroku authorizations:rotate` or rotate it from"
        " Account Settings. Then audit the account's app list, config vars and"
        " add-on credentials — a platform key can read every config var on"
        " every app it can reach, so treat those as exposed too, and rotate"
        " any Heroku Postgres or Redis credentials it could have surfaced."
    ),
    tags=["cloud", "heroku", "platform-api"],
)


# ===================================================
# HASHICORP VAULT — RECOVERY TOKENS (2026-09-07)
# ===================================================

# The third and last member of Vault's token-prefix family, and the one the
# 'hvb.' block above named as a gap: 'hvs.' service tokens, 'hvb.' batch tokens
# and 'hvr.' recovery tokens.
#
# Recovery tokens exist only on auto-unsealed Vault clusters, where the
# recovery keys replace the unseal keys. A recovery token is generated through
# the `generate-root` / recovery workflow and is the credential of last resort:
# it is used to regain root-level control of a cluster whose normal auth is
# unavailable. That is why severity is critical rather than the batch token's
# high — a leaked recovery token is a path to root on the cluster, not a scoped
# bearer credential.
#
# Body bounds are copied VERBATIM from vault_batch_token so all three members
# of the family stay consistent: HashiCorp documents the prefix as being
# followed by "at least 24 randomly-generated characters", so the floor is the
# vendor's own wording rather than a measured width, and the trailing
# (?![A-Za-z0-9]) guard is what makes the greedy run take the whole token
# instead of a 24-character prefix of it.
#
# 'hvr.' cannot overlap either sibling: the three prefixes differ in their
# third character, so an hvs. token still resolves to vault_token and an hvb.
# token to vault_batch_token. Tests pin all three directions.

VAULT_RECOVERY_TOKEN = SecretPattern(
    id="vault_recovery_token",
    name="HashiCorp Vault Recovery Token",
    description=(
        "HashiCorp Vault recovery token — the 'hvr.' prefix followed by at"
        " least 24 randomly-generated characters. Recovery tokens are issued"
        " on auto-unsealed clusters, where recovery keys stand in for unseal"
        " keys, and they are the credential of last resort for regaining"
        " root-level control of a cluster. A leaked recovery token is a path to"
        " root on that Vault, and therefore to every secret it stores."
    ),
    provider="vault",
    severity="critical",
    # Prefix and the "at least 24 randomly-generated characters" body floor are
    # HashiCorp's own, from its token concepts page — identical bounds to the
    # 'hvs.' and 'hvb.' siblings above. Guards, confidence and
    # known_test_values are ClassiFinder's own.
    # Source: https://developer.hashicorp.com/vault/docs/concepts/tokens
    regex=re.compile(
        r"(?P<secret>hvr\.[A-Za-z0-9]{24,})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    # Prefix-anchored tier, matched to vault_batch_token rather than
    # vault_token's 0.97 so the two most recently authored members of the
    # family agree. Deliberately kept at/above 0.85 so the FP-wordlist penalty
    # (-0.40, scanner.py) can never silently sink a real recovery token that
    # sits next to the word "test" or "demo".
    confidence_base=0.95,
    # 0.0 on purpose: the body is a fixed-charset random run, so any entropy
    # floor a masked placeholder failed would also sink short real tokens. The
    # literal 'hvr.' prefix carries the precision instead.
    entropy_threshold=0.0,
    context_keywords=[
        "vault",
        "VAULT_TOKEN",
        "hashicorp",
        "recovery",
        "generate-root",
        "hvr",
    ],
    known_test_values={
        # The masked shape that dominates Vault runbooks and issue reports.
        # Assembled by concatenation so no contiguous token-shaped literal
        # exists in this repository. Down-scores to ~0.15.
        "hvr." + "X" * 28,
        "hvr." + "x" * 24,
    },
    recommendation=(
        "Revoke this token with `vault token revoke` and treat the cluster as"
        " compromised for the whole window the token was exposed: a recovery"
        " token exists to regain root-level control, so assume every secret"
        " the Vault stores was readable. Re-key the recovery shares"
        " (`vault operator rekey-recovery-key`), rotate the encryption key"
        " (`vault operator rotate`), and rotate the downstream credentials"
        " Vault brokers — database, cloud and PKI — rather than only the token."
        " Then read the audit device for requests carrying it."
    ),
    tags=["cloud", "vault", "secrets", "recovery-token"],
)


# ===================================================
# YANDEX CLOUD API KEY (2026-09-07)
# ===================================================

# The third Yandex credential in this module, and the LONG-LIVED one. The
# distinction matters operationally:
#   - yandex_cloud_iam_token ('t1.')  — ~12h derived bearer token, medium
#   - yandex_passport_oauth_token ('y[0-3]_') — user credential, critical
#   - yandex_cloud_api_key ('AQVN')   — service-account API key, here
# An API key is bound to a service account and does not expire on its own; it
# authenticates the Speech, Vision and Translate APIs directly, so a leak is
# billable compute plus data access for as long as nobody rotates it. Severity
# high: it is a scoped service credential rather than the account-wide Passport
# token, but it outlives an IAM token by an unbounded margin.
#
# The regex is the VENDOR'S OWN. Yandex publishes the character class and the
# {35,38} width verbatim in its public documentation repository, in the
# security-standard authentication page, labelled "Yandex.Cloud API Keys
# (Speechkit, Vision, Translate)". The width is a range rather than a constant
# because that is what the vendor states — pinning one value would be inventing
# format.
#
# Both boundary guards carry the full body charset, which is what keeps a
# 35-character window from being carved out of a longer base64url run: inside a
# JWT payload or a base64 blob every neighbouring character is in the class, so
# the left guard fails and there is no match. It also means a 43-character
# AQVN-prefixed run matches nothing at all — greedy 38 fails the right guard,
# and every shorter backtrack fails it too — which is the correct behaviour for
# a value that is not a key of this format.

YANDEX_CLOUD_API_KEY = SecretPattern(
    id="yandex_cloud_api_key",
    name="Yandex Cloud API Key",
    description=(
        "Yandex Cloud service-account API key — the literal 'AQVN' prefix"
        " followed by 35 to 38 urlsafe-base64 characters. Used to authenticate"
        " SpeechKit, Vision and Translate API calls on behalf of a service"
        " account. Unlike a Yandex Cloud IAM token, an API key does not expire"
        " on its own, so a leaked one keeps working — and keeps billing — until"
        " it is explicitly deleted."
    ),
    provider="yandex_cloud",
    severity="high",
    # The prefix, the [A-Za-z0-9_-] body charset and the {35,38} width are
    # published verbatim by Yandex in its own public documentation repository
    # (en/_includes/security/standard/authentication.md), labelled
    # "Yandex.Cloud API Keys (Speechkit, Vision, Translate)". The boundary
    # guards, confidence and known_test_values are ClassiFinder's own.
    # Source: https://github.com/yandex-cloud/docs/blob/master/en/_includes/security/standard/authentication.md
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>AQVN[A-Za-z0-9_-]{35,38})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # vendor literal + bounded width carry the precision
    context_keywords=[
        "yandex",
        "yandexcloud",
        "api_key",
        "API_KEY",
        "speechkit",
        "translate",
        "yc",
    ],
    known_test_values={
        # Masks that appear in Yandex quickstarts and redacted configs.
        # confidence_base 0.95 sits above the 0.85 FP-wordlist gate, so the
        # wordlist never prices these down; pinned here, they land at ~0.15.
        "AQVN" + "x" * 35,
        "AQVN" + "X" * 38,
        "AQVN" + "0" * 36,
    },
    recommendation=(
        "Delete this API key in the Yandex Cloud console under the owning"
        " service account's API keys, or with"
        " `yc iam api-key delete --id <id>`, and issue a fresh one. API keys do"
        " not expire, so the exposure window runs from the leak until the"
        " delete. Review the service account's roles and billing usage for the"
        " period the key was public, and prefer short-lived IAM tokens or"
        " authorized keys for workloads that can obtain them."
    ),
    tags=["cloud", "yandex_cloud", "service-account"],
)


# ===================================================
# AZURE IOT HUB SAS TOKEN (2026-09-14)
# ===================================================

# A SIGNED IoT Hub security token, as opposed to the key that signs it.
# AZURE_IOT_KEY above detects the 44-character 'AIoT'-signature shared access
# / device key; this pattern detects what that key MINTS:
#
#   SharedAccessSignature sr={URL-encoded resourceURI}&sig={signature}
#                         &se={expiry}&skn={policyName}
#
# Microsoft Learn's IoT Hub SAS article documents the layout field by field:
# 'sr' is the lower-case URL-encoded resource URI and starts with the hub host
# name ('<hub>.azure-devices.net', optionally followed by '/devices/<id>'),
# 'sig' is the URL-encoded base64 of an HMAC-SHA256 — 43 data characters plus
# one '=' pad, which the vendor's own generators percent-encode as '%3D' —
# 'se' is the expiry in epoch seconds, and 'skn' names the shared access policy
# and is ABSENT for a device-scoped token signed with a device key. So 'skn' is
# not required; everything up to '&se=' is.
#
# THE CO-OCCURRENCE IS THE PATTERN: the literal 'SharedAccessSignature sr='
# scheme, the '.azure-devices.net' host, '&sig=' and '&se=' must all appear in
# that order in one unbroken token, which is the order every generator on the
# vendor page emits. No entropy gate is needed. The captured span is the
# signature alone, so a redacted token keeps its hub and device readable.
#
# DISJOINT FROM azure_storage_sas_token, which requires the 'sv=20YY-MM-DD'
# signed-version date an IoT Hub token never carries. A test pins that.
#
# Severity critical: a token minted from the 'iothubowner' or 'service' policy
# is a hub-wide credential until it expires, and nothing can revoke a single
# token — only rotating the signing key does.

AZURE_IOT_HUB_SAS_TOKEN = SecretPattern(
    id="azure_iot_hub_sas_token",
    name="Azure IoT Hub SAS Token",
    description=(
        "Azure IoT Hub shared access signature token — 'SharedAccessSignature"
        " sr=<hub>.azure-devices.net[/devices/<id>]&sig=<signature>&se=<expiry>'"
        " with an optional '&skn=<policy>'. The signature is the URL-encoded"
        " base64 HMAC-SHA256 of the resource URI and expiry; the token grants"
        " whatever its signing policy or device key allows until it expires."
    ),
    provider="azure",
    severity="critical",
    # Token layout, field order and the '%3D'-encoded pad per Microsoft Learn's
    # IoT Hub SAS article (SAS token structure + the vendor's own generators).
    # Format per https://learn.microsoft.com/azure/iot-hub/authenticate-authorize-sas
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])SharedAccessSignature\s+sr="
        r"[A-Za-z0-9-]{1,63}\.azure-devices\.net"
        r"[^\s&" '"' r"'<>]{0,200}"
        r"&sig=(?P<secret>(?:[A-Za-z0-9+/]|%2[BbFf]){43}(?:=|%3[Dd])?)"
        r"&se=\d{1,12}(?!\d)",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # four-literal structural anchor; a floor could only sink real tokens
    context_keywords=[
        "azure-devices.net",
        "SharedAccessSignature",
        "iothub",
        "skn=",
        "DeviceId",
        "azure",
    ],
    known_test_values={
        # The two complete signatures Microsoft Learn prints in its IoT Hub SAS
        # article (hub-level 'registryRead' token and device-scoped token), in
        # the encoded, raw and lower-case-encoded spellings. Split so no
        # contiguous signature literal is committed.
        "JdyscqTpXdEJs49elIUC" + "cohw2DlFDR3zfH5KqGJo4r4%3D",
        "JdyscqTpXdEJs49elIUC" + "cohw2DlFDR3zfH5KqGJo4r4%3d",
        "JdyscqTpXdEJs49elIUC" + "cohw2DlFDR3zfH5KqGJo4r4=",
        "13y8ejUk2z7PLmvtwR5R" + "qlGBOVwiq7rQR3WZ5xZX3N4%3D",
        "13y8ejUk2z7PLmvtwR5R" + "qlGBOVwiq7rQR3WZ5xZX3N4%3d",
        "13y8ejUk2z7PLmvtwR5R" + "qlGBOVwiq7rQR3WZ5xZX3N4=",
        # Single-character fills used to redact a signature.
        "A" * 43 + "%3D",
        "A" * 43 + "=",
        "X" * 43 + "%3D",
        "x" * 43 + "%3D",
        "0" * 43 + "%3D",
    },
    recommendation=(
        "A SAS token cannot be revoked on its own: rotate the key that signed"
        " it. For a hub-level token (one with '&skn=<policy>'), regenerate that"
        " shared access policy's key in the Azure Portal (IoT Hub > Shared"
        " access policies); for a device-scoped token without 'skn', regenerate"
        " the device's symmetric key. Audit device-to-cloud traffic, twin"
        " updates and registry changes for the exposure window, and prefer"
        " short token lifetimes or Entra ID for back-end services."
    ),
    tags=["cloud", "azure", "iot", "sas", "delegated"],
)


# ===================================================
# AZURE SIGNALR CONNECTION STRING (2026-09-14)
# ===================================================

# Azure SignalR Service access key, in the connection-string form the Azure
# Portal's Keys blade and 'az signalr key list' emit:
#
#   Endpoint=https://<resource_name>.service.signalr.net;AccessKey=<key>;Version=1.0;
#
# Microsoft Learn's SignalR connection-string article documents that template,
# says keys are not case sensitive, lists the optional Port / ClientEndpoint /
# ServerEndpoint / Version pairs, and describes AccessKey as a Base64 key
# string that is "similar to a root password for your service". Real keys are
# 256-bit, i.e. 43 base64 characters plus one '=' pad; the vendor does not
# state a width, so a modest 40-64 range (plus up to two pads) is accepted
# rather than an exact one.
#
# THE CO-OCCURRENCE IS THE PATTERN, as for the App Configuration connection
# string above: the literal '.service.signalr.net' endpoint host and an
# 'AccessKey=' pair in the same unbroken string. Up to three other 'key=value;'
# pairs may sit between them (a Port or a reverse-proxy endpoint). The
# 'Endpoint=' prefix itself is not required — the '=' before 'https' satisfies
# the left guard. Entra ID strings ('AuthType=azure…', no AccessKey) carry no
# key and cannot match. The captured span is the key alone.
#
# DISJOINT FROM azure_storage_key (which keys on 'AccountKey=') and from the
# 'SharedAccessKey=' identifiable-key patterns; tests pin both.

AZURE_SIGNALR_CONNECTION_STRING = SecretPattern(
    id="azure_signalr_connection_string",
    name="Azure SignalR Connection String",
    description=(
        "Azure SignalR Service access key in connection-string form —"
        " 'Endpoint=https://<resource>.service.signalr.net;AccessKey=<base64"
        " key>;Version=1.0;'. The access key signs the tokens the service"
        " accepts, so it acts as a root password for the SignalR resource."
    ),
    provider="azure",
    severity="critical",
    # Template, key names and the base64 AccessKey per Microsoft Learn's
    # "Connection strings in Azure SignalR Service" article.
    # Format per https://learn.microsoft.com/azure/azure-signalr/concept-connection-string
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"https://[A-Za-z0-9-]{1,63}\.service\.signalr\.net(?::\d{1,5})?/?;"
        r"(?:[A-Za-z]{1,20}=[^;\s" '"' r"'<>]{0,200};){0,3}?"
        r"[Aa]ccess[Kk]ey=(?P<secret>[A-Za-z0-9+/]{40,64}={0,2})"
        r"(?![A-Za-z0-9+/=])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # two-literal structural anchor; a floor could only sink real keys
    context_keywords=[
        "signalr",
        "service.signalr.net",
        "AccessKey",
        "Azure:SignalR:ConnectionString",
        "AddAzureSignalR",
        "azure",
    ],
    known_test_values={
        # Built by multiplication on purpose: a contiguous literal of this
        # shape trips GitHub Push Protection on the public engine repository.
        "A" * 43 + "=",
        "a" * 43 + "=",
        "X" * 43 + "=",
        "x" * 43 + "=",
        "0" * 43 + "=",
    },
    recommendation=(
        "Regenerate the leaked key in the Azure Portal (SignalR Service > Keys"
        " > Regenerate primary/secondary key, or 'az signalr key renew'),"
        " rolling the secondary first so app servers can cut over, then update"
        " every 'Azure:SignalR:ConnectionString' setting that carried it. Anyone"
        " holding the key can mint client and server tokens for every hub on"
        " the resource. Prefer a managed identity or Entra ID application and"
        " disable access-key auth entirely where possible."
    ),
    tags=["cloud", "azure", "signalr", "realtime"],
)


register(
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    # 2026-08-17 — STS temporary session token, the third component of the
    # AWS credential triple (ASIA key ID + secret key were already covered)
    AWS_STS_SESSION_TOKEN,
    GCP_API_KEY,
    GCP_SERVICE_ACCOUNT_KEY,
    AZURE_STORAGE_KEY,
    AZURE_AD_CLIENT_SECRET,
    DIGITALOCEAN_TOKEN,
    HEROKU_API_KEY,
    CLOUDFLARE_API_TOKEN,
    CLOUDFLARE_GLOBAL_API_KEY,
    CLOUDFLARE_ORIGIN_CA_KEY,
    DOPPLER_TOKEN,
    TERRAFORM_CLOUD_TOKEN,
    VAULT_TOKEN,
    PULUMI_ACCESS_TOKEN,
    FLY_API_TOKEN,
    # 2026-09-09 — the 'fm2_' MACAROON access token, the form flyctl and
    # the Fly.io GraphQL API carry today, registered alongside the older
    # 'fo1_' deploy token above rather than replacing it.
    FLY_MACAROON_ACCESS_TOKEN,
    ALIBABA_ACCESS_KEY,
    VERCEL_ACCESS_TOKEN,
    VERCEL_REFRESH_TOKEN,
    VERCEL_PERSONAL_ACCESS_TOKEN,
    VERCEL_INTEGRATION_TOKEN,
    # VERCEL_AI_GATEWAY_KEY (vck_) is registered from patterns/ai.py
    NETLIFY_TOKEN,
    DROPBOX_SHORT_LIVED_API_TOKEN,
    DROPBOX_LONG_LIVED_API_TOKEN,
    JFROG_API_KEY,
    ARTIFACTORY_REFERENCE_TOKEN,
    IBM_CLOUD_API_KEY,
    OKTA_API_TOKEN,
    BUILDKITE_TOKEN,
    RAILWAY_TOKEN,
    # Batch 8 — vendor-sourced patterns (2026-06-22)
    GOOGLE_OAUTH_ACCESS_TOKEN,
    TENCENT_CLOUD_SECRET_ID,
    # Batch 10 — vendor-sourced patterns (2026-07-06)
    YANDEX_CLOUD_IAM_TOKEN,
    # Batch 12 — vendor-sourced patterns (2026-07-13)
    ELASTIC_CLOUD_API_KEY,
    # 2026-07-16 — Render API key (prefix-anchored, vendor + OpenAI-skill sourced)
    RENDER_API_KEY,
    # 2026-07-22 — Amazon MWS auth token (prefix-anchored 'amzn.mws.' + UUID, SPDB CC-BY-4.0)
    AMAZON_MWS_AUTH_TOKEN,
    # 2026-07-30 — Infisical service token ('st.' + UUID + 32 hex, generator-sourced)
    INFISICAL_SERVICE_TOKEN,
    # 2026-08-03 — the remaining five Doppler auth-token families (vendor-published regexes)
    DOPPLER_CLI_TOKEN,
    DOPPLER_SERVICE_TOKEN,
    DOPPLER_SERVICE_ACCOUNT_TOKEN,
    DOPPLER_AUDIT_TOKEN,
    DOPPLER_SCIM_TOKEN,
    # 2026-08-03 — GCS HMAC access key ID (ID only; paired secret deliberately not registered)
    GCS_HMAC_ACCESS_KEY_ID,
    # 2026-08-17 — Microsoft "identifiable" / annotated keys: a fixed 4-char
    # signature at a fixed offset, derived from microsoft/security-utilities
    # (MIT). See ATTRIBUTION.md.
    AZURE_COSMOS_DB_KEY,
    AZURE_FUNCTIONS_KEY,
    AZURE_SEARCH_KEY,
    AZURE_EVENT_HUB_KEY,
    AZURE_SERVICE_BUS_KEY,
    AZURE_IOT_KEY,
    AZURE_CONTAINER_REGISTRY_KEY,
    AZURE_APIM_KEY,
    MICROSOFT_CASK_KEY,
    # 2026-08-24 — Vault batch token ('hvb.'), OpenShift OAuth access token
    # ('sha256~' + derived 43-char digest), Scalingo API token ('tk-us-'),
    # Yandex Passport OAuth token (long-lived, exchanged for IAM tokens).
    VAULT_BATCH_TOKEN,
    OPENSHIFT_OAUTH_ACCESS_TOKEN,
    SCALINGO_API_TOKEN,
    YANDEX_PASSPORT_OAUTH_TOKEN,
    # 2026-08-31 — Google OAuth client secret ('GOCSPX-' + 28 base64url)
    # and the DigitalOcean OAuth access/refresh tokens ('doo_v1_' /
    # 'dor_v1_' + 64 hex), siblings of the 'dop_v1_' personal token.
    GOOGLE_OAUTH_CLIENT_SECRET,
    DIGITALOCEAN_OAUTH_ACCESS_TOKEN,
    DIGITALOCEAN_OAUTH_REFRESH_TOKEN,
    # 2026-09-03 — Azure Storage SAS token: structurally anchored on the
    # mandatory 'sv=' signed-version date literal co-occurring with 'sig=' in
    # one query string. Distinct from AZURE_STORAGE_KEY (the account key).
    AZURE_STORAGE_SAS_TOKEN,
    # 2026-09-04 — Azure App Configuration connection string: the
    # '.azconfig.io' store endpoint, ';Id=' and ';Secret=' must co-occur.
    AZURE_APP_CONFIGURATION_CONNECTION_STRING,
    # 2026-09-07 — Heroku's self-anchoring 'HRKU-' platform API key
    # (the older heroku_api_key is a context-gated bare UUID), the
    # third member of the Vault token-prefix family ('hvr.' recovery
    # tokens, beside 'hvs.' service and 'hvb.' batch), and the
    # long-lived Yandex Cloud service-account API key ('AQVN').
    HEROKU_API_KEY_V2,
    VAULT_RECOVERY_TOKEN,
    YANDEX_CLOUD_API_KEY,
    # 2026-09-14 — Azure IoT Hub SAS token ('SharedAccessSignature sr=' +
    # '.azure-devices.net' + '&sig=' + '&se=', the token AZURE_IOT_KEY mints)
    # and the Azure SignalR connection string ('.service.signalr.net' +
    # 'AccessKey=').
    AZURE_IOT_HUB_SAS_TOKEN,
    AZURE_SIGNALR_CONNECTION_STRING,
)
