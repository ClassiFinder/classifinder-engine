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
)
