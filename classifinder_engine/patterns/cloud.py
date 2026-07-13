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


register(
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
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
)
