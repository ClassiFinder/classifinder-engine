"""
SecretSweep — Cloud Provider Patterns

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
        "AWS IAM access key, 20 characters starting with AKIA (permanent)"
        " or ASIA (temporary STS)."
    ),
    provider="aws",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>(?:AKIA|ASIA)[0-9A-Z]{16,20})"
        r"(?![0-9A-Za-z])",  # negative lookahead: must not be followed by more alnum
        re.ASCII
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # prefix-anchored, no entropy check needed
    context_keywords=[
        "aws", "access_key", "access-key", "AWS_ACCESS_KEY_ID", "credential", "iam",
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
    regex=re.compile(
        # Match when preceded by common env var names or config keys
        r"(?:"
        r"(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|SecretAccessKey|secret_access_key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9/+=]{40})"
        r"(?![A-Za-z0-9/+=])",
        re.ASCII
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
    ),
    provider="gcp",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>AIza[0-9A-Za-z\-_]{35})"
        r"(?![0-9A-Za-z\-_])",
        re.ASCII
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "google", "gcp", "api_key", "api-key", "GOOGLE_API_KEY", "firebase",
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
    regex=re.compile(
        r"(?P<secret>"
        r"\"private_key\"\s*:\s*\"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----"
        r"[^\"]{50,2048}"  # capture enough of the key to confirm, but cap it
        r"-----END\s(?:RSA\s)?PRIVATE\sKEY-----\\n\""
        r")",
        re.DOTALL
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "service_account", "client_email", "project_id", "type", "google",
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
    description=(
        "Azure Storage account access key, 88-character base64 string"
        " ending with ==."
    ),
    provider="azure",
    severity="critical",
    regex=re.compile(
        r"(?:"
        r"(?:AccountKey|account_key|AZURE_STORAGE_KEY|azure_storage_key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9+/]{86}==)",
        re.ASCII
    ),
    confidence_base=0.90,
    entropy_threshold=4.0,
    context_keywords=[
        "azure", "storage", "account_key", "AccountKey",
        "blob", "DefaultEndpointsProtocol",
    ],
    known_test_values={
        "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq"
        "/K1SZFPTOtr/KBHBeksoGMGw==",
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
    regex=re.compile(
        r"(?:"
        r"(?:AZURE_CLIENT_SECRET|client_secret|clientSecret)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9~_.]{34,44})"
        r"(?![A-Za-z0-9~_.])",
        re.ASCII
    ),
    confidence_base=0.75,  # lower base -- format is less distinctive
    entropy_threshold=3.5,
    context_keywords=[
        "azure", "client_secret", "tenant", "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID", "active_directory",
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
    description=(
        "DigitalOcean API token with dop_v1_ prefix, 64 hex characters."
    ),
    provider="digitalocean",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>dop_v1_[a-f0-9]{64})"
        r"(?![a-f0-9])",
        re.ASCII
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["digitalocean", "do_token", "DIGITALOCEAN_TOKEN"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in the DigitalOcean control panel"
        " under API > Tokens."
    ),
    tags=["cloud", "digitalocean"],
)


# ===================================================
# HEROKU
# ===================================================

HEROKU_API_KEY = SecretPattern(
    id="heroku_api_key",
    name="Heroku API Key",
    description=(
        "Heroku API key, a UUID-format string"
        " (36 chars including hyphens)."
    ),
    provider="heroku",
    severity="high",
    regex=re.compile(
        r"(?:"
        r"(?:HEROKU_API_KEY|heroku_api_key|heroku.*api.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        re.ASCII | re.IGNORECASE
    ),
    confidence_base=0.80,  # UUID format is common, context-dependent
    entropy_threshold=0.0,
    context_keywords=["heroku", "api_key", "HEROKU_API_KEY"],
    known_test_values=set(),
    recommendation=(
        "Regenerate your Heroku API key via"
        " `heroku authorizations:create` or the Heroku dashboard."
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
        "Cloudflare API token, 40-character alphanumeric string"
        " with underscores and hyphens."
    ),
    provider="cloudflare",
    severity="critical",
    regex=re.compile(
        r"(?:"
        r"(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN|cloudflare.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9_\-]{40})"
        r"(?![A-Za-z0-9_\-])",
        re.ASCII
    ),
    confidence_base=0.80,
    entropy_threshold=3.5,
    context_keywords=["cloudflare", "cf_", "api_token", "CF_API_TOKEN"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in the Cloudflare dashboard"
        " under My Profile > API Tokens."
    ),
    tags=["cloud", "cloudflare"],
)


# ===================================================
# DOPPLER
# ===================================================

DOPPLER_TOKEN = SecretPattern(
    id="doppler_token",
    name="Doppler Service Token",
    description=(
        "Doppler service token with dp.pt. prefix."
        " Grants access to secrets stored in Doppler."
    ),
    provider="doppler",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>dp\.pt\.[A-Za-z0-9]{40,44})"
        r"(?![A-Za-z0-9])",
        re.ASCII
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["doppler", "DOPPLER_TOKEN", "dp_token"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in the Doppler dashboard"
        " under Access > Service Tokens."
    ),
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
    regex=re.compile(
        r"(?P<secret>[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67})"
        r"(?![A-Za-z0-9])",
        re.ASCII
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "terraform", "TF_TOKEN", "TFE_TOKEN", "atlas", "terraform_cloud",
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
        "HashiCorp Vault service token with hvs. prefix."
        " Grants access to secrets stored in Vault."
    ),
    provider="vault",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>hvs\.[A-Za-z0-9]{24,})"
        r"(?![A-Za-z0-9])",
        re.ASCII
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "vault", "VAULT_TOKEN", "hashicorp", "hvs",
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
    regex=re.compile(
        r"(?P<secret>pul-[a-f0-9]{40})"
        r"(?![a-f0-9])",
        re.ASCII
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "pulumi", "PULUMI_ACCESS_TOKEN", "pulumi_token",
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
    regex=re.compile(
        r"(?P<secret>fo1_[A-Za-z0-9]{39})"
        r"(?![A-Za-z0-9])",
        re.ASCII
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "fly", "FLY_API_TOKEN", "fly_token", "flyctl",
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
    regex=re.compile(
        r"(?P<secret>LTAI[A-Za-z0-9]{17,21})"
        r"(?![A-Za-z0-9])",
        re.ASCII
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "alibaba", "aliyun", "ALIBABA_ACCESS_KEY", "alicloud",
    ],
    known_test_values=set(),
    recommendation=(
        "Rotate this key in the Alibaba Cloud RAM console."
        " Audit AccessKey usage via ActionTrail."
    ),
    tags=["cloud", "alibaba", "iam"],
)


# Register all cloud patterns
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
    DOPPLER_TOKEN,
    TERRAFORM_CLOUD_TOKEN,
    VAULT_TOKEN,
    PULUMI_ACCESS_TOKEN,
    FLY_API_TOKEN,
    ALIBABA_ACCESS_KEY,
)
