"""
ClassiFinder — Data, Analytics, and Dev Tools Patterns (Batch 4 Part 2.3)

Patterns for data warehouses (ClickHouse Cloud, PlanetScale), product analytics
(PostHog), API tooling (Postman), search infrastructure (Algolia), and headless
CMSes (Contentful).

Pattern design notes:
- All patterns use prefix anchors or context gating per Betterleaks observations.
- ClickHouse uses a fixed-byte prefix (4b1d) — not a vendor-published anchor but
  empirically observed across BL's corpus.
- PlanetScale ships 3 distinct token types with pscale_<type>_ prefixes; the
  vendor-published "ID dependency" rule (BL's planetscale-id) isn't ported —
  we accept slightly higher FP risk on the bare prefixes for simplicity.
- Body shapes from Betterleaks MIT cmd/generate/config/rules/*.go.
- All test fixtures use clearly-synthetic patterns to avoid triggering
  external secret scanners.
"""

import re

from .registry import SecretPattern, register

# ===================================================
# CLICKHOUSE CLOUD
# ===================================================

CLICKHOUSE_CLOUD_API_SECRET_KEY = SecretPattern(
    id="clickhouse_cloud_api_secret_key",
    name="ClickHouse Cloud API Secret Key",
    description=(
        "ClickHouse Cloud API secret key (4b1d prefix + 38 alphanumeric chars)."
        " Used to authenticate against ClickHouse Cloud's management API."
    ),
    provider="clickhouse",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/clickhouse.go) — 4b1d prefix.
    regex=re.compile(
        r"(?P<secret>4b1d[A-Za-z0-9]{38})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.93,
    entropy_threshold=3.0,
    context_keywords=["clickhouse", "CLICKHOUSE_CLOUD", "api_secret"],
    known_test_values=set(),
    recommendation=(
        "Revoke this ClickHouse Cloud API secret in the cloud console under"
        " Account > API Keys."
    ),
    tags=["data", "clickhouse", "data-warehouse"],
)


# ===================================================
# PLANETSCALE
# ===================================================

PLANETSCALE_API_TOKEN = SecretPattern(
    id="planetscale_api_token",
    name="PlanetScale API Token",
    description=(
        "PlanetScale API token with pscale_tkn_ prefix (32-64 alphanumeric/extended chars)."
        " Used to authenticate against PlanetScale DBaaS management APIs."
    ),
    provider="planetscale",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/planetscale.go) — pscale_tkn_ prefix
    regex=re.compile(
        r"(?P<secret>pscale_tkn_[\w=.\-]{32,64})"
        r"(?![\w=.\-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["planetscale", "PSCALE_TOKEN", "pscale_tkn"],
    known_test_values=set(),
    recommendation=(
        "Revoke this PlanetScale API token at app.planetscale.com under"
        " Account Settings > API Tokens."
    ),
    tags=["data", "planetscale", "database"],
)


PLANETSCALE_OAUTH_TOKEN = SecretPattern(
    id="planetscale_oauth_token",
    name="PlanetScale OAuth Token",
    description=(
        "PlanetScale OAuth token with pscale_oauth_ prefix (32-64 chars)."
        " Used by OAuth-integrated PlanetScale applications."
    ),
    provider="planetscale",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/planetscale.go) — pscale_oauth_ prefix
    regex=re.compile(
        r"(?P<secret>pscale_oauth_[\w=.\-]{32,64})"
        r"(?![\w=.\-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["planetscale", "pscale_oauth", "oauth"],
    known_test_values=set(),
    recommendation=(
        "Revoke this PlanetScale OAuth token via the OAuth application's"
        " management interface."
    ),
    tags=["data", "planetscale", "database", "oauth"],
)


PLANETSCALE_PASSWORD = SecretPattern(
    id="planetscale_password",
    name="PlanetScale Database Password",
    description=(
        "PlanetScale database password with pscale_pw_ prefix (32-64 chars)."
        " Used for direct database connections to PlanetScale-hosted branches."
    ),
    provider="planetscale",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/planetscale.go) — pscale_pw_ prefix
    regex=re.compile(
        r"(?P<secret>pscale_pw_[\w=.\-]{32,64})"
        r"(?![\w=.\-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["planetscale", "pscale_pw", "password", "DATABASE_URL"],
    known_test_values=set(),
    recommendation=(
        "Rotate this PlanetScale database password at app.planetscale.com"
        " under the branch's Connect dialog."
    ),
    tags=["data", "planetscale", "database", "password"],
)


# ===================================================
# POSTHOG
# ===================================================

POSTHOG_PROJECT_API_KEY = SecretPattern(
    id="posthog_project_api_key",
    name="PostHog Project API Key",
    description=(
        "PostHog project-scoped API key with phc_ prefix (43 alphanumeric chars)."
        " Used by client SDKs to send events; not strictly secret but identifies the project."
    ),
    provider="posthog",
    severity="medium",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/posthog.go) — phc_ prefix
    regex=re.compile(
        r"(?P<secret>phc_[A-Za-z0-9]{43})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.93,
    entropy_threshold=3.0,
    context_keywords=["posthog", "POSTHOG_PROJECT_API_KEY", "phc_"],
    known_test_values=set(),
    recommendation=(
        "Project API keys are sent by client SDKs and are semi-public, but"
        " if found alongside personal API keys, both should be rotated in PostHog."
    ),
    tags=["data", "posthog", "analytics"],
)


POSTHOG_PERSONAL_API_KEY = SecretPattern(
    id="posthog_personal_api_key",
    name="PostHog Personal API Key",
    description=(
        "PostHog personal API key with phx_ prefix (47 alphanumeric chars)."
        " Used for administrative PostHog API operations — higher privilege."
    ),
    provider="posthog",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/posthog.go) — phx_ prefix
    regex=re.compile(
        r"(?P<secret>phx_[A-Za-z0-9]{47})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=3.0,
    context_keywords=["posthog", "POSTHOG_PERSONAL_API_KEY", "phx_"],
    known_test_values=set(),
    recommendation=(
        "Revoke this PostHog personal API key in user settings under"
        " Account Settings > Personal API Keys."
    ),
    tags=["data", "posthog", "analytics"],
)


# ===================================================
# POSTMAN
# ===================================================

POSTMAN_API_TOKEN = SecretPattern(
    id="postman_api_token",
    name="Postman API Token",
    description=(
        "Postman API token with PMAK- prefix (24-hex + - + 34-hex structure)."
        " Used to authenticate against Postman's collection and workspace APIs."
    ),
    provider="postman",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/postman.go) — PMAK- prefix
    regex=re.compile(
        r"(?P<secret>PMAK-[a-f0-9]{24}-[a-f0-9]{34})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=3.0,
    context_keywords=["postman", "POSTMAN_API_KEY", "PMAK"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Postman API key in user settings under Account > API keys."
    ),
    tags=["data", "postman", "api-tooling"],
)


# ===================================================
# ALGOLIA
# ===================================================

ALGOLIA_API_KEY = SecretPattern(
    id="algolia_api_key",
    name="Algolia API Key",
    description=(
        "Algolia API key (32 hex chars, context-gated near algolia keyword)."
        " Used to authenticate against Algolia's search APIs."
    ),
    provider="algolia",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/algolia.go) — context-gated 32-hex
    regex=re.compile(
        r"(?:"
        r"(?:ALGOLIA[_-]?(?:API[_-]?KEY|ADMIN[_-]?KEY|SEARCH[_-]?KEY|TOKEN)|algolia.*key|algolia.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=3.0,
    context_keywords=["algolia", "search", "ALGOLIA_API_KEY"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Algolia API key in the Algolia dashboard under API Keys."
        " Admin keys grant full index access — treat as critical if leaked."
    ),
    tags=["data", "algolia", "search"],
)


# ===================================================
# CONTENTFUL
# ===================================================

CONTENTFUL_DELIVERY_API_TOKEN = SecretPattern(
    id="contentful_delivery_api_token",
    name="Contentful Delivery API Token",
    description=(
        "Contentful delivery API token (43 alphanumeric chars, context-gated)."
        " Used to fetch published content from Contentful headless CMS."
    ),
    provider="contentful",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/contentful.go) — context-gated 43-char
    regex=re.compile(
        r"(?:"
        r"(?:CONTENTFUL[_-]?(?:TOKEN|API[_-]?KEY|DELIVERY[_-]?TOKEN|ACCESS[_-]?TOKEN)|contentful.*token|contentful.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9_\-]{43})"
        r"(?![A-Za-z0-9_\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=3.0,
    context_keywords=["contentful", "CONTENTFUL_TOKEN", "CONTENTFUL_DELIVERY_TOKEN"],
    known_test_values=set(),
    recommendation=(
        "Rotate this Contentful API token in the dashboard under"
        " Settings > API keys."
    ),
    tags=["data", "contentful", "cms"],
)


# ===================================================
# PINECONE
# ===================================================

PINECONE_API_KEY = SecretPattern(
    id="pinecone_api_key",
    name="Pinecone API Key",
    description=(
        "Pinecone API key with pcsk_ prefix. Grants access to Pinecone vector"
        " database indexes."
    ),
    provider="pinecone",
    severity="high",
    # Independently authored — pcsk_ vendor-published prefix per Pinecone CLI
    # command reference (https://docs.pinecone.io/reference/cli/command-reference).
    regex=re.compile(
        r"(?P<secret>pcsk_[A-Za-z0-9_-]{20,})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["pinecone", "PINECONE_API_KEY", "pcsk"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Pinecone console under API Keys."
        " Generate a new key and update your configuration."
    ),
    tags=["data", "pinecone", "vector-db"],
)


# ===================================================
# TURBOPUFFER
# ===================================================

TURBOPUFFER_API_KEY = SecretPattern(
    id="turbopuffer_api_key",
    name="Turbopuffer API Key",
    description=(
        "Turbopuffer API key with tpuf_ prefix. Grants access to Turbopuffer"
        " serverless vector database."
    ),
    provider="turbopuffer",
    severity="high",
    # Independently authored — tpuf_ vendor-published prefix per Turbopuffer
    # authentication docs (https://turbopuffer.com/docs/auth).
    regex=re.compile(
        r"(?P<secret>tpuf_[A-Za-z0-9]{20,})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["turbopuffer", "TURBOPUFFER_API_KEY", "tpuf"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Turbopuffer dashboard."
        " Generate a new key and update your configuration."
    ),
    tags=["data", "turbopuffer", "vector-db"],
)


# ===================================================
# CHROMA
# ===================================================

CHROMA_API_KEY = SecretPattern(
    id="chroma_api_key",
    name="Chroma Cloud API Key",
    description=(
        "Chroma Cloud API key with ck- prefix. Grants access to Chroma Cloud"
        " vector database collections."
    ),
    provider="chroma",
    severity="high",
    # Independently authored — ck- vendor-published prefix per Chroma CLI login
    # docs (https://docs.trychroma.com/docs/cli/login). Short prefix is boundary-
    # and entropy-gated to avoid matching words like "lock-"/"buck-".
    regex=re.compile(
        r"(?<![A-Za-z0-9])"
        r"(?P<secret>ck-[A-Za-z0-9]{32,})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=3.5,
    context_keywords=["chroma", "CHROMA_API_KEY", "trychroma"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Chroma Cloud dashboard under API Keys."
        " Generate a new key and update your configuration."
    ),
    tags=["data", "chroma", "vector-db"],
)


# ===================================================
# TYPEFORM (Batch 8 — 2026-06-22)
# ===================================================

TYPEFORM_PERSONAL_ACCESS_TOKEN = SecretPattern(
    id="typeform_personal_access_token",
    name="Typeform Personal Access Token",
    description=(
        "Typeform personal access token with the 'tfp_' prefix followed by the"
        " token body. Grants access to a Typeform account's forms and responses."
    ),
    provider="typeform",
    severity="high",
    # Source: https://www.typeform.com/developers/get-started/personal-access-token/
    regex=re.compile(
        r"(?P<secret>tfp_[A-Za-z0-9]{40,60})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["typeform", "TYPEFORM_TOKEN", "personal_access_token", "tfp"],
    known_test_values={
        "tfp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf",
    },
    recommendation=(
        "Revoke this token in Typeform under Settings > Personal tokens and"
        " generate a replacement."
    ),
    tags=["data", "typeform"],
)


register(
    CLICKHOUSE_CLOUD_API_SECRET_KEY,
    PLANETSCALE_API_TOKEN,
    PLANETSCALE_OAUTH_TOKEN,
    PLANETSCALE_PASSWORD,
    POSTHOG_PROJECT_API_KEY,
    POSTHOG_PERSONAL_API_KEY,
    POSTMAN_API_TOKEN,
    ALGOLIA_API_KEY,
    CONTENTFUL_DELIVERY_API_TOKEN,
    PINECONE_API_KEY,
    TURBOPUFFER_API_KEY,
    CHROMA_API_KEY,
    # Batch 8 — vendor-sourced patterns (2026-06-22)
    TYPEFORM_PERSONAL_ACCESS_TOKEN,
)
