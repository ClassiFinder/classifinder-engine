"""
ClassiFinder — Data, Analytics, and Dev Tools Patterns (Batch 4 Part 2.3)

Patterns for data warehouses (ClickHouse Cloud, PlanetScale), product analytics
(PostHog), API tooling (Postman), search infrastructure (Algolia), and headless
CMSes (Contentful, Ghost).

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
        "PostHog project-scoped API key with phc_ prefix and a 44-character base57 body."
        " Used by client SDKs to send events; not strictly secret but identifies the project."
    ),
    provider="posthog",
    severity="medium",
    # Body charset is PostHog's BASE57 = BASE62 minus the ambiguous characters
    # 0, 1, O, I and l, so a token can never contain those five. Length is
    # exactly 44: generate_random_token(32) forces the top bit of a 256-bit
    # integer and base-57 encodes it without zero padding, and
    # 57**43 == 2**250.8 < 2**255 <= value < 2**256 < 2**256.6 == 57**44.
    # Corrected 2026-08-08: the previous [A-Za-z0-9]{43} bound came from a
    # third-party detector catalog rather than the generator, and with the
    # right-hand boundary it matched only ~2% of real keys.
    # Source: https://github.com/PostHog/posthog/blob/master/posthog/models/utils.py
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>phc_[23456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ]{44})"
        r"(?![A-Za-z0-9_-])",
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
        "PostHog personal API key with phx_ prefix and a 48-49 character base57 body."
        " Used for administrative PostHog API operations — higher privilege."
    ),
    provider="posthog",
    severity="critical",
    # Body charset is PostHog's BASE57 = BASE62 minus the ambiguous characters
    # 0, 1, O, I and l. Length is 48 OR 49: the key is "phx_" +
    # generate_random_token(35), which forces the top bit of a 280-bit integer
    # and base-57 encodes it without zero padding. 57**48 == 2**279.98 < 2**280,
    # so about 3% of tokens carry a 49th character — the same arithmetic as the
    # phs_ token below. Corrected 2026-08-08: the previous [A-Za-z0-9]{47} bound
    # came from a third-party detector catalog rather than the generator, and
    # with the right-hand boundary it matched only ~2% of real keys.
    # Source: https://github.com/PostHog/posthog/blob/master/posthog/models/utils.py
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>phx_[23456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ]{48,49})"
        r"(?![A-Za-z0-9_-])",
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


POSTHOG_SECRET_API_TOKEN = SecretPattern(
    id="posthog_secret_api_token",
    name="PostHog Secret API Token",
    description=(
        "PostHog secret API token with phs_ prefix and a 48-49 character base57 body."
        " Authenticates feature-flag local evaluation, which returns every flag"
        " definition for the project including rollout percentages and cohort filters."
    ),
    provider="posthog",
    severity="high",
    # Body charset is PostHog's BASE57 = BASE62 minus the ambiguous characters
    # 0, 1, O, I and l, so a token can never contain those five. Length is 48 OR
    # 49: generate_random_token_secret() is "phs_" + generate_random_token(35),
    # which forces the top bit of a 280-bit integer and base-57 encodes it
    # without zero padding. 57**48 == 2**279.98 < 2**280, so about 3% of tokens
    # carry a 49th character; a fixed {48} bound would silently miss those.
    # Source: https://github.com/PostHog/posthog/blob/master/posthog/models/utils.py
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>phs_[23456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ]{48,49})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=4.0,
    context_keywords=[
        "posthog",
        "POSTHOG_SECRET_API_KEY",
        "local_evaluation",
        "feature_flag",
        "phs_",
    ],
    known_test_values=set(),
    recommendation=(
        "Rotate this PostHog secret API token under Project Settings > Feature"
        " flags > Secure API key, then update every service that calls"
        " /api/feature_flag/local_evaluation. Treat the flag definitions it"
        " exposed as disclosed — rollout conditions and cohort definitions"
        " commonly embed user-property filters."
    ),
    tags=["data", "posthog", "analytics", "feature-flags"],
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


# ===================================================
# CLOUDINARY (Batch 10 — 2026-07-06)
# ===================================================

CLOUDINARY_URL = SecretPattern(
    id="cloudinary_url",
    name="Cloudinary URL (with API secret)",
    description=(
        "Cloudinary connection URL — the CLOUDINARY_URL environment-variable"
        " format: cloudinary://<api_key>:<api_secret>@<cloud_name>. The api_key"
        " is a 15-digit numeric string, the api_secret is a ~27-char base64url"
        " token, and cloud_name is the account slug. Prefix-anchored on the"
        " 'cloudinary://' scheme; the api_secret (the captured value) grants full"
        " Admin + Upload API access to the media account (upload, delete, admin)."
    ),
    provider="cloudinary",
    severity="high",
    # Format per https://cloudinary.com/documentation/node_quickstart
    # (cloudinary://<api_key>:<api_secret>@<cloud_name>): api_key = 15 digits,
    # api_secret = base64url token, cloud_name = account slug. Only the
    # api_secret (between ':' and '@') is captured so redaction masks the secret
    # and not the whole URL. Regex independently authored from the vendor spec.
    # Format per https://cloudinary.com/documentation/node_quickstart
    regex=re.compile(
        r"cloudinary://[0-9]{15}:"
        r"(?P<secret>[A-Za-z0-9_-]{20,40})"
        r"@[a-zA-Z0-9][a-zA-Z0-9_-]{1,40}",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["cloudinary", "CLOUDINARY_URL", "cloud_name", "api_secret"],
    known_test_values={
        # The captured secret is the api_secret only (between ':' and '@').
        # Synthetic; concatenated so no scannable secret literal exists in source.
        "A" * 27,
    },
    recommendation=(
        "Rotate the API secret in the Cloudinary console under Settings > Access"
        " Keys, then update the CLOUDINARY_URL in every environment that used it."
    ),
    tags=["data", "cloudinary", "media"],
)


# ===================================================
# FRAME.IO DEVELOPER TOKEN
# ===================================================
# Legacy v2 (api.frame.io) developer tokens carry the distinctive 'fio-u-'
# prefix. The prefix is the citable anchor: Frame.io's official Python SDK
# (Frameio/python-frameio-client) documents `fioctl --token fio-u-...`, and
# GitGuardian independently ships a prefixed "Frame IO Token" detector. Only the
# exact body length/charset are documented by other scanners, so this pattern is
# deliberately PREFIX-ANCHORED on the public 'fio-u-' spec with a generous body
# range rather than a hardcoded length. Frame.io v4 (Adobe Developer Console) has
# migrated to OAuth bearer tokens, but v2 fio-u- tokens are real and still exist.

FRAMEIO_DEVELOPER_TOKEN = SecretPattern(
    id="frameio_developer_token",
    name="Frame.io Developer Token",
    description=(
        "Frame.io legacy v2 developer token, anchored on the public 'fio-u-'"
        " prefix followed by a URL-safe token body. Grants API access to the"
        " Frame.io video-review account (assets, comments, projects). The prefix"
        " is documented by Frame.io's official Python SDK; v4 has since migrated"
        " to OAuth bearer tokens, but v2 fio-u- tokens remain valid where issued."
    ),
    provider="frameio",
    severity="high",
    # Source: https://github.com/Frameio/python-frameio-client
    # (official Frame.io Python SDK README documents the fio-u- developer-token
    # prefix: `fioctl --token fio-u-YOUR_TOKEN_HERE`). Prefix-anchored and
    # independently authored from the vendor-published prefix; body is a
    # bounded URL-safe charset, not a copied fixed length.
    regex=re.compile(
        r"(?P<secret>fio-u-[0-9A-Za-z_-]{20,100})(?![0-9A-Za-z_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["frame.io", "frameio", "fio-u-", "FRAME_IO", "fioctl"],
    known_test_values={
        # Synthetic — clearly-fake all-'A' body, kept out of git as a real token
        # shape. Registered so the documented example down-scores to ~0.15.
        "fio-u-" + "A" * 64,
    },
    recommendation=(
        "Revoke this token in the Frame.io developer settings and issue a"
        " replacement; migrate to OAuth bearer tokens on Frame.io v4 where"
        " available."
    ),
    tags=["data", "frameio", "media"],
)


# ===================================================
# APIFY (Batch 12 — 2026-07-13; prefix-anchored)
# ===================================================

APIFY_API_TOKEN = SecretPattern(
    id="apify_api_token",
    name="Apify API Token",
    description=(
        "Apify (web-scraping / automation platform) API token — the literal"
        " 'apify_api_' prefix followed by a 36-character alphanumeric body. Used"
        " to authenticate against the Apify API and run/manage actors."
        " Prefix-anchored; grants full access to the account's actors, datasets,"
        " and storage."
    ),
    provider="apify",
    severity="high",
    # Source: https://docs.apify.com/platform/integrations/api
    # (Apify API docs — personal API tokens carry the 'apify_api_' prefix followed
    # by a fixed alphanumeric body). Independently authored — prefix anchor plus a
    # 36-char [A-Za-z0-9] body (no hyphen in the token body per the vendor spec).
    regex=re.compile(
        r"(?P<secret>apify_api_[A-Za-z0-9]{36})(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["apify", "apify_api_", "APIFY_TOKEN", "APIFY_API_TOKEN"],
    known_test_values={
        # Synthetic — clearly-fake all-'A' body, concatenated to avoid a
        # real-looking literal. Down-scores to ~0.15.
        "apify_api_" + "A" * 36,
    },
    recommendation=(
        "Revoke this token in the Apify Console under Settings > Integrations >"
        " API tokens and rotate it in every integration that used it."
    ),
    tags=["data", "apify", "automation"],
)


# ===================================================
# DATABENTO (2026-07-27)
# ===================================================

DATABENTO_API_KEY = SecretPattern(
    id="databento_api_key",
    name="Databento API Key",
    description=(
        "Databento (databento.com) API key — the credential for a paid market"
        " data subscription. The format is the literal 'db-' prefix followed by"
        " exactly 29 alphanumeric characters, 32 characters in total. That"
        " length is not a convention but a hard invariant: Databento's own"
        " client libraries reject any key whose length is not 32, so a"
        " well-formed match is a real key shape. Because Databento bills per"
        " byte of data delivered, a leaked key is a direct financial liability"
        " on top of the data access it grants. Severity is high."
        " The 'db-' prefix is short, so the pattern pins the body length"
        " exactly and requires hard non-word boundaries on both sides rather"
        " than accepting an open-ended body."
    ),
    provider="databento",
    severity="high",
    # Independently authored from Databento's own Rust client, whose ApiKey
    # constructor rejects any key whose length is not 32 with the message
    # "expected to be 32-characters long", and which documents the 'db-'
    # prefix. That fixes the body at exactly 29 characters after the prefix.
    # No third-party detector was consulted.
    # Source: https://github.com/databento/databento-rs/blob/main/src/lib.rs
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])(?P<secret>db-[0-9A-Za-z]{29})(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.85,  # short prefix, but the exact 32-char total is vendor-enforced
    entropy_threshold=3.5,  # short prefix means the body must actually look random
    context_keywords=[
        "databento",
        "DATABENTO_API_KEY",
        "db-",
        "market data",
        "Authorization",
    ],
    known_test_values={
        # Synthetic alphabet-sequence body, assembled by concatenation.
        # Down-scores to ~0.15.
        "db-" + "AbCdEfGhIj" + "KlMnOpQrSt" + "UvWxYz012",
    },
    recommendation=(
        "Delete this key in the Databento portal under Settings > API keys and"
        " create a replacement. Check the account's usage and billing pages for"
        " unexpected data downloads charged while the key was exposed."
    ),
    tags=["data", "databento", "market-data"],
)


# ===================================================
# CONTENTFUL — MANAGEMENT PERSONAL ACCESS TOKEN (2026-08-01)
# ===================================================
# A second, distinct Contentful credential. CONTENTFUL_DELIVERY_API_TOKEN above
# is a context-gated, read-only 43-character DELIVERY token with no prefix. This
# one is the Content Management API personal access token: prefix-anchored on
# the literal CFPAT-, and it authenticates writes — creating, updating,
# publishing and deleting entries, assets and content types across every space
# the issuing user can reach, and managing those spaces' own API keys. Hence
# severity critical, where the delivery token stays high.
#
# The prefix and the body charset come from Contentful's own redaction regex,
# which the vendor applies to its CLI debug output:
#
#   contentful/experience-design-system-sdk-public
#     packages/experience-design-system-cli/src/lib/debug-logger.ts
#       /CFPAT-[A-Za-z0-9_-]{20,}/
#
# That pins the prefix and the base64url charset but is far too loose to ship as
# a detector, so the body length is pinned separately. There are two real shapes:
#
#   * CURRENT — 43 characters of [A-Za-z0-9_-]. That is 32 random bytes in
#     unpadded base64url, exactly the shape Contentful already uses for its
#     delivery token. Confirmed empirically: every CFPAT- occurrence harvested
#     across 60 public repositories has a 43-character body (length histogram
#     43:15, 42:2, 20:1 — the short ones being truncated placeholders).
#   * LEGACY — 64 lowercase hex characters. Confirmed by a real token captured
#     in Contentful's own PHP SDK end-to-end HTTP recording,
#     tests/Recordings/e2e_personal_access_token_create_get_revoke.json, whose
#     payload timestamps are 2018-04-16. No 64-hex body occurs anywhere in the
#     public corpus outside that recording, so it is treated as the older format
#     and kept only so historical leaks still resolve.
#
# The alternation is ordered 43-then-64 and closed by a negative lookahead, so a
# 64-hex body can never be mis-reported as a 43-character match: the first
# alternative consumes 43 characters, the lookahead sees hex still to come and
# fails, and the engine backtracks into the 64-hex alternative. An off-by-one on
# either body therefore matches nothing at all rather than matching short.
#
# No entropy threshold — the six-character vendor prefix plus the two fixed body
# lengths carry the signal, and gating a lowercase-hex body (max 4.0 bits per
# character) on entropy would only add false negatives.
#
# Additive, not a duplicate of contentful_delivery_api_token. That pattern is
# gated on a CONTENTFUL…TOKEN context word followed by exactly 43 characters
# closed by (?![A-Za-z0-9_-]); a CFPAT- token puts six extra characters of the
# same class in front of its body, so that 43-character window can never close
# on its trailing boundary and the delivery pattern cannot fire on a management
# token. Asserted in test_contentful_management_pat_does_not_collide_with_
# delivery_token, with a companion recall guard for the delivery token itself.
#
# The 2018 recording holds a real (long-since-revoked) token and is deliberately
# NOT registered as a known_test_value; the registered placeholders are all-zero
# bodies, assembled by concatenation so no scannable token literal exists in
# this file (GitHub push protection scans the public engine repo).

CONTENTFUL_MANAGEMENT_PERSONAL_ACCESS_TOKEN = SecretPattern(
    id="contentful_management_personal_access_token",
    name="Contentful Management Personal Access Token",
    description=(
        "Contentful Content Management API personal access token — the literal"
        " CFPAT- prefix followed by either 43 base64url characters (current"
        " format) or 64 lowercase hex characters (legacy format). Unlike the"
        " read-only delivery token, this credential writes: it creates,"
        " updates, publishes and deletes content and content types, and manages"
        " API keys, across every space the issuing user can reach."
    ),
    provider="contentful",
    severity="critical",
    # Prefix and body charset per Contentful's own CLI debug-output redaction
    # regex /CFPAT-[A-Za-z0-9_-]{20,}/ in experience-design-system-sdk-public
    # (packages/experience-design-system-cli/src/lib/debug-logger.ts). The
    # 43-character current body is the vendor's 32-byte base64url token shape,
    # corroborated by every CFPAT- occurrence in the public corpus; the 64-hex
    # legacy body is a real token recorded in the vendor's own PHP SDK
    # end-to-end HTTP fixture. Independently authored from those vendor
    # sources; no third-party detector code was consulted or ported.
    # Source: https://github.com/contentful/contentful-management.php/blob/master/tests/Recordings/e2e_personal_access_token_create_get_revoke.json
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>CFPAT-(?:[A-Za-z0-9_-]{43}|[0-9a-f]{64}))"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,  # vendor-unique prefix + two generator-fixed lengths
    entropy_threshold=0.0,
    context_keywords=[
        "contentful",
        "CONTENTFUL_MANAGEMENT_TOKEN",
        "CONTENTFUL_MANAGEMENT_API_ACCESS_TOKEN",
        "management-token",
        "personal access token",
    ],
    known_test_values={
        # All-zero bodies in both shapes — the canonical placeholder form for
        # this token and definitionally not live credentials. Built by
        # concatenation so no scannable token literal exists in source.
        "CFPAT-" + "0" * 43,
        "CFPAT-" + "0" * 64,
    },
    recommendation=(
        "Revoke this personal access token in Contentful under Account"
        " Settings > CMA tokens, then issue a replacement and update it"
        " everywhere it is configured — CI, the contentful CLI, migration"
        " scripts, and local .env files. Because a CMA personal access token"
        " carries the full permissions of the user who created it, review the"
        " audit log for every space that user can reach for unexpected"
        " content, content-type or API-key changes while the token was exposed."
    ),
    tags=["data", "contentful", "cms"],
)


# ===================================================
# GHOST (2026-08-10)
# ===================================================
# Ghost's Admin API key is the colon-joined pair {id}:{secret}, and it is the
# only pattern in this module with NO literal prefix to anchor on. The anchor is
# structural instead — a fixed-width 24-hex + ':' + 64-hex run, 89 characters
# exactly — so it is priced in the PEM-block / connection-string family
# (confidence_base 0.90) rather than the 0.95 the prefix-anchored siblings above
# get, and it carries no entropy threshold: hex is low-Shannon by construction
# (a real key measures ~4.0 bits) and any penalty would suppress every genuine
# credential.
#
# The two fixed widths come from the vendor's own code, not from prose:
#   - The generator, TryGhost/framework packages/security/lib/secret.js, branches
#     on the key type — 'content' takes 13 bytes / 26 hex, everything else takes
#     32 bytes / 64 hex via crypto.randomBytes(bytes).toString('hex').
#     TryGhost/Ghost core/server/models/api-key.js calls
#     security.secret.create(this.get('type')), and 'admin' falls to that else
#     branch, so the admin secret is exactly 64 lowercase hex characters. The
#     26-hex CONTENT key is a different, lower-privilege credential and is
#     deliberately not matched.
#   - The 24-hex left half is a bson-objectid (Ghost's primary key), and the
#     vendor's SDK validates the whole thing with /[0-9a-f]{24}:[0-9a-f]{64}/,
#     erroring with "'key' must have the following format {A}:{B}, where A is 24
#     hex characters and B is 64 hex characters".
# token.js in the same package does key.split(':') and uses the halves as the
# JWT 'keyid' header and the HS256 signing key, which is why the leaked artifact
# is the single joined string rather than either half.
#
# Both boundary guards are load-bearing, and the left one carries ':' on purpose:
#   - Without ':' in the lookbehind, an Astra DB application token
#     (AstraCS:<24 alnum>:<64 hex>, database.py) whose client id happened to be
#     all lowercase hex would embed this exact shape and be double-reported.
#   - Hex characters in the same lookbehind are what defeat the colon-joined
#     hash pair, the realistic FP surface here: an 'md5:sha256' manifest line
#     offers a 32-hex left side, which cannot donate a 24-hex suffix once the
#     preceding character must be non-hex. 'sha1:sha256' fails the same way.
# A bare ObjectId, a bare sha256, and 23/25-hex or 63/65-hex near-misses all
# fall out for want of the other half or the exact width. Every case is pinned
# in tests.

GHOST_ADMIN_API_KEY = SecretPattern(
    id="ghost_admin_api_key",
    name="Ghost Admin API Key",
    description=(
        "Ghost Admin API key — a 24-character hexadecimal key id, a ':'"
        " separator, and a 64-character lowercase-hex secret, 89 characters in"
        " total. The two halves are split apart by Ghost's SDK and used as the"
        " JWT 'keyid' header and the HS256 signing key, so the joined string is"
        " the whole credential. Grants full Ghost Admin API access: creating and"
        " modifying posts and pages, reading member PII including email"
        " addresses, and managing users, integrations and themes. Distinct from"
        " the 26-hex read-only Content API key, which is not matched."
    ),
    provider="ghost",
    severity="critical",
    # Width of the admin secret per Ghost's own generator,
    # https://github.com/TryGhost/framework/blob/main/packages/security/lib/secret.js
    # ('content' => 13 bytes/26 hex, else => 32 bytes/64 hex), selected by
    # https://github.com/TryGhost/Ghost/blob/main/ghost/core/core/server/models/api-key.js
    # which calls security.secret.create(this.get('type')). Both widths and the
    # colon join are restated as a machine-readable spec by the vendor's own SDK
    # validator. Independently authored from those vendor sources — the
    # boundary guards, confidence and known_test_values are ClassiFinder's own.
    # Source: https://github.com/TryGhost/SDK/blob/main/packages/admin-api/lib/admin-api.js
    regex=re.compile(
        r"(?<![0-9A-Za-z:._-])"
        r"(?P<secret>[0-9a-f]{24}:[0-9a-f]{64})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    # Structural anchor, not a prefix anchor — same family as the PEM blocks and
    # connection strings, so 0.90 rather than the 0.95 used above.
    confidence_base=0.90,
    # Deliberately 0.0: a 64-hex body tops out near 4.0 bits, so any threshold
    # that a placeholder failed would also fail real keys.
    entropy_threshold=0.0,
    context_keywords=[
        "ghost",
        "GHOST_ADMIN_API_KEY",
        "admin api key",
        "ghost-admin-api",
        "@tryghost/admin-api",
    ],
    known_test_values={
        # All-zero halves — the canonical placeholder form, assembled by
        # concatenation so no contiguous key literal exists in this file.
        # Down-scores to ~0.15.
        "0" * 24 + ":" + "0" * 64,
    },
    recommendation=(
        "Delete this integration's key in Ghost under Settings > Integrations,"
        " create a replacement, and update it everywhere the Admin API is"
        " called — CI, deployment scripts, and any @tryghost/admin-api client."
        " Because the key grants full Admin API access, review the site for"
        " unexpected posts, pages, users, themes or integrations, and treat"
        " member email addresses as exposed while the key was public."
    ),
    tags=["data", "ghost", "cms"],
)


# ===================================================
# TABLEAU
# ===================================================

# The Tableau Personal Access Token secret is a prefixless FIXED-WIDTH COMPOSITE
# and is anchorable only because of that: 22 characters of [A-Za-z0-9+/], the
# '==' base64 padding, a ':' joint, then exactly 32 mixed-case alphanumerics --
# 57 characters in total. The head is standard base64 that decodes to exactly
# 16 bytes (a 128-bit id), which is what makes the '==' padding structurally
# guaranteed rather than incidental, and the '==:' joint the safe anchor.
#
# Ten independent samples were measured before shipping -- Tableau's own
# published example plus nine unrelated real-world occurrences -- and all ten
# measured identically 22 + '==' + ':' + 32. Both widths are pinned in tests.
#
# The whole composite is the secret. Tableau's REST API reference shows it as
# the single `personalAccessTokenSecret` attribute value, so a pattern that
# reported only the 32-character tail would under-report the credential.
#
# Boundary guards are load-bearing and deliberately ASYMMETRIC:
#   - Left `(?<![A-Za-z0-9+/])` stops the head from being the last 22 characters
#     of a longer base64 body. It does NOT carry '=': `TABLEAU_PAT_SECRET=<v>`
#     is a primary carrier for this credential, and excluding '=' on the left
#     would blind the pattern to every env assignment.
#   - Right `(?![A-Za-z0-9=])` stops the tail from being the leading run of a
#     longer token, and carries '=' so a longer base64 body that merely
#     contains this shape cannot be reported.
#
# The mixed-case requirement on the tail is the false-positive defence. Its
# surface is checksum/manifest lines: base64 of 16 bytes IS the wire form of an
# MD5 digest, and a 32-character hex digest also satisfies [A-Za-z0-9]{32}, so
# '<base64 md5>==:<hex md5>' would otherwise match. Hex is single-case and
# always fails the two lookaheads; a genuine 32-character mixed-case tail fails
# them with probability ~3e-8. Measured, not assumed: the loose shape produced
# zero corpus hits, so this is preventive rather than reactive.

TABLEAU_PERSONAL_ACCESS_TOKEN_SECRET = SecretPattern(
    id="tableau_personal_access_token_secret",
    name="Tableau Personal Access Token Secret",
    description=(
        "Tableau Personal Access Token secret — 22 base64 characters, '==', a"
        " ':' joint, and 32 mixed-case alphanumerics, 57 characters in total"
        " with no prefix. Presented to the Tableau REST API sign-in endpoint as"
        " the `personalAccessTokenSecret` attribute alongside the token name,"
        " and grants full REST API access as the token's owner: querying and"
        " publishing workbooks and data sources, and — for a site or server"
        " administrator's token — site administration."
    ),
    provider="tableau",
    severity="high",
    # Composite widths and the '==:' joint per Tableau's own REST API
    # authentication reference, which publishes a concrete
    # personalAccessTokenSecret value of exactly this shape; corroborated by
    # nine further independent real-world occurrences, all measuring 22 + '=='
    # + ':' + 32. The boundary guards, the mixed-case tail requirement, the
    # confidence and the known_test_values are ClassiFinder's own.
    # Source: https://help.tableau.com/current/api/rest_api/en-us/REST/rest_api_ref_authentication.htm
    regex=re.compile(
        r"(?<![A-Za-z0-9+/])"
        r"(?P<secret>[A-Za-z0-9+/]{22}==:"
        r"(?=[A-Za-z0-9]{0,31}[a-z])"
        r"(?=[A-Za-z0-9]{0,31}[A-Z])"
        r"[A-Za-z0-9]{32})"
        r"(?![A-Za-z0-9=])",
        re.ASCII,
    ),
    # Structural anchor, not a prefix anchor — same family as the PEM blocks,
    # connection strings and the Ghost admin key above, so 0.90. It is also a
    # floor rather than a preference: below 0.85 the FP-wordlist penalty (-0.40)
    # would sink real secrets that merely sit in a *test* / *demo* / *staging*
    # context, and Tableau PATs are routinely issued per-environment.
    confidence_base=0.90,
    # Deliberately 0.0: every character of both halves is fixed-width and
    # random, so any entropy floor a placeholder failed would also fail real
    # secrets. The mixed-case tail requirement does the placeholder filtering.
    entropy_threshold=0.0,
    context_keywords=[
        "tableau",
        "personalAccessTokenSecret",
        "personal_access_token",
        "tableau_auth",
        "pat_secret",
        "tsRequest",
    ],
    known_test_values={
        # The literal Tableau prints in its own REST API authentication
        # reference — the single most-copied value of this shape. Assembled by
        # concatenation so no contiguous full-shape literal exists in this
        # repository. Down-scores to ~0.15.
        "vFel4qtGTZ2+Po0ZWT7YWg" + "==:" + "nMmSHnQ5kJBP17ZtsBgPtuVWdYJFAbBG",
    },
    recommendation=(
        "Revoke this personal access token in Tableau under My Account Settings"
        " > Personal Access Tokens (or, for another user's token, in Server/"
        "Cloud site settings), and issue a replacement. Update it everywhere the"
        " REST API is signed into — CI jobs, tabcmd/Tableau CLI wrappers, and"
        " any tableauserverclient script. Because the token authenticates as its"
        " owner, review the site's sign-in and job history for activity you did"
        " not initiate while the secret was exposed."
    ),
    tags=["data", "tableau", "analytics", "business-intelligence"],
)

register(
    CLICKHOUSE_CLOUD_API_SECRET_KEY,
    PLANETSCALE_API_TOKEN,
    PLANETSCALE_OAUTH_TOKEN,
    PLANETSCALE_PASSWORD,
    POSTHOG_PROJECT_API_KEY,
    POSTHOG_PERSONAL_API_KEY,
    # 2026-08-07 — PostHog secret API token (phs_), the feature-flag
    # local-evaluation credential; distinct from phc_ and phx_ above
    POSTHOG_SECRET_API_TOKEN,
    POSTMAN_API_TOKEN,
    ALGOLIA_API_KEY,
    CONTENTFUL_DELIVERY_API_TOKEN,
    PINECONE_API_KEY,
    TURBOPUFFER_API_KEY,
    CHROMA_API_KEY,
    # Batch 8 — vendor-sourced patterns (2026-06-22)
    TYPEFORM_PERSONAL_ACCESS_TOKEN,
    # Batch 10 — vendor-sourced patterns (2026-07-06)
    CLOUDINARY_URL,
    # 2026-07-10 — Frame.io developer token (prefix-anchored, vendor SDK sourced)
    FRAMEIO_DEVELOPER_TOKEN,
    # Batch 12 — vendor-sourced patterns (2026-07-13)
    APIFY_API_TOKEN,
    # 2026-07-27 — Databento API key (vendor SDK enforces the exact 32-char length)
    DATABENTO_API_KEY,
    # 2026-08-01 — Contentful Management personal access token (CFPAT- prefix,
    # distinct from the context-gated read-only delivery token above)
    CONTENTFUL_MANAGEMENT_PERSONAL_ACCESS_TOKEN,
    # 2026-08-10 — Ghost Admin API key (structurally anchored 24hex:64hex, the
    # only prefix-less pattern in this module; the 26-hex Content key is excluded)
    GHOST_ADMIN_API_KEY,
    # 2026-08-21 — Tableau personal access token secret (prefixless fixed-width
    # composite, 22 base64 + '==:' + 32 mixed-case alnum; vendor REST API ref)
    TABLEAU_PERSONAL_ACCESS_TOKEN_SECRET,
)
