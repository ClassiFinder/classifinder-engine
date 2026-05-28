"""
ClassiFinder — Enterprise Identity & Collaboration Patterns (Batch 4 Part 2.4)

Patterns for enterprise identity, collaboration, and customer-facing SaaS:
Atlassian (Jira/Confluence), 1Password, HubSpot, Mapbox, MaxMind, Zendesk.

Pattern design notes:
- Atlassian: modern ATATT3 prefix shipped; legacy 24-char (20-alphanum + 4-hex)
  format deliberately omitted as too generic.
- 1Password: two distinct token types — secret keys (A3- prefix, hyphenated
  blocks) and service-account tokens (ops_eyJ JWT-like prefix).
- Most others use vendor-specific prefixes or context-gated structural shapes.
- Body shapes from Betterleaks MIT cmd/generate/config/rules/*.go.
- Test fixtures use clearly-synthetic patterns.
"""

import re

from .registry import SecretPattern, register

# ===================================================
# ATLASSIAN (Jira / Confluence)
# ===================================================

ATLASSIAN_API_TOKEN = SecretPattern(
    id="atlassian_api_token",
    name="Atlassian API Token (Jira/Confluence)",
    description=(
        "Atlassian API token with ATATT3 prefix (186 alphanumeric/special chars)."
        " Used to authenticate against Jira, Confluence, and Bitbucket Cloud APIs."
    ),
    provider="atlassian",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/atlassian.go) — ATATT3 prefix.
    # Two BL variants exist; we ship only the modern ATATT3 prefix. Legacy 24-char
    # (20-alphanum + 4-hex) is too generic to ship without high FP risk.
    regex=re.compile(
        r"(?P<secret>ATATT3[A-Za-z0-9_\-=]{186})"
        r"(?![A-Za-z0-9_\-=])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=3.5,
    context_keywords=["atlassian", "confluence", "jira", "bitbucket", "ATATT3"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Atlassian API token at id.atlassian.com/manage-profile/security/api-tokens."
    ),
    tags=["identity", "atlassian", "collaboration"],
)


# ===================================================
# 1PASSWORD
# ===================================================

ONEPASSWORD_SECRET_KEY = SecretPattern(
    id="1password_secret_key",
    name="1Password Secret Key",
    description=(
        "1Password Secret Key with A3- prefix (hyphenated alphanumeric blocks)."
        " Used to derive encryption keys for a 1Password account — critical if leaked."
    ),
    provider="1password",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/1password.go) — A3- prefix.
    # Hyphens are purely for readability; matching the standard 6-6-5-5-5-5 hyphenated form.
    regex=re.compile(
        r"(?P<secret>A3-[A-Z0-9]{5,8}(?:-[A-Z0-9]{5,8}){4,6})"
        r"(?![A-Z0-9\-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.5,
    context_keywords=["1password", "onepassword", "secret_key", "1PASSWORD_SECRET_KEY"],
    known_test_values=set(),
    recommendation=(
        "If a 1Password Secret Key is leaked, sign out all devices, change the"
        " account password, and rotate the Secret Key via My Profile."
        " The Secret Key combined with the master password derives encryption keys."
    ),
    tags=["identity", "1password", "password-manager"],
)


ONEPASSWORD_SERVICE_ACCOUNT_TOKEN = SecretPattern(
    id="1password_service_account_token",
    name="1Password Service Account Token",
    description=(
        "1Password service account token with ops_eyJ prefix (JWT-like base64 body, 250+ chars)."
        " Used by automation to access 1Password vaults — high privilege."
    ),
    provider="1password",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/1password.go) — ops_eyJ prefix.
    # eyJ is base64-encoded "{", indicating a JWT-like structure following the ops_ prefix.
    regex=re.compile(
        r"(?P<secret>ops_eyJ[A-Za-z0-9+/=_\-]{250,})"
        r"(?![A-Za-z0-9+/=_\-])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=4.0,
    context_keywords=["1password", "service_account", "OP_SERVICE_ACCOUNT_TOKEN", "ops_"],
    known_test_values=set(),
    recommendation=(
        "Revoke this 1Password service account token in the 1Password admin console"
        " under Integrations > Service Accounts."
    ),
    tags=["identity", "1password", "service-account"],
)


# ===================================================
# HUBSPOT
# ===================================================

HUBSPOT_API_KEY = SecretPattern(
    id="hubspot_api_key",
    name="HubSpot API Key",
    description=(
        "HubSpot API key (UUID format, context-gated near hubspot keyword)."
        " Used to authenticate against HubSpot's CRM APIs."
    ),
    provider="hubspot",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/hubspot.go) — context-gated UUID.
    regex=re.compile(
        r"(?:"
        r"(?:HUBSPOT[_-]?(?:API[_-]?KEY|TOKEN|HAPIKEY)|hubspot.*key|hubspot.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
        r"(?![0-9a-fA-F\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=["hubspot", "hapikey", "CRM"],
    known_test_values=set(),
    recommendation=(
        "Rotate this HubSpot API key in account settings under Integrations > API Key."
    ),
    tags=["identity", "hubspot", "crm"],
)


# ===================================================
# MAPBOX
# ===================================================

MAPBOX_API_TOKEN = SecretPattern(
    id="mapbox_api_token",
    name="Mapbox API Token",
    description=(
        "Mapbox API token with pk. prefix (60 alphanumeric + . + 22 alphanumeric)."
        " Used for Mapbox geospatial APIs (maps, geocoding, navigation)."
    ),
    provider="mapbox",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/mapbox.go) — pk. prefix.
    regex=re.compile(
        r"(?P<secret>pk\.[A-Za-z0-9]{60}\.[A-Za-z0-9]{22})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["mapbox", "geospatial", "MAPBOX_TOKEN", "pk."],
    known_test_values=set(),
    recommendation=(
        "Rotate this Mapbox token at account.mapbox.com under Access tokens."
    ),
    tags=["identity", "mapbox", "geospatial"],
)


# ===================================================
# MAXMIND
# ===================================================

MAXMIND_LICENSE_KEY = SecretPattern(
    id="maxmind_license_key",
    name="MaxMind License Key",
    description=(
        "MaxMind license key (6-alphanumeric + _ + 29-alphanumeric + _mmk suffix)."
        " Used to download MaxMind GeoIP database updates."
    ),
    provider="maxmind",
    severity="medium",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/maxmind.go) — _mmk suffix.
    regex=re.compile(
        r"(?P<secret>[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)"
        r"(?![A-Za-z0-9_])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=4.0,
    context_keywords=["maxmind", "geoip", "license_key", "MAXMIND_LICENSE_KEY"],
    known_test_values=set(),
    recommendation=(
        "Rotate this MaxMind license key in account.maxmind.com under My License Key."
    ),
    tags=["identity", "maxmind", "geoip"],
)


# ===================================================
# ZENDESK
# ===================================================

ZENDESK_SECRET_KEY = SecretPattern(
    id="zendesk_secret_key",
    name="Zendesk Secret Key",
    description=(
        "Zendesk secret key (40 alphanumeric chars, context-gated near zendesk keyword)."
        " Used to authenticate against Zendesk support/ticketing APIs."
    ),
    provider="zendesk",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/zendesk.go) — context-gated 40-char.
    regex=re.compile(
        r"(?:"
        r"(?:ZENDESK[_-]?(?:SECRET[_-]?KEY|API[_-]?KEY|TOKEN)|zendesk.*key|zendesk.*token|zendesk.*secret)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9]{40})"
        r"(?![A-Za-z0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=3.5,
    context_keywords=["zendesk", "support", "ticketing"],
    known_test_values=set(),
    recommendation=(
        "Rotate this Zendesk secret key in the Admin Center under Apps and integrations > APIs."
    ),
    tags=["identity", "zendesk", "support"],
)


# ===================================================
# ASANA
# ===================================================

ASANA_PAT = SecretPattern(
    id="asana_pat",
    name="Asana Personal Access Token",
    description=(
        "Asana Personal Access Token with 0/ prefix followed by 32-64 hex chars."
        " Detected when Asana context keywords are present."
        " Grants access to Asana project management APIs."
    ),
    provider="asana",
    severity="high",
    # Independently authored — context-gated with 0/ prefix per Asana developer
    # documentation (https://developers.asana.com/docs/personal-access-token).
    # Asana docs note that token formats may change; this covers the observed 0/ format.
    regex=re.compile(
        r"(?:"
        r"(?:ASANA_PAT|ASANA_ACCESS_TOKEN|ASANA_TOKEN|asana.*token|asana.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>0/[a-f0-9]{32,64})"
        r"(?![a-f0-9/])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.5,
    context_keywords=["asana", "ASANA_PAT", "ASANA_TOKEN", "ASANA_ACCESS_TOKEN"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token at app.asana.com/0/my-apps under Personal Access Tokens."
    ),
    tags=["identity", "asana", "project-management"],
)


# ===================================================
# HASURA
# ===================================================

HASURA_ADMIN_SECRET = SecretPattern(
    id="hasura_admin_secret",
    name="Hasura Admin Secret",
    description=(
        "Hasura GraphQL Engine admin secret."
        " Detected by HASURA_GRAPHQL_ADMIN_SECRET env var or x-hasura-admin-secret header."
        " Grants unrestricted access to the Hasura GraphQL API and underlying database."
    ),
    provider="hasura",
    severity="critical",
    # Independently authored — env-var-style pattern gated on HASURA_GRAPHQL_ADMIN_SECRET,
    # as documented at https://hasura.io/docs/latest/deployment/graphql-engine-flags/reference/.
    regex=re.compile(
        r"(?P<context_key>"
        r"(?:HASURA_GRAPHQL_ADMIN_SECRET|x-hasura-admin-secret)"
        r")"
        r"[\s]*[=:\"'\s]+"
        r"(?P<secret>[^\s\"'#]{8,128})"
        r"[\"']?",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.88,
    entropy_threshold=1.5,
    context_keywords=["hasura", "HASURA_GRAPHQL_ADMIN_SECRET", "x-hasura-admin-secret", "graphql"],
    known_test_values={
        "password",
        "secret",
        "changeme",
        "admin",
        "myadminsecret",
    },
    recommendation=(
        "Rotate the Hasura admin secret by updating the HASURA_GRAPHQL_ADMIN_SECRET env var"
        " and redeploying. Enable JWT or webhook auth as the primary auth mode."
    ),
    tags=["identity", "hasura", "graphql"],
)


# ===================================================
# JUMPCLOUD
# ===================================================

JUMPCLOUD_API_KEY = SecretPattern(
    id="jumpcloud_api_key",
    name="JumpCloud API Key",
    description=(
        "JumpCloud API key, a 40-character hex string."
        " Detected when preceded by JumpCloud-specific context keywords."
        " Grants access to JumpCloud directory and identity APIs."
    ),
    provider="jumpcloud",
    severity="high",
    # Independently authored — context-gated 40-char hex per JumpCloud API
    # documentation (https://docs.jumpcloud.com/api/1.0/).
    regex=re.compile(
        r"(?:"
        r"(?:JUMPCLOUD_API_KEY|jumpcloud.*key|jumpcloud.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{40})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=3.5,
    context_keywords=["jumpcloud", "JUMPCLOUD_API_KEY"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the JumpCloud Admin Console under API Settings."
    ),
    tags=["identity", "jumpcloud", "directory"],
)


# ===================================================
# CLICKUP
# ===================================================

CLICKUP_PAT = SecretPattern(
    id="clickup_pat",
    name="ClickUp Personal API Token",
    description=(
        "ClickUp personal API token with pk_ prefix followed by a numeric user ID"
        " and a 32-character alphanumeric hash."
        " The numeric segment after pk_ is structurally distinct from Stripe's"
        " pk_live_ and pk_test_ prefixes — no collision risk."
    ),
    provider="clickup",
    severity="high",
    # Vendor-published format — pk_<numeric_user_id>_<hash> per ClickUp API documentation
    # (https://developer.clickup.com/). The numeric segment after pk_ is structurally
    # distinct from Stripe's pk_live_ and pk_test_ prefixes (no collision risk).
    regex=re.compile(
        r"(?P<secret>pk_[0-9]+_[A-Za-z0-9]{32})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.93,
    entropy_threshold=0.0,
    context_keywords=["clickup", "CLICKUP_API_KEY", "ClickUp"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token at app.clickup.com under Settings > Apps."
        " Generate a new token and update your integrations."
    ),
    tags=["identity", "clickup", "project-management"],
)


register(
    ATLASSIAN_API_TOKEN,
    ONEPASSWORD_SECRET_KEY,
    ONEPASSWORD_SERVICE_ACCOUNT_TOKEN,
    HUBSPOT_API_KEY,
    MAPBOX_API_TOKEN,
    MAXMIND_LICENSE_KEY,
    ZENDESK_SECRET_KEY,
    ASANA_PAT,
    HASURA_ADMIN_SECRET,
    JUMPCLOUD_API_KEY,
    CLICKUP_PAT,
)
