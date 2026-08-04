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


# ===================================================
# ONFIDO (Batch 8 — 2026-06-22)
# ===================================================

ONFIDO_API_TOKEN = SecretPattern(
    id="onfido_api_token",
    name="Onfido API Token",
    description=(
        "Onfido identity-verification API token with an 'api_live.' or"
        " 'api_sandbox.' prefix followed by the token body. Grants access to"
        " Onfido's KYC / identity-check APIs."
    ),
    provider="onfido",
    severity="high",
    # Source: https://documentation.onfido.com/api/3.6.0/
    regex=re.compile(
        r"(?P<secret>api_(?:live|sandbox)\.[A-Za-z0-9_\-]{20,})"
        r"(?![A-Za-z0-9_\-])",
        re.ASCII,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=["onfido", "ONFIDO_API_TOKEN", "api_token", "identity"],
    known_test_values={
        "api_live.AbCdEfGhIjKlMnOpQrStUvWx",
    },
    recommendation=(
        "Revoke this token in the Onfido dashboard under Settings > Tokens and"
        " issue a replacement."
    ),
    tags=["identity", "onfido", "kyc"],
)


# ===================================================
# SALESFORCE (Batch 12 — 2026-07-13; structural, '!'-anchored)
# ===================================================

SALESFORCE_ACCESS_TOKEN = SecretPattern(
    id="salesforce_access_token",
    name="Salesforce Access Token",
    description=(
        "Salesforce OAuth access token / session ID — a 15-character org/session"
        " prefix (starting with '00'), a literal '!' delimiter at index 15, and a"
        " long signed tail. The '!' delimiter is the structural anchor and is what"
        " distinguishes it from other '00'-prefixed identifiers. Grants API access"
        " to the Salesforce org for the token's session scope."
    ),
    provider="salesforce",
    severity="high",
    # Salesforce OAuth token / session-ID format: a '00'-prefixed org/session id,
    # a '!' separator, then a signed tail. Deliberately does NOT overlap the
    # keyword-gated Okta '00' token (okta_api_token), which lacks the '!' and
    # matches a 40-char [A-Za-z0-9_-] body — this pattern anchors on the '!'.
    # Source: https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_tokens.htm
    # Independently authored — anchored on the '!' delimiter at index 15 + 96+ tail.
    regex=re.compile(
        r"(?P<secret>00[A-Za-z0-9]{13}![A-Za-z0-9._]{96,})(?![A-Za-z0-9._])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=3.0,
    context_keywords=["salesforce", "sfdc", "access_token", "instance_url", "force.com"],
    known_test_values={
        # Synthetic — fixed 'D'*13 prefix body + 'A'*96 tail, concatenated so the
        # source literal is never a real-looking token. Down-scores to ~0.15.
        "00" + "D" * 13 + "!" + "A" * 96,
    },
    recommendation=(
        "Revoke this token / session in Salesforce Setup under Session Management"
        " (or the connected app's OAuth usage) and re-authenticate the integration."
    ),
    tags=["identity", "salesforce", "crm"],
)


# ===================================================
# ADOBE (Batch 12 — 2026-07-13; prefix-anchored)
# ===================================================

ADOBE_OAUTH_CLIENT_SECRET = SecretPattern(
    id="adobe_oauth_client_secret",
    name="Adobe OAuth Server-to-Server Client Secret",
    description=(
        "Adobe OAuth Server-to-Server (and Adobe I/O) client secret — the literal"
        " 'p8e-' prefix followed by a 32-character body. Paired with a client ID"
        " to obtain access tokens for Adobe APIs (Creative Cloud, Document"
        " Services, etc.). Prefix-anchored on 'p8e-'; leaking one lets an attacker"
        " mint access tokens for the integration."
    ),
    provider="adobe",
    severity="high",
    # Source: https://developer.adobe.com/developer-console/docs/guides/authentication/ServerToServerAuthentication/
    # (Adobe Developer Console — OAuth Server-to-Server client secrets carry the
    # 'p8e-' prefix). Independently authored — anchored on the 'p8e-' prefix so it
    # does not collide with any Adobe detector matching a bare 32-hex value.
    regex=re.compile(
        r"(?P<secret>p8e-[A-Za-z0-9-]{32})(?![A-Za-z0-9-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["adobe", "p8e-", "client_secret", "ims-na1", "adobe.io"],
    known_test_values={
        # Synthetic — clearly-fake all-'A' body, concatenated. Down-scores to ~0.15.
        "p8e-" + "A" * 32,
    },
    recommendation=(
        "Revoke this secret in the Adobe Developer Console under your project's"
        " OAuth Server-to-Server credential and generate a new client secret."
    ),
    tags=["identity", "adobe", "oauth"],
)


# ===================================================
# ZOHO (2026-07-27)
# ===================================================

ZOHO_OAUTH_TOKEN = SecretPattern(
    id="zoho_oauth_token",
    name="Zoho OAuth Token",
    description=(
        "Zoho OAuth token — the literal '1000.' portal segment followed by two"
        " dot-separated 32-character lowercase-hex segments. Zoho's own OAuth"
        " documentation publishes concrete values in this shape for the"
        " access_token, the refresh_token, and the authorization grant code, so"
        " one pattern covers all three. Access tokens are bearer credentials for"
        " every Zoho API (CRM, Mail, Desk, Books, WorkDrive) and expire after an"
        " hour; refresh tokens carry the same shape but do not expire, so a"
        " leaked one grants indefinite access to the connected org's data until"
        " it is revoked. The non-secret client_id shares the '1000.' lead but is"
        " a single uppercase-alphanumeric segment with no second dot, so the"
        " two-segment lowercase-hex requirement excludes it by construction."
    ),
    provider="zoho",
    severity="high",
    # Zoho's OAuth docs print real-shaped example tokens rather than
    # placeholders: access_token "1000.<32 hex>.<32 hex>" and refresh_token in
    # the identical shape. The leading segment is the literal "1000.", the
    # charset is lowercase hex (not alphanumeric), and each segment is exactly
    # 32 characters. Independently authored — no third-party detector was
    # consulted. Boundaries are asymmetric on purpose: the lookbehind also
    # rejects a preceding '.' so the pattern cannot fire on a slice of a longer
    # dotted blob, and the lookahead rejects a following '.<word char>' for the
    # same reason while still allowing a sentence-ending period.
    # Format per https://www.zoho.com/accounts/protocol/oauth/web-apps/access-token-expiry.html
    regex=re.compile(
        r"(?<![A-Za-z0-9._-])"
        r"(?P<secret>1000\.[a-f0-9]{32}\.[a-f0-9]{32})"
        r"(?!\.?[A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,  # '1000.' lead + rigid 32/32 lowercase-hex structure
    entropy_threshold=0.0,
    context_keywords=[
        "zoho",
        "zohoapis",
        "ZOHO_REFRESH_TOKEN",
        "access_token",
        "refresh_token",
    ],
    known_test_values={
        # Zoho's own published documentation examples — the most-copied values
        # of this shape, so they are registered as test values and down-score to
        # ~0.15. Built by concatenation so no scannable token literal exists in
        # source.
        "1000." + "2deaf8d0c268e3c85daa2a013a843b10" + "." + "703adef2bb337b8ca36cfc5d7b83cf24",
        "1000." + "86a03ca5dbfccb7445b1889b8215efb0" + "." + "cad9e1ae4989a1196fe05aa729fcb4e1",
        "1000." + "18e983526f0ca8575ea9c53b0cd5bb58" + "." + "1bd83a6f2e22c3a7e1309d96ae439cc1",
        # Synthetic all-zero placeholder in the documented shape.
        "1000." + "0" * 32 + "." + "0" * 32,
    },
    recommendation=(
        "Revoke this token from the Zoho API Console (Self Client / connected"
        " app > revoke) or by calling the OAuth revoke endpoint, then re-run the"
        " authorization flow to issue a replacement. Audit recent API activity on"
        " the affected Zoho org for unauthorized record or mailbox access."
    ),
    tags=["identity", "zoho", "oauth"],
)


# ===================================================
# AUTHRESS (2026-07-27)
# ===================================================

AUTHRESS_SERVICE_CLIENT_ACCESS_KEY = SecretPattern(
    id="authress_service_client_access_key",
    name="Authress Service Client Access Key",
    description=(
        "Authress (authress.io) service client access key — a single opaque"
        " string that packs four dot-separated segments: the 'sc_' service"
        " client id, a short key id, an account id beginning with the literal"
        " 'acc' and a separator, and finally a base64-encoded PKCS#8 private"
        " key. That last segment is the actual signing material: whoever holds"
        " it can mint Authress access tokens for any user or role in the"
        " account, which makes this a full authorization-system compromise —"
        " severity is critical."
        " The 'sc_' prefix on its own is far too generic to detect safely, so"
        " this pattern requires the entire four-segment structure including the"
        " literal 'acc' marker in segment three. Do not relax it to a bare"
        " 'sc_' plus alphanumerics; that shape is a false-positive factory."
    ),
    provider="authress",
    severity="critical",
    # Independently authored from Authress's own service-client access-key
    # documentation, which describes the access key as the concatenation of the
    # service client id ('sc_' prefixed), the key id, the account id ('acc'
    # prefixed), and the base64 PKCS#8 private key, joined with '.' separators.
    # The full four-segment structure is required on purpose — 'sc_' alone
    # matches far too much ordinary text. No third-party detector was consulted.
    # Source: https://authress.io/knowledge-base/docs/authorization/service-clients/access-keys
    regex=re.compile(
        r"(?<![0-9A-Za-z_])"
        r"(?P<secret>sc_[0-9A-Za-z]{5,30}\.[0-9A-Za-z]{4,6}\."
        r"acc[_-][0-9a-z-]{10,32}\.[0-9A-Za-z+/_=-]{30,120})"
        r"(?![0-9A-Za-z+/=])",
        re.ASCII,
    ),
    confidence_base=0.95,  # four-segment structure with two literal markers is unique
    entropy_threshold=0.0,  # structure is the anchor; the key segment is base64
    context_keywords=[
        "authress",
        "AUTHRESS_ACCESS_KEY",
        "serviceClientAccessKey",
        "accessKey",
        "authorization",
    ],
    known_test_values={
        # Synthetic four-segment placeholder in the documented shape, assembled
        # by concatenation. Down-scores to ~0.15.
        "sc_" + "AbCdEfGhIjKlMnOp" + "." + "xY3z" + "."
        + "acc_" + "a1b2c3d4e5f6g7h8" + "."
        + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    },
    recommendation=(
        "Delete this service client's access key in the Authress management"
        " portal (Clients > the affected service client > Access keys) and"
        " generate a new one — the leaked segment is a private signing key, so"
        " rotating it is the only remediation. Then review Authress audit logs"
        " for tokens minted by this client and confirm none were unexpected."
    ),
    tags=["identity", "authress", "authorization"],
)


# ===================================================
# UNKEY
# ===================================================

UNKEY_ROOT_KEY = SecretPattern(
    id="unkey_root_key",
    name="Unkey Root Key",
    description=(
        "Unkey (unkey.com) root key — the literal 'unkey_' prefix followed by 24"
        " Bitcoin-base58 characters, 30 in total. A root key administers the whole"
        " workspace: it can mint, revoke and read every API key Unkey manages for the"
        " account, so leaking one compromises every downstream API it protects."
    ),
    provider="unkey",
    severity="critical",
    # Charset is Bitcoin base58, taken from Unkey's own key-generation module:
    # the standard alphabet EXCLUDES the four visually ambiguous characters
    # 0 (zero), O (capital o), I (capital i) and l (lowercase L). Using a plain
    # [A-Za-z0-9] class here would be wrong — it would accept bodies the
    # generator can never emit.
    # Source: https://github.com/unkeyed/unkey/blob/main/web/internal/keys/src/v1.ts
    regex=re.compile(
        r"(?<![0-9A-Za-z_])"
        r"(?P<secret>unkey_[1-9A-HJ-NP-Za-km-z]{24})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # vendor prefix + fixed base58 length are the anchor
    context_keywords=[
        "unkey",
        "UNKEY_ROOT_KEY",
        "root_key",
        "api_key",
        "workspace",
    ],
    known_test_values={"unkey_" + "1" * 24},
    recommendation=(
        "Revoke this root key in the Unkey dashboard under Settings > Root Keys and"
        " issue a replacement. Then audit the workspace's key-creation and"
        " key-verification logs for activity you do not recognize."
    ),
    tags=["identity", "unkey", "api-key-management"],
)


# ===================================================
# HUBSPOT — PRIVATE APP ACCESS TOKEN
# ===================================================

HUBSPOT_PRIVATE_APP_TOKEN = SecretPattern(
    id="hubspot_private_app_token",
    name="HubSpot Private App Access Token",
    description=(
        "HubSpot private app access token — a region prefix ('pat-na1-' or 'pat-eu1-')"
        " followed by a canonical 8-4-4-4-12 hex UUID, 44 characters in total. This is"
        " the credential that replaced HubSpot's deprecated bare-UUID API key; it carries"
        " whatever CRM scopes the private app was granted, commonly full read/write on"
        " contacts, companies and deals."
    ),
    provider="hubspot",
    severity="high",
    # Prefix-anchored, unlike the pre-existing context-gated bare-UUID
    # hubspot_api_key above: the region tag makes the token self-identifying,
    # so no surrounding keyword is needed. The two published regions are
    # na1 (North America) and eu1 (Europe).
    # Source: https://developers.hubspot.com/docs/guides/apps/private-apps/overview
    regex=re.compile(
        r"(?<![0-9A-Za-z\-])"
        r"(?P<secret>pat-(?:na1|eu1)-"
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
        r"(?![0-9a-fA-F\-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["hubspot", "private_app", "HUBSPOT_TOKEN", "crm", "Authorization"],
    known_test_values={"pat-na1-" + "00000000-0000-0000-0000-000000000000"},
    recommendation=(
        "Rotate this token in HubSpot under Settings > Integrations > Private Apps >"
        " the affected app > Auth. Then review the app's call log for requests you do"
        " not recognize."
    ),
    tags=["identity", "hubspot", "crm", "private-app"],
)


# ===================================================
# HCAPTCHA — SITEVERIFY SECRET KEY
# ===================================================

HCAPTCHA_SITEVERIFY_SECRET_KEY = SecretPattern(
    id="hcaptcha_siteverify_secret_key",
    name="hCaptcha Siteverify Secret Key",
    description=(
        "hCaptcha server-side secret key, the credential POSTed as 'secret' to"
        " https://api.hcaptcha.com/siteverify. Two live shapes: the legacy/standard"
        " '0x' + 40 hex characters, and the current enterprise 'ES_' + 32 hex"
        " characters. Detected only when an hCaptcha context word ('hcaptcha' or"
        " 'siteverify') precedes the value on the same line — the '0x' + 40-hex form is"
        " byte-identical to a public Ethereum wallet ADDRESS, which is not a secret and"
        " appears freely in ordinary text, so matching it bare would be an FP cannon."
    ),
    provider="hcaptcha",
    severity="medium",
    # Context-gated on purpose, following the ethereum_private_key precedent in
    # payment.py: the '0x' + 40-hex branch has exactly the shape of an Ethereum
    # address, so an ungated format-only regex would fire on every wallet address,
    # contract address and block-explorer link in ordinary text. Requiring an
    # hCaptcha-specific word before the value makes an uncontextualised address
    # unmatchable rather than merely low-confidence. The vendor's published dummy
    # secret (all zeros) is registered as a known test value below.
    # Source: https://docs.hcaptcha.com/ (Developer Guide — siteverify secret key)
    regex=re.compile(
        r"(?:hcaptcha|siteverify)"
        r"[^\n]{0,60}?"
        r"(?<![A-Za-z0-9_])"
        r"(?P<secret>0x[a-fA-F0-9]{40}|ES_[a-fA-F0-9]{32})"
        r"(?![a-fA-F0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=3.0,
    context_keywords=[
        "hcaptcha",
        "HCAPTCHA_SECRET",
        "siteverify",
        "captcha",
        "hcaptcha.com",
    ],
    known_test_values={
        # Vendor-published dummy secret from the hCaptcha test key pairs.
        # Written by concatenation so no contiguous key literal exists in source.
        "0x" + "0" * 40,
    },
    recommendation=(
        "Rotate this secret key in the hCaptcha dashboard (Settings > Secret Key) and"
        " update every server that calls https://api.hcaptcha.com/siteverify. The secret"
        " authenticates verification calls, so a leaked one lets a third party verify"
        " tokens against your account and burn your verification quota."
    ),
    tags=["identity", "hcaptcha", "captcha", "anti-bot"],
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
    # Batch 8 — vendor-sourced patterns (2026-06-22)
    ONFIDO_API_TOKEN,
    # Batch 12 — vendor-sourced patterns (2026-07-13)
    SALESFORCE_ACCESS_TOKEN,
    ADOBE_OAUTH_CLIENT_SECRET,
    # 2026-07-27 — Zoho OAuth token (vendor sourced, '1000.' + 32/32 lowercase hex)
    ZOHO_OAUTH_TOKEN,
    # 2026-07-27 — Authress service client access key (four-segment structure)
    AUTHRESS_SERVICE_CLIENT_ACCESS_KEY,
    # 2026-08-03 — Unkey root key ('unkey_' + 24 base58) and HubSpot private app token
    UNKEY_ROOT_KEY,
    HUBSPOT_PRIVATE_APP_TOKEN,
    # 2026-08-04 — hCaptcha siteverify secret key (context-gated; 0x+40hex / ES_+32hex)
    HCAPTCHA_SITEVERIFY_SECRET_KEY,
)
