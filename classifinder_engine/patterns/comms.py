"""
ClassiFinder — Communication & SaaS Patterns

Patterns for Slack, Twilio, SendGrid, Mailgun, Discord, and Telegram credentials.
These are common in agent workflows because agents frequently interact with
messaging platforms and notification services.

Pattern design notes:
- Slack tokens have very reliable prefixes: xoxb- (bot), xoxp- (user), xoxa- (app).
- Slack webhook URLs contain a full URL with known structure.
- Twilio Account SIDs always start with AC and are 34 hex chars.
- SendGrid keys start with SG. prefix -- very distinctive.
- Discord bot tokens are base64-encoded and have a distinctive 3-part dot structure.
"""

import re

from .registry import SecretPattern, register

# ===================================================
# SLACK
# ===================================================

SLACK_BOT_TOKEN = SecretPattern(
    id="slack_bot_token",
    name="Slack Bot Token",
    description=(
        "Slack bot user OAuth token with xoxb- prefix."
        " Grants bot-level access to a Slack workspace."
    ),
    provider="slack",
    severity="critical",
    # Body shape widened 2026-05-22: optional hyphen separator, hyphens in body
    # charset, length range {20,80} (was {24,36}). Captures real BL-observed bot
    # tokens with hyphens in body or lengths >36 chars. Negative lookahead bounds.
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/slack.go) — xoxb- prefix.
    regex=re.compile(
        r"(?P<secret>xoxb-[0-9]{10,13}-[0-9]{10,13}-?[a-zA-Z0-9-]{20,80})"
        r"(?![a-zA-Z0-9-])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["slack", "bot", "token", "SLACK_BOT_TOKEN", "xoxb"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in the Slack App management page."
        " Regenerate it under OAuth & Permissions."
    ),
    tags=["comms", "slack", "bot"],
)


SLACK_USER_TOKEN = SecretPattern(
    id="slack_user_token",
    name="Slack User Token",
    description=(
        "Slack user OAuth token with xoxp- or xoxe- prefix."
        " Grants user-level access to a Slack workspace"
        " -- more privileged than bot tokens."
    ),
    provider="slack",
    severity="critical",
    # Vendor-published format — xoxp- (standard) and xoxe- (rotating) per
    # docs.slack.dev/authentication/tokens. Body shape widened 2026-05-21
    # from [a-f0-9]{32} to [a-zA-Z0-9-]{28,34} per Betterleaks empirical
    # observation; the prior hex-only regex would miss tokens with uppercase
    # letters or hyphens (which real tokens contain). The collision with
    # slack_config_refresh_token (also xoxe-) is structural: user tokens
    # have 4 hyphen-separated groups; config-refresh has a single digit
    # followed by 146 chars with no further hyphens. The shapes are
    # mutually exclusive.
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/slack.go)
    regex=re.compile(
        r"(?P<secret>xox[pe]-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9-]{28,34})"
        r"(?![a-zA-Z0-9-])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["slack", "user", "token", "SLACK_USER_TOKEN", "xoxp", "xoxe"],
    known_test_values=set(),
    recommendation=(
        "Revoke this user token immediately."
        " It has the permissions of the user who authorized it,"
        " potentially including access to private channels and DMs."
    ),
    tags=["comms", "slack"],
)


SLACK_WEBHOOK_URL = SecretPattern(
    id="slack_webhook_url",
    name="Slack Incoming Webhook URL",
    description=(
        "Slack incoming webhook URL. Allows posting messages"
        " to a specific channel without authentication."
    ),
    provider="slack",
    severity="high",
    # Expanded 2026-05-22 with three path alternations: services/ (incoming
    # webhooks, original shape), workflows/ (4-segment shape per docs.slack.dev
    # example T123ABC456/AXYZ987TUV/1234567890987/A314159B271828), and triggers/
    # (loose tail match — structure beyond T-id is undocumented).
    # Vendor-published format — hooks.slack.com URL structure per docs.slack.dev.
    regex=re.compile(
        r"(?P<secret>"
        r"https://hooks\.slack\.com/"
        r"(?:"
        r"services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[a-zA-Z0-9]{24}"
        r"|workflows/T[A-Z0-9]{8,12}/A[A-Z0-9]{8,12}/[0-9]{10,18}/[a-zA-Z0-9]{12,40}"
        r"|triggers/T[A-Z0-9]{8,12}/[a-zA-Z0-9/]{20,200}"
        r")"
        r")",
        re.ASCII,
    ),
    confidence_base=0.99,
    entropy_threshold=0.0,
    context_keywords=["slack", "webhook", "incoming", "hooks.slack.com"],
    known_test_values=set(),
    recommendation=(
        "Deactivate this webhook in Slack under Apps > Incoming Webhooks."
        " An attacker can post messages to the linked channel."
    ),
    tags=["comms", "slack", "webhook"],
)


# ---------------------------------------------------
# BATCH 4 Part 1.2 — Slack variant expansions (2026-05-21)
# ---------------------------------------------------
# Vendor docs (https://docs.slack.dev/authentication/tokens) confirm all
# prefixes below as current or legacy Slack token types. Body shapes derived
# from Betterleaks MIT cmd/generate/config/rules/slack.go (which contains
# verbatim test tokens for each rule — self-validated 2026-05-21). Exotic
# prefixes (xapp-, xoxe.xoxp-, xoxe-) corroborated by 5+ independent code
# corpus sources including Google's osv-scalibr scanner.

SLACK_APP_TOKEN = SecretPattern(
    id="slack_app_token",
    name="Slack App-Level Token",
    description=(
        "Slack app-level token with xapp- prefix."
        " Used to authenticate Socket Mode connections and apps acting on their own behalf."
    ),
    provider="slack",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/slack.go) — xapp- prefix.
    # Vendor-confirmed prefix per docs.slack.dev/authentication/tokens.
    regex=re.compile(
        r"(?P<secret>xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["slack", "xapp", "SLACK_APP_TOKEN", "app_token", "socket_mode"],
    known_test_values=set(),
    recommendation=(
        "Revoke this app-level token in the Slack app's Basic Information page"
        " under App-Level Tokens. Regenerate if still needed."
    ),
    tags=["comms", "slack", "app"],
)


SLACK_CONFIG_ACCESS_TOKEN = SecretPattern(
    id="slack_config_access_token",
    name="Slack Configuration Access Token",
    description=(
        "Slack configuration access token with xoxe.xoxp- or xoxe.xoxb- compound prefix."
        " Grants programmatic access to manage Slack app configuration."
    ),
    provider="slack",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/slack.go) — config-access compound prefix.
    # Vendor-confirmed compound prefix per docs.slack.dev/authentication/tokens.
    regex=re.compile(
        r"(?P<secret>xoxe\.xox[bp]-\d-[A-Z0-9]{163,166})",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "slack", "config", "SLACK_APP_CONFIG_TOKEN", "xoxe.xoxp", "xoxe.xoxb",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this configuration access token via the Slack app configuration API."
        " These tokens grant broad access to manage app configuration — treat as critical."
    ),
    tags=["comms", "slack", "config"],
)


SLACK_CONFIG_REFRESH_TOKEN = SecretPattern(
    id="slack_config_refresh_token",
    name="Slack Configuration Refresh Token",
    description=(
        "Slack configuration refresh token with xoxe- prefix (146-char body)."
        " Used to refresh expired configuration access tokens — long-lived credential."
    ),
    provider="slack",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/slack.go) — xoxe- config-refresh shape.
    # Distinct from xoxe- user-token shape: this rule requires exactly 146 alphanumeric chars after
    # the single-digit version, while user tokens have multiple hyphen-separated groups.
    regex=re.compile(
        r"(?P<secret>xoxe-\d-[A-Z0-9]{146})",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["slack", "xoxe", "config", "refresh", "SLACK_APP_CONFIG_REFRESH_TOKEN"],
    known_test_values=set(),
    recommendation=(
        "Rotate this configuration refresh token via the Slack app configuration API."
        " Refresh tokens grant persistent ability to mint new access tokens."
    ),
    tags=["comms", "slack", "config"],
)


SLACK_LEGACY_BOT_TOKEN = SecretPattern(
    id="slack_legacy_bot_token",
    name="Slack Legacy Bot Token",
    description=(
        "Legacy Slack bot token (xoxb- with shorter single-number-group shape)."
        " Older bot tokens with a simpler structure than current xoxb- tokens."
    ),
    provider="slack",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/slack.go) — legacy xoxb- shape.
    # Distinct from current slack_bot_token by structure: legacy has ONE number group, current has TWO.
    # Slack has been progressively rotating these out, but leaked legacy tokens may still exist.
    regex=re.compile(
        r"(?P<secret>xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.93,
    entropy_threshold=0.0,
    context_keywords=["slack", "xoxb", "bot", "legacy", "SLACK_BOT_TOKEN"],
    known_test_values=set(),
    recommendation=(
        "Revoke this legacy bot token in Slack. The legacy format is deprecated —"
        " regenerate as the current xoxb- format under OAuth & Permissions."
    ),
    tags=["comms", "slack", "bot", "legacy"],
)


SLACK_LEGACY_WORKSPACE_TOKEN = SecretPattern(
    id="slack_legacy_workspace_token",
    name="Slack Legacy Workspace Token",
    description=(
        "Legacy Slack workspace token with xoxa- (access) or xoxr- (refresh) prefix."
        " Deprecated workspace-scoped tokens from the legacy workspace apps program."
    ),
    provider="slack",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/slack.go) — xoxa-/xoxr- legacy.
    # Loose pattern matching the recognizable head (Betterleaks does not capture full body).
    regex=re.compile(
        r"(?P<secret>xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48})"
        r"(?![0-9a-zA-Z])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["slack", "xoxa", "xoxr", "workspace", "legacy"],
    known_test_values=set(),
    recommendation=(
        "Revoke this legacy workspace token in Slack. Workspace apps program is"
        " deprecated — migrate to the modern app/bot token model."
    ),
    tags=["comms", "slack", "workspace", "legacy"],
)


SLACK_SESSION_COOKIE = SecretPattern(
    id="slack_session_cookie",
    name="Slack Session Cookie",
    description=(
        "Slack browser/desktop session cookie with xoxd- prefix."
        " Authenticates user sessions in Slack web and desktop clients."
        " High-value credential — full account access."
    ),
    provider="slack",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/slack.go) — xoxd- session cookie.
    # Used by Slack desktop/browser clients to maintain authenticated sessions; if leaked, an attacker
    # gains the same access as the user (including private channels and DMs).
    regex=re.compile(
        r"(?P<secret>xoxd-[\w/\\+-]{100,}={0,2})"
        r"(?:[^\w/+=-]|\Z)",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["slack", "xoxd", "cookie", "session", "d_cookie"],
    known_test_values=set(),
    recommendation=(
        "Sign out of all Slack sessions in the workspace settings."
        " If this cookie is leaked, an attacker has full account access until session expiry."
    ),
    tags=["comms", "slack", "session", "cookie"],
)


SLACK_SESSION_TOKEN = SecretPattern(
    id="slack_session_token",
    name="Slack Session Token",
    description=(
        "Slack session token with xoxc- prefix."
        " Short-lived companion token paired with session cookies (xoxd-)."
    ),
    provider="slack",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/slack.go) — xoxc- session token.
    # Companion to xoxd- session cookies; together they authenticate Slack client sessions.
    regex=re.compile(
        r"(?P<secret>xoxc-\d{9,15}-\d{9,15}-\d{9,15}-[a-f0-9]{64})"
        r"\b",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["slack", "xoxc", "session", "token"],
    known_test_values=set(),
    recommendation=(
        "Sign out of all Slack sessions. Session tokens are short-lived but treat any"
        " leak as a credential rotation event."
    ),
    tags=["comms", "slack", "session"],
)


# ===================================================
# TWILIO
# ===================================================

TWILIO_ACCOUNT_SID = SecretPattern(
    id="twilio_account_sid",
    name="Twilio Account SID",
    description=(
        "Twilio Account SID, 34 characters starting with AC."
        " Not secret alone but often found alongside auth tokens."
    ),
    provider="twilio",
    severity="medium",
    # Vendor-published format — AC prefix is Twilio-documented Account SID format
    regex=re.compile(
        r"(?P<secret>AC[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["twilio", "account_sid", "TWILIO_ACCOUNT_SID"],
    known_test_values={
        "ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    },
    recommendation=(
        "The Account SID is semi-public, but if found alongside an Auth Token,"
        " both should be rotated in the Twilio Console."
    ),
    tags=["comms", "twilio"],
)


TWILIO_AUTH_TOKEN = SecretPattern(
    id="twilio_auth_token",
    name="Twilio Auth Token",
    description=(
        "Twilio Auth Token, 32-character hex string. Used with Account SID for API authentication."
    ),
    provider="twilio",
    severity="critical",
    # Independently authored — context-gated 32-char hex; Twilio-documented credential
    regex=re.compile(
        r"(?:"
        r"(?:TWILIO_AUTH_TOKEN|twilio.*auth.*token|auth_token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=3.0,
    context_keywords=[
        "twilio",
        "auth_token",
        "TWILIO_AUTH_TOKEN",
        "account_sid",
    ],
    known_test_values=set(),
    recommendation=(
        "Rotate this auth token in the Twilio Console under Account > API Credentials."
    ),
    tags=["comms", "twilio"],
)


# ===================================================
# SENDGRID
# ===================================================

SENDGRID_API_KEY = SecretPattern(
    id="sendgrid_api_key",
    name="SendGrid API Key",
    description=(
        "SendGrid API key with SG. prefix. Grants access to send"
        " emails and manage the SendGrid account."
    ),
    provider="sendgrid",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4230) — SG. vendor prefix
    regex=re.compile(r"(?P<secret>SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})", re.ASCII),
    confidence_base=0.99,  # SG. prefix + structure is extremely distinctive
    entropy_threshold=0.0,
    context_keywords=["sendgrid", "api_key", "SENDGRID_API_KEY", "email"],
    known_test_values=set(),
    recommendation=(
        "Delete and recreate this API key in the SendGrid dashboard"
        " under Settings > API Keys."
        " An attacker can send emails as your domain."
    ),
    tags=["comms", "sendgrid", "email"],
)


# ===================================================
# MAILGUN
# ===================================================

MAILGUN_API_KEY = SecretPattern(
    id="mailgun_api_key",
    name="Mailgun API Key",
    description=("Mailgun API key with key- prefix followed by a 32-character hex string."),
    provider="mailgun",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:3570) — key- vendor prefix
    regex=re.compile(
        r"(?P<secret>key-[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["mailgun", "api_key", "MAILGUN_API_KEY", "email"],
    known_test_values={
        "key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    },
    recommendation=(
        "Rotate this API key in the Mailgun control panel under Settings > API Security."
    ),
    tags=["comms", "mailgun", "email"],
)


# Batch 4 Part 1.7 — Mailgun additions (2026-05-21)
# Body shapes from Betterleaks MIT cmd/generate/config/rules/mailgun.go.

MAILGUN_PUB_KEY = SecretPattern(
    id="mailgun_pub_key",
    name="Mailgun Public API Key",
    description=(
        "Mailgun public API key with pubkey- prefix (32 hex chars)."
        " Lower-severity than private API keys but still credential-shaped."
    ),
    provider="mailgun",
    severity="low",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/mailgun.go) — pubkey- prefix
    regex=re.compile(
        r"(?P<secret>pubkey-[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.93,
    entropy_threshold=0.0,
    context_keywords=["mailgun", "pubkey", "public_key", "MAILGUN_PUB_KEY"],
    known_test_values=set(),
    recommendation=(
        "Mailgun public keys identify the sender domain; they're not strictly secret"
        " but should still be rotated if exposed alongside other credentials."
    ),
    tags=["comms", "mailgun", "email", "public-key"],
)


MAILGUN_SIGNING_KEY = SecretPattern(
    id="mailgun_signing_key",
    name="Mailgun Webhook Signing Key",
    description=(
        "Mailgun webhook signing key (32-8-8 hyphenated hex with mailgun context)."
        " Used to verify webhook authenticity."
    ),
    provider="mailgun",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/mailgun.go) — signing-key shape.
    # Context-gated (the [a-h] charset is what BL uses; widening to [a-f] would be marginally more
    # strict but matches the practical hex shape).
    regex=re.compile(
        r"(?:"
        r"(?:mailgun.*sign|MAILGUN_SIGNING_KEY|signing_key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8})"
        r"(?![a-f0-9\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=["mailgun", "signing", "webhook"],
    known_test_values=set(),
    recommendation=(
        "Rotate this signing key in the Mailgun control panel."
        " A compromised signing key allows webhook forgery."
    ),
    tags=["comms", "mailgun", "email", "webhook"],
)


# ===================================================
# DISCORD
# ===================================================

DISCORD_BOT_TOKEN = SecretPattern(
    id="discord_bot_token",
    name="Discord Bot Token",
    description=(
        "Discord bot token. Three base64 segments separated by dots."
        " The first segment decodes to the bot's user ID."
    ),
    provider="discord",
    severity="critical",
    # Format per the official Discord developer reference (Authorization header example):
    #   https://docs.discord.com/developers/reference
    # Bot tokens are 3 base64url segments separated by dots; first segment encodes
    # the bot user ID, prefixed M (legacy) or N (newer-issued bots).
    # Range extensions ({23,27} / {27,40}) added to handle ID-length variance.
    # Independently composed from vendor documentation.
    regex=re.compile(
        r"(?P<secret>[MN][0-9A-Za-z]{23,27}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27,40})"
        r"(?![0-9A-Za-z_\-.])",
        re.ASCII,
    ),
    confidence_base=0.85,
    entropy_threshold=3.0,
    context_keywords=[
        "discord",
        "bot",
        "token",
        "DISCORD_TOKEN",
        "DISCORD_BOT_TOKEN",
    ],
    known_test_values=set(),
    recommendation=(
        "Reset this token immediately in the Discord Developer Portal"
        " under Bot > Reset Token."
        " An attacker with this token has full control of the bot."
    ),
    tags=["comms", "discord", "bot"],
)


# ===================================================
# TELEGRAM
# ===================================================

TELEGRAM_BOT_TOKEN = SecretPattern(
    id="telegram_bot_token",
    name="Telegram Bot Token",
    description=(
        "Telegram Bot API token. Format: numeric bot ID, colon, 35-character alphanumeric string."
    ),
    provider="telegram",
    severity="high",
    # Pattern attribution: secrets-patterns-db CC-BY-4.0 — numeric_id:token Telegram bot format
    regex=re.compile(
        r"(?P<secret>[0-9]{8,10}:[A-Za-z0-9_\-]{35})"
        r"(?![A-Za-z0-9_\-])",
        re.ASCII,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=[
        "telegram",
        "bot",
        "token",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_TOKEN",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token via @BotFather on Telegram using /revoke."
        " Generate a new token with /token."
    ),
    tags=["comms", "telegram", "bot"],
)


# ===================================================
# NEW RELIC
# ===================================================

NEWRELIC_ADMIN_API_KEY = SecretPattern(
    id="newrelic_admin_api_key",
    name="New Relic Admin API Key",
    description=(
        "New Relic admin API key with NRAA- prefix."
        " Grants administrative access to a New Relic account."
    ),
    provider="newrelic",
    severity="critical",
    # Pattern attribution: secrets-patterns-db CC-BY-4.0 (rules-stable.yml:2194) — NRAA- vendor prefix
    regex=re.compile(
        r"(?P<secret>NRAA-[a-f0-9]{27})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "newrelic",
        "new_relic",
        "NEW_RELIC_API_KEY",
        "nraa",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in New Relic under API Keys."
        " Generate a new admin key with minimal permissions."
    ),
    tags=["monitoring", "newrelic"],
)


NEWRELIC_INSIGHTS_KEY = SecretPattern(
    id="newrelic_insights_key",
    name="New Relic Insights Insert/Query Key",
    description=(
        "New Relic Insights key with NRI prefix (NRII for insert, NRIQ for query)."
        " Grants access to send or query event data."
    ),
    provider="newrelic",
    severity="high",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:3720) — NRII-/NRIQ- vendor prefix
    regex=re.compile(
        r"(?P<secret>NRI[IQ]-[A-Za-z0-9\-_]{32})"
        r"(?![A-Za-z0-9\-_])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "newrelic",
        "new_relic",
        "insights",
        "NEW_RELIC_INSERT_KEY",
        "NEW_RELIC_QUERY_KEY",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in New Relic under Insights > Manage Data."
        " Generate a new key with appropriate access."
    ),
    tags=["monitoring", "newrelic"],
)


NEWRELIC_USER_API_KEY = SecretPattern(
    id="newrelic_user_api_key",
    name="New Relic User API Key",
    description=(
        "New Relic user API key with NRAK- prefix. Grants access to NerdGraph and REST APIs."
    ),
    provider="newrelic",
    severity="high",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:3742) — NRAK- vendor prefix
    regex=re.compile(
        r"(?P<secret>NRAK-[a-z0-9]{27})"
        r"(?![a-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "newrelic",
        "new_relic",
        "NEW_RELIC_API_KEY",
        "nrak",
    ],
    known_test_values=set(),
    recommendation=("Revoke this key in New Relic under API Keys. Generate a new user API key."),
    tags=["monitoring", "newrelic"],
)


# ===================================================
# GRAFANA
# ===================================================

GRAFANA_API_KEY = SecretPattern(
    id="grafana_api_key",
    name="Grafana Service Account Token",
    description=(
        "Grafana Cloud service account token with glsa_ prefix."
        " Grants access to Grafana dashboards and data sources."
    ),
    provider="grafana",
    severity="high",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:3126) — glsa_ vendor prefix
    regex=re.compile(
        r"(?P<secret>glsa_[A-Za-z0-9]{32}_[a-f0-9]{8})"
        r"(?![A-Za-z0-9_])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "grafana",
        "GRAFANA_API_KEY",
        "grafana_token",
        "glsa",
    ],
    known_test_values=set(),
    recommendation=("Revoke this token in Grafana under Administration > Service Accounts."),
    tags=["monitoring", "grafana"],
)


# ===================================================
# LINEAR
# ===================================================

LINEAR_API_KEY = SecretPattern(
    id="linear_api_key",
    name="Linear API Key",
    description=(
        "Linear personal API key with lin_api_ prefix."
        " Grants access to Linear project management data."
    ),
    provider="linear",
    severity="high",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:3438) — lin_api_ vendor prefix
    regex=re.compile(
        r"(?P<secret>lin_api_[A-Za-z0-9]{40})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "linear",
        "LINEAR_API_KEY",
        "linear_token",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in Linear under Settings > API. Generate a new personal API key."
    ),
    tags=["saas", "linear", "project-management"],
)


# ===================================================
# NOTION
# ===================================================

NOTION_API_KEY = SecretPattern(
    id="notion_api_key",
    name="Notion Integration Token",
    description=(
        "Notion internal integration token with secret_ prefix."
        " Grants access to Notion pages and databases."
    ),
    provider="notion",
    severity="high",
    # Pattern attribution: secrets-patterns-db (CC-BY-4.0), entry at line 2250.
    #   https://github.com/mazen160/secrets-patterns-db
    # See ATTRIBUTION.md for full license notice.
    regex=re.compile(
        r"(?<![A-Za-z0-9_])"
        r"(?P<secret>secret_[A-Za-z0-9]{43})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "notion",
        "NOTION_API_KEY",
        "NOTION_TOKEN",
        "notion_secret",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in Notion under Settings > Integrations."
        " Create a new integration with minimal page access."
    ),
    tags=["saas", "notion"],
)


# ===================================================
# SENTRY
# ===================================================

SENTRY_ORG_TOKEN = SecretPattern(
    id="sentry_org_token",
    name="Sentry Organization Auth Token",
    description=(
        "Sentry organization auth token with sntrys_ prefix."
        " Contains a base64-encoded JWT payload."
        " Grants organization-level access to Sentry."
    ),
    provider="sentry",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4260) — sntrys_eyJ vendor prefix
    regex=re.compile(
        r"(?P<secret>sntrys_eyJ[A-Za-z0-9+/=_]{80,300})"
        r"(?![A-Za-z0-9+/=_])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "sentry",
        "SENTRY_AUTH_TOKEN",
        "sentry_token",
        "sntrys",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token at sentry.io under Settings > Auth Tokens."
        " Organization tokens grant broad access — rotate immediately."
    ),
    tags=["monitoring", "sentry"],
)


SENTRY_USER_TOKEN = SecretPattern(
    id="sentry_user_token",
    name="Sentry User Auth Token",
    description=("Sentry user auth token with sntryu_ prefix followed by 64 hex characters."),
    provider="sentry",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4270) — sntryu_ vendor prefix
    regex=re.compile(
        r"(?P<secret>sntryu_[a-f0-9]{64})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "sentry",
        "SENTRY_AUTH_TOKEN",
        "sentry_token",
        "sntryu",
    ],
    known_test_values=set(),
    recommendation=("Revoke this token at sentry.io under User Settings > Auth Tokens."),
    tags=["monitoring", "sentry"],
)


# ===================================================
# DATADOG
# ===================================================

DATADOG_API_KEY = SecretPattern(
    id="datadog_api_key",
    name="Datadog API Key",
    description=(
        "Datadog API key, a 32-character hex string."
        " Detected when preceded by Datadog-specific context keywords."
    ),
    provider="datadog",
    severity="high",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:676) — context-gated 32-char hex
    regex=re.compile(
        r"(?:"
        r"(?:DD_API_KEY|DATADOG_API_KEY|datadog.*api.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.70,
    entropy_threshold=3.0,
    context_keywords=[
        "datadog",
        "DD_API_KEY",
        "DATADOG_API_KEY",
        "dd_api",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in Datadog under Organization Settings > API Keys."
        " Generate a new key and update your agents and integrations."
    ),
    tags=["monitoring", "datadog"],
)


DATADOG_APP_KEY = SecretPattern(
    id="datadog_app_key",
    name="Datadog Application Key",
    description=(
        "Datadog application key, a 40-character hex string."
        " Detected when preceded by Datadog-specific context keywords."
    ),
    provider="datadog",
    severity="high",
    # Pattern attribution: secrets-patterns-db CC-BY-4.0 — context-gated 40-char hex
    regex=re.compile(
        r"(?:"
        r"(?:DD_APP_KEY|DATADOG_APP_KEY|datadog.*app.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{40})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.70,
    entropy_threshold=3.0,
    context_keywords=[
        "datadog",
        "DD_APP_KEY",
        "DATADOG_APP_KEY",
        "dd_app",
    ],
    known_test_values=set(),
    recommendation=("Revoke this key in Datadog under Organization Settings > Application Keys."),
    tags=["monitoring", "datadog"],
)


# ===================================================
# PAGERDUTY
# ===================================================

PAGERDUTY_API_KEY = SecretPattern(
    id="pagerduty_api_key",
    name="PagerDuty API Key",
    description=(
        "PagerDuty REST API key with u+ prefix and structured format."
        " Detected when PagerDuty context is present."
    ),
    provider="pagerduty",
    severity="high",
    # Pattern attribution: secrets-patterns-db (CC-BY-4.0), entry at line 2338.
    #   https://github.com/mazen160/secrets-patterns-db
    # See ATTRIBUTION.md for full license notice.
    regex=re.compile(
        r"(?:"
        r"(?:PAGERDUTY_API_KEY|pagerduty.*key|pagerduty.*token|pager_duty)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>u\+[a-zA-Z0-9_+\-]{18})"
        r"(?![a-zA-Z0-9_+\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=0.0,
    context_keywords=[
        "pagerduty",
        "pager_duty",
        "PAGERDUTY_API_KEY",
        "pd_api",
    ],
    known_test_values=set(),
    recommendation=("Revoke this key in PagerDuty under Integrations > API Access Keys."),
    tags=["monitoring", "pagerduty"],
)


# ===================================================
# FIGMA
# ===================================================

FIGMA_PAT = SecretPattern(
    id="figma_pat",
    name="Figma Personal Access Token",
    description=(
        "Figma personal access token with a distinctive UUID-like structure:"
        " 5-6 digit numeric prefix followed by hyphenated hex segments."
        " Detected when Figma context is present."
    ),
    provider="figma",
    severity="high",
    # Pattern attribution: secrets-patterns-db CC-BY-4.0 (rules-stable.yml:1068) — context-gated numeric+UUID
    regex=re.compile(
        r"(?:"
        r"(?:FIGMA_TOKEN|FIGMA_PAT|FIGMA_API_TOKEN|figma.*token|figma.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[0-9]{5,6}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=[
        "figma",
        "FIGMA_TOKEN",
        "FIGMA_PAT",
        "figma_api",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in Figma under Account Settings > Personal Access Tokens."
        " An attacker can read and modify your Figma files."
    ),
    tags=["saas", "figma", "design"],
)


# ===================================================
# AUTH0
# ===================================================

AUTH0_MANAGEMENT_TOKEN = SecretPattern(
    id="auth0_management_token",
    name="Auth0 Management API Token",
    description=(
        "Auth0 Management API token (JWT format) detected by auth0 context."
        " Grants access to manage Auth0 tenants, users, and applications."
    ),
    provider="auth0",
    severity="critical",
    # Independently authored — context-gated JWT (eyJ header); Auth0-documented token format
    regex=re.compile(
        r"(?:"
        r"(?:AUTH0_MANAGEMENT_TOKEN|AUTH0_TOKEN|AUTH0_API_TOKEN|auth0.*token|auth0.*key|auth0.*secret)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>eyJ[A-Za-z0-9_-]{10,500}\.[A-Za-z0-9_-]{10,1000}\.[A-Za-z0-9_-]{10,500})"
        r"(?![A-Za-z0-9_\-.])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=[
        "auth0",
        "AUTH0_TOKEN",
        "AUTH0_MANAGEMENT_TOKEN",
        "auth0_domain",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in the Auth0 Dashboard under Applications > APIs."
        " Management tokens grant full tenant access — rotate immediately."
    ),
    tags=["auth", "auth0", "identity"],
)


# ===================================================
# DISCORD WEBHOOK
# ===================================================

DISCORD_WEBHOOK_URL = SecretPattern(
    id="discord_webhook_url",
    name="Discord Webhook URL",
    description=(
        "Discord incoming webhook URL. Allows posting messages to a channel"
        " without bot authentication."
    ),
    provider="discord",
    severity="high",
    # Vendor-published format — discord.com/api/webhooks/ URL structure is Discord-documented
    regex=re.compile(
        r"(?P<secret>https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,68})"
        r"(?![A-Za-z0-9_\-])",
        re.ASCII,
    ),
    confidence_base=0.99,
    entropy_threshold=0.0,
    context_keywords=["discord", "webhook"],
    known_test_values=set(),
    recommendation=(
        "Delete this webhook in Discord Server Settings > Integrations > Webhooks."
        " An attacker can post messages to the linked channel."
    ),
    tags=["comms", "discord", "webhook"],
)


# ===================================================
# MICROSOFT TEAMS WEBHOOK
# ===================================================

TEAMS_WEBHOOK_URL = SecretPattern(
    id="teams_webhook_url",
    name="Microsoft Teams Incoming Webhook URL",
    description=(
        "Microsoft Teams incoming webhook URL."
        " Allows posting messages and cards to a Teams channel."
    ),
    provider="microsoft",
    severity="high",
    # Vendor-published format — webhook.office.com/webhookb2/ URL structure is Microsoft-documented
    regex=re.compile(
        r"(?P<secret>https://[a-z0-9\-]+\.webhook\.office\.com/webhookb2/"
        r"[a-f0-9\-]{36}@[a-f0-9\-]{36}/IncomingWebhook/[a-f0-9]{32}/[a-f0-9\-]{36})",
        re.ASCII,
    ),
    confidence_base=0.99,
    entropy_threshold=0.0,
    context_keywords=["teams", "webhook", "office", "microsoft"],
    known_test_values=set(),
    recommendation=(
        "Remove this webhook in Microsoft Teams under the channel's Connectors settings."
    ),
    tags=["comms", "teams", "webhook"],
)


# ===================================================
# MATTERMOST
# ===================================================

MATTERMOST_TOKEN = SecretPattern(
    id="mattermost_token",
    name="Mattermost Personal Access Token",
    description=(
        "Mattermost personal access token, a 26-character lowercase alphanumeric string."
        " Detected when preceded by Mattermost-specific context keywords."
    ),
    provider="mattermost",
    severity="high",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:3620) — context-gated 26-char
    regex=re.compile(
        r"(?:"
        r"(?:MATTERMOST_TOKEN|MATTERMOST_ACCESS_TOKEN|mattermost.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-z0-9]{26})"
        r"(?![a-z0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.0,
    context_keywords=["mattermost", "MATTERMOST_TOKEN"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in Mattermost under"
        " Account Settings > Security > Personal Access Tokens."
    ),
    tags=["comms", "mattermost"],
)


# ===================================================
# INTERCOM
# ===================================================

INTERCOM_ACCESS_TOKEN = SecretPattern(
    id="intercom_access_token",
    name="Intercom Access Token",
    description=(
        "Intercom access token (60 alphanumeric/special chars)."
        " Detected when preceded by Intercom-specific context keywords."
        " Grants access to Intercom customer messaging APIs."
    ),
    provider="intercom",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/intercom.go) —
    # context-gated 60-char alphanumeric-ext format.
    regex=re.compile(
        r"(?:"
        r"(?:INTERCOM_ACCESS_TOKEN|intercom.*token|intercom.*key|INTERCOM_API_KEY)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-zA-Z0-9=_\-]{60})"
        r"(?![a-zA-Z0-9=_\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.5,
    context_keywords=["intercom", "INTERCOM_ACCESS_TOKEN", "INTERCOM_API_KEY"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token at app.intercom.com under Settings > Integrations > Access Tokens."
    ),
    tags=["comms", "intercom", "crm"],
)


# ===================================================
# MESSAGEBIRD
# ===================================================

MESSAGEBIRD_API_KEY = SecretPattern(
    id="messagebird_api_key",
    name="MessageBird API Key",
    description=(
        "MessageBird API key, a 25-character lowercase alphanumeric string."
        " Detected when preceded by MessageBird context keywords."
        " Grants access to SMS, voice, and messaging APIs."
    ),
    provider="messagebird",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/messagebird.go) —
    # context-gated 25-char lowercase alphanumeric format.
    regex=re.compile(
        r"(?:"
        r"(?:MESSAGEBIRD_API_KEY|message[_-]?bird.*key|message[_-]?bird.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-z0-9]{25})"
        r"(?![a-z0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.5,
    context_keywords=["messagebird", "MESSAGEBIRD_API_KEY", "bird"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the MessageBird Dashboard under Developers > API access keys."
    ),
    tags=["comms", "messagebird", "sms"],
)


# ===================================================
# SENDBIRD
# ===================================================

SENDBIRD_TOKEN = SecretPattern(
    id="sendbird_token",
    name="SendBird Access Token",
    description=(
        "SendBird access token, a 40-character hex string."
        " Detected when preceded by SendBird-specific context keywords."
        " Grants access to SendBird in-app messaging APIs."
    ),
    provider="sendbird",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/sendbird.go) —
    # context-gated 40-char hex format (sendbird-access-token rule).
    regex=re.compile(
        r"(?:"
        r"(?:SENDBIRD_ACCESS_TOKEN|SENDBIRD_API_TOKEN|sendbird.*token|sendbird.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{40})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.5,
    context_keywords=["sendbird", "SENDBIRD_ACCESS_TOKEN", "SENDBIRD_API_TOKEN"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in the SendBird Dashboard under Settings > API Tokens."
    ),
    tags=["comms", "sendbird", "messaging"],
)


# ===================================================
# FRESHDESK
# ===================================================

FRESHDESK_API_KEY = SecretPattern(
    id="freshdesk_api_key",
    name="Freshdesk API Key",
    description=(
        "Freshdesk API key, a 16-24 character alphanumeric string."
        " Detected when preceded by Freshdesk-specific context keywords."
        " Grants access to Freshdesk customer support APIs."
    ),
    provider="freshdesk",
    severity="high",
    # Independently authored — context-gated 16-24 char alphanumeric per
    # Freshdesk API documentation (https://developers.freshdesk.com/api/#authentication).
    regex=re.compile(
        r"(?:"
        r"(?:FRESHDESK_API_KEY|freshdesk.*key|freshdesk.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-zA-Z0-9]{16,24})"
        r"(?![a-zA-Z0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.5,
    context_keywords=["freshdesk", "FRESHDESK_API_KEY", "freshdesk.com"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key at your-domain.freshdesk.com under Profile Settings > API Key."
    ),
    tags=["comms", "freshdesk", "support"],
)


# ===================================================
# MAILCHIMP
# ===================================================

MAILCHIMP_API_KEY = SecretPattern(
    id="mailchimp_api_key",
    name="Mailchimp API Key",
    description=(
        "Mailchimp API key: 32 hex characters followed by a '-usNN' datacenter"
        " suffix (e.g. '-us21'). The datacenter suffix is the distinctive anchor."
        " Grants access to Mailchimp marketing and audience APIs."
    ),
    provider="mailchimp",
    severity="high",
    # Format per Mailchimp Marketing API docs (key = 32 hex + '-' + datacenter id):
    #   https://mailchimp.com/developer/marketing/guides/quick-start/
    # Independently authored from the documented '<hex>-us<dc>' structure.
    regex=re.compile(
        r"(?P<secret>[0-9a-f]{32}-us[0-9]{1,2})(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["mailchimp", "MAILCHIMP_API_KEY", "api_key", "audience"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Mailchimp dashboard under Account > Extras >"
        " API keys, then issue a replacement."
    ),
    tags=["comms", "mailchimp", "email"],
)


# ===================================================
# RESEND
# ===================================================

RESEND_API_KEY = SecretPattern(
    id="resend_api_key",
    name="Resend API Key",
    description=(
        "Resend transactional-email API key with the 're_' prefix followed by"
        " a base62/underscore body. Grants permission to send email and manage"
        " domains via the Resend API."
    ),
    provider="resend",
    severity="high",
    # Format per Resend API reference (keys are prefixed 're_'):
    #   https://resend.com/docs/api-reference/introduction
    # Independently authored from the documented 're_' prefix + token body.
    regex=re.compile(
        r"(?P<secret>re_[A-Za-z0-9_]{20,})(?![A-Za-z0-9_])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["resend", "RESEND_API_KEY", "api_key", "email"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Resend dashboard under API Keys and rotate it."
    ),
    tags=["comms", "resend", "email"],
)


# ===================================================
# BREVO (formerly Sendinblue)
# ===================================================

BREVO_API_KEY = SecretPattern(
    id="brevo_api_key",
    name="Brevo API Key",
    description=(
        "Brevo (formerly Sendinblue) API key with the 'xkeysib-' prefix followed"
        " by an 81-character token body. Grants access to Brevo's transactional"
        " email, SMS, and marketing-automation APIs."
    ),
    provider="brevo",
    severity="high",
    # Format per Brevo API docs (keys prefixed 'xkeysib-'):
    #   https://developers.brevo.com/docs/getting-started
    # Independently authored from the documented 'xkeysib-' prefix + token body.
    regex=re.compile(
        r"(?P<secret>xkeysib-[A-Za-z0-9_-]{81})(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=["brevo", "sendinblue", "BREVO_API_KEY", "api_key"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Brevo dashboard under SMTP & API > API Keys."
    ),
    tags=["comms", "brevo", "sendinblue", "email"],
)


# ===================================================
# SENTRY DSN (Batch 8 — 2026-06-22)
# ===================================================

SENTRY_DSN = SecretPattern(
    id="sentry_dsn",
    name="Sentry DSN",
    description=(
        "Sentry Data Source Name (DSN) — a client key embedded in an ingest URL."
        " Contains the public key, organization ingest host, and project ID;"
        " allows submitting (and, with the secret variant, reading) events."
    ),
    provider="sentry",
    severity="high",
    # Source: https://docs.sentry.io/product/sentry-basics/dsn-explainer/
    regex=re.compile(
        r"(?P<secret>https://[0-9a-f]{32}@o\d+\.ingest(?:\.[a-z]{2})?\.sentry\.io/\d+)",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["sentry", "dsn", "SENTRY_DSN", "ingest"],
    known_test_values={
        "https://abcdef0123456789abcdef0123456789@o123456.ingest.us.sentry.io/7891011",
    },
    recommendation=(
        "Rotate this DSN's client key at sentry.io under Settings > Projects >"
        " Client Keys (DSN). A leaked DSN lets attackers spoof or flood events."
    ),
    tags=["monitoring", "sentry", "dsn"],
)


# ===================================================
# TWILIO API KEY (Batch 8 — 2026-06-22)
# ===================================================

TWILIO_API_KEY = SecretPattern(
    id="twilio_api_key",
    name="Twilio API Key SID",
    description=(
        "Twilio API Key SID with the 'SK' prefix followed by 32 hex characters."
        " Paired with an API Key secret to authenticate Twilio REST API calls."
    ),
    provider="twilio",
    severity="high",
    # Vendor-published format — SK prefix is Twilio's documented API Key SID format
    # Source: https://www.twilio.com/docs/iam/api-keys
    regex=re.compile(
        r"(?P<secret>SK[0-9a-f]{32})"
        r"(?![0-9a-f])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["twilio", "TWILIO_API_KEY", "api_key", "api_sid"],
    known_test_values={
        "SK" + "0" * 32,  # synthetic; concatenated so no scannable Twilio SK secret literal exists in source
    },
    recommendation=(
        "Delete this API Key in the Twilio Console under Account > API keys & tokens"
        " and issue a replacement. Rotate the paired API Key secret as well."
    ),
    tags=["comms", "twilio"],
)


register(
    SLACK_BOT_TOKEN,
    SLACK_USER_TOKEN,
    SLACK_WEBHOOK_URL,
    SLACK_APP_TOKEN,
    SLACK_CONFIG_ACCESS_TOKEN,
    SLACK_CONFIG_REFRESH_TOKEN,
    SLACK_LEGACY_BOT_TOKEN,
    SLACK_LEGACY_WORKSPACE_TOKEN,
    SLACK_SESSION_COOKIE,
    SLACK_SESSION_TOKEN,
    TWILIO_ACCOUNT_SID,
    TWILIO_AUTH_TOKEN,
    SENDGRID_API_KEY,
    MAILGUN_API_KEY,
    MAILGUN_PUB_KEY,
    MAILGUN_SIGNING_KEY,
    DISCORD_BOT_TOKEN,
    TELEGRAM_BOT_TOKEN,
    NEWRELIC_ADMIN_API_KEY,
    NEWRELIC_INSIGHTS_KEY,
    NEWRELIC_USER_API_KEY,
    GRAFANA_API_KEY,
    LINEAR_API_KEY,
    NOTION_API_KEY,
    SENTRY_ORG_TOKEN,
    SENTRY_USER_TOKEN,
    DATADOG_API_KEY,
    DATADOG_APP_KEY,
    PAGERDUTY_API_KEY,
    FIGMA_PAT,
    AUTH0_MANAGEMENT_TOKEN,
    DISCORD_WEBHOOK_URL,
    TEAMS_WEBHOOK_URL,
    MATTERMOST_TOKEN,
    INTERCOM_ACCESS_TOKEN,
    MESSAGEBIRD_API_KEY,
    SENDBIRD_TOKEN,
    FRESHDESK_API_KEY,
    # Batch 7 — email providers (2026-06-18)
    MAILCHIMP_API_KEY,
    RESEND_API_KEY,
    BREVO_API_KEY,
    # Batch 8 — vendor-sourced patterns (2026-06-22)
    SENTRY_DSN,
    TWILIO_API_KEY,
)
