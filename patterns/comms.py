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
    regex=re.compile(r"(?P<secret>xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,36})", re.ASCII),
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
        "Slack user OAuth token with xoxp- prefix."
        " Grants user-level access to a Slack workspace"
        " -- more privileged than bot tokens."
    ),
    provider="slack",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32})", re.ASCII
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["slack", "user", "token", "SLACK_USER_TOKEN", "xoxp"],
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
    regex=re.compile(
        r"(?P<secret>https://hooks\.slack\.com/services/"
        r"T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[a-zA-Z0-9]{24})",
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
    regex=re.compile(
        r"(?P<secret>[MN][A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40})"
        r"(?![A-Za-z0-9_\-.])",
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
    regex=re.compile(
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
    recommendation="Revoke this token in Mattermost under Account Settings > Security > Personal Access Tokens.",
    tags=["comms", "mattermost"],
)


register(
    SLACK_BOT_TOKEN,
    SLACK_USER_TOKEN,
    SLACK_WEBHOOK_URL,
    TWILIO_ACCOUNT_SID,
    TWILIO_AUTH_TOKEN,
    SENDGRID_API_KEY,
    MAILGUN_API_KEY,
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
)
