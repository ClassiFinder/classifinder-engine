"""
SecretSweep — Communication & SaaS Patterns

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
    regex=re.compile(
        r"(?P<secret>xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,36})",
        re.ASCII
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
        "Slack user OAuth token with xoxp- prefix."
        " Grants user-level access to a Slack workspace"
        " -- more privileged than bot tokens."
    ),
    provider="slack",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32})",
        re.ASCII
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
        re.ASCII
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
        re.ASCII
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
        "Twilio Auth Token, 32-character hex string."
        " Used with Account SID for API authentication."
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
        re.ASCII | re.IGNORECASE
    ),
    confidence_base=0.80,
    entropy_threshold=3.0,
    context_keywords=[
        "twilio", "auth_token", "TWILIO_AUTH_TOKEN", "account_sid",
    ],
    known_test_values=set(),
    recommendation=(
        "Rotate this auth token in the Twilio Console"
        " under Account > API Credentials."
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
    regex=re.compile(
        r"(?P<secret>SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})",
        re.ASCII
    ),
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
    description=(
        "Mailgun API key with key- prefix followed by"
        " a 32-character hex string."
    ),
    provider="mailgun",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>key-[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["mailgun", "api_key", "MAILGUN_API_KEY", "email"],
    known_test_values={
        "key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    },
    recommendation=(
        "Rotate this API key in the Mailgun control panel"
        " under Settings > API Security."
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
        re.ASCII
    ),
    confidence_base=0.85,
    entropy_threshold=3.0,
    context_keywords=[
        "discord", "bot", "token", "DISCORD_TOKEN", "DISCORD_BOT_TOKEN",
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
        "Telegram Bot API token. Format: numeric bot ID, colon,"
        " 35-character alphanumeric string."
    ),
    provider="telegram",
    severity="high",
    regex=re.compile(
        r"(?P<secret>[0-9]{8,10}:[A-Za-z0-9_\-]{35})"
        r"(?![A-Za-z0-9_\-])",
        re.ASCII
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=[
        "telegram", "bot", "token", "TELEGRAM_BOT_TOKEN", "TELEGRAM_TOKEN",
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
        re.ASCII
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "newrelic", "new_relic", "NEW_RELIC_API_KEY", "nraa",
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
        re.ASCII
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "newrelic", "new_relic", "insights", "NEW_RELIC_INSERT_KEY",
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
        "New Relic user API key with NRAK- prefix."
        " Grants access to NerdGraph and REST APIs."
    ),
    provider="newrelic",
    severity="high",
    regex=re.compile(
        r"(?P<secret>NRAK-[a-z0-9]{27})"
        r"(?![a-z0-9])",
        re.ASCII
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "newrelic", "new_relic", "NEW_RELIC_API_KEY", "nrak",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in New Relic under API Keys."
        " Generate a new user API key."
    ),
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
        re.ASCII
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "grafana", "GRAFANA_API_KEY", "grafana_token", "glsa",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in Grafana under"
        " Administration > Service Accounts."
    ),
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
        re.ASCII
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "linear", "LINEAR_API_KEY", "linear_token",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in Linear under Settings > API."
        " Generate a new personal API key."
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
        re.ASCII
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "notion", "NOTION_API_KEY", "NOTION_TOKEN", "notion_secret",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in Notion under Settings > Integrations."
        " Create a new integration with minimal page access."
    ),
    tags=["saas", "notion"],
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
)
