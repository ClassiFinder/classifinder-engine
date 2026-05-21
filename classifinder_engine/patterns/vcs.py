"""
ClassiFinder — Version Control & CI/CD Patterns

Patterns for GitHub, GitLab, Bitbucket, and CircleCI credentials.
These are among the most commonly leaked secret types -- GitHub tokens alone
account for a huge share of secrets found on public repos.

Pattern design notes:
- GitHub overhauled their token format in 2021+. Classic PATs use ghp_ prefix.
  Fine-grained tokens use github_pat_ prefix. OAuth app secrets use gho_.
  Each is a distinct detection.
- GitLab uses glpat- prefix for personal access tokens.
- Both GitHub and GitLab tokens have checksums, but we don't validate those
  at the regex level -- that's a potential future enhancement.
"""

import re

from .registry import SecretPattern, register

# ===================================================
# GITHUB
# ===================================================

GITHUB_PAT_CLASSIC = SecretPattern(
    id="github_pat_classic",
    name="GitHub Personal Access Token (Classic)",
    description=(
        "GitHub classic personal access token with ghp_ prefix."
        " Grants access based on the scopes assigned at creation."
    ),
    provider="github",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:2771) — ghp_ vendor prefix
    regex=re.compile(
        r"(?P<secret>ghp_[A-Za-z0-9]{30,40})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["github", "token", "GITHUB_TOKEN", "GH_TOKEN", "pat"],
    known_test_values={
        "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    },
    recommendation=(
        "Revoke this token immediately at github.com/settings/tokens."
        " Audit the token's scopes and any recent API activity."
    ),
    tags=["vcs", "github", "auth"],
)


GITHUB_PAT_FINE_GRAINED = SecretPattern(
    id="github_pat_fine_grained",
    name="GitHub Fine-Grained Personal Access Token",
    description=(
        "GitHub fine-grained PAT with github_pat_ prefix."
        " Has repository-level and permission-level granularity."
    ),
    provider="github",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:2717) — github_pat_ vendor prefix
    regex=re.compile(
        r"(?P<secret>github_pat_[A-Za-z0-9_]{82})"
        r"(?![A-Za-z0-9_])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "github",
        "token",
        "GITHUB_TOKEN",
        "fine-grained",
        "pat",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token at github.com/settings/tokens."
        " Fine-grained tokens have expiration dates"
        " -- check if it's still valid before rotating"
        " dependent systems."
    ),
    tags=["vcs", "github", "auth"],
)


GITHUB_OAUTH_SECRET = SecretPattern(
    id="github_oauth_secret",
    name="GitHub OAuth App Client Secret",
    description=("GitHub OAuth application client secret with gho_ prefix."),
    provider="github",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:2744) — gho_ vendor prefix
    regex=re.compile(
        r"(?P<secret>gho_[A-Za-z0-9]{36})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["github", "oauth", "client_secret", "app"],
    known_test_values=set(),
    recommendation=(
        "Regenerate the client secret in the GitHub OAuth App settings."
        " An attacker with this secret can impersonate your app."
    ),
    tags=["vcs", "github", "oauth"],
)


GITHUB_APP_INSTALLATION_TOKEN = SecretPattern(
    id="github_app_installation_token",
    name="GitHub App Installation Access Token",
    description=(
        "GitHub App installation token with ghs_ prefix."
        " Short-lived (1 hour) but grants repository access."
    ),
    provider="github",
    severity="high",
    # Vendor-published format (ghs_ prefix per GitHub Apps documentation)
    regex=re.compile(
        r"(?P<secret>ghs_[A-Za-z0-9]{36})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["github", "installation", "app", "token"],
    known_test_values=set(),
    recommendation=(
        "This installation token expires in ~1 hour, but if recently"
        " generated it may still be active."
        " Review the GitHub App's recent activity."
    ),
    tags=["vcs", "github", "app"],
)


GITHUB_USER_TO_SERVER_TOKEN = SecretPattern(
    id="github_user_to_server_token",
    name="GitHub User-to-Server Token",
    description=(
        "GitHub user-to-server token with ghu_ prefix."
        " Used by GitHub Apps acting on behalf of a user."
    ),
    provider="github",
    severity="critical",
    # Vendor-published format (ghu_ prefix per GitHub Apps documentation)
    regex=re.compile(
        r"(?P<secret>ghu_[A-Za-z0-9]{36})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["github", "user", "token"],
    known_test_values=set(),
    recommendation=(
        "Revoke access for the GitHub App that generated this token."
        " The token acts with the user's permissions."
    ),
    tags=["vcs", "github", "app"],
)


# ===================================================
# GITLAB
# ===================================================

GITLAB_PAT = SecretPattern(
    id="gitlab_pat",
    name="GitLab Personal Access Token",
    description="GitLab personal access token with glpat- prefix.",
    provider="gitlab",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:2925) — glpat- vendor prefix
    regex=re.compile(
        r"(?P<secret>glpat-[A-Za-z0-9\-_]{20,})"
        r"(?![A-Za-z0-9\-_])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "gitlab",
        "token",
        "GITLAB_TOKEN",
        "pat",
        "private_token",
    ],
    known_test_values=set(),
    recommendation=("Revoke this token in GitLab under User Settings > Access Tokens."),
    tags=["vcs", "gitlab", "auth"],
)


GITLAB_PIPELINE_TRIGGER = SecretPattern(
    id="gitlab_pipeline_trigger",
    name="GitLab Pipeline Trigger Token",
    description="GitLab CI pipeline trigger token with glptt- prefix.",
    provider="gitlab",
    severity="high",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:2973) — glptt- vendor prefix
    regex=re.compile(
        r"(?P<secret>glptt-[A-Za-z0-9\-_]{20,})"
        r"(?![A-Za-z0-9\-_])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["gitlab", "trigger", "pipeline", "ci"],
    known_test_values=set(),
    recommendation=(
        "Revoke this trigger token in the GitLab project CI/CD settings."
        " An attacker can trigger arbitrary pipelines with this token."
    ),
    tags=["vcs", "gitlab", "ci"],
)


# ---------------------------------------------------
# BATCH 4 Part 1.3 — GitLab variant expansions (2026-05-21)
# ---------------------------------------------------
# Prefixes confirmed by GitLab's own source repository:
#   - gitlabhq/doc/security/tokens/_index.md (the canonical prefix table)
#   - gitlabhq/app/models/clusters/agent_token.rb defines TOKEN_PREFIX = "glagent-"
# Body shapes from Betterleaks MIT cmd/generate/config/rules/gitlab.go.
# Cross-corroborated against Gitleaks, Cariddi, and TruffleHog (observed
# for triangulation only — no code copied).
#
# All 8 patterns share the same charset [0-9a-zA-Z_-] but use different body
# lengths per token type (20, 25, 50, 64). The bounded lengths make these
# patterns precise — they reject random alphanumeric strings of arbitrary length.

GITLAB_DEPLOY_TOKEN = SecretPattern(
    id="gitlab_deploy_token",
    name="GitLab Deploy Token",
    description=(
        "GitLab deploy token with gldt- prefix."
        " Used to authenticate package/container registry access at the repo or group level."
    ),
    provider="gitlab",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/gitlab.go) — gldt- vendor prefix
    regex=re.compile(
        r"(?P<secret>gldt-[0-9a-zA-Z_\-]{20})"
        r"(?![0-9a-zA-Z_\-])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["gitlab", "deploy", "DEPLOY_TOKEN", "deploy_token"],
    known_test_values=set(),
    recommendation=(
        "Revoke this deploy token in the GitLab project under"
        " Settings > Repository > Deploy tokens."
    ),
    tags=["vcs", "gitlab", "deploy"],
)


GITLAB_FEED_TOKEN = SecretPattern(
    id="gitlab_feed_token",
    name="GitLab Feed Token",
    description=(
        "GitLab feed token with glft- prefix."
        " Used to authenticate access to GitLab's RSS/Atom feeds and ICS calendars."
    ),
    provider="gitlab",
    severity="medium",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/gitlab.go) — glft- vendor prefix
    regex=re.compile(
        r"(?P<secret>glft-[0-9a-zA-Z_\-]{20})"
        r"(?![0-9a-zA-Z_\-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["gitlab", "feed", "rss", "atom", "feed_token"],
    known_test_values=set(),
    recommendation=(
        "Rotate this feed token in GitLab user settings."
        " Feed tokens expose private repo activity, issues, and merge-request feeds."
    ),
    tags=["vcs", "gitlab", "feed"],
)


GITLAB_INCOMING_MAIL_TOKEN = SecretPattern(
    id="gitlab_incoming_mail_token",
    name="GitLab Incoming Mail Token",
    description=(
        "GitLab incoming mail token with glimt- prefix (25-char body)."
        " Used to create issues, comments, and merge requests via email."
    ),
    provider="gitlab",
    severity="medium",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/gitlab.go) — glimt- vendor prefix
    regex=re.compile(
        r"(?P<secret>glimt-[0-9a-zA-Z_\-]{25})"
        r"(?![0-9a-zA-Z_\-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["gitlab", "incoming", "mail", "email"],
    known_test_values=set(),
    recommendation=(
        "Rotate this incoming mail token in GitLab user settings."
        " Attackers can use it to post via email-to-GitLab on the user's behalf."
    ),
    tags=["vcs", "gitlab", "mail"],
)


GITLAB_KUBERNETES_AGENT_TOKEN = SecretPattern(
    id="gitlab_kubernetes_agent_token",
    name="GitLab Kubernetes Agent Token",
    description=(
        "GitLab Kubernetes agent (KAS) token with glagent- prefix (50-char body)."
        " Authenticates the GitLab agent running inside a Kubernetes cluster."
        " Critical — provides cluster-level access to the GitLab control plane."
    ),
    provider="gitlab",
    severity="critical",
    # Vendor-confirmed prefix per gitlabhq/app/models/clusters/agent_token.rb TOKEN_PREFIX = "glagent-".
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/gitlab.go) — body length + charset.
    regex=re.compile(
        r"(?P<secret>glagent-[0-9a-zA-Z_\-]{50})"
        r"(?![0-9a-zA-Z_\-])",
        re.ASCII,
    ),
    confidence_base=0.98,
    entropy_threshold=0.0,
    context_keywords=["gitlab", "agent", "kubernetes", "k8s", "KAS", "agentk"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Kubernetes agent token in GitLab under"
        " Infrastructure > Kubernetes clusters > Agents."
        " Compromised agent tokens grant access to the cluster they manage."
    ),
    tags=["vcs", "gitlab", "kubernetes", "infrastructure"],
)


GITLAB_OAUTH_APP_SECRET = SecretPattern(
    id="gitlab_oauth_app_secret",
    name="GitLab OAuth Application Secret",
    description=(
        "GitLab OAuth/OIDC application secret with gloas- prefix (64-char body)."
        " Used by registered OAuth apps to authenticate against GitLab's auth endpoints."
    ),
    provider="gitlab",
    severity="critical",
    # Vendor-confirmed prefix per gitlabhq/doc/security/tokens/_index.md.
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/gitlab.go).
    regex=re.compile(
        r"(?P<secret>gloas-[0-9a-zA-Z_\-]{64})"
        r"(?![0-9a-zA-Z_\-])",
        re.ASCII,
    ),
    confidence_base=0.98,
    entropy_threshold=0.0,
    context_keywords=["gitlab", "oauth", "client_secret", "app_secret", "oidc"],
    known_test_values=set(),
    recommendation=(
        "Rotate this OAuth application secret in GitLab under"
        " Admin Area > Applications (or user-owned OAuth applications)."
        " Compromised secrets let attackers impersonate the OAuth application."
    ),
    tags=["vcs", "gitlab", "oauth"],
)


GITLAB_RUNNER_AUTHENTICATION_TOKEN = SecretPattern(
    id="gitlab_runner_authentication_token",
    name="GitLab Runner Authentication Token",
    description=(
        "GitLab runner authentication token with glrt- prefix."
        " Used by GitLab Runners to authenticate against the GitLab instance."
    ),
    provider="gitlab",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/gitlab.go) — glrt- vendor prefix
    regex=re.compile(
        r"(?P<secret>glrt-[0-9a-zA-Z_\-]{20})"
        r"(?![0-9a-zA-Z_\-])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["gitlab", "runner", "RUNNER_TOKEN", "ci_runner"],
    known_test_values=set(),
    recommendation=(
        "Revoke this runner token in GitLab under"
        " Admin Area > CI/CD > Runners (or project/group runner settings)."
        " A compromised runner token allows job hijacking."
    ),
    tags=["vcs", "gitlab", "runner", "ci"],
)


GITLAB_SCIM_TOKEN = SecretPattern(
    id="gitlab_scim_token",
    name="GitLab SCIM Token",
    description=(
        "GitLab SCIM token with glsoat- prefix."
        " Authenticates SCIM provisioning of users/groups from external identity providers."
    ),
    provider="gitlab",
    severity="high",
    # Vendor-confirmed prefix per gitlabhq/doc/security/tokens/_index.md.
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/gitlab.go) — glsoat- vendor prefix
    regex=re.compile(
        r"(?P<secret>glsoat-[0-9a-zA-Z_\-]{20})"
        r"(?![0-9a-zA-Z_\-])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["gitlab", "scim", "SCIM_TOKEN", "provisioning"],
    known_test_values=set(),
    recommendation=(
        "Rotate this SCIM token in GitLab group settings under"
        " Settings > SAML SSO > SCIM Token."
        " Compromised SCIM tokens allow attackers to provision/deprovision users."
    ),
    tags=["vcs", "gitlab", "scim", "identity"],
)


GITLAB_FEATURE_FLAG_CLIENT_TOKEN = SecretPattern(
    id="gitlab_feature_flag_client_token",
    name="GitLab Feature Flag Client Token",
    description=(
        "GitLab feature flag client token with glffct- prefix."
        " Used by client applications to fetch GitLab-managed feature flag state."
    ),
    provider="gitlab",
    severity="medium",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/gitlab.go) — glffct- vendor prefix
    regex=re.compile(
        r"(?P<secret>glffct-[0-9a-zA-Z_\-]{20})"
        r"(?![0-9a-zA-Z_\-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["gitlab", "feature", "flag", "feature_flag", "unleash"],
    known_test_values=set(),
    recommendation=(
        "Rotate this feature flag client token in GitLab project settings under"
        " Operations > Feature Flags."
        " Compromised tokens expose feature-flag state for the project."
    ),
    tags=["vcs", "gitlab", "feature-flag"],
)


# ===================================================
# BITBUCKET
# ===================================================

BITBUCKET_APP_PASSWORD = SecretPattern(
    id="bitbucket_app_password",
    name="Bitbucket App Password",
    description=(
        "Bitbucket app password, typically a 20-character alphanumeric"
        " string used for API authentication."
    ),
    provider="bitbucket",
    severity="high",
    # Independently authored — context-gated 20-40 char; Bitbucket-documented app password format
    regex=re.compile(
        r"(?:"
        r"(?:BITBUCKET_APP_PASSWORD|bitbucket.*password|bitbucket.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9]{20,40})"
        r"(?![A-Za-z0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,  # no distinctive prefix, context-dependent
    entropy_threshold=3.0,
    context_keywords=[
        "bitbucket",
        "app_password",
        "BITBUCKET_APP_PASSWORD",
    ],
    known_test_values=set(),
    recommendation=(
        "Delete this app password in Bitbucket under Personal Settings > App Passwords."
    ),
    tags=["vcs", "bitbucket", "auth"],
)


# ===================================================
# CI/CD
# ===================================================

CIRCLECI_TOKEN = SecretPattern(
    id="circleci_token",
    name="CircleCI API Token",
    description=("CircleCI personal or project API token. Typically a 40-character hex string."),
    provider="circleci",
    severity="high",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml) — context-gated 40-char hex
    regex=re.compile(
        r"(?:"
        r"(?:CIRCLECI_TOKEN|CIRCLE_TOKEN|circleci.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{40})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=3.0,
    context_keywords=[
        "circleci",
        "circle",
        "ci",
        "token",
        "CIRCLE_TOKEN",
    ],
    known_test_values=set(),
    recommendation=("Revoke this token in CircleCI under User Settings > Personal API Tokens."),
    tags=["ci", "circleci"],
)


# ===================================================
# PACKAGE REGISTRIES
# ===================================================

NPM_TOKEN = SecretPattern(
    id="npm_token",
    name="npm Access Token",
    description=(
        "npm registry access token with npm_ prefix."
        " Grants access to publish and manage npm packages."
    ),
    provider="npm",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:3761) — npm_ vendor prefix
    regex=re.compile(
        r"(?P<secret>npm_[A-Za-z0-9]{36})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "npm",
        "NPM_TOKEN",
        "npmrc",
        "registry",
        "node",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token at npmjs.com under Access Tokens."
        " An attacker can publish malicious packages under your name."
    ),
    tags=["vcs", "npm", "registry"],
)


PYPI_TOKEN = SecretPattern(
    id="pypi_token",
    name="PyPI API Token",
    description=(
        "PyPI API token with pypi-AgEIcHlwaS5vcmc prefix."
        " Grants access to upload packages to the Python Package Index."
    ),
    provider="pypi",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4139) — pypi-AgEI base64 anchor
    regex=re.compile(
        r"(?P<secret>pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,})"
        r"(?![A-Za-z0-9\-_])",
        re.ASCII,
    ),
    confidence_base=0.99,
    entropy_threshold=0.0,
    context_keywords=[
        "pypi",
        "PYPI_TOKEN",
        "twine",
        "upload",
        "pip",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token at pypi.org under Account Settings > API Tokens."
        " An attacker can publish malicious Python packages."
    ),
    tags=["vcs", "pypi", "registry"],
)


RUBYGEMS_TOKEN = SecretPattern(
    id="rubygems_token",
    name="RubyGems API Key",
    description=(
        "RubyGems API key with rubygems_ prefix. Grants access to publish and manage Ruby gems."
    ),
    provider="rubygems",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4192) — rubygems_ vendor prefix
    regex=re.compile(
        r"(?P<secret>rubygems_[A-Za-z0-9]{48})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "rubygems",
        "RUBYGEMS_API_KEY",
        "gem",
        "gem_host_api_key",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key at rubygems.org under Settings > API Keys."
        " An attacker can publish malicious gems."
    ),
    tags=["vcs", "rubygems", "registry"],
)


# ===================================================
# AIRTABLE
# ===================================================

AIRTABLE_API_KEY = SecretPattern(
    id="airtable_api_key",
    name="Airtable Personal Access Token",
    description=(
        "Airtable personal access token with pat prefix,"
        " 14 alphanumeric chars, a dot, and 64 hex chars."
        " Highly distinctive structure."
    ),
    provider="airtable",
    severity="high",
    # Format per Airtable official docs:
    #   https://airtable.com/developers/web/guides/personal-access-tokens
    #   https://support.airtable.com/docs/creating-personal-access-tokens
    # Structure: "pat" + 14-char Token ID (per Airtable support doc) + "." + 64-char hex secret.
    # Independently derived from vendor documentation.
    regex=re.compile(
        r"(?P<secret>pat[0-9A-Za-z]{14}\.[0-9a-f]{64})"
        r"(?![0-9a-f])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "airtable",
        "AIRTABLE_API_KEY",
        "airtable_token",
    ],
    known_test_values=set(),
    recommendation=("Revoke this token at airtable.com/account under Personal Access Tokens."),
    tags=["saas", "airtable"],
)


# ===================================================
# NUGET
# ===================================================

NUGET_API_KEY = SecretPattern(
    id="nuget_api_key",
    name="NuGet API Key",
    description=(
        "NuGet package registry API key with oy2 prefix. Used to publish and manage .NET packages."
    ),
    provider="nuget",
    severity="critical",
    # Pattern attribution: secrets-patterns-db CC-BY-4.0 (rules-stable.yml:5280) — oy2 vendor prefix
    regex=re.compile(
        r"(?P<secret>oy2[a-z0-9]{43})"
        r"(?![a-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=[
        "nuget",
        "NUGET_API_KEY",
        "nuget_token",
        "dotnet",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key at nuget.org under Account Settings > API Keys."
        " An attacker can publish malicious .NET packages."
    ),
    tags=["vcs", "nuget", "registry"],
)


register(
    GITHUB_PAT_CLASSIC,
    GITHUB_PAT_FINE_GRAINED,
    GITHUB_OAUTH_SECRET,
    GITHUB_APP_INSTALLATION_TOKEN,
    GITHUB_USER_TO_SERVER_TOKEN,
    GITLAB_PAT,
    GITLAB_PIPELINE_TRIGGER,
    GITLAB_DEPLOY_TOKEN,
    GITLAB_FEED_TOKEN,
    GITLAB_INCOMING_MAIL_TOKEN,
    GITLAB_KUBERNETES_AGENT_TOKEN,
    GITLAB_OAUTH_APP_SECRET,
    GITLAB_RUNNER_AUTHENTICATION_TOKEN,
    GITLAB_SCIM_TOKEN,
    GITLAB_FEATURE_FLAG_CLIENT_TOKEN,
    BITBUCKET_APP_PASSWORD,
    CIRCLECI_TOKEN,
    NPM_TOKEN,
    PYPI_TOKEN,
    RUBYGEMS_TOKEN,
    AIRTABLE_API_KEY,
    NUGET_API_KEY,
)
