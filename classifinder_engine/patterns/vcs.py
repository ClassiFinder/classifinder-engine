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
    BITBUCKET_APP_PASSWORD,
    CIRCLECI_TOKEN,
    NPM_TOKEN,
    PYPI_TOKEN,
    RUBYGEMS_TOKEN,
    AIRTABLE_API_KEY,
    NUGET_API_KEY,
)
