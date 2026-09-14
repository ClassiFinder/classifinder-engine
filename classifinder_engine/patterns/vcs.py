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


# ===================================================
# CRATES.IO
# ===================================================

CRATES_IO_API_TOKEN = SecretPattern(
    id="crates_io_api_token",
    name="crates.io API Token",
    description=(
        "crates.io API token: the literal cio prefix followed by exactly 32"
        " alphanumeric characters, 35 characters in total."
        " Grants publish and yank rights on the Rust package registry."
    ),
    provider="crates_io",
    severity="critical",
    # crates.io's own token generator is the authority for this shape:
    # PlainToken::generate() returns TOKEN_PREFIX + generate_secure_alphanumeric_string(
    # TOKEN_LENGTH), where TOKEN_PREFIX = "cio" and TOKEN_LENGTH = 32, and the helper
    # draws from rand::distr::Alphanumeric (a-z, A-Z, 0-9). HashedToken::parse()
    # rejects any token that does not start with the prefix, and the source carries
    # the comment "NEVER CHANGE THE PREFIX OF EXISTING TOKENS!!!" — so the prefix is
    # both mandatory and stable. The `cio` anchor is only three characters, so the
    # exact {32} bound, the two alphanumeric boundaries and the entropy threshold
    # are what carry the precision here, not the prefix.
    # Source: https://github.com/rust-lang/crates.io/blob/main/crates/crates_io_database/src/utils/token.rs
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>cio[A-Za-z0-9]{32})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.80,
    entropy_threshold=3.5,
    context_keywords=[
        "cargo",
        "crates.io",
        "crates",
        "CARGO_REGISTRY_TOKEN",
        "registry.token",
        "credentials.toml",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token at crates.io under Account Settings > API Tokens,"
        " then run `cargo logout` and re-authenticate."
        " An attacker can publish or yank crates under your name."
    ),
    tags=["vcs", "crates-io", "registry"],
)



# ===================================================
# BLOCK PROTOCOL
# ===================================================

BLOCK_PROTOCOL_API_KEY = SecretPattern(
    id="block_protocol_api_key",
    name="Block Protocol API Key",
    description=(
        "Block Protocol Hub API key, used by the `blockprotocol` CLI (and by the"
        " official WordPress plugin) to authenticate publish requests. Shaped"
        " b10ck5.<32 lowercase hex>.<canonical UUID>, 76 characters. Grants the"
        " ability to publish and overwrite blocks under the issuing account."
    ),
    provider="block_protocol",
    severity="high",
    # Three dot-separated segments of fixed width: the literal `b10ck5`, a
    # 32-character lowercase-hex public portion, and a canonical hyphenated
    # UUID (8-4-4-4-12). 6 + 1 + 32 + 1 + 36 = 76 characters.
    #
    # The whole three-part structure is anchored, not just the prefix. The
    # vendor documents the 32-hex middle segment as the deliberately
    # non-secret "public" portion of the key; it is the trailing UUID that
    # makes the value sensitive, so matching `b10ck5.` plus a loose tail would
    # report a non-credential as a leak.
    #
    # No entropy gate: `b10ck5` is distinctive leetspeak rather than a natural
    # substring, and the two fixed-width hex segments carry the rest of the
    # signal, so an entropy floor could only sink legitimate keys — including
    # the vendor's own all-zeros CLI template, which is instead registered as
    # a known_test_value below. Lowercase-only hex is the vendor's charset and
    # is deliberately not widened to [0-9a-fA-F]: it excludes the X-masked
    # placeholders that dominate hand-redacted public samples.
    # Source: blockprotocol/blockprotocol,
    #   libs/blockprotocol/cli/commands/publish/find-api-key.js — the CLI's own
    #   config template literal `api-key=b10ck5.<32 zeros>.<zero UUID>`
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>b10ck5\.[0-9a-f]{32}\."
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        r"(?![A-Za-z0-9-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "blockprotocol",
        "block-protocol",
        "blockprotocolrc",
        "BLOCK_PROTOCOL_API_KEY",
        "block protocol",
    ],
    # The `blockprotocol` CLI writes this all-zeros template into every new
    # `.blockprotocolrc`, so it is the single most likely value to appear in a
    # public repository. Assembled by concatenation so no whole key-shaped
    # literal is written as one string in this file.
    known_test_values={
        "b10ck5." + "0" * 32 + "." + "00000000-0000-0000-0000-000000000000",
    },
    recommendation=(
        "Revoke this key in the Block Protocol Hub under your account's API"
        " Keys page, issue a replacement, and update the `.blockprotocolrc`"
        " file or BLOCK_PROTOCOL_API_KEY environment variable that carries it."
        " An attacker can publish or overwrite blocks under your name."
    ),
    tags=["vcs", "block-protocol", "registry", "blocks"],
)


# ===================================================
# GITLAB CI/CD JOB TOKEN
# ===================================================

GITLAB_CICD_JOB_TOKEN = SecretPattern(
    id="gitlab_cicd_job_token",
    name="GitLab CI/CD Job Token",
    description=(
        "GitLab CI/CD job token — the 'glcbt-' prefix, a short routing"
        " segment of up to 5 alphanumeric characters, an underscore, and a"
        " 20-character base64url body. Injected into every job as CI_JOB_TOKEN"
        " and valid only while that job runs, which is exactly why it leaks:"
        " it is echoed into build logs, baked into artifacts, and passed to"
        " third-party services by scripts that treat it as harmless. While"
        " live it authenticates against the project's container and package"
        " registries, can clone dependent repositories, and can trigger"
        " downstream pipelines."
    ),
    provider="gitlab",
    severity="high",
    # Prefix per GitLab's own token-prefix table, which lists 'glcbt-' for
    # the CI/CD job token alongside the prefixes already registered here
    # (glpat-, glrt-, gldt-, glptt-, glft-, glimt-, glagent-, gloas-,
    # glsoat-, glffct-). The routing segment is the short alphanumeric run
    # GitLab places between the prefix and the random body in its routable
    # token format; it is bounded {1,5} rather than pinned because GitLab
    # documents the prefix, not the routing width.
    #
    # The body is 20 base64url characters, matching the width GitLab uses
    # across this token family.
    #
    # No entropy gate: a 20-character random body behind a vendor-unique
    # prefix leaves no placeholder an entropy floor would catch that the
    # prefix does not already exclude.
    # Source: https://docs.gitlab.com/security/tokens/
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"(?P<secret>glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20})"
        r"(?![0-9A-Za-z_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # vendor-unique prefix carries the precision
    context_keywords=[
        "gitlab",
        "CI_JOB_TOKEN",
        "job token",
        "ci",
        "pipeline",
    ],
    known_test_values={
        # Single-character masks — how CI documentation and redacted job logs
        # render this token. confidence_base 0.95 sits above the 0.85
        # FP-wordlist gate (scanner.py:197), so the wordlist never prices
        # these down; they are pinned here and land at ~0.15.
        "glcbt-1_" + "x" * 20,
        "glcbt-1_" + "X" * 20,
        "glcbt-1_" + "0" * 20,
    },
    recommendation=(
        "A job token dies with its job, so the fix is to stop emitting it"
        " rather than to rotate it: find the step that printed or forwarded"
        " CI_JOB_TOKEN and remove it, and purge the affected job logs and"
        " artifacts, which keep the value long after the job ended. If the"
        " token was still live when it leaked, review the project's container"
        " and package registries for pushes you did not make and check for"
        " unexpected downstream pipeline triggers. Under Settings > CI/CD >"
        " Job token permissions, narrow the allowlist of projects this"
        " project's tokens may reach."
    ),
    tags=["vcs", "gitlab", "ci"],
)


# 2026-09-06 — the GitLab runner REGISTRATION token, the legacy half of
# GitLab's runner-token migration. 'GR1348941' is a literal vendor constant,
# not a family abbreviation: GitLab's own
# app/models/concerns/runners_token_prefixable.rb sets
# RUNNERS_TOKEN_PREFIX = 'GR1348941' and explains it as "GR (for Gitlab
# Runner) combined with the rotation date (20220225) decimal to hex encoded".
GITLAB_RUNNER_REGISTRATION_TOKEN = SecretPattern(
    id="gitlab_runner_registration_token",
    name="GitLab Runner Registration Token",
    description=(
        "GitLab runner registration token — the literal 'GR1348941' prefix"
        " followed by a 20-character urlsafe-base64 body, 29 characters in"
        " total. Deprecated in GitLab 15.6 and superseded by the 'glrt-'"
        " runner authentication token, but still live on older self-managed"
        " instances and still abundant in legacy .gitlab-ci.yml files,"
        " docker-compose services, Helm values and 'gitlab-runner register'"
        " invocations. It registers new runners against a project, group or"
        " instance, so a leaked one lets an attacker attach a runner of their"
        " own and receive that scope's CI jobs — along with every variable"
        " those jobs are handed."
    ),
    provider="gitlab",
    severity="medium",
    # The body is 20 characters of Devise.friendly_token output (urlsafe
    # base64), which fixes the charset as [0-9A-Za-z_-]. GitLab's own
    # doc/ci/runners/new_creation_workflow.md publishes a concrete example
    # whose body contains a hyphen and is exactly 20 characters wide.
    #
    # The {20} body width is exact ON PURPOSE. gitlab-runner's error logs emit
    # a TRUNCATED short form of the token; a loosened quantifier would turn
    # every such log line into a finding, so the short form is deliberately
    # not matched.
    #
    # No entropy gate: a 20-character random body behind a nine-character
    # vendor-unique literal leaves no placeholder an entropy floor would catch
    # that the prefix does not already exclude.
    # Source: https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/models/concerns/runners_token_prefixable.rb
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"(?P<secret>GR1348941[0-9A-Za-z_-]{20})"
        r"(?![0-9A-Za-z_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # vendor-unique literal prefix carries the precision
    context_keywords=[
        "gitlab",
        "runner",
        "registration",
        "registration_token",
        "registration-token",
        "REGISTRATION_TOKEN",
        "gitlab-runner",
        "ci",
    ],
    known_test_values={
        # Single-character masks — how GitLab documentation, tutorials and
        # redacted docker-compose files render this token. confidence_base
        # 0.95 sits above the 0.85 FP-wordlist gate (scanner.py:197), so the
        # wordlist never prices these down; they are pinned here and land at
        # ~0.15. Written as concatenations so no contiguous
        # registration-token literal is committed to source.
        "GR" + "1348941" + "x" * 20,
        "GR" + "1348941" + "X" * 20,
        "GR" + "1348941" + "0" * 20,
    },
    recommendation=(
        "Reset this registration token, then migrate off registration tokens"
        " entirely. Reset it under Settings > CI/CD > Runners for the project"
        " or group, or in the Admin Area for an instance-wide token; the old"
        " value dies immediately and already-registered runners keep working,"
        " because they hold authentication tokens rather than this one. Then"
        " create runners through the new authentication-token workflow, which"
        " issues a per-runner 'glrt-' token that can be revoked individually"
        " — a registration token cannot, which is why GitLab deprecated it."
        " Audit the scope's runner list for runners you did not register, and"
        " treat every CI/CD variable the affected jobs could reach as exposed"
        " for the whole window the token was public."
    ),
    tags=["vcs", "gitlab", "runner", "ci", "deprecated"],
)


# 2026-09-08 — GitLab's Rails SESSION COOKIE. Unlike every other GitLab
# pattern registered here, the anchor is not a token prefix: it is the
# literal first-party cookie NAME, '_gitlab_session=', documented at
# docs.gitlab.com/development/cookies/ as the cookie Rails uses to track a
# signed-in session. Whoever holds the value IS the user for the rest of
# that session.
GITLAB_SESSION_COOKIE = SecretPattern(
    id="gitlab_session_cookie",
    name="GitLab Session Cookie",
    description=(
        "GitLab's Rails session cookie — the literal first-party cookie name"
        " '_gitlab_session=' followed by an optional deployment prefix and a"
        " 32-character lowercase-hex session id. It is not a scoped token:"
        " whoever holds it is the signed-in user for the remaining lifetime"
        " of the session, with no password, no second factor and no scope"
        " narrowing what they can reach. GitLab's own issue tracker puts it"
        " plainly — an actor with this cookie 'is able to gain access to the"
        " user's account and impersonate them'. It leaks the way session"
        " cookies always leak: pasted 'Cookie:' headers in bug reports,"
        " captured HAR files, curl reproductions and browser-devtools dumps."
    ),
    provider="gitlab",
    severity="high",
    # The optional leading segment is GitLab's configurable session-cookie
    # token prefix — gitlab_rails['session_store_session_cookie_token_prefix'],
    # empty by default, which GitLab.com's Cells work sets per cell (the
    # published example is 'cell2-'). Omitting it would MISS every value on a
    # prefixed deployment, so the shape allows up to 24 leading
    # [A-Za-z0-9_-] characters and then requires the real body.
    #
    # The body is exactly 32 lowercase hex characters. The trailing negative
    # lookahead means a longer hex run cannot be silently truncated into a
    # 32-character "match" — the greedy prefix backtracks so the span is the
    # whole value.
    #
    # No entropy gate: the literal cookie name carries all the precision, and
    # any floor high enough to reject a placeholder would sink real session
    # ids first.
    # Source: https://gitlab.com/gitlab-com/gl-infra/production-engineering/-/issues/25621
    regex=re.compile(
        r"_gitlab_session="
        r"(?P<secret>[A-Za-z0-9_-]{0,24}[0-9a-f]{32})"
        r"(?![0-9a-f])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # the literal cookie name carries the precision
    context_keywords=[
        "gitlab",
        "cookie",
        "session",
        "_gitlab_session",
        "Set-Cookie",
    ],
    known_test_values={
        # Hex masks — how a redacted 'Cookie:' header, a docs example or a
        # HAR scrubber renders this value. Note the catalogue placeholder
        # 'xxxx…' cannot reach here at all: 'x' is not a hex character, so
        # the body class rejects it before scoring. confidence_base 0.95 sits
        # above the 0.85 FP-wordlist gate (scanner.py:197), so the wordlist
        # never prices these down; they are pinned here and land at ~0.15.
        "0" * 32,
        "a" * 32,
        "f" * 32,
        "0123456789abcdef" * 2,
        "deadbeef" * 4,
    },
    recommendation=(
        "Treat the account as compromised for the whole window the cookie was"
        " public. Sign out every active session immediately — in GitLab under"
        " User Settings > Active Sessions, revoking all of them, not just the"
        " one you recognise — and rotate the account password, which"
        " invalidates the session server-side rather than merely dropping the"
        " browser's copy. There is nothing to 'revoke' the way a token is"
        " revoked: the cookie is the session. Then check Active Sessions and"
        " the audit events for IPs and devices you do not recognise, and"
        " rotate any personal access token, SSH key or CI/CD variable that"
        " account could have read while the session was live. Scrub the"
        " carrier too — a cookie pasted into an issue, a HAR attachment or a"
        " curl reproduction stays readable in history after the session dies."
    ),
    tags=["vcs", "gitlab", "session", "cookie"],
)


# ===================================================
# GITHUB OAUTH REFRESH TOKEN
# ===================================================

GITHUB_OAUTH_REFRESH_TOKEN = SecretPattern(
    id="github_oauth_refresh_token",
    name="GitHub OAuth Refresh Token",
    description=(
        "GitHub OAuth refresh token — the literal 'ghr_' prefix followed by"
        " 36 alphanumeric characters. Issued to GitHub Apps that have user"
        " token expiration enabled, beside the 'ghu_' user-to-server token,"
        " and exchanged for a fresh user token without the user present."
        " Severity is critical for the reason it is on any refresh token: it"
        " outlives the 8-hour user token it renews, so a leaked one is"
        " durable access to everything that user granted the app until the"
        " authorization is revoked. Completes the 'gh*_' family already"
        " registered here — ghp_, gho_, ghu_, ghs_ and github_pat_."
    ),
    provider="github",
    severity="critical",
    # The 'ghr_' prefix and the 36-character alphanumeric body follow the
    # same generator shape as the rest of GitHub's 2021 prefixed token
    # family: a role-naming four-character prefix and a fixed-width random
    # body. Registered as its own pattern rather than folded into a prefix
    # alternation so the finding names the token's role — a refresh token is
    # a longer-lived exposure than the user token it renews, and the
    # recommendation differs.
    #
    # No entropy gate: 'ghr_' is a vendor-unique anchor and the body is a
    # fixed-width random run, so any floor a placeholder failed would also
    # sink real tokens.
    # Source: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"(?P<secret>ghr_[0-9A-Za-z]{36})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,  # vendor-unique prefix + fixed-width random body
    context_keywords=[
        "github",
        "refresh_token",
        "GITHUB_TOKEN",
        "oauth",
        "github app",
    ],
    known_test_values={
        # Single-character masks — the redaction shape GitHub's own docs use.
        # confidence_base 0.97 is above the 0.85 FP-wordlist gate, so they are
        # pinned here rather than priced down by the wordlist. Assembled by
        # concatenation so no scannable literal exists in source — GitHub's
        # partner scanner recognises this prefix.
        "ghr_" + "x" * 36,
        "ghr_" + "X" * 36,
        "ghr_" + "0" * 36,
    },
    recommendation=(
        "Revoke the app's authorization for the affected user — the user can"
        " do it under Settings > Applications > Authorized GitHub Apps, and an"
        " app owner can call the OAuth token-revocation API — which"
        " invalidates the refresh token and the user token minted from it"
        " together. Do not wait for the user token to expire: the refresh"
        " token renews it indefinitely. Then re-run the authorization flow,"
        " and audit the user's repository, package and Actions activity for"
        " the exposure window against the scopes the app holds."
    ),
    tags=["vcs", "github", "oauth", "auth"],
)


# ===================================================
# BITBUCKET ACCESS TOKEN — 'ATCTT' (2026-09-14)
# ===================================================

# Bitbucket Cloud repository / project / workspace ACCESS TOKENS. They sit in
# the same Atlassian token envelope as the account API token that
# ATLASSIAN_API_TOKEN (identity.py) already detects — a fixed twelve-character
# head, then a base64url-style body closed by '=' plus an eight-character
# checksum, 192 characters in total — but the head is 'ATCTT3xFfGN0' where
# the account API token's is 'ATATT3xFfGF0'. Neither the existing Atlassian
# pattern nor the context-gated BITBUCKET_APP_PASSWORD recognises this family,
# so before this pattern a leaked access token surfaced only as a generic
# catch-all finding.
#
# THE EVIDENCE IS EMPIRICAL AND IS LABELLED AS SUCH. Atlassian's pages publish
# neither the prefix nor the length. The twelve-character head is a literal
# seen on every observed value, and the 192-character total was measured on
# real public values (41 of 48 were exactly 192; the rest were truncations or
# elisions). None of those values is cited, linked or copied — every literal
# in tests and corpus is synthetic.
#
# The regex deliberately mirrors ATLASSIAN_API_TOKEN's structure — the same
# [A-Za-z0-9_=-] body charset and the same right guard — with the head
# substituted and the body width reduced by the six extra literal head
# characters (192 - 12 = 180), so the two siblings stay consistent. A left
# guard is added so the head is never carved out of a longer token; it does
# NOT exclude '=', so 'BITBUCKET_TOKEN=ATCTT…' still detects.
#
# Severity critical: a repository or workspace access token can push code,
# read private source and, depending on its scopes, administer pipelines.

BITBUCKET_ACCESS_TOKEN = SecretPattern(
    id="bitbucket_access_token",
    name="Bitbucket Access Token",
    description=(
        "Bitbucket Cloud repository, project or workspace access token — the"
        " literal 'ATCTT3xFfGN0' head followed by 180 characters of"
        " [A-Za-z0-9_=-], 192 characters in total, in the same envelope as an"
        " Atlassian 'ATATT3' API token. Authenticates git and REST API calls"
        " with the scopes it was created with."
    ),
    provider="bitbucket",
    severity="critical",
    # Head and 192-character width measured on real public values (41 of 48
    # exactly 192); Atlassian publishes neither. None is cited or copied.
    # Independently authored — structural analysis consistent with Atlassian's ATATT token envelope
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>ATCTT3xFfGN0[A-Za-z0-9_\-=]{180})"
        r"(?![A-Za-z0-9_\-=])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.5,  # mirrors ATLASSIAN_API_TOKEN; real bodies sit near 5.9
    context_keywords=[
        "bitbucket",
        "atlassian",
        "access_token",
        "BITBUCKET_ACCESS_TOKEN",
        "x-token-auth",
        "ATCTT3",
    ],
    known_test_values={
        # Single-character fills are how a redacted token gets written down.
        # Built by concatenation so no contiguous token literal is committed.
        "ATCTT3" + "xFfGN0" + "X" * 180,
        "ATCTT3" + "xFfGN0" + "x" * 180,
        "ATCTT3" + "xFfGN0" + "0" * 180,
    },
    recommendation=(
        "Revoke this access token in Bitbucket Cloud (Repository, Project or"
        " Workspace settings > Security > Access tokens), then create a"
        " replacement with only the scopes it needs and update the CI"
        " variables, git remotes ('x-token-auth') and deploy scripts that"
        " present it. Audit the repository's push, pull-request and pipeline"
        " history for the exposure window: an access token acts as its own"
        " bot user and can push code and read private source."
    ),
    tags=["vcs", "bitbucket", "atlassian", "auth"],
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
    CRATES_IO_API_TOKEN,
    BLOCK_PROTOCOL_API_KEY,
    # 2026-08-31 — GitLab CI/CD job token ('glcbt-') and the GitHub OAuth
    # refresh token ('ghr_'), completing the 'gh*_' prefix family.
    GITLAB_CICD_JOB_TOKEN,
    GITHUB_OAUTH_REFRESH_TOKEN,
    # 2026-09-06 — the legacy GitLab runner REGISTRATION token ('GR1348941'),
    # the deprecated counterpart to GITLAB_RUNNER_AUTHENTICATION_TOKEN.
    GITLAB_RUNNER_REGISTRATION_TOKEN,
    # 2026-09-08 — GitLab's Rails session cookie, anchored on the literal
    # first-party cookie name '_gitlab_session=' rather than a token prefix.
    GITLAB_SESSION_COOKIE,
    # 2026-09-14 — Bitbucket Cloud access token ('ATCTT3xFfGN0' + 180 of
    # [A-Za-z0-9_=-]; the access-token sibling of Atlassian's ATATT3 token).
    BITBUCKET_ACCESS_TOKEN,
)
