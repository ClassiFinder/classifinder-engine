"""
ClassiFinder — DevOps, CI/CD, Observability & Security Patterns (Batch 4 Part 2)

Patterns for DevOps platforms (Databricks, Dynatrace, LaunchDarkly, Harness,
Octopus Deploy, Fastly, Gitea, Travis CI, Prefect, Infracost, Sumo Logic) and
security tooling (Snyk, SonarQube, Sourcegraph).

Pattern design notes:
- Prefix-anchored where possible (Databricks dapi, Dynatrace dt0c01., Harness
  pat./sat., Octopus API-, Prefect pnu_, Infracost ico-, Sonar squ_/sqp_/sqa_,
  Sourcegraph sgp_).
- Context-gated for providers whose tokens are bare alphanumeric strings
  (LaunchDarkly, Fastly, Gitea, Travis CI, Sumo Logic, Snyk).
- Body shapes from Betterleaks MIT cmd/generate/config/rules/*.go.
- All test fixtures use clearly-synthetic patterns (sequential alphabets,
  repeated chars) to avoid triggering external secret scanners — see
  classifinder-knowledge/tasks/2026-05-21-audit-test-fixtures-for-realistic-tokens.md.
"""

import re

from .registry import SecretPattern, register

# ===================================================
# DATABRICKS
# ===================================================

DATABRICKS_API_TOKEN = SecretPattern(
    id="databricks_api_token",
    name="Databricks API Token",
    description=(
        "Databricks personal access token with dapi prefix (32 hex chars + optional -N suffix)."
        " Used to authenticate against Databricks workspace APIs for jobs, clusters, and notebooks."
    ),
    provider="databricks",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/databricks.go) — dapi prefix.
    regex=re.compile(
        r"(?P<secret>dapi[a-f0-9]{32}(?:-\d)?)"
        r"(?![a-f0-9\-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["databricks", "DATABRICKS_TOKEN", "dapi"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Databricks PAT in the workspace UI under User Settings > Access tokens."
        " Audit recent jobs and notebook runs — compromised tokens grant broad workspace access."
    ),
    tags=["devops", "databricks", "data"],
)


# ===================================================
# DYNATRACE
# ===================================================

DYNATRACE_API_TOKEN = SecretPattern(
    id="dynatrace_api_token",
    name="Dynatrace API Token",
    description=(
        "Dynatrace API token with dt0c01. prefix (24-char public + 64-char private parts)."
        " Used to authenticate against Dynatrace's observability APIs."
    ),
    provider="dynatrace",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/dynatrace.go) — dt0c01. prefix.
    regex=re.compile(
        r"(?P<secret>dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64})"
        r"(?![a-z0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["dynatrace", "DT_API_TOKEN", "dt0c01"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Dynatrace token in the environment settings under"
        " Access tokens. Audit recent API activity for compromised data exposure."
    ),
    tags=["devops", "dynatrace", "observability"],
)


# ===================================================
# LAUNCHDARKLY
# ===================================================

LAUNCHDARKLY_ACCESS_TOKEN = SecretPattern(
    id="launchdarkly_access_token",
    name="LaunchDarkly Access Token",
    description=(
        "LaunchDarkly access token (40 alphanumeric/special chars, context-gated)."
        " Grants programmatic access to manage feature flags."
    ),
    provider="launchdarkly",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/launchdarkly.go) — context-gated.
    # LaunchDarkly tokens are bare 40-char alphanumeric — context required.
    regex=re.compile(
        r"(?:"
        r"(?:LAUNCHDARKLY[_-]?(?:TOKEN|API[_-]?KEY|ACCESS[_-]?TOKEN)|launchdarkly.*token|launchdarkly.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9._\-]{40})"
        r"(?![A-Za-z0-9._\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=3.5,
    context_keywords=["launchdarkly", "feature_flag", "ld_token"],
    known_test_values=set(),
    recommendation=(
        "Revoke this LaunchDarkly access token in the dashboard under Account Settings > Authorization."
    ),
    tags=["devops", "launchdarkly", "feature-flag"],
)


# ===================================================
# HARNESS
# ===================================================

HARNESS_API_KEY = SecretPattern(
    id="harness_api_key",
    name="Harness API Key (PAT/SAT)",
    description=(
        "Harness Personal Access Token (pat.) or Service Account Token (sat.) with"
        " 4-part structure: prefix.22chars.24hex.20chars. Used for Harness CI/CD APIs."
    ),
    provider="harness",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/harness.go) — pat./sat. prefix.
    regex=re.compile(
        r"(?P<secret>(?:pat|sat)\.[a-zA-Z0-9_\-]{22}\.[0-9a-f]{24}\.[a-zA-Z0-9]{20})"
        r"(?![a-zA-Z0-9._\-])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["harness", "HARNESS_API_KEY", "HARNESS_TOKEN"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Harness API key in the Harness platform under Account Settings > Access Management."
    ),
    tags=["devops", "harness", "ci-cd"],
)


# ===================================================
# OCTOPUS DEPLOY
# ===================================================

OCTOPUS_DEPLOY_API_KEY = SecretPattern(
    id="octopus_deploy_api_key",
    name="Octopus Deploy API Key",
    description=(
        "Octopus Deploy API key with API- prefix (26 uppercase alphanumeric chars)."
        " Used to automate Octopus Deploy CI/CD operations."
    ),
    provider="octopus",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/octopusdeploy.go) — API- prefix.
    regex=re.compile(
        r"(?P<secret>API-[A-Z0-9]{26})"
        r"(?![A-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.93,
    entropy_threshold=3.0,
    context_keywords=["octopus", "octopusdeploy", "OCTOPUS_API_KEY", "apikey"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Octopus Deploy API key in the user profile under"
        " API Keys. Audit recent deployment activity."
    ),
    tags=["devops", "octopus", "ci-cd"],
)


# ===================================================
# FASTLY
# ===================================================

FASTLY_API_TOKEN = SecretPattern(
    id="fastly_api_token",
    name="Fastly API Token",
    description=(
        "Fastly API token (32 alphanumeric-extended chars, context-gated)."
        " Used to authenticate against Fastly's CDN/edge APIs."
    ),
    provider="fastly",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/fastly.go) — context-gated 32-char.
    regex=re.compile(
        r"(?:"
        r"(?:FASTLY[_-]?(?:TOKEN|API[_-]?KEY)|fastly.*token|fastly.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9._\-]{32})"
        r"(?![A-Za-z0-9._\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=3.5,
    context_keywords=["fastly", "cdn", "edge"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Fastly token in the dashboard under Account > API Tokens."
    ),
    tags=["devops", "fastly", "cdn"],
)


# ===================================================
# GITEA
# ===================================================

GITEA_ACCESS_TOKEN = SecretPattern(
    id="gitea_access_token",
    name="Gitea Access Token",
    description=(
        "Gitea access token (40 hex chars, context-gated near gitea keyword)."
        " Used to authenticate against self-hosted Gitea Git repositories."
    ),
    provider="gitea",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/gitea.go) — context-gated 40-hex.
    regex=re.compile(
        r"(?:"
        r"(?:gitea[_.-]?(?:token|key|secret|access)|GITEA_TOKEN)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{40})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=3.0,
    context_keywords=["gitea"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Gitea access token in user settings under Applications."
    ),
    tags=["devops", "gitea", "vcs"],
)


# ===================================================
# TRAVIS CI
# ===================================================

TRAVISCI_ACCESS_TOKEN = SecretPattern(
    id="travisci_access_token",
    name="Travis CI Access Token",
    description=(
        "Travis CI access token (22 alphanumeric chars, context-gated near travis keyword)."
    ),
    provider="travisci",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/travisci.go) — context-gated 22-char.
    regex=re.compile(
        r"(?:"
        r"(?:TRAVIS[_-]?(?:TOKEN|API[_-]?KEY)|travis.*token|travis.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9]{22})"
        r"(?![A-Za-z0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.5,
    context_keywords=["travis", "travisci"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Travis CI token in user settings under Settings > Access Tokens."
    ),
    tags=["devops", "travisci", "ci"],
)


# ===================================================
# PREFECT
# ===================================================

PREFECT_API_TOKEN = SecretPattern(
    id="prefect_api_token",
    name="Prefect API Token",
    description=(
        "Prefect API token with pnu_ prefix (36 alphanumeric chars)."
        " Used to authenticate against Prefect Cloud workflow orchestration APIs."
    ),
    provider="prefect",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/prefect.go) — pnu_ prefix.
    regex=re.compile(
        r"(?P<secret>pnu_[a-zA-Z0-9]{36})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["prefect", "PREFECT_API_KEY", "PREFECT_API_TOKEN", "pnu"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Prefect API token in Prefect Cloud under Settings > API Keys."
    ),
    tags=["devops", "prefect", "workflow"],
)


# ===================================================
# INFRACOST
# ===================================================

INFRACOST_API_TOKEN = SecretPattern(
    id="infracost_api_token",
    name="Infracost API Token",
    description=(
        "Infracost API token with ico- prefix (32 alphanumeric chars)."
        " Used to authenticate Infracost cost-estimation CLI/API."
    ),
    provider="infracost",
    severity="medium",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/infracost.go) — ico- prefix.
    regex=re.compile(
        r"(?P<secret>ico-[a-zA-Z0-9]{32})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.93,
    entropy_threshold=3.0,
    context_keywords=["infracost", "INFRACOST_API_KEY", "ico-"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Infracost token at infracost.io under Org Settings > API."
    ),
    tags=["devops", "infracost", "iac"],
)


# ===================================================
# SUMO LOGIC
# ===================================================

SUMOLOGIC_ACCESS_ID = SecretPattern(
    id="sumologic_access_id",
    name="Sumo Logic Access ID",
    description=(
        "Sumo Logic access ID (su prefix + 12 alphanumeric chars, context-gated)."
        " Not strictly secret alone, but typically found alongside access tokens."
    ),
    provider="sumologic",
    severity="medium",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/sumologic.go) — context-gated.
    regex=re.compile(
        r"(?:"
        r"(?:SUMO[_-]?(?:LOGIC[_-]?)?(?:ACCESS[_-]?ID|ID)|sumo.*access.*id|sumo.*id)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>su[a-zA-Z0-9]{12})"
        r"(?![a-zA-Z0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.0,
    context_keywords=["sumo", "sumologic"],
    known_test_values=set(),
    recommendation=(
        "Rotate the associated access key in Sumo Logic under"
        " Administration > Security > Access Keys."
    ),
    tags=["devops", "sumologic", "logs"],
)


SUMOLOGIC_ACCESS_TOKEN = SecretPattern(
    id="sumologic_access_token",
    name="Sumo Logic Access Token",
    description=(
        "Sumo Logic access token (64 alphanumeric chars, context-gated near sumo keyword)."
    ),
    provider="sumologic",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/sumologic.go) — context-gated 64-char.
    regex=re.compile(
        r"(?:"
        r"(?:SUMO[_-]?(?:LOGIC[_-]?)?(?:ACCESS[_-]?TOKEN|TOKEN|KEY)|sumo.*access.*key|sumo.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9]{64})"
        r"(?![A-Za-z0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=3.5,
    context_keywords=["sumo", "sumologic"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Sumo Logic access key in Administration > Security > Access Keys."
    ),
    tags=["devops", "sumologic", "logs"],
)


# ===================================================
# BATCH 4 PART 2.2 — Security tooling
# ===================================================

SNYK_API_TOKEN = SecretPattern(
    id="snyk_api_token",
    name="Snyk API Token",
    description=(
        "Snyk API token (UUID format, context-gated near snyk keyword)."
        " Used to authenticate against Snyk vulnerability scanning APIs."
    ),
    provider="snyk",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/snyk.go) — context-gated UUID.
    regex=re.compile(
        r"(?:"
        r"(?:SNYK[_-]?(?:TOKEN|API[_-]?(?:TOKEN|KEY)|OAUTH[_-]?KEY)|snyk.*token|snyk.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
        r"(?![0-9a-fA-F\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=["snyk"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Snyk API token in Account Settings > General > Authentication."
    ),
    tags=["security", "snyk", "scanning"],
)


SONAR_API_TOKEN = SecretPattern(
    id="sonar_api_token",
    name="SonarQube/Sonar API Token",
    description=(
        "SonarQube/Sonar API token with squ_ (user) / sqp_ (project) / sqa_ (application) prefix."
        " 40 alphanumeric chars after the 4-char prefix. Used for Sonar code-quality APIs."
    ),
    provider="sonar",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/sonar.go) — squ_/sqp_/sqa_ prefixes.
    regex=re.compile(
        r"(?P<secret>(?:squ_|sqp_|sqa_)[a-zA-Z0-9]{40})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["sonar", "sonarqube", "SONAR_TOKEN", "SONAR_LOGIN"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Sonar token in user account under Security > User Tokens."
    ),
    tags=["security", "sonar", "code-quality"],
)


SOURCEGRAPH_ACCESS_TOKEN = SecretPattern(
    id="sourcegraph_access_token",
    name="Sourcegraph Access Token",
    description=(
        "Sourcegraph access token with sgp_ prefix (multiple shape variants)."
        " Used to authenticate against Sourcegraph code search APIs."
    ),
    provider="sourcegraph",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/sourcegraph.go) — sgp_ prefix.
    # Two BL variants captured: sgp_<16-hex-or-local><40-hex>, and sgp_<40-hex>.
    regex=re.compile(
        r"(?P<secret>sgp_(?:[a-fA-F0-9]{16}|local)[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})"
        r"(?![a-fA-F0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["sourcegraph", "sgp_"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Sourcegraph access token in User Settings > Access tokens."
    ),
    tags=["security", "sourcegraph", "code-search"],
)


# ===================================================
# KUBERNETES SECRET YAML
# ===================================================
# Multi-line context pattern — fundamentally different shape from prefix-anchored
# token regex. Matches inline Kubernetes Secret manifests in YAML files (committed
# to git, present in Helm charts, in-line in CI config). The data: block contains
# base64-encoded credentials by Kubernetes convention; Phase 1 captures the first
# base64 value as the "secret" group for finding/redaction purposes (the goal is
# to surface that the manifest exists, not to enumerate every value).
#
# FP tuning: charset [A-Za-z0-9+/] excludes Helm template chars ({, }, ., space)
# so {{ .Values.X | b64enc }} doesn't fire. Entropy threshold 4.0 demotes
# low-entropy values like 'aaaaaa' or 'changeme' below the default surface
# threshold. ConfigMap and other non-Secret kinds don't match because of the
# trailing whitespace requirement after "Secret".
#
# Deferred to a future task: file-extension constraint (.yaml/.yml only),
# explicit Helm template allowlist, multi-value extraction.

KUBERNETES_SECRET_YAML = SecretPattern(
    id="kubernetes_secret_yaml",
    name="Kubernetes Secret (inline YAML manifest)",
    description=(
        "Inline Kubernetes Secret manifest with base64-encoded data values."
        " Found in committed YAML files, Helm charts, kustomize bases, and CI"
        " configs. Indicates credentials checked into git rather than mounted"
        " via an external secret store."
    ),
    provider="kubernetes",
    severity="high",
    # kind: Secret + within 200 chars + data: + base64 value >=10 chars.
    # The {0,200} bound prevents runaway matching across unrelated manifests.
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/kubernetes.go) — kind:Secret + data: shape.
    regex=re.compile(
        r"kind:\s*[\"']?Secret[\"']?\s+"
        r"(?s:.{0,200}?)"
        r"data:\s*"
        r"[\s\S]*?(?P<secret>[A-Za-z0-9+/]{10,}={0,2})",
        re.MULTILINE,
    ),
    confidence_base=0.65,
    entropy_threshold=4.0,
    context_keywords=[
        "kubernetes",
        "secret",
        "k8s",
        "kubectl",
        "manifest",
        "apiVersion",
        "metadata",
    ],
    known_test_values=set(),
    recommendation=(
        "Move credentials out of the committed YAML. Use sealed-secrets,"
        " external-secrets-operator, SOPS, or the cluster's CSI secret driver."
        " Committed Kubernetes Secrets are base64-encoded, not encrypted —"
        " anyone with repo read access can decode them."
    ),
    tags=["devops", "kubernetes", "yaml", "manifest"],
)


# ===================================================
# TAILSCALE
# ===================================================

TAILSCALE_API_KEY = SecretPattern(
    id="tailscale_api_key",
    name="Tailscale API Key",
    description=(
        "Tailscale key with the 'tskey-' prefix and a typed segment"
        " (e.g. 'tskey-api-', 'tskey-auth-') followed by an id and secret part."
        " Grants programmatic control over a Tailscale tailnet."
    ),
    provider="tailscale",
    severity="high",
    # Format per Tailscale key-prefix reference (tskey-<type>-<id>-<secret>):
    #   https://tailscale.com/kb/1277/key-prefixes
    # Independently authored from the documented 'tskey-' prefix structure.
    regex=re.compile(
        r"(?P<secret>tskey-[a-z]+-[0-9A-Za-z_]+-[0-9A-Za-z_]+)"
        r"(?![0-9A-Za-z_])",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=["tailscale", "tskey", "tailnet", "TS_API_KEY"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Tailscale admin console under Settings > Keys."
    ),
    tags=["devops", "tailscale", "networking"],
)


# ===================================================
# README (readme.com)
# ===================================================

README_API_KEY = SecretPattern(
    id="readme_api_key",
    name="ReadMe API Key",
    description=(
        "ReadMe (readme.com) API key with the 'rdme_' prefix followed by 70"
        " lowercase-hex-style characters. Grants access to ReadMe's developer"
        " documentation management API."
    ),
    provider="readme",
    severity="medium",
    # Format per ReadMe API authentication docs ('rdme_' prefix + fixed body):
    #   https://docs.readme.com/main/reference/intro/authentication
    # Independently authored from the documented 'rdme_' prefix + 70-char body.
    regex=re.compile(
        r"(?P<secret>rdme_[a-z0-9]{70})(?![a-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=["readme", "rdme", "README_API_KEY"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the ReadMe dashboard under Configuration > API Keys."
    ),
    tags=["devops", "readme", "docs"],
)


# ===================================================
# TELNYX
# ===================================================

TELNYX_API_KEY = SecretPattern(
    id="telnyx_api_key",
    name="Telnyx API Key",
    description=(
        "Telnyx API v2 key beginning with 'KEY' followed by 55 token characters."
        " The bare 'KEY' prefix is weakly distinctive, so this pattern is"
        " context-gated: it only fires when a Telnyx keyword precedes the value."
        " Grants access to Telnyx voice, messaging, and number APIs."
    ),
    provider="telnyx",
    severity="high",
    # Format per Telnyx API authentication docs (v2 keys begin with 'KEY'):
    #   https://developers.telnyx.com/docs/api/v2/overview
    # Independently authored — context-gated because the bare 'KEY' prefix is
    # low-entropy and high-FP without a nearby telnyx keyword.
    regex=re.compile(
        r"(?:"
        r"(?:TELNYX[_-]?(?:API[_-]?KEY|KEY|TOKEN)|telnyx.*key|telnyx.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>KEY[0-9A-Za-z_-]{55})"
        r"(?![0-9A-Za-z_-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=3.5,
    context_keywords=["telnyx", "TELNYX_API_KEY", "messaging", "voice"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Telnyx portal under Auth > API Keys and rotate it."
    ),
    tags=["devops", "telnyx", "comms"],
)


# ===================================================
# DEFINED NETWORKING (Batch 8 — 2026-06-22)
# ===================================================

DEFINED_NETWORKING_API_TOKEN = SecretPattern(
    id="defined_networking_api_token",
    name="Defined Networking API Token",
    description=(
        "Defined Networking API token with the 'dnkey-' prefix followed by the"
        " token body. Grants programmatic control over a Defined Networking"
        " (Nebula-based) network."
    ),
    provider="defined_networking",
    severity="high",
    # Source: https://docs.defined.net/guides/rotating-api-keys/
    regex=re.compile(
        r"(?P<secret>dnkey-[A-Za-z0-9]{20,60})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=["defined", "dnkey", "DN_API_TOKEN", "defined.net"],
    known_test_values={
        "dnkey-AbCdEfGhIjKlMnOpQrStUvWx",
    },
    recommendation=(
        "Revoke this token in the Defined Networking admin panel under API Keys"
        " and rotate it."
    ),
    tags=["devops", "defined_networking", "networking"],
)


register(
    # Part 2.1 — DevOps / CI-CD / Observability
    DATABRICKS_API_TOKEN,
    DYNATRACE_API_TOKEN,
    LAUNCHDARKLY_ACCESS_TOKEN,
    HARNESS_API_KEY,
    OCTOPUS_DEPLOY_API_KEY,
    FASTLY_API_TOKEN,
    GITEA_ACCESS_TOKEN,
    TRAVISCI_ACCESS_TOKEN,
    PREFECT_API_TOKEN,
    INFRACOST_API_TOKEN,
    SUMOLOGIC_ACCESS_ID,
    SUMOLOGIC_ACCESS_TOKEN,
    # Part 2.2 — Security tooling
    SNYK_API_TOKEN,
    SONAR_API_TOKEN,
    SOURCEGRAPH_ACCESS_TOKEN,
    # Part 2.1 follow-up — multi-line context detector
    KUBERNETES_SECRET_YAML,
    # Batch 7 — networking / dev tooling / comms infra (2026-06-18)
    TAILSCALE_API_KEY,
    README_API_KEY,
    TELNYX_API_KEY,
    # Batch 8 — vendor-sourced patterns (2026-06-22)
    DEFINED_NETWORKING_API_TOKEN,
)
