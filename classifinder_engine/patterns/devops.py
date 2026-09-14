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


# ===================================================
# ADAFRUIT IO (Batch 9 — 2026-06-29; regex corrected from invented 'aio_' prefix)
# ===================================================

ADAFRUIT_IO_KEY = SecretPattern(
    id="adafruit_io_key",
    name="Adafruit IO Key",
    description=(
        "Adafruit IO (AIO) API key — a 32-character lowercase-hex string (a"
        " UUIDv4 with dashes stripped) presented via the 'X-AIO-Key' HTTP header,"
        " 'x-aio-key' query param, or an 'AIO_KEY' env var. The value carries no"
        " distinctive prefix, so this detector is context-gated: it only fires"
        " when an Adafruit IO key label sits immediately before the value. Grants"
        " full read/write access to an account's feeds, dashboards, and connected"
        " IoT devices."
    ),
    provider="adafruit_io",
    severity="high",
    # Format per https://io.adafruit.com/api/docs/ and the 2016 key-length
    # changelog https://io.adafruit.com/blog/changelog/2016/03/22/key-length/ :
    # AIO keys are 32-char lowercase hex (UUIDv4 with dashes stripped), supplied
    # via the X-AIO-Key header / x-aio-key query param — there is no 'aio_'
    # prefix. A bare 32-hex string is MD5-shaped and high-FP on its own, so the
    # regex requires an adjacent AIO / X-AIO-Key / ADAFRUIT key label.
    # Format per io.adafruit.com docs (URLs above); confidence_base 0.60.
    regex=re.compile(
        r"(?:"
        r"(?:X-AIO-Key|AIO[_-]?KEY|ADAFRUIT[_-]?(?:IO[_-]?)?(?:KEY|TOKEN))"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.60,  # format-only — value has no distinctive prefix
    entropy_threshold=3.0,  # penalize low-entropy 32-hex (e.g. all-zeros)
    context_keywords=[
        "adafruit",
        "aio",
        "x-aio-key",
        "AIO_KEY",
        "adafruit.io",
        "io.adafruit.com",
    ],
    known_test_values={
        # Synthetic, sequential hex — not a live key.
        "00112233445566778899aabbccddeeff",
    },
    recommendation=(
        "Revoke this key in Adafruit IO under My Key (regenerate) and rotate it"
        " in any connected devices. Compromised AIO keys grant full account access."
    ),
    tags=["devops", "adafruit_io", "iot"],
)


# ===================================================
# NGROK (Batch 10 — 2026-07-06; context-gated)
# ===================================================

NGROK_AUTHTOKEN = SecretPattern(
    id="ngrok_authtoken",
    name="ngrok Authtoken",
    description=(
        "ngrok agent authtoken — two base62 segments joined by a single"
        " underscore (~27 + 1 + ~21 chars). The value carries no reliable"
        " leading anchor, so this detector is context-gated: it only fires when"
        " an ngrok / authtoken label sits immediately before the value (e.g."
        " 'ngrok config add-authtoken <token>', 'NGROK_AUTHTOKEN=<token>', or"
        " 'authtoken: <token>'). Grants control of the account's tunnels."
    ),
    provider="ngrok",
    severity="high",
    # Format per https://ngrok.com/docs/agent/ : the authtoken is two base62
    # segments joined by a single underscore. There is no documented stable
    # leading anchor, so a bare token is high-FP; the regex requires an adjacent
    # ngrok / add-authtoken / NGROK_AUTHTOKEN / authtoken label. confidence_base
    # 0.60 (format-only, context-gated).
    # Format per https://ngrok.com/docs/agent/
    regex=re.compile(
        r"(?:"
        r"NGROK[_-]?AUTHTOKEN|add-authtoken|authtoken|ngrok"
        r")"
        r"[\s]*[=:\"'\s]+"
        r"(?P<secret>[0-9A-Za-z]{22,27}_[0-9A-Za-z]{18,24})"
        r"(?![0-9A-Za-z_])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.60,  # format-only — value has no distinctive prefix
    entropy_threshold=3.0,
    context_keywords=["ngrok", "authtoken", "NGROK_AUTHTOKEN", "add-authtoken"],
    known_test_values={
        # Synthetic, sequential base62 — not a live token.
        "AbCdEfGhIjKlMnOpQrStUvWxYz" + "_" + "0123456789AbCdEfGhIj",
    },
    recommendation=(
        "Revoke this authtoken in the ngrok dashboard under Your Authtoken and"
        " rotate it in every agent config / CI environment that used it."
    ),
    tags=["devops", "ngrok", "networking"],
)


# ===================================================
# OPSGENIE (Batch 10 — 2026-07-06; context-gated UUID)
# ===================================================

OPSGENIE_API_KEY = SecretPattern(
    id="opsgenie_api_key",
    name="Opsgenie API Key",
    description=(
        "Atlassian Opsgenie API key — a canonical hex UUID v4. A bare UUID is"
        " extremely high-FP, so this detector is context-gated: it only fires"
        " when the 'GenieKey' auth-scheme label (the Authorization header prefix)"
        " or an opsgenie API host sits immediately before the value. Grants"
        " access to Opsgenie alerts, schedules, and incident data."
    ),
    provider="opsgenie",
    severity="high",
    # Format per https://support.atlassian.com/opsgenie/docs/api-key-management/ :
    # the API key is a hex UUID passed via 'Authorization: GenieKey <uuid>'. A
    # bare UUID is high-FP, so the regex requires the GenieKey auth-scheme label
    # (primary) or an opsgenie API host. confidence_base 0.60 (context-gated).
    # Format per https://support.atlassian.com/opsgenie/docs/api-key-management/
    regex=re.compile(
        r"(?:"
        r"GenieKey|opsgenie|api\.opsgenie\.com|api\.eu\.opsgenie\.com"
        r")"
        r"[\s]*[=:\"'/\s]+"
        r"(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        r"(?![0-9a-f])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.60,  # context-gated bare UUID
    entropy_threshold=0.0,
    context_keywords=[
        "GenieKey",
        "opsgenie",
        "api.opsgenie.com",
        "api.eu.opsgenie.com",
    ],
    known_test_values={
        # Synthetic UUID — not a live key.
        "00112233-4455-6677-8899-aabbccddeeff",
    },
    recommendation=(
        "Revoke this API key in Opsgenie under Settings > API key management and"
        " issue a replacement for the integration that used it."
    ),
    tags=["devops", "opsgenie", "incident"],
)


# ===================================================
# CLOJARS (Batch 10 — 2026-07-06; prefix-anchored)
# ===================================================

CLOJARS_DEPLOY_TOKEN = SecretPattern(
    id="clojars_deploy_token",
    name="Clojars Deploy Token",
    description=(
        "Clojars deploy token — the 'CLOJARS_' prefix followed by exactly 60"
        " lowercase-hex characters. Used to publish (deploy) Clojure/Java"
        " artifacts to the Clojars repository. Prefix-anchored; leaking one"
        " lets an attacker push malicious releases under the owner's groups."
    ),
    provider="clojars",
    severity="high",
    # Format per https://github.com/clojars/clojars-web/blob/main/src/clojars/db.clj
    # (vendor source; validation regex ^CLOJARS_[0-9a-f]{60}$). Independently
    # authored — 'CLOJARS_' prefix + exactly 60 lowercase-hex chars, bounded so
    # it does not over-capture. confidence_base 0.95 (prefix-anchored).
    # Format per https://github.com/clojars/clojars-web/blob/main/src/clojars/db.clj
    regex=re.compile(
        r"CLOJARS_(?P<secret>[0-9a-f]{60})(?![0-9a-f])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["clojars", "deploy", "CLOJARS_", "lein", "deps.edn"],
    known_test_values={
        # The captured secret is the 60 hex chars after the 'CLOJARS_' prefix.
        # Synthetic, sequential hex — not a live token.
        "0123456789abcdef" * 3 + "0123456789ab",
    },
    recommendation=(
        "Revoke this deploy token in Clojars under Dashboard > Deploy Tokens and"
        " generate a new one for the affected CI / publishing pipeline."
    ),
    tags=["devops", "clojars", "package"],
)


# ===================================================
# DOCKER (Batch 12 — 2026-07-13; prefix-anchored)
# ===================================================

DOCKER_ACCESS_TOKEN = SecretPattern(
    id="docker_access_token",
    name="Docker Personal / Org Access Token",
    description=(
        "Docker Hub access token — a personal access token ('dckr_pat_' prefix)"
        " or organization access token ('dckr_oat_' prefix) followed by a"
        " URL-safe token body. Used with 'docker login' and the Docker Hub API in"
        " place of a password. Prefix-anchored; leaking one grants push/pull"
        " access to the account's or organization's repositories."
    ),
    provider="docker",
    severity="high",
    # Source: https://docs.docker.com/security/for-developers/access-tokens/
    # (Docker's own access-token docs document the 'dckr_pat_' personal-access-token
    # prefix; organization access tokens use the parallel 'dckr_oat_' prefix).
    # Independently authored — prefix-anchored on the vendor-published 'dckr_pat_'
    # / 'dckr_oat_' spec with a bounded URL-safe body, not a copied fixed length.
    regex=re.compile(
        r"(?P<secret>dckr_(?:pat|oat)_[A-Za-z0-9_-]{20,40})(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["docker", "dckr_pat_", "dckr_oat_", "DOCKER_TOKEN", "docker login"],
    known_test_values={
        # Synthetic — clearly-fake all-'A' body, concatenated so the source
        # literal is never a real-looking token. Down-scores to ~0.15.
        "dckr_pat_" + "A" * 27,
    },
    recommendation=(
        "Revoke this token in Docker Hub under Account Settings > Personal access"
        " tokens (or Organization > Access tokens) and issue a replacement for the"
        " client or CI pipeline that used it."
    ),
    tags=["devops", "docker", "registry"],
)


# ===================================================
# ROOTLY (Batch 12 — 2026-07-13; prefix-anchored)
# ===================================================

ROOTLY_API_KEY = SecretPattern(
    id="rootly_api_key",
    name="Rootly API Key",
    description=(
        "Rootly (incident-management platform) API key — the literal 'rootly_'"
        " prefix followed by exactly 64 lowercase-hex characters. Sent as a"
        " bearer token to the Rootly API. Prefix-anchored; grants access to the"
        " organization's incidents, on-call schedules, and workflows."
    ),
    provider="rootly",
    severity="high",
    # Source: https://docs.rootly.com/api-reference/overview
    # (Rootly API docs — keys are issued with the 'rootly_' prefix and used as a
    # bearer token). Independently authored — 'rootly_' prefix + exactly 64
    # lowercase-hex chars, bounded so it does not over-capture.
    regex=re.compile(
        r"(?P<secret>rootly_[a-f0-9]{64})(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["rootly", "rootly_", "ROOTLY_API_KEY", "incident"],
    known_test_values={
        # Synthetic, sequential hex — not a live key. Down-scores to ~0.15.
        "rootly_" + "0123456789abcdef" * 4,
    },
    recommendation=(
        "Revoke this key in Rootly under Organization Settings > API Keys and"
        " rotate it in every integration / CI environment that used it."
    ),
    tags=["devops", "rootly", "incident"],
)


# ===================================================
# CISCO MERAKI (Batch 13 — 2026-07-18; context-gated 40-hex)
# ===================================================

CISCO_MERAKI_API_KEY = SecretPattern(
    id="cisco_meraki_api_key",
    name="Cisco Meraki API Key",
    description=(
        "Cisco Meraki Dashboard API key — a 40-character lowercase-hex string with"
        " no distinctive prefix, supplied via the 'X-Cisco-Meraki-API-Key' HTTP"
        " header (Dashboard API v0) or an 'Authorization: Bearer' header (v1). A"
        " bare 40-hex value collides with SHA-1 digests and git object hashes, so"
        " this detector is context-gated: it only fires when a Meraki key label"
        " (X-Cisco-Meraki-API-Key / MERAKI_DASHBOARD_API_KEY / meraki) sits"
        " immediately before the value. Grants full read/write control over the"
        " organization's networks, devices, and clients."
    ),
    provider="cisco_meraki",
    severity="high",
    # Format per https://developer.cisco.com/meraki/api-v1/authorization/ :
    # Dashboard API keys are 40-char lowercase hex, passed via the
    # 'X-Cisco-Meraki-API-Key' header (v0) or 'Authorization: Bearer <key>' (v1).
    # A bare 40-hex string is SHA-1 / git-hash shaped and high-FP on its own, so
    # the regex requires an adjacent X-Cisco-Meraki-API-Key / MERAKI_DASHBOARD_API_KEY
    # / meraki label (mirrors the adafruit_io_key context-gated approach).
    # Format per https://developer.cisco.com/meraki/api-v1/authorization/
    regex=re.compile(
        r"(?:"
        r"X-Cisco-Meraki-API-Key|MERAKI[_-]?DASHBOARD[_-]?API[_-]?KEY"
        r"|MERAKI[_-]?API[_-]?KEY|meraki"
        r")"
        r"[\s]*[=:\"'\s]+"
        r"(?P<secret>[a-f0-9]{40})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.60,  # format-only — value has no distinctive prefix
    entropy_threshold=3.0,  # penalize low-entropy 40-hex (e.g. all-zeros)
    context_keywords=[
        "meraki",
        "cisco",
        "x-cisco-meraki-api-key",
        "MERAKI_DASHBOARD_API_KEY",
        "dashboard.meraki.com",
        "api.meraki.com",
    ],
    known_test_values={
        # The concrete example printed in Cisco's public authorization docs — a
        # documentation placeholder, not a live key. Down-scores to ~0.15.
        "6bec40cf957de430a6f1f2baf056b99a4fac9ea0",
    },
    recommendation=(
        "Revoke this key in the Meraki Dashboard under My Profile > API access"
        " (Generate new API key) and rotate it in every integration / script that"
        " used it. Compromised Meraki keys grant full org-wide network control."
    ),
    tags=["devops", "cisco_meraki", "networking"],
)


# ===================================================
# INNGEST SIGNING KEY
# ===================================================
# Inngest signing keys authenticate the Inngest platform to a user's serve
# endpoint: the value is the HMAC secret used to sign (and verify) inbound
# function-invocation requests, so a leak lets an attacker forge webhook
# signatures and invoke functions directly.
#
# Shape is fully vendor-defined. Inngest's Go server declares the prefix set
# (SigningKeyPrefix "signkey-", plus the -test-/-branch-/-prod- environment
# segments) and validates keys with `^signkey-\w+-`; the JS SDK strips the same
# `^signkey-[\w]+-` prefix and then consumes the remainder AS HEX
# (sha256().update(key, "hex")). Because the body is a hex-encoded SHA256 hash,
# its 64-char length is structurally forced, not merely observed.
#
# The {64} bound is this pattern's ONLY FP-control mechanism and must not be
# loosened: Inngest's own SDK tests ship short toy keys (signkey-prod-12345678,
# signkey-test-abc123, signkey-prod-abc) that the length bound excludes. The
# environment segment is left as `\w+` -- matching the vendor's own regex --
# rather than a prod|test|branch alternation, so future environment names stay
# covered without inventing segments the vendor never defined.

INNGEST_SIGNING_KEY = SecretPattern(
    id="inngest_signing_key",
    name="Inngest Signing Key",
    description=(
        "Inngest signing key — the 'signkey-' prefix, an environment segment"
        " (prod / test / branch), and a hex-encoded SHA256 hash (64 hex chars)."
        " Used as the HMAC secret that signs requests between Inngest and a"
        " serve endpoint; a leaked key allows forging webhook signatures and"
        " invoking functions. Anchored on the vendor prefix with the"
        " structurally-forced 64-hex body as the false-positive control."
    ),
    provider="inngest",
    severity="high",
    # Corroborating vendor sources, each checked directly:
    #   inngest-js packages/inngest/src/helpers/strings.ts — strips
    #     /^signkey-[\w]+-/ then decodes the remainder as hex.
    #   inngest-py .env.example — signkey-prod- + exactly 64 hex chars.
    # Independently authored from those vendor sources; no detector catalog used.
    # Source: https://github.com/inngest/inngest/blob/main/pkg/authn/signing_key_strategy.go
    regex=re.compile(
        r"(?P<secret>signkey-\w+-[0-9a-f]{64})(?![0-9a-f])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["inngest", "signkey", "INNGEST_SIGNING_KEY", "signing_key", "signingKey"],
    known_test_values={
        # Vendor-published sample keys. Built by concatenation so the literal
        # key shape never appears in the source of the public engine repo
        # (GitHub Push Protection scans for provider-prefixed keys).
        # inngest-py/.env.example — all-zeros placeholder.
        "signkey-" + "prod-" + "0" * 64,
        # inngest-rs/inngest/src/handler.rs — all-ones placeholder.
        "signkey-" + "test-" + "1" * 64,
        # inngest-rs/inngest/src/signature.rs — signature round-trip fixtures.
        "signkey-" + "test-" + "8ee2262a15e8d3c42d6a840db7af3de2aab08ef632b32a37a687f24b34dba3ff",
        "signkey-" + "test-" + "e4bf4a2e7f55c7eb954b6e72f8f69628fbc409fe7da6d0f6958770987dcf0e02",
        # inngest-kt BearerTokenKtTest.kt — same hash under both env segments.
        "signkey-" + "prod-" + "b2ed992186a5cb19f6668aade821f502c1d00970dfd0e35128d51bac4649916c",
        "signkey-" + "test-" + "b2ed992186a5cb19f6668aade821f502c1d00970dfd0e35128d51bac4649916c",
    },
    recommendation=(
        "Rotate this signing key in the Inngest dashboard (Manage > Signing Key)"
        " and roll it out to every serve endpoint; until rotated, an attacker"
        " holding it can forge signed requests to your Inngest functions."
    ),
    tags=["devops", "inngest", "webhook", "signing"],
)


# ===================================================
# WAKATIME
# ===================================================

WAKATIME_API_KEY = SecretPattern(
    id="wakatime_api_key",
    name="WakaTime API Key",
    description=(
        "WakaTime API key — the literal 'waka_' prefix followed by a strict UUID v4."
        " Stored in ~/.wakatime.cfg ([settings] api_key) and sent via HTTP Basic Auth;"
        " grants read/write access to a developer's coding-activity account and"
        " dashboards. Anchored on the 'waka_' prefix because a bare UUID v4 is"
        " indistinguishable from any generic UUID and would be extremely high-FP."
    ),
    provider="wakatime",
    severity="high",
    # Format confirmed against WakaTime's own CLI, which validates keys with
    # ^(waka_)?[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$.
    # The prefix is optional in the wild but required here as the anti-FP anchor.
    # Independently authored from the vendor source (BSD 3-Clause).
    # Format per https://github.com/wakatime/wakatime-cli/blob/develop/pkg/params/params.go
    regex=re.compile(
        r"(?P<secret>waka_[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["wakatime", "WAKATIME_API_KEY", "waka_", ".wakatime.cfg"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in WakaTime under Settings > Account > Secret API Key"
        " (use the reset action). Audit recent API activity — the key exposes"
        " your full coding-activity history and heartbeat data."
    ),
    tags=["devops", "wakatime", "developer-tools"],
)


# ===================================================
# ZUPLO (2026-07-27)
# ===================================================

ZUPLO_CONSUMER_API_KEY = SecretPattern(
    id="zuplo_consumer_api_key",
    name="Zuplo Consumer API Key",
    description=(
        "Zuplo (zuplo.com) consumer API key — the credential Zuplo's API Key"
        " Service issues to a consumer of a gateway-fronted API. The format is"
        " the literal 'zpka_' prefix, a 32-character alphanumeric body, an"
        " underscore, and an 8-character lowercase-hex CRC32 checksum, for"
        " exactly 46 characters. Zuplo publishes this shape precisely so that"
        " leak-detection services can recognize it, and the trailing checksum"
        " means a well-formed match is almost certainly a real key rather than"
        " a random string. A leaked key lets an attacker call the protected API"
        " as that consumer, consuming their quota and reaching whatever"
        " upstream data their policy permits. Severity is high."
    ),
    provider="zuplo",
    severity="high",
    # Independently authored from Zuplo's own API-key leak-detection article,
    # which publishes the key shape for exactly this purpose: the 'zpka_'
    # prefix, a 32-character alphanumeric body, and an 8-character CRC32
    # checksum suffix separated by an underscore (46 characters total). No
    # third-party detector was consulted.
    # Source: https://zuplo.com/docs/articles/api-key-leak-detection
    regex=re.compile(
        r"(?<![0-9A-Za-z_])(?P<secret>zpka_[0-9A-Za-z]{32}_[0-9a-f]{8})(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.95,  # unique prefix + fixed length + CRC32 checksum tail
    entropy_threshold=0.0,  # the checksum suffix is the anchor, not randomness
    context_keywords=[
        "zuplo",
        "zpka_",
        "ZUPLO_API_KEY",
        "api-key",
        "Authorization",
    ],
    known_test_values={
        # Synthetic alphabet-sequence body plus a sequential hex checksum,
        # assembled by concatenation. Down-scores to ~0.15.
        "zpka_" + "AbCdEfGhIjKlMnOpQrStUvWxYz012345" + "_" + "0123abcd",
    },
    recommendation=(
        "Revoke this key in the Zuplo portal under the affected project's API"
        " Key Consumers and issue a fresh key to the consumer. Review the"
        " gateway's request logs for calls made with the leaked key before"
        " rotation."
    ),
    tags=["devops", "zuplo", "api-gateway"],
)


# ===================================================
# CFX.RE (2026-07-27)
# ===================================================

CFXRE_SERVER_KEY = SecretPattern(
    id="cfxre_server_key",
    name="Cfx.re Server Key",
    description=(
        "Cfx.re server key (FiveM / RedM server license key) in the newer"
        " 'cfxk_' format: the literal 'cfxk_' prefix, an alphanumeric body that"
        " may contain underscores, an underscore separator, and a short base62"
        " CRC32B checksum. The key authorizes a game server to register with"
        " the Cfx.re platform under its owner's account; a leak lets a third"
        " party impersonate the server, which typically costs the owner their"
        " server listing rather than exposing data — so severity is medium."
        " The vendor's own validation regex uses very loose bounds"
        " ('{1,60}_{1,20}') which would happily match a string as short as"
        " 'cfxk_a_b'; this pattern deliberately tightens the body to 20-40"
        " characters and the checksum to 4-10 characters to stay out of"
        " false-positive territory."
    ),
    provider="cfxre",
    severity="medium",
    # Independently authored from txAdmin's regexSvLicenseNew (Cfx.re's own
    # first-party server admin tool) and the Cfx.re forum announcement of the
    # new server-key format, which describes the 'cfxk_' prefix and the
    # trailing base62 CRC32B checksum segment. The vendor bounds are
    # deliberately tightened here; see the description. No third-party detector
    # was consulted.
    # Source: https://github.com/citizenfx/txAdmin/blob/master/shared/consts.ts
    regex=re.compile(
        r"(?<![0-9A-Za-z_])"
        r"(?P<secret>cfxk_[0-9A-Za-z_]{20,40}_[0-9A-Za-z]{4,10})"
        r"(?![0-9A-Za-z_])",
        re.ASCII,
    ),
    confidence_base=0.90,  # distinctive prefix + checksum tail, but loose body charset
    entropy_threshold=3.0,
    context_keywords=[
        "cfx",
        "cfxk_",
        "sv_licenseKey",
        "fivem",
        "txadmin",
    ],
    known_test_values={
        # Synthetic alphabet-sequence body plus a sequential checksum,
        # assembled by concatenation. Down-scores to ~0.15.
        "cfxk_" + "AbCdEfGhIjKlMnOpQrStUvWx" + "_" + "0a1b2c",
    },
    recommendation=(
        "Revoke this key at keymaster.fivem.net and generate a replacement,"
        " then update sv_licenseKey in the server's server.cfg. Do not commit"
        " server.cfg to version control — load the key from an environment"
        " variable or an untracked include file instead."
    ),
    tags=["devops", "cfxre", "fivem", "gaming"],
)


# ===================================================
# TRIGGER.DEV (2026-07-29)
# ===================================================
# Trigger.dev is fully open source, so the key format is not inferred from
# examples — it is read directly off the generator. apps/webapp/app/utils/
# apiKeys.ts declares
#     const apiKeyId = customAlphabet("1234567890abcdef...XYZ", 24)
# (the full 62-character alphanumeric alphabet, length 24), and apiKeyPrefix()
# returns exactly one of 'tr_dev_' / 'tr_stg_' / 'tr_prod_' / 'tr_preview_'.
# generateRootApiKey() emits `${prefix}${id}`; generateAdditionalApiKey() emits
# `${prefix}sk_${id}` — hence the optional 'sk_' segment.
#
# Deliberately NOT matched: the sibling 'pk_dev_' / 'pk_prod_' publishable keys
# (packages/cli-v3/src/utilities/getApiKeyType.ts types tr_* as "server" and
# pk_* as "public"), and the 'tr_pat_' personal access token, which is a
# different credential with a hex body.

TRIGGER_DEV_SECRET_KEY = SecretPattern(
    id="trigger_dev_secret_key",
    name="Trigger.dev Secret Key",
    description=(
        "Trigger.dev secret (server) API key — the environment prefix"
        " 'tr_dev_', 'tr_stg_', 'tr_prod_' or 'tr_preview_', an optional 'sk_'"
        " segment marking a non-root key, and exactly 24 alphanumeric"
        " characters from the vendor generator's 62-character alphabet. Sent as"
        " TRIGGER_SECRET_KEY; it authenticates writes to the environment it"
        " belongs to — triggering tasks, cancelling runs, and reading run"
        " payloads, which routinely carry customer data. The publishable"
        " 'pk_dev_' / 'pk_prod_' keys are client-side by design and are"
        " excluded."
    ),
    provider="trigger-dev",
    severity="high",
    # Format read off the vendor's own key generator rather than an example:
    # apps/webapp/app/utils/apiKeys.ts uses customAlphabet(<62-char alnum>, 24)
    # and apiKeyPrefix() returns tr_dev_ / tr_stg_ / tr_prod_ / tr_preview_,
    # with generateAdditionalApiKey() inserting a literal 'sk_'. Corroborated by
    # the vendor's own unit test apps/webapp/app/utils/apiKeys.test.ts, which
    # asserts ^{prefix}[A-Za-z0-9]{24}$ and ^{prefix}sk_[A-Za-z0-9]{24}$ for all
    # four environments. No entropy threshold: the multi-segment vendor prefix
    # and the fixed 24-character body carry the signal, and the body is
    # generator-random over a full alphanumeric alphabet, so a gate would only
    # add false-negative risk. Independently authored — no detector catalog used.
    # Source: https://github.com/triggerdotdev/trigger.dev/blob/main/apps/webapp/app/utils/apiKeys.ts
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>tr_(?:dev|stg|prod|preview)_(?:sk_)?[A-Za-z0-9]{24})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,  # prefix-anchored + generator-fixed 24-character body
    entropy_threshold=0.0,
    context_keywords=[
        "trigger.dev",
        "triggerdotdev",
        "TRIGGER_SECRET_KEY",
        "secretKey",
        "trigger",
    ],
    known_test_values={
        # Placeholder published in Trigger.dev's own docs
        # (docs/guides/example-projects/clickhouse-chat-agent.mdx) — it happens
        # to be exactly 24 characters, so it matches the real shape. Built by
        # string concatenation so no scannable key literal exists in source,
        # which GitHub push protection would otherwise block on the public
        # engine repo.
        "tr_" + "dev_" + "x" * 24,
    },
    recommendation=(
        "Revoke this key in the Trigger.dev dashboard under the project's"
        " Environments / API keys page (regenerating the environment key"
        " invalidates it), then update TRIGGER_SECRET_KEY everywhere it is"
        " configured — CI, deploy targets, and local .env files. Review the"
        " environment's run history for tasks triggered or cancelled while the"
        " key was exposed; a production key can read the payloads of every run"
        " in that environment."
    ),
    tags=["devops", "trigger-dev", "background-jobs"],
)


# ===================================================
# THUNDERSTORE
# ===================================================

THUNDERSTORE_API_TOKEN = SecretPattern(
    id="thunderstore_api_token",
    name="Thunderstore API Token",
    description=(
        "Thunderstore (thunderstore.io) service account API token — the literal 'tss_'"
        " prefix followed by a deterministic 36-character body (30 random alphanumerics"
        " plus a 6-character base62 CRC32 checksum), 40 characters in total. Scope is"
        " narrow: publishing mod packages under the owning team. Severity medium."
    ),
    provider="thunderstore",
    severity="medium",
    # Body shape read off Thunderstore's own token generator: a 30-character
    # random alphanumeric run followed by a 6-character base62 CRC32 checksum,
    # emitted behind the literal 'tss_' prefix — 36 body characters, always.
    # Source: https://github.com/thunderstore-io/Thunderstore/blob/master/django/thunderstore/account/tokens.py
    regex=re.compile(
        r"(?<![0-9A-Za-z_])"
        r"(?P<secret>tss_[0-9A-Za-z]{36})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,  # prefix + exact 36-character generator length are the anchor
    context_keywords=[
        "thunderstore",
        "TSS",
        "THUNDERSTORE_API_TOKEN",
        "service_account",
        "publish",
    ],
    known_test_values={"tss_" + "0" * 36},
    recommendation=(
        "Delete the owning service account in the Thunderstore team settings and issue a"
        " new token. Review recent package uploads for the affected team."
    ),
    tags=["devops", "thunderstore", "package-registry"],
)


# ===================================================
# LOGFIRE
# ===================================================

# Logfire is Pydantic's hosted observability platform. A write token is what
# the SDK sends to the ingestion endpoint -- `logfire.configure(token=...)`,
# or the `LOGFIRE_TOKEN` / `PYDANTIC_LOGFIRE_TOKEN` environment variables --
# so anyone holding it can write spans, logs and metrics into the owning
# project.
#
# THE STRUCTURE IS THE VENDOR'S OWN PARSING REGEX, not an inference from
# samples. logfire/_internal/auth.py compiles PYDANTIC_LOGFIRE_TOKEN_PATTERN
# from
#   ^(?P<safe_part>pylf_v(?P<version>[0-9]+)_(?P<region>[a-z]+)_
#   (?:(?P<organization_id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-
#   [0-9a-f]{4}-[0-9a-f]{12})_)?)(?P<token>[a-zA-Z0-9]+)$
# and LOGFIRE_TOKEN_REGION_PATTERN from
#   ^pylf_v[0-9]+_(?P<region>[a-z]+)_
# Every element below -- the `pylf_v` literal, the numeric version, the
# lowercase-only region, the OPTIONAL lowercase-hex organization UUID
# followed by '_', and the strictly alphanumeric body -- is read off that
# definition. The vendor also treats the string as secret-bearing itself:
# logfire/_internal/scrubbing.py lists r'pylf_v\d+_' among its DEFAULT_PATTERNS.
#
# THE REGION IS `[a-z]{2,20}`, NOT A `us|eu` ALTERNATION. The REGIONS dict
# ships only 'us' and 'eu', but the vendor's own fixtures carry 'local',
# 'stagingeu' and 'unknownregion', so pinning the two production regions
# would blind the pattern to real tokens. The bound is a ReDoS-safety
# ceiling, not a claim about the region vocabulary.
#
# THE 44-CHARACTER BODY IS EMPIRICAL, AND THAT IS STATED HONESTLY: the
# vendor's regex leaves the body unbounded (`[a-zA-Z0-9]+`), so {44} comes
# from measurement rather than from the vendor. Every realistic full-length
# token in the vendor repository is exactly 44 characters, across two
# DISTINCT bodies and five region/version combinations -- 'pylf_v1_us_<44>'
# and 'pylf_v1_eu_<44>' in tests/conftest.py, and the org-scoped
# 'pylf_v2_stagingeu_<uuid>_<44>' in tests/test_variables.py. The width is
# load-bearing rather than decorative: the same repository is full of toy
# stubs ('pylf_v1_us_token1', 'pylf_v1_eu_token3', 'pylf_v1_us_test_token')
# that an unbounded body would report as live credentials. Those stubs are
# pinned as negatives. Do not relax {44} to `+`.
#
# Boundary guards. Left `(?<![A-Za-z0-9_-])` keeps `pylf_v` from being the
# tail of a longer identifier; right `(?![A-Za-z0-9])` carries exactly the
# body charset, so a 44-character run that is really the head of a longer
# body cannot be reported as a whole token.
#
# The mixed-case lookaheads are the placeholder defence and are close to
# free. confidence_base 0.95 sits well above the 0.85 FP-wordlist gate
# (scanner.py:197), so the wordlist never gets a chance to price a masked
# value down -- the lookaheads have to. A 44-character run of 'x', of 'X' or
# of '0' fails one of them, while a random base62 body lacks lowercase (or
# uppercase) with probability ~4e-11.

LOGFIRE_WRITE_TOKEN = SecretPattern(
    id="logfire_write_token",
    name="Logfire Write Token",
    description=(
        "Pydantic Logfire write token — `pylf_v<version>_<region>_` followed by an"
        " optional lowercase-hex organization UUID and a 44-character alphanumeric"
        " body. Passed to `logfire.configure(token=...)` or carried in"
        " `LOGFIRE_TOKEN` / `PYDANTIC_LOGFIRE_TOKEN`, and it authorizes writes into"
        " the owning Logfire project: an attacker can poison the project's traces,"
        " logs and metrics, bury real signals under noise, and drive metered"
        " ingestion cost."
    ),
    provider="logfire",
    severity="high",
    # Structure taken from the vendor's own token-parsing regex —
    # PYDANTIC_LOGFIRE_TOKEN_PATTERN and LOGFIRE_TOKEN_REGION_PATTERN — in the
    # MIT-licensed pydantic/logfire SDK. The 44-character body bound, the
    # {2,20} region ceiling, the boundary guards, the mixed-case lookaheads,
    # the confidence and the known_test_values are ClassiFinder's own.
    # Source: https://github.com/pydantic/logfire/blob/main/logfire/_internal/auth.py
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>pylf_v[0-9]{1,3}_[a-z]{2,20}_"
        r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_)?"
        r"(?=[A-Za-z0-9]{0,43}[a-z])"
        r"(?=[A-Za-z0-9]{0,43}[A-Z])"
        r"[A-Za-z0-9]{44})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    # Prefix-anchored tier: `pylf_v<digits>_<region>_` is a literal vendor
    # prefix, not a shape. It is also a floor rather than a preference — the
    # vendor's own fixtures sit in *test* / *staging* / *local* contexts, and
    # below 0.85 the FP-wordlist penalty (-0.40) would silently sink real
    # tokens that merely live next to those words.
    confidence_base=0.95,
    # Deliberately 0.0: the body is a fixed-width random base62 run, so any
    # entropy floor a placeholder failed would also fail real tokens. The
    # mixed-case lookaheads do the placeholder filtering instead.
    entropy_threshold=0.0,
    context_keywords=[
        "logfire",
        "LOGFIRE_TOKEN",
        "PYDANTIC_LOGFIRE_TOKEN",
        "logfire.configure",
        "pylf_",
        "pydantic",
    ],
    known_test_values={
        # The two token bodies that appear in pydantic/logfire's own test
        # fixtures — the values every tutorial and bug report copies. Assembled
        # by concatenation so no contiguous full-shape literal exists in this
        # repository. Each down-scores to ~0.15.
        "pylf_" + "v1_us_" + "0kYhc414Ys2FNDRdt5vFB05xFx5NjVcbcBMy4Kp6PH0W",
        "pylf_" + "v1_eu_" + "0kYhc414Ys2FNDRdt5vFB05xFx5NjVcbcBMy4Kp6PH0W",
        "pylf_" + "v2_eu_" + "0kYhc414Ys2FNDRdt5vFB05xFx5NjVcbcBMy4Kp6PH0W",
        "pylf_" + "v1_unknownregion_" + "0kYhc414Ys2FNDRdt5vFB05xFx5NjVcbcBMy4Kp6PH0W",
        "pylf_" + "v1_local_" + "ZQHXp1vFjkR0dWxyQ8jCB4DPDlpd4752XWjpcNtdsPB6",
        "pylf_"
        + "v2_stagingeu_"
        + "9f9ba85a-b759-4181-9527-d812e03f9f7f_"
        + "0kYhc414Ys2FNDRdt5vFB05xFx5NjVcbcBMy4Kp6PH0W",
    },
    recommendation=(
        "Revoke this write token in the Logfire dashboard under the project's"
        " Settings > Write tokens, then issue a replacement and update every"
        " place it is configured — `logfire.configure(token=...)`, the"
        " `LOGFIRE_TOKEN` / `PYDANTIC_LOGFIRE_TOKEN` environment variables, CI"
        " secrets, and container or deployment manifests. Review the project's"
        " recent traces and metrics for spans your services did not emit:"
        " a leaked write token cannot read your data, but it can inject"
        " fabricated telemetry, hide a real incident under volume, and run up"
        " ingestion charges."
    ),
    tags=["devops", "logfire", "pydantic", "observability", "telemetry"],
)

# SETTLEMINT (2026-08-24)
# ===================================================

# SettleMint issues three access-token families and distinguishes them purely by
# the prefix: 'sm_pat_' personal access tokens (a human's credential),
# 'sm_aat_' application access tokens (machine-to-machine, long-lived) and
# 'sm_sat_' service account tokens. The vendor's own SDK carries the masking
# regex /sm_(pat|aat|sat)_[0-9a-zA-Z]+/g, which is what attests the body charset
# as strictly alphanumeric — no '-', no '_' after the prefix.
#
# The {16,} floor is the shortest body the vendor renders for this family (its
# docs show the sibling token shape as 'sm_..._' followed by sixteen x's), and
# it is a FLOOR rather than a fixed width on purpose: the vendor's own regex is
# unbounded, so pinning an exact width would be inventing format. The trailing
# (?![0-9a-zA-Z]) guard makes the greedy run take the whole token rather than a
# 16-character prefix of it.
#
# 'sm_pat_' and 'sm_aat_' are shipped as two separate patterns rather than one
# alternation because the two credentials have genuinely different blast radii
# and remediation paths — a personal token is revoked by its owner, an
# application token by rotating the application's credential — and a single
# finding type would collapse that distinction in the API response.

SETTLEMINT_PERSONAL_ACCESS_TOKEN = SecretPattern(
    id="settlemint_personal_access_token",
    name="SettleMint Personal Access Token",
    description=(
        "SettleMint personal access token — the 'sm_pat_' prefix followed by at"
        " least 16 alphanumerics. This is a human user's credential and carries"
        " that user's permissions across every workspace and application they"
        " can reach: reading and deploying blockchain networks, nodes, smart"
        " contract sets, and the private keys and integration credentials held"
        " alongside them."
    ),
    provider="settlemint",
    severity="high",
    # Prefix and the strictly-alphanumeric body charset are SettleMint's own,
    # attested by the masking regex /sm_(pat|aat|sat)_[0-9a-zA-Z]+/g in the
    # vendor SDK's access-token schema. Body floor, boundary guard, confidence
    # and known_test_values are ClassiFinder's own.
    # Source: https://github.com/settlemint/sdk/blob/main/sdk/utils/src/validation/access-token.schema.ts
    regex=re.compile(
        r"(?<![A-Za-z0-9_])"
        r"(?P<secret>sm_pat_[0-9a-zA-Z]{16,})"
        r"(?![0-9a-zA-Z])",
        re.ASCII,
    ),
    # Prefix-anchored tier, and above the 0.85 FP-wordlist gate so a token in a
    # *test* / *demo* context is not silently priced below threshold.
    confidence_base=0.95,
    # 0.0 on purpose: a seven-character literal prefix already carries the
    # precision, and an entropy floor on a 16-character body would sink short
    # legitimate tokens.
    entropy_threshold=0.0,
    context_keywords=[
        "settlemint",
        "SETTLEMINT_ACCESS_TOKEN",
        "personal access token",
        "sm_pat",
    ],
    known_test_values={
        # The vendor's own masked placeholder shape (prefix + sixteen x's).
        # Assembled by concatenation. Down-scores to ~0.15.
        "sm_pat_" + "x" * 16,
    },
    recommendation=(
        "Revoke this token in the SettleMint platform under your user Account"
        " Settings > API tokens and issue a replacement scoped to the narrowest"
        " workspace the caller needs. Because a personal token inherits the"
        " user's full access, treat the blockchain node credentials, private"
        " keys and integration secrets in every workspace it could reach as"
        " exposed and rotate them. Review the workspace audit log for"
        " deployments or key exports you did not perform."
    ),
    tags=["devops", "settlemint", "blockchain"],
)


SETTLEMINT_APPLICATION_ACCESS_TOKEN = SecretPattern(
    id="settlemint_application_access_token",
    name="SettleMint Application Access Token",
    description=(
        "SettleMint application access token — the 'sm_aat_' prefix followed by"
        " at least 16 alphanumerics. This is a machine-to-machine credential"
        " scoped to one application and is long-lived by design, so a leak is"
        " durable: it grants API access to that application's blockchain nodes,"
        " smart contract sets and integration services until it is rotated."
    ),
    provider="settlemint",
    severity="high",
    # Prefix and the strictly-alphanumeric body charset are SettleMint's own,
    # attested by the masking regex /sm_(pat|aat|sat)_[0-9a-zA-Z]+/g in the
    # vendor SDK's access-token schema. Body floor, boundary guard, confidence
    # and known_test_values are ClassiFinder's own.
    # Source: https://github.com/settlemint/sdk/blob/main/sdk/utils/src/validation/access-token.schema.ts
    regex=re.compile(
        r"(?<![A-Za-z0-9_])"
        r"(?P<secret>sm_aat_[0-9a-zA-Z]{16,})"
        r"(?![0-9a-zA-Z])",
        re.ASCII,
    ),
    # Prefix-anchored tier, and above the 0.85 FP-wordlist gate.
    confidence_base=0.95,
    # 0.0 on purpose — see the personal-access-token note above.
    entropy_threshold=0.0,
    context_keywords=[
        "settlemint",
        "SETTLEMINT_ACCESS_TOKEN",
        "application access token",
        "sm_aat",
    ],
    known_test_values={
        # The vendor's own masked placeholder shape (prefix + sixteen x's).
        # Assembled by concatenation. Down-scores to ~0.15.
        "sm_aat_" + "x" * 16,
    },
    recommendation=(
        "Rotate this token in the SettleMint platform under the application's"
        " Access tokens tab, then update every deployment, CI job and service"
        " that presents it. Application tokens do not expire on their own, so"
        " rotation is the only containment. Audit the application's blockchain"
        " node and smart-contract activity for transactions or deployments"
        " originating outside your own automation while it was exposed."
    ),
    tags=["devops", "settlemint", "blockchain", "machine-to-machine"],
)


# ===================================================
# DOCKER SWARM (2026-08-24)
# ===================================================

# A Swarm join token is what `docker swarm join --token` takes, and possessing
# the manager variant is equivalent to owning the cluster: a new manager joins
# the Raft quorum and can read every service definition, every mounted Docker
# secret and every config in the swarm. Worker tokens are lower-blast-radius but
# still let an attacker place a node inside the overlay network.
#
# Both segment widths are cryptographic constants read off swarmkit's own CA
# config, not measured from samples: base36DigestLen = 50 (the root CA
# certificate's SHA-256 digest rendered in base 36 and zero-left-padded) and
# maxGeneratedSecretLength = 25 (16 bytes of entropy, generatedSecretEntropyBytes,
# likewise base-36 zero-left-padded). Base 36 is why the charset is [0-9a-z] and
# never uppercase.
#
# Two token versions exist and both are covered by one alternation. v1 is
# 'SWMTKN-1-'; the FIPS-era v2 form inserts a single [01] flag segment,
# 'SWMTKN-2-0-' / 'SWMTKN-2-1-', and keeps the same two widths after it.

DOCKER_SWARM_JOIN_TOKEN = SecretPattern(
    id="docker_swarm_join_token",
    name="Docker Swarm Join Token",
    description=(
        "Docker Swarm join token — 'SWMTKN-1-' (or the FIPS 'SWMTKN-2-0-' /"
        " 'SWMTKN-2-1-' form) followed by the root CA certificate's SHA-256"
        " digest as 50 base-36 characters, a hyphen, and a 16-byte secret as 25"
        " base-36 characters. Presenting it to `docker swarm join` adds a node"
        " to the cluster; the manager token makes the joiner part of the Raft"
        " quorum, with read access to every service definition, Docker secret"
        " and config in the swarm."
    ),
    provider="docker",
    severity="high",
    # Structure and both segment widths per Docker/moby swarmkit's own CA
    # configuration — base36DigestLen = 50, maxGeneratedSecretLength = 25,
    # generatedSecretEntropyBytes = 16, joinTokenBase = 36. Guards, confidence
    # and known_test_values are ClassiFinder's own.
    # Source: https://github.com/moby/swarmkit/blob/master/ca/config.go
    regex=re.compile(
        r"(?<![A-Za-z0-9-])"
        r"(?P<secret>SWMTKN-(?:1|2-[01])-[0-9a-z]{50}-[0-9a-z]{25})"
        r"(?![0-9a-z])",
        re.ASCII,
    ),
    # Prefix-anchored tier: a literal 'SWMTKN-' plus two fixed cryptographic
    # widths leaves essentially no false-positive surface. Also above the 0.85
    # FP-wordlist gate, so a token pasted into a *test* cluster runbook is not
    # silently sunk.
    confidence_base=0.95,
    # 0.0 on purpose: the digest half is a fixed-width hash and the secret half
    # a fixed-width random value, so an entropy floor could only sink real
    # tokens.
    entropy_threshold=0.0,
    context_keywords=[
        "docker",
        "swarm",
        "docker swarm join",
        "SWMTKN",
        "manager",
        "worker",
    ],
    known_test_values={
        # The zero-filled placeholder shape — both segments are zero-left-padded
        # base 36, so an all-zero token is the natural redaction and the one
        # that shows up in tutorials. Assembled by concatenation. ~0.15.
        "SWMTKN-1-" + "0" * 50 + "-" + "0" * 25,
    },
    recommendation=(
        "Rotate the affected join token on a manager node — `docker swarm"
        " join-token --rotate manager` or `--rotate worker` — which invalidates"
        " the leaked value immediately; existing nodes stay joined. If the"
        " MANAGER token leaked, also assume every Docker secret and config in"
        " the swarm was readable and rotate those, and audit `docker node ls`"
        " for nodes you did not add. Stop pasting join tokens into provisioning"
        " scripts, CI logs or issue reports; fetch them at join time instead."
    ),
    tags=["devops", "docker", "swarm", "cluster"],
)


# ===================================================
# UNLEASH
# ===================================================

UNLEASH_API_TOKEN = SecretPattern(
    id="unleash_api_token",
    name="Unleash API Token",
    description=(
        "Unleash API token — the three-part '<projects>:<environment>.<hash>'"
        " form, where the hash is exactly 56 lowercase hex characters. The"
        " projects segment is a single project id, '[]' (a specific set of"
        " projects) or '*' (all current and future projects). Sent as the"
        " 'Authorization' header; a client token reads every feature-flag"
        " configuration in its scope, and an admin token ('*:*.<hash>') is"
        " full control of the Unleash instance."
    ),
    provider="unleash",
    severity="high",
    # Structure, body width and charset all come from Unleash's own generator
    # rather than from observed samples:
    #   src/lib/services/api-token-service.ts
    #     generateSecretKey({ projects, environment }):
    #       const randomStr = crypto.randomBytes(28).toString('hex');
    #       return `${projects[0]}:${environment}.${randomStr}`
    #       (with '[]' in place of projects[0] when projects.length > 1)
    #   src/lib/types/models/api-token.ts
    #     ALL = '*'   — the all-projects / all-environments scope
    #
    # BOTH segments accept '*', not just the first: an ADMIN token is scoped to
    # ALL for project and environment alike and is minted as '*:*.<hash>'. That
    # is the highest-severity variant of this credential, so the environment
    # alternation carries '*' as well — omitting it would silently miss exactly
    # the token that grants full control of the instance.
    #
    # randomBytes(28) -> hex is DETERMINISTICALLY 56 lowercase hex characters,
    # so the body width is exact rather than a measured range. The vendor's own
    # documentation agrees independently: docs.getunleash.io publishes three
    # concrete example tokens (new-checkout-flow:development.<hash>,
    # []:production.<hash>, *:development.<hash>) whose hashes each measure 56
    # characters over [0-9a-f].
    #
    # THE DOC PROSE SAYING "a 64-character-long hexadecimal string" IS STALE,
    # and is resolved rather than ignored — it contradicts both the generator
    # and the same page's own examples. Commit dfb890c63 ("Feat: Api-Tokens",
    # 2021-03-29) generated a BARE crypto.randomBytes(32).toString('hex') — 64
    # hex, with no project/environment prefix at all. Commit c4b697b57d
    # ("Feat/api key scoping", 2021-09-15) replaced it in a single hunk:
    #     -return crypto.randomBytes(32).toString('hex');
    #     +const randomStr = crypto.randomBytes(28).toString('hex');
    #     +return `${project}:${environment}.${randomStr}`;
    # i.e. the width change and the introduction of the colon+period structure
    # landed together. The ANCHORED three-part form has therefore ONLY ever
    # been 56 hex, and the "64" prose describes the pre-scoping bare-hex token.
    # The width is pinned at {56} and deliberately NOT widened to {56,64}:
    # widening would match nothing real and only add false-positive surface.
    #
    # The LEGACY bare 64-hex form is deliberately NOT registered. Unanchored
    # 64-hex is indistinguishable from any other hex digest (git object ids,
    # sha256 sums, session ids), so registering it would be a false-positive
    # factory. It is knowingly left undetected.
    #
    # PERSONAL ACCESS TOKENS are also NOT registered. src/lib/features/pat/
    # pat-service.ts mints them as `user:${crypto.randomBytes(28).toString(
    # 'hex')}` — 56 hex with NO period — so this regex cannot match them by
    # construction. A `user:` + 56-hex alternation would carry ONE delimiter
    # instead of two and would cost precision, so it is traded away.
    #
    # ANCHORING: there is no literal prefix here — the projects segment is a
    # user-chosen slug — so the precision is carried entirely by the two
    # MANDATORY delimiters (':' then '.') plus the exact 56-hex body, and by
    # two independently authored boundary guards. The left guard keeps the
    # projects segment from starting mid-identifier; the right guard carries
    # the body charset, so a 56-character run that is really the head of a
    # longer hex digest is never reported as a whole token.
    #
    # No entropy gate: the body is a fixed-width random hex run (Shannon
    # entropy is capped at 4.0 by the 16-symbol alphabet), so any floor a
    # placeholder failed would also sink real tokens.
    # Source: https://github.com/Unleash/unleash/blob/main/src/lib/services/api-token-service.ts
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>(?:\*|\[\]|[A-Za-z0-9_-]{1,64}):(?:\*|[A-Za-z0-9_-]{1,64})\.[0-9a-f]{56})"
        r"(?![0-9a-f])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,  # fixed-width random hex body; a floor could only sink real tokens
    context_keywords=[
        "unleash",
        "UNLEASH_API_TOKEN",
        "getunleash",
        "feature_flag",
        "feature-toggle",
    ],
    known_test_values={
        # The vendor's OWN published example hash. docs.getunleash.io prints it
        # three times — once per scope shape — so it is copied verbatim into
        # every walkthrough, README and support thread that follows the docs.
        # confidence_base 0.90 sits above the 0.85 FP-wordlist gate, so the
        # wordlist never gets a chance to price these down; they are pinned
        # here instead and land at ~0.15.
        "new-checkout-flow:development."
        + "be44368985f7fb3237c584ef"
        + "86f3d6bdada42ddbd63a019d26955178",
        "[]:production." + "be44368985f7fb3237c584ef" + "86f3d6bdada42ddbd63a019d26955178",
        "*:development." + "be44368985f7fb3237c584ef" + "86f3d6bdada42ddbd63a019d26955178",
        # Single-character masks — how redacted logs and documentation render
        # the hash once it has been scrubbed.
        "*:production." + "0" * 56,
        "*:production." + "a" * 56,
        "*:production." + "f" * 56,
        "[]:production." + "0" * 56,
        "default:development." + "0" * 56,
    },
    recommendation=(
        "Revoke this token in the Unleash admin UI under Configure > API access"
        " (or DELETE /api/admin/api-tokens/:token) and issue a replacement,"
        " then update UNLEASH_API_TOKEN everywhere it is configured — SDK"
        " initialisation, CI, Edge/proxy deployments and local .env files."
        " Check the scope before assuming the blast radius: a '*:*' admin token"
        " is full control of the instance, while a project- and"
        " environment-scoped client token still exposes every flag"
        " configuration and strategy constraint in its scope, including the"
        " segment and context-field values that can reveal customer"
        " identifiers."
    ),
    tags=["devops", "unleash", "feature-flag", "feature-toggle"],
)

# ===================================================
# PORTAINER
# ===================================================

PORTAINER_API_ACCESS_TOKEN = SecretPattern(
    id="portainer_api_access_token",
    name="Portainer API Access Token",
    description=(
        "Portainer API access token — the literal 'ptr_' prefix followed by a"
        " 44-character standard-base64 body (43 data characters plus exactly"
        " one '=' pad), 48 characters in total. Sent as the 'X-API-Key'"
        " request header and authenticated as the Portainer user it was minted"
        " for, with that user's role across every environment the instance"
        " manages: an administrator's token is control of the Docker, Swarm or"
        " Kubernetes endpoints behind it — deploy a container, mount the host"
        " filesystem, read every stack file, registry credential and"
        " environment variable Portainer holds."
    ),
    provider="portainer",
    severity="high",
    # Prefix, body width and charset all come from Portainer's own generator
    # rather than from observed samples:
    #   api/apikey/service.go
    #     const portainerAPIKeyPrefix = "ptr_"
    #     func (a *APIKeyService) GenerateApiKey(user, description) {
    #       randKey          := GenerateRandomKey(32)
    #       encodedRawAPIKey := base64.StdEncoding.EncodeToString(randKey)
    #       prefixedAPIKey   := portainerAPIKeyPrefix + encodedRawAPIKey
    #       ...
    #       apiKey := &portainer.APIKey{... Prefix: prefixedAPIKey[:7] ...}
    #     }
    #     func GenerateRandomKey(length int) []byte   // io.ReadFull(rand.Reader)
    #
    # The body width is therefore DETERMINISTIC, not a measured range: 32 bytes
    # is 3*10 + 2, so StdEncoding always emits 43 data characters followed by
    # exactly one '=' pad — 44 characters, 48 with the prefix. `Prefix:
    # prefixedAPIKey[:7]` corroborates independently that 'ptr_' is part of the
    # RAW key rather than a display decoration: the stored 7-character lookup
    # prefix is 'ptr_' plus the first three body characters.
    #
    # The alphabet is STANDARD base64 ([A-Za-z0-9+/] with '=' padding), NOT
    # base64url and NOT RawStdEncoding — base64.StdEncoding is the padded
    # standard encoder, so '+' and '/' are both reachable body characters and
    # the single '=' is always present. Dropping either would silently miss
    # real tokens.
    #
    # Only the token itself is matched. The DERIVED digest that Portainer
    # stores is base64.StdEncoding of a SHA-256 (HashRaw) — a 44-character
    # padded base64 run with NO 'ptr_' prefix, indistinguishable from any other
    # base64'd sha256 sum — so it is knowingly left undetected rather than
    # traded for a false-positive factory, and a test pins that decision.
    #
    # 'ptr_' is a WEAK anchor on its own — 'ptr' is the universal abbreviation
    # for "pointer", so it appears inside ordinary C/C++/Rust identifiers
    # (raw_ptr_, char_ptr_, shared_ptr_) — so the precision is carried by the
    # exact 44-character padded body plus two independently authored boundary
    # guards. The left guard also excludes '-' because base64url is the one
    # alphabet in which the literal 'ptr_' can appear INSIDE a random-looking
    # run ('_' is not in the standard alphabet, so a standard-base64 blob can
    # never contain it); without that guard a base64url payload ending in a
    # 'ptr_'-prefixed tail could be claimed. The right guard carries the body
    # charset AND '=', so a 43-character run that is really the head of a
    # longer base64 payload is never reported as a whole token ('ptr_' + 43
    # chars + '==' is not a canonical encoding of 32 bytes and is correctly
    # rejected).
    #
    # The 43rd body character is in fact constrained to [AEIMQUYcgkosw048]:
    # the two leftover bytes leave only four significant bits in the final
    # 6-bit group. The regex deliberately keeps the BROADER [0-9A-Za-z+/]
    # superset — the single '=' pad already pins the payload to 3k+2 bytes and,
    # with 43 data characters, to exactly 32 — so narrowing would buy nothing
    # the pad does not already enforce while adding a brittle dependency on the
    # encoder never emitting stray low bits. A test pins the observation.
    #
    # No entropy gate: the body is a fixed-width random base64 run, so any
    # floor a placeholder failed would also sink real tokens.
    # Source: https://github.com/portainer/portainer/blob/develop/api/apikey/service.go
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"(?P<secret>ptr_[0-9A-Za-z+/]{43}=)"
        r"(?![0-9A-Za-z+/=])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,  # fixed-width random base64 body; a floor could only sink real tokens
    context_keywords=[
        "portainer",
        "PORTAINER_API_KEY",
        "X-API-Key",
        "api/endpoints",
        "api/stacks",
    ],
    known_test_values={
        # Single-character masks — how documentation and redacted logs render
        # this token. confidence_base 0.90 sits above the 0.85 FP-wordlist gate
        # (scanner.py:197), so the wordlist never gets a chance to price these
        # down; they are pinned here instead and land at ~0.15.
        "ptr_" + "x" * 43 + "=",
        "ptr_" + "X" * 43 + "=",
        "ptr_" + "0" * 43 + "=",
        "ptr_" + "A" * 43 + "=",
    },
    recommendation=(
        "Remove this token in Portainer under My account > Access tokens (or"
        " DELETE /api/users/:id/tokens/:tokenId) and issue a replacement, then"
        " update PORTAINER_API_KEY everywhere it is configured — CI jobs,"
        " deployment scripts, Terraform/Ansible providers and local .env"
        " files. Audit the blast radius by the token owner's ROLE, not by the"
        " token: an administrator's token is control of every Docker, Swarm or"
        " Kubernetes environment the instance manages, so review container and"
        " stack activity for the exposure window and rotate anything the"
        " instance itself holds — registry credentials, stack environment"
        " variables and Kubernetes secrets were all readable with it."
    ),
    tags=["devops", "portainer", "containers", "docker", "kubernetes"],
)

# ===================================================
# CIRCLECI v2 API TOKENS
# ===================================================

CIRCLECI_PERSONAL_ACCESS_TOKEN = SecretPattern(
    id="circleci_personal_access_token",
    name="CircleCI Personal Access Token",
    description=(
        "CircleCI personal API token in the 2023 prefixed format — the"
        " literal 'CCIPAT_' prefix, 22 base58 characters, an underscore, and"
        " 40 lowercase hex characters. Acts as the user who minted it across"
        " every organization and project that user can reach: it can read"
        " build logs and environment-variable names, trigger and cancel"
        " pipelines, and manage contexts. The registry's older"
        " 'circleci_token' pattern covers the LEGACY bare 40-hex token, which"
        " has no prefix and is only detectable next to a CIRCLE_TOKEN-style"
        " keyword; this pattern covers the self-identifying replacement."
    ),
    provider="circleci",
    severity="high",
    # Structure per CircleCI's own changelog announcing the format:
    # personal tokens carry the 'CCIPAT_' prefix and project tokens
    # 'CCIPRJ_', each followed by a random component and the legacy 40-hex
    # token value, joined by an underscore. The 22-character component is
    # BASE58 — the Bitcoin alphabet, [1-9A-HJ-NP-Za-km-z], which drops the
    # four visually ambiguous characters 0, O, I and l. Spelling it as
    # base58 rather than as a loose alphanumeric class is what keeps this
    # from being a generic '<prefix>_<22 alnum>_<40 hex>' matcher.
    #
    # No double-match with the legacy 'circleci_token' pattern: that one
    # requires a CIRCLECI_TOKEN / CIRCLE_TOKEN keyword followed immediately
    # by [=:"'\s]+ and then the 40 hex characters. Here the intervening
    # 'CCIPAT_<base58>_' means hex never begins at the separator, so the
    # legacy pattern cannot fire on a prefixed token. A test pins that a
    # prefixed token in a CIRCLE_TOKEN assignment yields exactly one finding.
    #
    # No entropy gate: both halves are fixed-width random runs, so any floor
    # a placeholder failed would also sink real tokens.
    # Source: https://circleci.com/changelog/new-format-for-api-access-tokens
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"(?P<secret>CCIPAT_[1-9A-HJ-NP-Za-km-z]{22}_[a-f0-9]{40})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # fixed-width random halves; a floor could only sink real tokens
    context_keywords=[
        "circleci",
        "CIRCLE_TOKEN",
        "CIRCLECI_TOKEN",
        "circleci.com/api",
        "personal api token",
    ],
    known_test_values={
        # Single-character masks. confidence_base 0.95 sits above the 0.85
        # FP-wordlist gate (scanner.py:197), so the wordlist never prices
        # these down; they are pinned here and land at ~0.15. 'x' and 'X' are
        # both in the base58 alphabet; '0' is not, so the all-zero mask uses
        # '1' for the base58 half.
        "CCIPAT_" + "x" * 22 + "_" + "0" * 40,
        "CCIPAT_" + "X" * 22 + "_" + "f" * 40,
        "CCIPAT_" + "1" * 22 + "_" + "a" * 40,
    },
    recommendation=(
        "Revoke this token in CircleCI under User Settings > Personal API"
        " Tokens and issue a replacement, then update CIRCLE_TOKEN everywhere"
        " it is configured. Scope the audit to the OWNER, not the token: it"
        " acted as that user across every organization and project they can"
        " reach, so review recent pipeline triggers, context changes and"
        " project-settings edits, and rotate any credential stored in a"
        " CircleCI context or project environment variable that the user"
        " could read."
    ),
    tags=["devops", "ci", "circleci"],
)


CIRCLECI_PROJECT_ACCESS_TOKEN = SecretPattern(
    id="circleci_project_access_token",
    name="CircleCI Project Access Token",
    description=(
        "CircleCI project API token in the 2023 prefixed format — the literal"
        " 'CCIPRJ_' prefix, 22 base58 characters, an underscore, and 40"
        " lowercase hex characters. Scoped to a single project rather than to"
        " a user: it can trigger and cancel that project's pipelines and read"
        " its build artifacts and logs. Lower blast radius than the sibling"
        " personal token ('CCIPAT_'), which acts as a whole user, but it is"
        " the token that most often ends up hardcoded in a webhook or a"
        " deploy script."
    ),
    provider="circleci",
    severity="high",
    # Same vendor changelog, same generator shape as the personal token: the
    # prefix names the token's SCOPE ('CCIPRJ_' project, 'CCIPAT_' personal)
    # and the body is a 22-character base58 component plus the legacy 40-hex
    # token value, joined by an underscore. Registered as its own pattern
    # rather than folded into a prefix alternation so the finding names the
    # scope — the rotation path and the blast radius differ.
    #
    # Base58 is [1-9A-HJ-NP-Za-km-z] — the Bitcoin alphabet, without the four
    # visually ambiguous characters 0, O, I and l.
    #
    # No entropy gate: both halves are fixed-width random runs.
    # Source: https://circleci.com/changelog/new-format-for-api-access-tokens
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"(?P<secret>CCIPRJ_[1-9A-HJ-NP-Za-km-z]{22}_[a-f0-9]{40})"
        r"(?![a-f0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # fixed-width random halves; a floor could only sink real tokens
    context_keywords=[
        "circleci",
        "CIRCLE_TOKEN",
        "project api token",
        "circleci.com/api",
        "pipeline",
    ],
    known_test_values={
        "CCIPRJ_" + "x" * 22 + "_" + "0" * 40,
        "CCIPRJ_" + "X" * 22 + "_" + "f" * 40,
        "CCIPRJ_" + "1" * 22 + "_" + "a" * 40,
    },
    recommendation=(
        "Revoke this token in CircleCI under Project Settings > API"
        " Permissions and issue a replacement, then update every webhook,"
        " deploy script and external service that presents it. Review the"
        " project's recent pipeline triggers for runs you did not start, and"
        " treat any artifact or build log the project produced during the"
        " exposure window as readable."
    ),
    tags=["devops", "ci", "circleci"],
)


# ===================================================
# DOCKER SWARM UNLOCK KEY
# ===================================================

DOCKER_SWARM_UNLOCK_KEY = SecretPattern(
    id="docker_swarm_unlock_key",
    name="Docker Swarm Unlock Key",
    description=(
        "Docker Swarm unlock key — the literal 'SWMKEY-1-' prefix followed by"
        " 43 unpadded standard-base64 characters. Printed once when autolock"
        " is enabled on a swarm and required by `docker swarm unlock` before"
        " a restarted manager will rejoin the cluster. It is the key that"
        " decrypts the Raft log at rest, so autolock's entire purpose is"
        " defeated by leaking it: whoever holds it plus a copy of a manager's"
        " /var/lib/docker/swarm directory can read every Docker secret,"
        " config and TLS key the swarm stores. Distinct from the JOIN token"
        " ('SWMTKN-1-'), which adds a node rather than unlocking one."
    ),
    provider="docker",
    severity="high",
    # Structure per Docker's own swarm-manager locking documentation, which
    # prints the key `docker swarm init --autolock` emits. 'SWMKEY-1-' is a
    # literal, and the 43-character body is base64 of a 32-byte key with the
    # padding stripped — 32 bytes is 3*10 + 2, so a padded encoding would be
    # 43 data characters plus one '='; the emitted key carries no pad, so the
    # width is exact rather than a measured range.
    #
    # The alphabet is STANDARD base64 ([A-Za-z0-9+/]), not base64url: '+' and
    # '/' are both reachable body characters, and the documentation's own
    # sample carries both. Spelling it as base64url would silently miss real
    # keys.
    #
    # Disjoint from DOCKER_SWARM_JOIN_TOKEN by BOTH halves — a different
    # literal ('SWMKEY-1-' vs 'SWMTKN-1-' / 'SWMTKN-2-[01]-') and a different
    # alphabet (standard base64 vs lowercase base 36 in two hyphen-separated
    # fixed-width segments). A test pins that neither claims the other's
    # value.
    #
    # The right guard carries '=' as well as the body charset so a 43-
    # character run that is really the head of a longer PADDED base64 payload
    # is never reported as a whole key.
    #
    # No entropy gate: the body is a fixed-width random base64 run.
    # Source: https://docs.docker.com/engine/swarm/swarm_manager_locking/
    regex=re.compile(
        r"(?<![0-9A-Za-z+/-])"
        r"(?P<secret>SWMKEY-1-[0-9A-Za-z+/]{43})"
        r"(?![0-9A-Za-z+/=])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # fixed-width random base64 body; a floor could only sink real keys
    context_keywords=[
        "docker",
        "swarm",
        "docker swarm unlock",
        "autolock",
        "unlock key",
        "SWMKEY",
    ],
    known_test_values={
        # Docker's PUBLISHED documentation sample — the key printed in the
        # swarm-manager locking guide, which is copied verbatim into every
        # walkthrough that follows it. confidence_base 0.95 sits above the
        # 0.85 FP-wordlist gate (scanner.py:197), so the wordlist never gets
        # a chance to price it down; it is pinned here instead and lands at
        # ~0.15. Assembled by concatenation to keep no contiguous key-shaped
        # literal in source.
        "SWMKEY-1-" + "WuYH/IX284+lRcXuoVf38viIDK3HJEKY1" + "3MIHX+tTt8",
        # Single-character masks.
        "SWMKEY-1-" + "x" * 43,
        "SWMKEY-1-" + "0" * 43,
    },
    recommendation=(
        "Rotate the key on a manager node — `docker swarm unlock-key --rotate`"
        " — which re-encrypts the Raft log and invalidates the leaked value"
        " immediately; running managers stay up, so there is no outage."
        " Distribute the new key to whoever restarts managers and remove the"
        " old one from password managers, runbooks and provisioning scripts."
        " If a manager's /var/lib/docker/swarm directory could also have been"
        " copied, assume every Docker secret, config and TLS key in the swarm"
        " was readable and rotate those too."
    ),
    tags=["devops", "docker", "swarm", "cluster", "encryption"],
)


# ===================================================
# DEPENDENCY-TRACK API KEY (2026-09-07)
# ===================================================

# TWO DOCUMENTED FORMS, AND BOTH MUST MATCH. Dependency-Track changed its key
# layout in 4.13.0 and the old one is still in the field on every instance that
# has not upgraded:
#   v4.9.0 - 4.12   'odt_' + 32 random characters                 (36 total)
#   v4.13.0+        'odt_' + 8-character publicId + '_' + 32 key  (45 total)
# The vendor's 4.13.0 release note states it exactly: "Keys generated by
# version 4.13.0 and later will follow the format odt_<publicId>_<key>, where
# publicId consists of 8 random characters, and key of the usual 32 random
# characters." Upstream detector catalogues still ship the legacy shape alone,
# which misses every key minted by a current release — the optional
# '[A-Za-z0-9]{8}_' group is what closes that gap, and tests pin both widths.
#
# The two forms cannot be confused with one another. The legacy branch is
# 32 characters of [A-Za-z0-9], which cannot contain the '_' that separates a
# v4.13+ publicId from its key, so the alternation is unambiguous in both
# directions and the engine reports one finding either way.
#
# Both boundary guards carry '_' as well as the body charset, so a key is never
# carved out of the middle of a longer underscore-joined identifier.
#
# A Dependency-Track API key belongs to a team and carries that team's
# permissions, which on a typical deployment include reading every project's
# SBOM and vulnerability posture and uploading new BOMs. Severity high.

DEPENDENCY_TRACK_API_KEY = SecretPattern(
    id="dependency_track_api_key",
    name="Dependency-Track API Key",
    description=(
        "Dependency-Track API key in either documented form: the legacy"
        " 'odt_' + 32-character shape minted by 4.9.0 through 4.12, or the"
        " 'odt_<8-character publicId>_<32-character key>' shape introduced in"
        " 4.13.0. The key carries its team's permissions on the"
        " Dependency-Track instance — typically read access to every project's"
        " SBOM and vulnerability findings, and the ability to upload BOMs."
    ),
    provider="dependency_track",
    severity="high",
    # Both forms are the vendor's own. The legacy 'odt_' + 32 shape and the
    # 4.13.0 'odt_<publicId>_<key>' composition, including the 8-character
    # publicId and the "usual 32 random characters" key, are stated verbatim in
    # the project's 4.13.0 release announcement. Guards, confidence and
    # known_test_values are ClassiFinder's own.
    # Source: https://docs.dependencytrack.org/2025/04/07/v4.13.0/
    regex=re.compile(
        r"(?<![A-Za-z0-9_])"
        r"(?P<secret>odt_(?:[A-Za-z0-9]{8}_)?[A-Za-z0-9]{32})"
        r"(?![A-Za-z0-9_])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # the 'odt_' literal plus an exact width anchors it
    context_keywords=[
        "dependency-track",
        "dependencytrack",
        "dtrack",
        "DT_API_KEY",
        "api_key",
        "X-Api-Key",
        "bom",
    ],
    known_test_values={
        # Masks used in Dependency-Track docs, CI examples and issue reports,
        # in both the legacy and the 4.13+ shapes. confidence_base 0.95 sits
        # above the 0.85 FP-wordlist gate, so these are pinned here rather than
        # left to the wordlist, and land at ~0.15.
        "odt" + "_" + "x" * 32,
        "odt" + "_" + "X" * 32,
        "odt" + "_" + "0" * 32,
        "odt" + "_" + "x" * 8 + "_" + "x" * 32,
        "odt" + "_" + "0" * 8 + "_" + "0" * 32,
    },
    recommendation=(
        "Delete this key from the owning team in Dependency-Track under"
        " Administration > Access Management > Teams, and generate a"
        " replacement. Then review the team's permissions: if it holds"
        " BOM_UPLOAD or PROJECT_CREATION, an attacker could have injected"
        " findings as well as read them. Treat every project's SBOM and"
        " vulnerability data reachable by that team as disclosed, and check"
        " the audit log for API activity during the exposure window."
    ),
    tags=["devops", "dependency-track", "sbom", "supply-chain"],
)


# ===================================================
# PIXIE API KEY (2026-09-07)
# ===================================================

# Pixie is the CNCF Kubernetes observability project (New Relic-stewarded, but
# the credential is Pixie's own, so provider is 'pixie' and not 'new-relic').
# The format comes from the vendor's own Apache-2.0 source rather than from
# prose: src/cloud/auth/apikey/api_key.go sets `apiKeyPrefix = "px-api-"` and
# builds a key as `apiKeyPrefix + keyID.String()` where keyID is a
# `uuid.NewV4()` — so the body is a canonical 36-character dashed UUID and the
# whole key is exactly 43 characters.
#
# ONLY 'px-api-' IS SHIPPED. A 'px-dep-' deploy-key variant is sometimes
# claimed elsewhere; it does not appear in api_key.go, so registering it would
# be inventing a format. If it turns up in vendor source later it belongs in
# its own pattern, with its own severity — a deploy key and an API key are
# different credentials.
#
# The UUID's version and variant nibbles are deliberately NOT pinned. The
# generator is uuid.NewV4() today, so they would match, but seven fixed
# vendor-unique characters plus full UUID structure is already a strong anchor
# and pinning generator internals is exactly the kind of over-fit that silently
# stops matching after a library swap.
#
# Severity high: a Pixie API key authenticates against the Pixie Cloud API for
# its org, and Pixie's whole purpose is full-fidelity telemetry — request
# bodies, HTTP headers and database queries from inside the cluster. A leak is
# a data-exfiltration path even though it is not cluster-admin.

PIXIE_API_KEY = SecretPattern(
    id="pixie_api_key",
    name="Pixie API Key",
    description=(
        "Pixie API key — the literal 'px-api-' prefix followed by a canonical"
        " 36-character dashed UUID, 43 characters in total. Authenticates"
        " against the Pixie Cloud API for the owning organization. Pixie"
        " captures full-fidelity Kubernetes telemetry, so a leaked key is a"
        " path to request bodies, headers and database queries collected from"
        " inside the cluster."
    ),
    provider="pixie",
    severity="high",
    # Prefix and body shape are from Pixie's own Apache-2.0 source:
    # src/cloud/auth/apikey/api_key.go sets apiKeyPrefix = "px-api-" and
    # composes the key as that prefix plus a uuid.NewV4() string. Corroborated
    # by https://docs.px.dev/reference/admin/api-keys/. Guards, confidence and
    # known_test_values are ClassiFinder's own.
    # Source: https://github.com/pixie-io/pixie/blob/main/src/cloud/auth/apikey/api_key.go
    regex=re.compile(
        r"(?<![0-9A-Za-z-])"
        r"(?P<secret>px-api-"
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        r"(?![0-9A-Za-z-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # 'px-api-' plus UUID structure carries the precision
    context_keywords=[
        "pixie",
        "px-api",
        "PX_API_KEY",
        "pixie-cloud",
        "px",
        "kubernetes",
    ],
    known_test_values={
        # The nil UUID and the all-f UUID are how Pixie docs, tests and issue
        # reports render a redacted key. confidence_base 0.95 sits above the
        # 0.85 FP-wordlist gate, so they are pinned here and land at ~0.15.
        "px-api-" + "00000000-0000-0000-0000-000000000000",
        "px-api-" + "ffffffff-ffff-ffff-ffff-ffffffffffff",
    },
    recommendation=(
        "Delete this key with `px api-key delete <id>` or in the Pixie Cloud"
        " UI under Admin > API Keys, then issue a replacement. Review what the"
        " key could reach: Pixie collects request and response bodies, HTTP"
        " headers and database queries, so treat the telemetry for the"
        " exposure window as disclosed and rotate any application credentials"
        " that could have appeared inside it."
    ),
    tags=["devops", "pixie", "kubernetes", "observability"],
)


# ===================================================
# PANGEA SERVICE TOKEN (2026-09-11)
# ===================================================

# Pangea sells security services as APIs — Vault, Secure Audit Log, AI Guard,
# Redact, Embargo, File Scan and more — and every one of them authenticates
# with a bearer "service token" carrying the literal 'pts_' prefix. The SDKs
# and the vendor's MCP server read it from a PANGEA_*_TOKEN env family
# (PANGEA_TOKEN, PANGEA_AUDIT_TOKEN, PANGEA_AI_GUARD_TOKEN, PANGEA_VAULT_TOKEN).
#
# THE 32-CHARACTER WIDTH IS THE VENDOR'S, NOT A GUESS. Pangea's docs only ever
# print real tokens elided — 'pts_qbzbij...ajvp3j' — which fixes the charset
# (lowercase alphanumerics) but not the length. The vendor's own
# pangea-mcp-server README fixes the length: it sets PANGEA_VAULT_TOKEN to
# 'pts_' plus exactly thirty-two zeros. Real values measured in public repos
# all carry 32-character lowercase-alnum bodies, and Kingfisher (MongoDB,
# Apache-2.0) rule kingfisher.pangea.1 publishes two examples of the same
# width; that rule was corroboration only and nothing was ported.
#
# BOTH GUARDS ARE LOAD-BEARING BECAUSE 'pts_' IS ONLY FOUR CHARACTERS. It ends
# plenty of English plurals in snake_case — counts_, prompts_, receipts_,
# scripts_ — so the left guard refuses any preceding [A-Za-z0-9_]. The right
# guard refuses the same class, so a 32-character window is never cut out of
# a longer run and half-redacted. The exact {32} body plus both guards is what
# lets this carry prefix-anchored confidence without an entropy gate.
#
# OUT OF SCOPE ON PURPOSE: the same README sets 'pvi_' (vault item ID) and
# 'pci_' (config ID) values of identical shape. Those are identifiers, not
# secrets, and a test pins that neither is claimed here.
#
# Severity high: a service token authorizes every Pangea service it was
# granted — on a Vault-enabled token that means reading the stored secrets
# and keys themselves, and on an audit token, writing tamper-evident log
# entries in the owner's name.

PANGEA_SERVICE_TOKEN = SecretPattern(
    id="pangea_service_token",
    name="Pangea Service Token",
    description=(
        "Pangea service token — the literal 'pts_' prefix followed by exactly"
        " 32 lowercase alphanumerics, 36 characters in total. It is the"
        " bearer credential for Pangea's security APIs (Vault, Secure Audit"
        " Log, AI Guard, Redact and others) and authorizes every service the"
        " token was granted — on a Vault-enabled token, that includes reading"
        " the secrets and keys stored there."
    ),
    provider="pangea",
    severity="high",
    # Prefix and charset from Pangea's own docs, which print real tokens in
    # elided lowercase-alnum form (pangea.cloud/docs/audit/getting-started/
    # multiple-configurations). Width from the vendor's MCP server README,
    # which sets PANGEA_VAULT_TOKEN to 'pts_' + 32 zeros. Guards, confidence
    # and known_test_values are ClassiFinder's own.
    # Source: https://github.com/pangeacyber/pangea-mcp-server/blob/main/README.md
    regex=re.compile(
        r"(?<![A-Za-z0-9_])"
        r"(?P<secret>pts_[a-z0-9]{32})"
        r"(?![A-Za-z0-9_])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # the 'pts_' literal plus an exact width anchors it
    context_keywords=[
        "pangea",
        "PANGEA_TOKEN",
        "PANGEA_AUDIT_TOKEN",
        "PANGEA_VAULT_TOKEN",
        "PANGEA_AI_GUARD_TOKEN",
        "aiguard",
        "bearer",
    ],
    known_test_values={
        # The vendor's own README placeholder ('pts_' + 32 zeros) and the
        # common single-character masks. confidence_base 0.95 sits above the
        # 0.85 FP-wordlist gate, so these are pinned here rather than left to
        # the wordlist, and land at ~0.15.
        "pts" + "_" + "0" * 32,
        "pts" + "_" + "x" * 32,
        "pts" + "_" + "a" * 32,
    },
    recommendation=(
        "Rotate or delete this token in the Pangea User Console on the"
        " project's Tokens page, then issue a replacement granted only the"
        " services that need it. Check which services the token carried: if"
        " it included Vault, treat every secret and key stored there as"
        " disclosed and rotate them; if it included Secure Audit Log, review"
        " the log for entries written during the exposure window. Update"
        " every PANGEA_*_TOKEN variable that held the old value."
    ),
    tags=["devops", "pangea", "security", "api"],
)


# ===================================================
# GUARDSQUARE APPSWEEP API KEY (2026-09-12)
# ===================================================

# Guardsquare AppSweep is a mobile-app security testing service. Its API key is
# what the AppSweep Gradle plugin, the Guardsquare/appsweep-action GitHub Action
# and the Bitrise scan step present to upload an Android build for scanning.
# It is set in build.gradle / build.gradle.kts (appsweep { apiKey = "..." }),
# in a secrets.defaults.properties or gradle.properties line, or read from the
# APPSWEEP_API_KEY environment variable — which is why real keys end up
# committed inside Android projects.
#
# THE 7_32 SPLIT IS EMPIRICAL, AND SAID SO. Guardsquare's own READMEs confirm
# the product and the APPSWEEP_API_KEY name but never print the key format.
# Three independent real keys found in unrelated public Android repos (distinct
# SHA-256 digests, so not one key copied around) all measured exactly
# 'gs_appsweep_' + 7 alphanumerics + '_' + 32 alphanumerics, mixed case in
# both segments, 52 characters in total. Third-party catalog examples of other
# shapes (an 8_23 split, a 24-character unseparated body) are synthetic
# placeholders and are deliberately NOT accepted; widening the body to fit them
# would be inventing format. The vendor placeholder 'gs_appsweep_SOME_API_KEY'
# cannot match the fixed-width composite body.
#
# BOTH GUARDS CARRY THE BODY CHARSET PLUS '_' AND '-', so a key is never carved
# out of a longer identifier or base64url run, and a segment one character too
# long matches nothing at all rather than being truncated and half-redacted.
# The 12-character literal plus the fixed composite body is what lets this carry
# prefix-anchored confidence without an entropy gate.
#
# Severity high: the key authorizes uploading builds to the owner's AppSweep
# organization and reading its scan results — a list of the app's own
# unremediated security findings.

GUARDSQUARE_APPSWEEP_API_KEY = SecretPattern(
    id="guardsquare_appsweep_api_key",
    name="Guardsquare AppSweep API Key",
    description=(
        "Guardsquare AppSweep API key — the literal 'gs_appsweep_' prefix"
        " followed by 7 alphanumerics, an underscore and 32 alphanumerics, 52"
        " characters in total. It is the credential the AppSweep Gradle plugin"
        " and CI integrations use to upload Android builds for security"
        " scanning, and it grants access to the organization's scan results."
    ),
    provider="guardsquare",
    severity="high",
    # Prefix, carriers and the APPSWEEP_API_KEY name from Guardsquare's own
    # appsweep-action and Bitrise-step READMEs; the 7_32 body split measured on
    # three independent real keys in unrelated public Android build files.
    # Guards, confidence and known_test_values are ClassiFinder's own.
    # Source: https://github.com/Guardsquare/appsweep-action
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>gs_appsweep_[A-Za-z0-9]{7}_[A-Za-z0-9]{32})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # the 12-char literal plus a fixed 7_32 body anchors it
    context_keywords=[
        "appsweep",
        "APPSWEEP_API_KEY",
        "guardsquare",
        "apiKey",
        "gradle",
    ],
    known_test_values={
        # The common single-character masks. confidence_base 0.95 sits above
        # the 0.85 FP-wordlist gate, so these are pinned here rather than left
        # to the wordlist, and land at ~0.15.
        "gs" + "_appsweep_" + "x" * 7 + "_" + "x" * 32,
        "gs" + "_appsweep_" + "X" * 7 + "_" + "X" * 32,
        "gs" + "_appsweep_" + "0" * 7 + "_" + "0" * 32,
        "gs" + "_appsweep_" + "a" * 7 + "_" + "a" * 32,
    },
    recommendation=(
        "Revoke this key in the AppSweep web app under the organization's API"
        " keys settings, then create a replacement and store it only as a CI"
        " secret (APPSWEEP_API_KEY) rather than in build.gradle,"
        " build.gradle.kts or a committed properties file. Review the"
        " organization's recent uploads and scan results for activity during"
        " the exposure window, and purge the key from repository history."
    ),
    tags=["devops", "guardsquare", "appsweep", "security", "mobile", "api"],
)


# ===================================================
# AXIOM API TOKEN (2026-09-13)
# ===================================================

# Axiom is a log / event / trace store. Its bearer credentials carry a literal
# four-letter prefix: 'xaat-' for an API token and 'xapt-' for the older
# personal token, which the vendor's clients now flag as deprecated but still
# accept. Both authorize Axiom's ingest and query APIs and are read from
# AXIOM_TOKEN (NEXT_PUBLIC_AXIOM_TOKEN in next-axiom apps), a Wrangler secret,
# or an OTLP 'Authorization: Bearer' header.
#
# THE PREFIXES AND THE BODY LAYOUT ARE BOTH THE VENDOR'S. axiom-go's
# internal/config/token.go tests strings.HasPrefix(token, "xaat-") and
# "xapt-"; axiom-js warns that 'xapt-' personal tokens are deprecated in favour
# of 'xaat-' API tokens. axiom-go's own config_test.go masks both as the prefix
# + 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX', and Cloudflare's Workers docs page
# "Export to Axiom" prints the same 8-4-4-4-12 mask: 41 characters in total.
# The hex is lowercase because that is how a UUID string is rendered. The v4
# version / variant nibbles are deliberately NOT required — no vendor source
# says the body is strictly v4, and pinning them would silently miss a key
# minted any other way.
#
# BOTH GUARDS REFUSE [A-Za-z0-9_-]. The dashed UUID body is exactly what the
# context-gated heroku / hubspot / wise UUID patterns look for; those require
# a separator directly before the UUID, so the 'xaat-' prefix keeps them off,
# and the guards keep this pattern from being carved out of a longer
# hyphenated run. Tests pin a single axiom finding next to those keywords.
#
# Severity high: an API token can ingest into, and depending on its scopes
# query, every dataset it was granted; a personal token acts as the user
# across every organization they belong to.

AXIOM_API_TOKEN = SecretPattern(
    id="axiom_api_token",
    name="Axiom API Token",
    description=(
        "Axiom API token — the literal 'xaat-' prefix (or 'xapt-' for the"
        " deprecated personal token) followed by a lowercase dashed UUID, 41"
        " characters in total. Authorizes Axiom's ingest and query APIs for"
        " the datasets it was granted; a personal token acts as its user."
    ),
    provider="axiom",
    severity="high",
    # Prefixes from axiom-go internal/config/token.go (IsAPIToken 'xaat-',
    # IsPersonalToken 'xapt-'); 8-4-4-4-12 body from the vendor's own
    # config_test.go masks, corroborated by Cloudflare's Workers docs at
    # https://developers.cloudflare.com/workers/observability/exporting-opentelemetry-data/axiom/
    # Guards, confidence and known_test_values are ClassiFinder's own.
    # Source: https://github.com/axiomhq/axiom-go/blob/main/internal/config/config_test.go
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>xa[ap]t-"
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # 'xaat-'/'xapt-' plus UUID structure carries the precision
    context_keywords=[
        "axiom",
        "AXIOM_TOKEN",
        "NEXT_PUBLIC_AXIOM_TOKEN",
        "xaat-",
        "xapt-",
    ],
    known_test_values={
        # The nil UUID and the all-f UUID are how docs and issue reports render
        # a redacted token. confidence_base 0.95 sits above the 0.85
        # FP-wordlist gate, so they are pinned here and land at ~0.15.
        "xa" + "at-" + "00000000-0000-0000-0000-000000000000",
        "xa" + "at-" + "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "xa" + "pt-" + "00000000-0000-0000-0000-000000000000",
        "xa" + "pt-" + "ffffffff-ffff-ffff-ffff-ffffffffffff",
    },
    recommendation=(
        "Delete this token in the Axiom console (the organization's API tokens"
        " for 'xaat-', your profile's personal tokens for 'xapt-'), then create"
        " a replacement scoped to"
        " only the datasets and actions it needs, preferring an 'xaat-' API"
        " token over a deprecated 'xapt-' personal token. Review the affected"
        " datasets for unexpected ingest or queries during the exposure window,"
        " and purge the token from repository history."
    ),
    tags=["devops", "axiom", "observability", "logging", "api"],
)


# ===================================================
# CODE CLIMATE TEST REPORTER ID (2026-09-14)
# ===================================================

# Code Climate's test-coverage upload credential: the "test reporter ID"
# (CC_TEST_REPORTER_ID, read by the current cc-test-reporter) or, for the
# older per-language reporters, the "repo token" (CODECLIMATE_REPO_TOKEN).
# Either is 64 lowercase hex characters with no prefix, so the pattern is
# KEY-NAME ANCHORED: one of those two variable names, a ':' or '=' separator
# with optional quotes and whitespace, then exactly 64 hex characters. The
# format comes from Nosey Parker rule np.codeclimate.1 (Apache-2.0); the
# guards, the separator set, the confidence tier and the known_test_values
# are ClassiFinder's own.
#
# THE KEY NAME CONTAINS 'TEST', SO THE PRICING WAS CHECKED. The FP wordlist
# lists 'test' and takes -0.40 off any finding priced under 0.85. The scanner
# runs the wordlist on the SECRET group only — the hex value, never
# 'CC_TEST_REPORTER_ID' — so the anchor itself cannot sink a finding. The
# hex value can, though: the default FP list includes the hex-legal runs
# '000000' and 'aaaaaa', so a keyword-anchored pattern priced in the usual
# 0.6-0.8 band would silently lose the occasional real value. confidence_base
# 0.90 keeps every real value above the gate, where the wordlist never runs;
# a test proves a realistic value (and one containing '000000') scores >= 0.85.
#
# Severity medium: the token only uploads coverage for one repository — but a
# leaked one lets anyone publish fraudulent coverage and quality signals.

CODECLIMATE_REPORTER_ID = SecretPattern(
    id="codeclimate_reporter_id",
    name="Code Climate Test Reporter ID",
    description=(
        "Code Climate test reporter ID / repo token — 64 lowercase hex"
        " characters assigned to CC_TEST_REPORTER_ID (or the legacy"
        " CODECLIMATE_REPO_TOKEN). Authorizes uploading test-coverage reports"
        " for the repository it belongs to."
    ),
    provider="codeclimate",
    severity="medium",
    # Key names + 64-hex body from Nosey Parker rule np.codeclimate.1
    # (crates/noseyparker/data/default/builtin/rules/codeclimate.yml, Apache-2.0).
    # Source: https://github.com/praetorian-inc/noseyparker
    regex=re.compile(
        r"(?<![A-Za-z0-9_])"
        r"(?:CC_TEST_REPORTER_ID|CODECLIMATE_REPO_TOKEN)"
        r"[\"']?[ \t]*(?:=|:)[ \t]*[\"']?"
        r"(?P<secret>[a-f0-9]{64})"
        r"(?![A-Za-z0-9_])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,  # fixed-width hex is capped at 4.0 bits; the key name carries precision
    context_keywords=[
        "codeclimate",
        "code climate",
        "cc-test-reporter",
        "CC_TEST_REPORTER_ID",
        "CODECLIMATE_REPO_TOKEN",
        "coverage",
    ],
    known_test_values={
        "0" * 64,
        "f" * 64,
        "a" * 64,
    },
    recommendation=(
        "Regenerate the test reporter ID in Code Climate (Repo Settings > Test"
        " coverage > Test Reporter ID > Regenerate) and update the CI secret"
        " that sets CC_TEST_REPORTER_ID. Store it as a CI secret rather than in"
        " a committed workflow or .travis.yml, and review the repository's"
        " recent coverage uploads for reports you did not send."
    ),
    tags=["devops", "codeclimate", "ci", "coverage"],
)


# ===================================================
# DJANGO SECRET_KEY — 'django-insecure-' (2026-09-14)
# ===================================================

# 'django-admin startproject' writes SECRET_KEY into settings.py as
# SECRET_KEY_INSECURE_PREFIX + get_random_secret_key(), i.e. the literal
# 'django-insecure-' followed by get_random_string(50, chars) with
#
#   chars = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)"
#
# (django/core/management/utils.py). The body is therefore EXACTLY 50
# characters from that 50-character alphabet: lower-case letters, digits and
# fourteen punctuation marks. A naive [A-Za-z0-9] body would under-match —
# most real keys contain '(', ')', '#', '$', '^', '&', '*' or '+' — so the
# class spells the full alphabet, with '-' escaped, and the right guard uses
# the same alphabet (plus upper-case letters, which Django never emits) so a
# 51-character run — or a 50-character run glued to more text — matches
# nothing.
#
# WHY IT IS A SECRET: SECRET_KEY signs sessions, password-reset tokens,
# messages and anything passed through django.core.signing. Holding it lets
# an attacker forge those — and, with pickle-based session serializers, reach
# code execution. The 'insecure' prefix is Django's own warning that the key
# was generated for development and must be replaced before deployment; a
# finding means it was not, or that a development key leaked alongside code.
#
# THE MATCHED VALUE ALWAYS CONTAINS 'insecure', WHICH IS ON THE FP WORDLIST.
# A confidence_base under 0.85 would take -0.40 on EVERY real key. 0.95 sits
# above the gate, so the wordlist never applies; a test pins that.

DJANGO_INSECURE_SECRET_KEY = SecretPattern(
    id="django_insecure_secret_key",
    name="Django Secret Key (django-insecure-)",
    description=(
        "Django SECRET_KEY as generated by 'django-admin startproject' — the"
        " literal 'django-insecure-' prefix followed by exactly 50 characters"
        " from Django's secret-key alphabet (a-z, 0-9 and !@#$%^&*(-_=+))."
        " Signs sessions, password-reset tokens and signed data."
    ),
    provider="django",
    severity="high",
    # Prefix (SECRET_KEY_INSECURE_PREFIX) and the 50-character alphabet from
    # django/core/management/utils.py get_random_secret_key().
    # Source: https://github.com/django/django/blob/main/django/core/management/utils.py
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>django-insecure-[a-z0-9!@#$%^&*()_=+\-]{50})"
        r"(?![A-Za-z0-9!@#$%^&*()_=+\-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # generator-fixed width and alphabet; a floor could only sink real keys
    context_keywords=[
        "django",
        "SECRET_KEY",
        "DJANGO_SECRET_KEY",
        "settings.py",
        "django-insecure-",
    ],
    known_test_values={
        # Single-character fills are how a redacted key gets written down.
        "django-" + "insecure-" + "x" * 50,
        "django-" + "insecure-" + "0" * 50,
        "django-" + "insecure-" + "*" * 50,
    },
    recommendation=(
        "Generate a new key (python -c 'from django.core.management.utils"
        " import get_random_secret_key; print(get_random_secret_key())'), load"
        " it from the environment or a secrets manager instead of settings.py,"
        " and deploy it. Rotating SECRET_KEY invalidates every session and"
        " password-reset link, which is the point; on Django 4.1+ move the old"
        " key into SECRET_KEY_FALLBACKS only if you must keep signed data"
        " valid briefly. Never deploy a 'django-insecure-' key to production."
    ),
    tags=["devops", "django", "framework", "signing-key"],
)


# ===================================================
# LAUNCHDARKLY SDK KEY — 'sdk-' (2026-09-14)
# ===================================================

# LaunchDarkly's server-side SDK key. The vendor's keys page states "SDK keys
# always start with the prefix sdk-"; the body is a lowercase dashed UUID in
# 8-4-4-4-12 groups (real values are v4, but the version / variant nibbles are
# deliberately not required — no vendor source pins them). The mobile key
# ('mob-') and the dash-free client-side ID are designed to be public and are
# NOT matched; neither is the bare UUID.
#
# confidence_base 0.90, one notch under the 0.95 prefix tier, because 'sdk-'
# is a generic-sounding four-character prefix that another vendor could plausibly
# put in front of a UUID. The full-UUID body and the guards carry the rest of
# the precision, and 0.90 still sits above the 0.85 FP-wordlist gate.
#
# OVERLAP WITH launchdarkly_access_token: that pattern is context-gated
# ('LAUNCHDARKLY…KEY=' + any 40 characters of [A-Za-z0-9._-]), and 'sdk-' + a
# UUID is exactly 40 such characters — so before this pattern an SDK key
# behind LAUNCHDARKLY_SDK_KEY= was mislabelled as a REST access token. Both
# now fire on the same span; this one prices at 0.90 + context against that
# one's 0.80 + context, so dedup keeps the specific reading. A test pins it.

LAUNCHDARKLY_SDK_KEY = SecretPattern(
    id="launchdarkly_sdk_key",
    name="LaunchDarkly SDK Key",
    description=(
        "LaunchDarkly server-side SDK key — the literal 'sdk-' prefix followed"
        " by a lowercase dashed UUID, 40 characters in total. Lets a server-side"
        " SDK read every flag and segment in its environment."
    ),
    provider="launchdarkly",
    severity="high",
    # "SDK keys always start with the prefix sdk-" per LaunchDarkly's keys docs;
    # the UUID body is the verified shape of real keys.
    # Format per https://launchdarkly.com/docs/home/account/environment/keys
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>sdk-"
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,  # 'sdk-' plus UUID structure carries the precision
    context_keywords=[
        "launchdarkly",
        "LAUNCHDARKLY_SDK_KEY",
        "LD_SDK_KEY",
        "ldclient",
        "sdk_key",
        "sdkKey",
    ],
    known_test_values={
        "sd" + "k-" + "00000000-0000-0000-0000-000000000000",
        "sd" + "k-" + "ffffffff-ffff-ffff-ffff-ffffffffffff",
    },
    recommendation=(
        "Reset this SDK key in LaunchDarkly (Organization settings > Projects >"
        " the environment's keys > Reset SDK key; optionally keep the old key"
        " valid for a short grace period) and redeploy the servers that use"
        " it. An SDK key exposes every flag rule, segment and targeted context"
        " in its environment — often including user identifiers and internal"
        " rollout plans — so it must never ship to a browser or mobile app."
    ),
    tags=["devops", "launchdarkly", "feature-flag", "sdk"],
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
    # Batch 9 — vendor-sourced patterns (2026-06-29)
    ADAFRUIT_IO_KEY,
    # Batch 10 — vendor-sourced patterns (2026-07-06)
    NGROK_AUTHTOKEN,
    OPSGENIE_API_KEY,
    CLOJARS_DEPLOY_TOKEN,
    # Batch 12 — vendor-sourced patterns (2026-07-13)
    DOCKER_ACCESS_TOKEN,
    ROOTLY_API_KEY,
    # Batch 13 — vendor-sourced patterns (2026-07-18)
    CISCO_MERAKI_API_KEY,
    # 2026-07-15 — Inngest signing key (prefix-anchored, vendor sourced)
    INNGEST_SIGNING_KEY,
    # Batch 13 — vendor-sourced pattern (2026-07-17)
    WAKATIME_API_KEY,
    # 2026-07-27 — Zuplo consumer API key (vendor sourced, CRC32-checksummed)
    ZUPLO_CONSUMER_API_KEY,
    # 2026-07-27 — Cfx.re server key (vendor sourced, bounds tightened)
    CFXRE_SERVER_KEY,
    # 2026-07-29 — Trigger.dev secret key (tr_<env>_ prefix, generator-sourced)
    TRIGGER_DEV_SECRET_KEY,
    # 2026-08-03 — Thunderstore API token ('tss_' + 30 random + 6-char CRC32 checksum)
    THUNDERSTORE_API_TOKEN,
    # 2026-08-25 — Logfire write token (vendor SDK parsing regex,
    # pylf_v<version>_<region>_ + optional org UUID + 44-char body)
    LOGFIRE_WRITE_TOKEN,
    # 2026-08-24 — SettleMint personal + application access tokens
    # (vendor SDK masking regex) and the Docker Swarm join token
    # (swarmkit CA constants: 50-char base-36 digest + 25-char secret).
    SETTLEMINT_PERSONAL_ACCESS_TOKEN,
    SETTLEMINT_APPLICATION_ACCESS_TOKEN,
    DOCKER_SWARM_JOIN_TOKEN,
    # 2026-08-29 — Unleash API token (vendor generator: crypto.randomBytes(28)
    # hex behind a mandatory '<projects>:<environment>.' structure)
    UNLEASH_API_TOKEN,
    # 2026-08-30 — Portainer API access token (vendor generator: 'ptr_' +
    # base64.StdEncoding of 32 random bytes = 43 chars + one '=' pad)
    PORTAINER_API_ACCESS_TOKEN,
    # 2026-08-31 — CircleCI v2 prefixed API tokens ('CCIPAT_' personal,
    # 'CCIPRJ_' project: 22 base58 + '_' + the legacy 40-hex value) and
    # the Docker Swarm unlock key ('SWMKEY-1-' + 43 unpadded base64).
    CIRCLECI_PERSONAL_ACCESS_TOKEN,
    CIRCLECI_PROJECT_ACCESS_TOKEN,
    DOCKER_SWARM_UNLOCK_KEY,
    # 2026-09-07 — Dependency-Track API key in BOTH documented forms
    # (legacy 'odt_' + 32, and the 4.13.0+ 'odt_<publicId>_<key>'),
    # and the Pixie API key ('px-api-' + a UUID, from Pixie's own
    # Apache-2.0 api_key.go).
    DEPENDENCY_TRACK_API_KEY,
    PIXIE_API_KEY,
    # 2026-09-11 — Pangea service token ('pts_' + exactly 32 lowercase
    # alphanumerics; width fixed by the vendor's own MCP server README).
    PANGEA_SERVICE_TOKEN,
    # 2026-09-12 — Guardsquare AppSweep API key ('gs_appsweep_' + 7 alnum +
    # '_' + 32 alnum; split measured on three independent real keys).
    GUARDSQUARE_APPSWEEP_API_KEY,
    # 2026-09-13 — Axiom API token ('xaat-', or the deprecated personal
    # 'xapt-', + a lowercase dashed UUID; prefixes and layout from axiom-go).
    AXIOM_API_TOKEN,
    # 2026-09-14 — Code Climate test reporter ID (key-name anchored 64 hex;
    # Nosey Parker np.codeclimate.1), Django 'django-insecure-' SECRET_KEY
    # (50 chars from Django's own secret-key alphabet), and the LaunchDarkly
    # server-side SDK key ('sdk-' + lowercase dashed UUID).
    CODECLIMATE_REPORTER_ID,
    DJANGO_INSECURE_SECRET_KEY,
    LAUNCHDARKLY_SDK_KEY,
)
