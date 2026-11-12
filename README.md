# ClassiFinder Engine

[![PyPI version](https://img.shields.io/pypi/v/classifinder-engine.svg)](https://pypi.org/project/classifinder-engine/) [![Python versions](https://img.shields.io/pypi/pyversions/classifinder-engine.svg)](https://pypi.org/project/classifinder-engine/) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

[![Provenance: PyPI Trusted Publishing](https://img.shields.io/badge/provenance-PyPI%20trusted%20publishing%20%2B%20PEP%20740-brightgreen.svg)](https://pypi.org/project/classifinder-engine/)

The open-source core of [ClassiFinder](https://classifinder.ai) — the secret scanner built for AI pipelines.

This is the code that touches your data. It's published here so you can read it yourself and verify that it does exactly what we claim: scan text for secrets, return findings, and discard everything. No I/O, no side effects, no storage.

## Install

```bash
pip install classifinder-engine
```

Zero runtime dependencies. Pure Python 3.12+.

## What's Here

The scanner engine is a pure function: **text in, findings out.** It has no database calls, no file writes, no network requests, no logging of secret values. It runs entirely in memory.

```
classifinder-engine/
└── classifinder_engine/
    ├── __init__.py         # Package entry: re-exports scan, redact, Finding, PATTERN_REGISTRY
    ├── scanner.py          # Core scan() function — the heart of the product
    ├── redactor.py         # redact() function — replaces secrets with safe labels
    ├── entropy.py          # Shannon entropy calculator for confidence scoring
    ├── decoders.py         # Base64 pre-scan decoder
    ├── false_positives.py  # Known-junk wordlist filter
    ├── data/               # fp_wordlist.txt
    └── patterns/
        ├── registry.py     # Pattern registry and SecretPattern dataclass
        ├── cloud.py            # AWS, GCP, Azure, Vercel, Fly.io, Doppler, Vault, and other cloud/infra keys (22 patterns) <!-- pattern-count-ignore: per-file count, not total -->
        ├── payment.py          # Stripe, PayPal, Square, Shopify, credit cards, crypto (14 patterns) <!-- pattern-count-ignore -->
        ├── vcs.py              # GitHub, GitLab, Bitbucket, CircleCI, npm, PyPI, package registries (14 patterns) <!-- pattern-count-ignore -->
        ├── comms.py            # Slack, Twilio, SendGrid, Datadog, Sentry, PagerDuty, observability and incident tools (25 patterns) <!-- pattern-count-ignore -->
        ├── database.py         # PostgreSQL, MySQL, MongoDB, Redis, Supabase, SSH, env passwords (8 patterns) <!-- pattern-count-ignore -->
        ├── generic.py          # JWT, Bearer, Basic Auth, generic API keys, high-entropy (5 patterns) <!-- pattern-count-ignore -->
        ├── ai.py               # OpenAI, Anthropic (user + admin), Cohere, xAI, Mistral, DeepSeek, HuggingFace, Replicate, Groq, ElevenLabs, AssemblyAI, Deepgram, LangFuse, AWS Bedrock, Vercel AI Gateway, Weights & Biases (18 patterns) <!-- pattern-count-ignore -->
        └── prompt_injection.py # Role-hijack tokens, jailbreak personas, instruction-override phrases — 4 phase-1 + 6 phase-2 (10 patterns) <!-- pattern-count-ignore -->
```

**463 detection patterns** — 449 secret types across 10 categories + 14 prompt-injection markers (4 phase-1 high-precision + 6 phase-2 medium-precision + 4 phase-3 SAFE-MCP-derived). Each pattern includes a regex, base confidence score, entropy threshold, context keywords, known test values, and remediation guidance.

## How It Works

```python
from classifinder_engine import scan, redact

# Scan text for secrets
findings = scan("AWS_ACCESS_KEY_ID=AKIAJGKJHSKLDJFH3284")
# Returns: [Finding(type="aws_access_key", confidence=0.95, severity="critical", ...)]

# Redact secrets from text
redacted_text, redaction_map = redact(text, findings, style="label")
# Returns: ("AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]", [...])
```

The `scan()` function:
1. Runs all 463 regex patterns against the input
2. Calculates confidence: `base + context_boost (+0.02/keyword, max +0.10) - entropy_penalty (-0.50 if below threshold) → override to 0.15 if test value → clamp [0.05, 0.99]`
3. Deduplicates overlapping findings (highest confidence wins)
4. Returns structured findings sorted by position

The `redact()` function:
1. Takes scan findings and replaces each secret in the original text
2. Processes spans in reverse order so replacements don't shift offsets
3. Supports three styles: `label` → `[AWS_ACCESS_KEY_REDACTED]`, `mask` → `AKIA**************`, `hash` → `[REDACTED:sha256:a1b2c3d4]`

## Self-host with Docker

Run the full ClassiFinder API on your own infrastructure. The image wraps this engine in the same HTTP server that runs at `api.classifinder.ai`. Your text never leaves your network.

```bash
docker run -d --name classifinder -p 8000:8000 \
  -e CLASSIFINDER_API_KEYS=change-me \
  ghcr.io/classifinder/classifinder:latest
```

```bash
curl -s -X POST http://localhost:8000/v1/redact \
  -H 'X-API-Key: change-me' -H 'Content-Type: application/json' \
  -d '{"text":"Deploy with AWS_ACCESS_KEY_ID=AKIAQWERTYUIOPASDFGH"}'
```

```json
{
  "findings_count": 1,
  "redacted_text": "Deploy with AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]",
  "findings": [
    { "type": "aws_access_key", "severity": "critical", "confidence": 0.99,
      "span": { "start": 30, "end": 50 }, "redacted_as": "[AWS_ACCESS_KEY_REDACTED]" }
  ],
  "summary": { "critical": 1, "high": 0, "medium": 0, "low": 0 }
}
```

Interactive API docs are served at `http://localhost:8000/docs`.

### What's in the image

- **Platforms:** `linux/amd64` and `linux/arm64` (Apple Silicon, Graviton).
- **Base:** `python:3.12-slim`, running as a non-root user. About 275 MB.
- **No database, no volume, no outbound calls.** The server holds nothing between requests, and it logs only metadata (request id, endpoint, input size, finding count, latency, status). It never logs request bodies or secret values.
- **Built in CI from the commit that deployed production.** Every merge to `main` publishes a new image, so the self-hosted pattern set matches the hosted API.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `CLASSIFINDER_API_KEYS` | *(empty)* | **Required.** Comma-separated keys accepted in the `X-API-Key` header. With none set, every request returns 401 and a warning is logged at startup. Any string works; use something long and random. |
| `CLASSIFINDER_RATE_LIMIT_PER_MINUTE` | `60` | Requests per minute per key. Raise it for internal pipelines. |
| `CLASSIFINDER_MAX_PAYLOAD_BYTES` | `262144` | Max request body (256 KB). |
| `WEB_CONCURRENCY` | `2` | Uvicorn worker processes. The rate limit is per worker, so the effective limit is workers × the per-minute value. |

### Endpoints

| Method | Path | Auth |
|---|---|---|
| `POST` | `/v1/scan` | `X-API-Key` |
| `POST` | `/v1/redact` | `X-API-Key` |
| `GET` | `/v1/types` | `X-API-Key` |
| `GET` | `/v1/health` | none (used by the container `HEALTHCHECK`) |

`/v1/keys/*` and `/v1/feedback` exist for the hosted service; with no database configured they return a clear error or write metadata to stdout.

### Docker Compose

```yaml
services:
  classifinder:
    image: ghcr.io/classifinder/classifinder:latest
    ports: ["127.0.0.1:8000:8000"]
    environment:
      CLASSIFINDER_API_KEYS: ${CLASSIFINDER_API_KEYS:?set a key}
      CLASSIFINDER_RATE_LIMIT_PER_MINUTE: "600"
    read_only: true
    tmpfs: [/tmp]
    restart: unless-stopped
```

### Using it from Python

The [Python SDK](https://pypi.org/project/classifinder/) takes a `base_url`:

```python
from classifinder import ClassiFinder

client = ClassiFinder(api_key="change-me", base_url="http://localhost:8000")
result = client.redact("my key is AKIAQWERTYUIOPASDFGH")
print(result.redacted_text)
```

### Tags

| Tag | Meaning |
|---|---|
| `latest` | Current `main`, same build as production |
| `YYYY.MM.DD-<sha7>` | Immutable build from a given day and commit. Pin this in production. |
| `sha-<full sha>` | Immutable, by commit |

### Verifying the image

Each image carries an SBOM and SLSA build provenance, attached by BuildKit in GitHub Actions:

```bash
docker buildx imagetools inspect ghcr.io/classifinder/classifinder:latest \
  --format '{{ json .Provenance }}'
docker buildx imagetools inspect ghcr.io/classifinder/classifinder:latest \
  --format '{{ json .SBOM }}'
```

The server code is plain Python at `/app` inside the image, so you can read exactly what runs:

```bash
docker run --rm --entrypoint sh ghcr.io/classifinder/classifinder:latest -c 'ls -R /app | head'
```

## The Hosted Service

Don't want to run a container? [ClassiFinder](https://classifinder.ai) hosts the same server as a fast, stateless API with auth, rate limiting, a Python SDK (`pip install classifinder`), and a LangChain integration. Free tier: 60 requests/minute, no credit card required.

Want a ready-to-use CLI? [cfsniff](https://github.com/ClassiFinder/cfsniff) wraps the ClassiFinder API to scan files, shell history, and configs for secrets (`pipx install cfsniff`).

## Verifying This Build

Every release is published via [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) with [PEP 740 build attestations](https://docs.pypi.org/attestations/). No long-lived API tokens. The wheel you `pip install` is byte-identical to what GitHub Actions built from a tagged commit.

To verify a release: visit the [project page on PyPI](https://pypi.org/project/classifinder-engine/), click **Download files**, and check the **Provenance** section under each artifact. You'll see the sigstore attestation, the GitHub workflow run, and the exact commit SHA — all logged to the public [Sigstore transparency log](https://search.sigstore.dev/) for independent verification.

This answers "is the wheel what's in the source?" — the cryptographic chain proves this wheel was built from `ClassiFinder/classifinder-engine` at the tagged commit, by a GitHub-hosted runner, and cannot be tampered with after the fact.

## License

MIT

See [ATTRIBUTION.md](./ATTRIBUTION.md) for third-party notices and pattern provenance.
