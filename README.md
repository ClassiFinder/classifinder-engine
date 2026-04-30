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
        ├── cloud.py        # AWS, GCP, Azure, and other cloud-provider keys (22 patterns)
        ├── payment.py      # Stripe, PayPal, Square, Shopify, credit cards, crypto (14 patterns)
        ├── vcs.py          # GitHub, GitLab, Bitbucket, CircleCI, package registries (14 patterns)
        ├── comms.py        # Slack, Twilio, SendGrid, observability and incident tools (25 patterns)
        ├── database.py     # PostgreSQL, MySQL, MongoDB, Redis, SSH, env passwords (8 patterns)
        ├── generic.py      # JWT, Bearer, Basic Auth, generic API keys, high-entropy (5 patterns)
        └── ai.py           # OpenAI, Anthropic, Cohere, HuggingFace, and other LLM provider keys (18 patterns)
```

**106 detection patterns** across 7 categories. Each pattern includes a regex, base confidence score, entropy threshold, context keywords, known test values, and remediation guidance.

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
1. Runs all 106 regex patterns against the input
2. Calculates confidence: `base + context_boost (+0.02/keyword, max +0.10) - entropy_penalty (-0.50 if below threshold) → override to 0.15 if test value → clamp [0.05, 0.99]`
3. Deduplicates overlapping findings (highest confidence wins)
4. Returns structured findings sorted by position

The `redact()` function:
1. Takes scan findings and replaces each secret in the original text
2. Processes spans in reverse order so replacements don't shift offsets
3. Supports three styles: `label` → `[AWS_ACCESS_KEY_REDACTED]`, `mask` → `AKIA**************`, `hash` → `[REDACTED:sha256:a1b2c3d4]`

## What's NOT Here

The hosted API layer (routes, middleware, auth, rate limiting, key provisioning) is not open-source. That's the business. What's here is the code that processes your text — the part you'd want to audit.

## Dockerfile

The included `Dockerfile` shows exactly what runs in production: Python 3.12, FastAPI, Uvicorn. No database driver, no persistent volume, no logging SDK that captures request bodies. A container with a small surface area.

## The Hosted Service

Don't want to run this yourself? [ClassiFinder](https://classifinder.ai) wraps this engine in a fast, stateless API with auth, rate limiting, a Python SDK (`pip install classifinder`), and a LangChain integration. Free tier: 60 requests/minute, no credit card required.

Want a ready-to-use CLI? [cfsniff](https://github.com/ClassiFinder/cfsniff) wraps the ClassiFinder API to scan files, shell history, and configs for secrets (`pipx install cfsniff`).

## Verifying This Build

Every release is published via [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) with [PEP 740 build attestations](https://docs.pypi.org/attestations/). No long-lived API tokens. The wheel you `pip install` is byte-identical to what GitHub Actions built from a tagged commit.

To verify a release: visit the [project page on PyPI](https://pypi.org/project/classifinder-engine/), click **Download files**, and check the **Provenance** section under each artifact. You'll see the sigstore attestation, the GitHub workflow run, and the exact commit SHA — all logged to the public [Sigstore transparency log](https://search.sigstore.dev/) for independent verification.

This answers "is the wheel what's in the source?" — the cryptographic chain proves this wheel was built from `ClassiFinder/classifinder-engine` at the tagged commit, by a GitHub-hosted runner, and cannot be tampered with after the fact.

## License

MIT

See [ATTRIBUTION.md](./ATTRIBUTION.md) for third-party notices and pattern provenance.
