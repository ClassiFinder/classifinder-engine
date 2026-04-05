# ClassiFinder Engine

The open-source core of [ClassiFinder](https://classifinder.ai) — the secret scanner built for AI pipelines.

This is the code that touches your data. It's published here so you can read it yourself and verify that it does exactly what we claim: scan text for secrets, return findings, and discard everything. No I/O, no side effects, no storage.

## What's Here

The scanner engine is a pure function: **text in, findings out.** It has no database calls, no file writes, no network requests, no logging of secret values. It runs entirely in memory.

```
classifinder-engine/
├── scanner.py          # Core scan() function — the heart of the product
├── redactor.py         # redact() function — replaces secrets with safe labels
├── entropy.py          # Shannon entropy calculator for confidence scoring
└── patterns/
    ├── registry.py     # Pattern registry and SecretPattern dataclass
    ├── cloud.py        # AWS, GCP, Azure, DigitalOcean, Heroku, Cloudflare, Doppler, Terraform, Vault, Pulumi, Fly.io, Alibaba, Vercel, Netlify, IBM Cloud (19 patterns)
    ├── payment.py      # Stripe, PayPal, Square, Shopify, credit cards with Luhn validation, Ethereum, Bitcoin (13 patterns)
    ├── vcs.py          # GitHub, GitLab, Bitbucket, CircleCI, npm, PyPI, RubyGems, Airtable, NuGet (14 patterns)
    ├── comms.py        # Slack, Twilio, SendGrid, Mailgun, Discord, Telegram, New Relic, Grafana, Linear, Notion, Sentry, Datadog, PagerDuty, Figma, Auth0 (22 patterns)
    ├── database.py     # PostgreSQL, MySQL, MongoDB, Redis, SSH keys, .env passwords, Supabase (8 patterns)
    ├── generic.py      # JWT, Bearer, Basic Auth, generic API keys, high-entropy strings (5 patterns)
    └── ai.py           # OpenAI, Anthropic, Cohere, HuggingFace, Replicate, Groq, DeepSeek (7 patterns)
```

**101 detection patterns** across 7 categories. Each pattern includes a regex, base confidence score, entropy threshold, context keywords, known test values, and remediation guidance.

## How It Works

```python
from scanner import scan
from redactor import redact

# Scan text for secrets
findings = scan("AWS_ACCESS_KEY_ID=AKIAJGKJHSKLDJFH3284")
# Returns: [Finding(type="aws_access_key", confidence=0.95, severity="critical", ...)]

# Redact secrets from text
redacted_text, redaction_map = redact(text, findings, style="label")
# Returns: ("AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]", [...])
```

The `scan()` function:
1. Runs all 101 regex patterns against the input
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

Want a ready-to-use CLI? [cfsniff](https://github.com/ThomasParas/cfsniff) wraps the ClassiFinder API to scan files, shell history, and configs for secrets (`pipx install cfsniff`).

## License

MIT
