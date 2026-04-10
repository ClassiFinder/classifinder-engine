# Contributing to ClassiFinder Engine

Thanks for your interest in contributing! This is the open-source scanner engine that powers [ClassiFinder](https://classifinder.ai). Contributions that improve detection accuracy, reduce false positives, or add new secret patterns are especially welcome.

## Getting Started

```bash
git clone https://github.com/classifinder/classifinder-engine.git
cd classifinder-engine
python -c "from scanner import scan; print(scan('AKIAIOSFODNN7EXAMPLE'))"
```

No dependencies beyond the Python 3.12+ standard library.

## Ways to Contribute

### Report a False Positive or False Negative

If the engine misclassifies text, [open an issue](https://github.com/classifinder/classifinder-engine/issues) with:

- The input text (use a fake/test value — never post real secrets)
- What the engine returned
- What you expected

You can also report these via the ClassiFinder API's `POST /v1/feedback` endpoint.

### Add a New Detection Pattern

Each pattern lives in one of the category files under `patterns/`:

| File | Category |
|------|----------|
| `cloud.py` | Cloud provider credentials (AWS, GCP, Azure, etc.) |
| `payment.py` | Payment and financial (Stripe, PayPal, credit cards) |
| `vcs.py` | Version control and CI/CD (GitHub, GitLab, CircleCI) |
| `comms.py` | Communications and SaaS (Slack, Twilio, SendGrid) |
| `database.py` | Database and infrastructure (connection strings, SSH keys) |
| `generic.py` | Format-based tokens (JWT, Bearer, Basic Auth, high-entropy) |
| `ai.py` | AI/LLM provider keys (OpenAI, Anthropic, Cohere) |

To add a pattern, create a `SecretPattern` instance with:

- `id` — unique snake_case identifier
- `name` — human-readable name
- `pattern` — compiled regex
- `base_confidence` — 0.60 for format-only, 0.90 for structural, 0.95 for prefix-anchored
- `severity` — "critical", "high", "medium", or "low"
- `provider` — service name (lowercase)
- `entropy_threshold` — minimum Shannon entropy (set to `None` to skip entropy check)
- `context_keywords` — list of nearby keywords that boost confidence
- `known_test_values` — list of documented example/test values to penalize
- `recommendation` — actionable remediation advice

Then register it in `patterns/registry.py` by adding it to `PATTERN_REGISTRY`.

### Improve an Existing Pattern

If a pattern's regex is too broad (false positives) or too narrow (misses valid secrets), open a PR with the fix and include test cases showing the before/after.

### Tune Confidence Scoring

The generic patterns (`generic_api_key_env`, `generic_high_entropy`) are the most false-positive-prone. Their accuracy depends on two parameters in the pattern definition:

- `entropy_threshold` — minimum Shannon entropy to avoid the confidence penalty (currently 3.0 for `generic_api_key_env`, 4.5 for `generic_high_entropy`)
- The entropy penalty itself — currently -0.50 in `scanner.py`

These values were tuned using `classifinder-benchmark/` (private), which scans public GitHub files and collects metadata-only signals (type, confidence, entropy, file context). If you're proposing threshold changes, include before/after data showing the impact on false positive rates. The `classifinder-tests/` corpus suite must pass with zero regressions.

## Code Style

- Python 3.12+, type hints on all functions
- No external dependencies — this engine must remain dependency-free
- No I/O of any kind — no file reads, no network calls, no logging of secret values
- PEP 8, 100-character line limit

## Writing Tests

Tests live in `tests/` and run with `python -m pytest tests/ -v`.

**Important:** GitHub push protection will block commits containing secret-like strings (e.g., `sk_live_*`, `ghp_*`). Since this is a secret scanner, our tests inherently need these patterns. Build test secrets at runtime instead of writing them as string literals:

```python
# Bad — GitHub blocks the push
scan("sk_live_" + "51H7bKLkdFJH38djfhKSDJfh29fhsdkjfh3")

# Good — assembled at runtime, invisible to static scanning
prefix = "sk_live_"
scan(f"STRIPE_KEY={prefix}{'0' * 32}")
```

This only affects prefixes that GitHub recognizes (Stripe, GitHub PATs, etc.). Most patterns are fine as plain strings.

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Include test cases for any new or modified patterns (input text + expected finding)
4. Ensure all existing tests still pass
5. Open a PR with a clear description of what changed and why

## Important: Engine Sync

This engine is mirrored in the hosted ClassiFinder API. Changes accepted here will be synced to the API server. This is handled by the maintainer — you don't need to worry about it.

## Security

If you discover a security vulnerability in the engine itself, please email security@classifinder.ai rather than opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
