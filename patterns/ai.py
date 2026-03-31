"""
ClassiFinder — AI / LLM Provider Patterns

Patterns for OpenAI, Anthropic, and Cohere API keys.
AI service secrets increased 81% year-over-year in 2025 (GitGuardian report).
These are critical severity -- a leaked key gives direct access to billable
API usage and potentially sensitive model interactions.

Pattern design notes:
- OpenAI keys use sk- prefix followed by 48+ alphanumeric chars. Project-scoped
  keys use sk-proj- prefix. Both formats are detected.
- Anthropic keys use sk-ant- prefix, highly distinctive.
- Cohere keys are 40-char alphanumeric strings with no reliable prefix, so we
  rely on context keywords (COHERE_API_KEY, cohere, etc.) for confidence.
"""

import re

from .registry import SecretPattern, register

# ===================================================
# OPENAI
# ===================================================

OPENAI_API_KEY = SecretPattern(
    id="openai_api_key",
    name="OpenAI API Key",
    description=(
        "OpenAI API key starting with sk- prefix. Grants access to GPT models,"
        " DALL-E, embeddings, and other OpenAI services."
    ),
    provider="openai",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>sk-(?:proj-)?[a-zA-Z0-9]{32,})"
        r"(?![a-zA-Z0-9])",
        re.ASCII
    ),
    confidence_base=0.90,
    entropy_threshold=3.0,
    context_keywords=["openai", "OPENAI_API_KEY", "openai_key", "gpt", "chatgpt", "api_key"],
    known_test_values={
        "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    },
    recommendation=(
        "Revoke this key immediately in the OpenAI Dashboard under API Keys."
        " Generate a new key and update your application."
        " Audit usage for unauthorized charges."
    ),
    tags=["ai", "openai", "llm"],
)


# ===================================================
# ANTHROPIC
# ===================================================

ANTHROPIC_API_KEY = SecretPattern(
    id="anthropic_api_key",
    name="Anthropic API Key",
    description=(
        "Anthropic API key starting with sk-ant- prefix."
        " Grants access to Claude models."
    ),
    provider="anthropic",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>sk-ant-[a-zA-Z0-9\-_]{32,})"
        r"(?![a-zA-Z0-9\-_])",
        re.ASCII
    ),
    confidence_base=0.97,  # sk-ant- prefix is highly distinctive
    entropy_threshold=0.0,
    context_keywords=["anthropic", "ANTHROPIC_API_KEY", "claude", "api_key"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key immediately in the Anthropic Console under API Keys."
        " Generate a new key and update your application."
    ),
    tags=["ai", "anthropic", "llm"],
)


# ===================================================
# COHERE
# ===================================================

COHERE_API_KEY = SecretPattern(
    id="cohere_api_key",
    name="Cohere API Key",
    description=(
        "Cohere API key. A 40-character alphanumeric string, typically found"
        " near COHERE_API_KEY or cohere context keywords."
    ),
    provider="cohere",
    severity="high",
    regex=re.compile(
        r"(?:"
        r"(?:COHERE_API_KEY|cohere.*api.*key|cohere.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-zA-Z0-9]{40})"
        r"(?![a-zA-Z0-9])",
        re.ASCII | re.IGNORECASE
    ),
    confidence_base=0.75,  # no distinctive prefix, relies on context
    entropy_threshold=3.5,
    context_keywords=[
        "cohere", "COHERE_API_KEY", "cohere_key", "embed", "rerank",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Cohere Dashboard under API Keys."
        " Generate a new key and update your application."
    ),
    tags=["ai", "cohere", "llm"],
)


register(
    OPENAI_API_KEY,
    ANTHROPIC_API_KEY,
    COHERE_API_KEY,
)
