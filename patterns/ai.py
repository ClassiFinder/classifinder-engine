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
        re.ASCII,
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
    description=("Anthropic API key starting with sk-ant- prefix. Grants access to Claude models."),
    provider="anthropic",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>sk-ant-[a-zA-Z0-9\-_]{32,})"
        r"(?![a-zA-Z0-9\-_])",
        re.ASCII,
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
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,  # no distinctive prefix, relies on context
    entropy_threshold=3.5,
    context_keywords=[
        "cohere",
        "COHERE_API_KEY",
        "cohere_key",
        "embed",
        "rerank",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Cohere Dashboard under API Keys."
        " Generate a new key and update your application."
    ),
    tags=["ai", "cohere", "llm"],
)


# ===================================================
# HUGGINGFACE
# ===================================================

HUGGINGFACE_TOKEN = SecretPattern(
    id="huggingface_token",
    name="HuggingFace Token",
    description=(
        "HuggingFace user access token with hf_ prefix."
        " Grants access to model repos, datasets, and Inference API."
    ),
    provider="huggingface",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>hf_[A-Za-z0-9]{34,})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "huggingface",
        "hugging_face",
        "HF_TOKEN",
        "hf_token",
        "HUGGINGFACE_TOKEN",
        "transformers",
    ],
    known_test_values={
        "hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    },
    recommendation=(
        "Revoke this token at huggingface.co/settings/tokens."
        " Generate a new token with minimal required permissions."
    ),
    tags=["ai", "huggingface", "ml"],
)


# ===================================================
# REPLICATE
# ===================================================

REPLICATE_API_TOKEN = SecretPattern(
    id="replicate_api_token",
    name="Replicate API Token",
    description=(
        "Replicate API token with r8_ prefix."
        " Grants access to run AI models on Replicate's infrastructure."
    ),
    provider="replicate",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>r8_[A-Za-z0-9]{36,})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "replicate",
        "REPLICATE_API_TOKEN",
        "replicate_token",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token at replicate.com/account/api-tokens."
        " Generate a new token and update your application."
    ),
    tags=["ai", "replicate", "ml"],
)


# ===================================================
# GROQ
# ===================================================

GROQ_API_KEY = SecretPattern(
    id="groq_api_key",
    name="Groq API Key",
    description=(
        "Groq API key with gsk_ prefix. Grants access to Groq's fast inference API for LLMs."
    ),
    provider="groq",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>gsk_[A-Za-z0-9]{52,})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "groq",
        "GROQ_API_KEY",
        "groq_key",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key at console.groq.com/keys. Generate a new key and update your application."
    ),
    tags=["ai", "groq", "llm"],
)


# ===================================================
# DEEPSEEK
# ===================================================

DEEPSEEK_API_KEY = SecretPattern(
    id="deepseek_api_key",
    name="DeepSeek API Key",
    description=(
        "DeepSeek API key with sk- prefix and 32 lowercase alphanumeric characters."
        " Shares the sk- prefix with OpenAI but uses shorter, hex-like values."
        " Detected only when DeepSeek context keywords are present."
    ),
    provider="deepseek",
    severity="critical",
    regex=re.compile(
        r"(?:"
        r"(?:DEEPSEEK_API_KEY|deepseek.*api.*key|deepseek.*key|deepseek)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>sk-[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.0,
    context_keywords=[
        "deepseek",
        "DEEPSEEK_API_KEY",
        "deepseek_key",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this key at platform.deepseek.com under API Keys."
        " Generate a new key and update your application."
    ),
    tags=["ai", "deepseek", "llm"],
)


# ===================================================
# XAI (GROK)
# ===================================================

XAI_API_KEY = SecretPattern(
    id="xai_api_key",
    name="xAI API Key",
    description="xAI (Grok) API key with xai- prefix. Grants access to Grok language models.",
    provider="xai",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>xai-[A-Za-z0-9]{20,})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["xai", "grok", "XAI_API_KEY", "xai_key"],
    known_test_values=set(),
    recommendation="Revoke this key at console.x.ai under API Keys.",
    tags=["ai", "xai", "llm"],
)


# ===================================================
# ELEVENLABS
# ===================================================

ELEVENLABS_API_KEY = SecretPattern(
    id="elevenlabs_api_key",
    name="ElevenLabs API Key",
    description=(
        "ElevenLabs API key, a 32-character hex string."
        " Detected when preceded by ElevenLabs-specific context keywords."
    ),
    provider="elevenlabs",
    severity="high",
    regex=re.compile(
        r"(?:"
        r"(?:ELEVENLABS_API_KEY|ELEVEN_LABS_API_KEY|xi-api-key|elevenlabs.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.5,
    context_keywords=["elevenlabs", "eleven_labs", "xi-api-key", "text_to_speech", "tts"],
    known_test_values=set(),
    recommendation="Revoke this key at elevenlabs.io under Profile > API Keys.",
    tags=["ai", "elevenlabs", "tts"],
)


# ===================================================
# ASSEMBLYAI
# ===================================================

ASSEMBLYAI_API_KEY = SecretPattern(
    id="assemblyai_api_key",
    name="AssemblyAI API Key",
    description=(
        "AssemblyAI API key, a 32-character hex string."
        " Detected when preceded by AssemblyAI-specific context keywords."
    ),
    provider="assemblyai",
    severity="high",
    regex=re.compile(
        r"(?:"
        r"(?:ASSEMBLYAI_API_KEY|ASSEMBLY_AI_KEY|assemblyai.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.5,
    context_keywords=["assemblyai", "assembly_ai", "transcription", "speech_to_text"],
    known_test_values=set(),
    recommendation="Revoke this key at assemblyai.com under Account > API Keys.",
    tags=["ai", "assemblyai", "stt"],
)


# ===================================================
# DEEPGRAM
# ===================================================

DEEPGRAM_API_KEY = SecretPattern(
    id="deepgram_api_key",
    name="Deepgram API Key",
    description=(
        "Deepgram API key, a 40-character hex string."
        " Detected when preceded by Deepgram-specific context keywords."
    ),
    provider="deepgram",
    severity="high",
    regex=re.compile(
        r"(?:"
        r"(?:DEEPGRAM_API_KEY|DEEPGRAM_KEY|deepgram.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{40})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.5,
    context_keywords=["deepgram", "DEEPGRAM_API_KEY", "speech", "transcription"],
    known_test_values=set(),
    recommendation="Revoke this key at console.deepgram.com under Settings > API Keys.",
    tags=["ai", "deepgram", "stt"],
)


# ===================================================
# LANGFUSE
# ===================================================

LANGFUSE_SECRET_KEY = SecretPattern(
    id="langfuse_secret_key",
    name="LangFuse Secret Key",
    description="LangFuse secret key with sk-lf- prefix. Grants access to LangFuse LLM observability.",
    provider="langfuse",
    severity="high",
    regex=re.compile(
        r"(?P<secret>sk-lf-[A-Za-z0-9\-]{20,})"
        r"(?![A-Za-z0-9\-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["langfuse", "LANGFUSE_SECRET_KEY", "langfuse_key"],
    known_test_values=set(),
    recommendation="Revoke this key at cloud.langfuse.com under Settings > API Keys.",
    tags=["ai", "langfuse", "observability"],
)


# ===================================================
# MISTRAL
# ===================================================

MISTRAL_API_KEY = SecretPattern(
    id="mistral_api_key",
    name="Mistral AI API Key",
    description=(
        "Mistral AI API key, a 32-character alphanumeric string."
        " Detected when preceded by Mistral-specific context keywords."
    ),
    provider="mistral",
    severity="critical",
    regex=re.compile(
        r"(?:"
        r"(?:MISTRAL_API_KEY|mistral.*key|mistral.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Za-z0-9]{32})"
        r"(?![A-Za-z0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,
    entropy_threshold=3.5,
    context_keywords=["mistral", "MISTRAL_API_KEY", "mistral_key"],
    known_test_values=set(),
    recommendation="Revoke this key at console.mistral.ai under API Keys.",
    tags=["ai", "mistral", "llm"],
)


register(
    OPENAI_API_KEY,
    ANTHROPIC_API_KEY,
    COHERE_API_KEY,
    HUGGINGFACE_TOKEN,
    REPLICATE_API_TOKEN,
    GROQ_API_KEY,
    DEEPSEEK_API_KEY,
    XAI_API_KEY,
    ELEVENLABS_API_KEY,
    ASSEMBLYAI_API_KEY,
    DEEPGRAM_API_KEY,
    LANGFUSE_SECRET_KEY,
    MISTRAL_API_KEY,
)
