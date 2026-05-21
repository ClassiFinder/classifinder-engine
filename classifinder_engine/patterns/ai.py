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
    # Independently authored — sk- prefix derived from OpenAI API documentation
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
    # Format per Anthropic Console (sk-ant-api<NN>- prefix is vendor-published).
    # Independently authored — broader than Betterleaks's stricter
    # `sk-ant-api03-...{93}AA` form to catch legacy/variant key shapes.
    regex=re.compile(
        r"(?P<secret>sk-ant-api[0-9]{2}-[a-zA-Z0-9\-_]{32,})"
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
    # Independently authored — context-gated 40-char format; no verbatim external source
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
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:3248) — hf_ vendor prefix
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


# Batch 4 Part 1.8 — HuggingFace organization API token (2026-05-21)
# Body shape from Betterleaks MIT cmd/generate/config/rules/huggingface.go.
# Note: charset is letters-only (no digits, no special chars) — 34 chars
# after the api_org_ prefix.

HUGGINGFACE_ORGANIZATION_API_TOKEN = SecretPattern(
    id="huggingface_organization_api_token",
    name="HuggingFace Organization API Token",
    description=(
        "HuggingFace organization-scoped API token with api_org_ prefix (34 letters)."
        " Grants access to organization-owned model repos, datasets, and Inference API."
        " Higher privilege than user tokens — treat as critical."
    ),
    provider="huggingface",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/huggingface.go) — api_org_ prefix.
    # Charset is letters-only per BL observation (no digits in the body).
    regex=re.compile(
        r"(?P<secret>api_org_[A-Za-z]{34})"
        r"(?![A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "huggingface", "hugging_face", "HF_ORG_TOKEN", "transformers", "api_org",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this organization token at huggingface.co/organizations/<org>/settings/tokens."
        " Organization tokens carry broader permissions than user tokens."
    ),
    tags=["ai", "huggingface", "ml", "organization"],
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
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4168) — r8_ vendor prefix
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
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:3146) — gsk_ vendor prefix
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
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:695) — sk- + DeepSeek context
    regex=re.compile(
        r"(?:"
        r"(?:DEEPSEEK_API_KEY|deepseek.*api.*key|deepseek.*key|deepseek)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>sk-[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.92,
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
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4956) — xai- vendor prefix
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
    # Pattern attribution: secrets-patterns-db CC-BY-4.0 — context-gated [a-f0-9]{32}
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
    # Pattern attribution: secrets-patterns-db CC-BY-4.0 — context-gated [a-f0-9]{32}
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
    # Pattern attribution: secrets-patterns-db CC-BY-4.0 — context-gated [a-f0-9]{40}
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
    description=(
        "LangFuse secret key with sk-lf- prefix."
        " Grants access to LangFuse LLM observability."
    ),
    provider="langfuse",
    severity="high",
    # Independently authored — sk-lf- vendor prefix per LangFuse documentation
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
    # Independently authored — context-gated 32-char format; no verbatim external source
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


# ===================================================
# ANTHROPIC ADMIN (org-level admin keys, distinct from sk-ant-api*)
# ===================================================

ANTHROPIC_ADMIN_API_KEY = SecretPattern(
    id="anthropic_admin_api_key",
    name="Anthropic Admin API Key",
    description=(
        "Anthropic Admin API key with sk-ant-admin01- prefix."
        " Distinct from sk-ant-api* user keys -- grants org-level"
        " administrative access to billing, members, and workspace config."
    ),
    provider="anthropic",
    severity="critical",
    # Pattern attribution: betterleaks v1.0.0 config/betterleaks.toml:197 (MIT)
    #   https://github.com/betterleaks/betterleaks
    # See ATTRIBUTION.md for full license notice.
    regex=re.compile(
        r"(?P<secret>sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)"
        r"(?![a-zA-Z0-9_\-])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["sk-ant-admin01", "anthropic", "admin"],
    known_test_values=set(),
    recommendation=(
        "Revoke this admin key immediately in the Anthropic Console under"
        " Organization Settings > API Keys. Audit org membership and billing"
        " for unauthorized changes."
    ),
    tags=["ai", "anthropic", "llm", "admin"],
)


# ===================================================
# AWS BEDROCK (AI service keys, distinct from IAM)
# ===================================================

AWS_BEDROCK_LONG_LIVED_KEY = SecretPattern(
    id="aws_bedrock_long_lived_key",
    name="AWS Bedrock Long-Lived API Key",
    description=(
        "Long-lived AWS Bedrock API key with ABSK prefix."
        " Distinct from IAM access keys -- grants direct access to Bedrock"
        " hosted foundation models (Claude, Llama, Titan, etc.)."
    ),
    provider="aws-bedrock",
    severity="critical",
    # Pattern attribution: betterleaks v1.0.0 config/betterleaks.toml:365 (MIT)
    #   https://github.com/betterleaks/betterleaks
    # See ATTRIBUTION.md for full license notice.
    regex=re.compile(
        r"(?P<secret>ABSK[A-Za-z0-9+/]{109,269}={0,2})"
        r"(?![A-Za-z0-9+/=])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=3.0,
    context_keywords=["absk", "bedrock", "aws_bedrock", "BEDROCK_API_KEY"],
    known_test_values=set(),
    recommendation=(
        "Revoke this Bedrock API key in the AWS Console under Bedrock >"
        " API keys. Rotate and audit model invocation logs for unauthorized usage."
    ),
    tags=["ai", "aws", "bedrock", "llm"],
)


AWS_BEDROCK_SHORT_LIVED_KEY = SecretPattern(
    id="aws_bedrock_short_lived_key",
    name="AWS Bedrock Short-Lived API Key",
    description=(
        "Short-lived AWS Bedrock API key. Begins with bedrock-api-key-"
        " followed by the literal base64 of bedrock.amazonaws.com -- a"
        " near-zero-FP signal."
    ),
    provider="aws-bedrock",
    severity="critical",
    # Pattern attribution: betterleaks v1.0.0 config/betterleaks.toml:375 (MIT)
    #   https://github.com/betterleaks/betterleaks
    # Extended with trailing [A-Za-z0-9+/=]+ to capture the full key body.
    # See ATTRIBUTION.md for full license notice.
    regex=re.compile(
        r"(?P<secret>bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t[A-Za-z0-9+/=]+)"
        r"(?![A-Za-z0-9+/=])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=3.0,
    context_keywords=["bedrock-api-key-", "bedrock", "aws_bedrock"],
    known_test_values=set(),
    recommendation=(
        "Short-lived Bedrock keys expire automatically but should still"
        " be rotated immediately if exposed. Audit Bedrock model invocation logs."
    ),
    tags=["ai", "aws", "bedrock", "llm"],
)


# ===================================================
# VERCEL AI GATEWAY (distinct from generic Vercel tokens)
# ===================================================

VERCEL_AI_GATEWAY_KEY = SecretPattern(
    id="vercel_ai_gateway_key",
    name="Vercel AI Gateway Key",
    description=(
        "Vercel AI Gateway API key with vck_ prefix. Routes inference to"
        " OpenAI, Anthropic, and other providers via Vercel's AI Gateway --"
        " exposes downstream AI billing."
    ),
    provider="vercel",
    severity="critical",
    # Pattern attribution: betterleaks v1.0.0 config/betterleaks.toml:4748 (MIT)
    #   https://github.com/betterleaks/betterleaks
    # See ATTRIBUTION.md for full license notice.
    regex=re.compile(
        r"(?P<secret>vck_[A-Za-z0-9_\-]{56})"
        r"(?![A-Za-z0-9_\-])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=3.5,
    context_keywords=["vck_", "vercel", "ai-gateway", "ai_gateway", "AI_GATEWAY_API_KEY"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Vercel dashboard under AI Gateway > API Keys."
        " Audit downstream model usage for unauthorized inference charges."
    ),
    tags=["ai", "vercel", "gateway", "llm"],
)


# ===================================================
# WEIGHTS & BIASES (ML experiment tracking)
# ===================================================

WEIGHTS_AND_BIASES_V1_KEY = SecretPattern(
    id="weights_and_biases_v1_key",
    name="Weights & Biases v1 API Key",
    description=(
        "Weights & Biases v1 API key with wandb_v1_ prefix."
        " Grants access to ML experiment tracking, artifact storage, and"
        " model registry."
    ),
    provider="wandb",
    severity="high",
    # Pattern attribution: betterleaks v1.0.0 config/betterleaks.toml:4930 (MIT)
    #   https://github.com/betterleaks/betterleaks
    # See ATTRIBUTION.md for full license notice.
    regex=re.compile(
        r"(?P<secret>wandb_v1_[A-Za-z0-9_]{77})"
        r"(?![A-Za-z0-9_])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=3.5,
    context_keywords=["wandb_v1_", "wandb", "WANDB_API_KEY", "weights_and_biases"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key at wandb.ai/authorize. Audit experiment, artifact,"
        " and model registry access for unauthorized changes."
    ),
    tags=["ai", "wandb", "ml", "experiment-tracking"],
)


register(
    OPENAI_API_KEY,
    ANTHROPIC_API_KEY,
    ANTHROPIC_ADMIN_API_KEY,
    COHERE_API_KEY,
    HUGGINGFACE_TOKEN,
    HUGGINGFACE_ORGANIZATION_API_TOKEN,
    REPLICATE_API_TOKEN,
    GROQ_API_KEY,
    DEEPSEEK_API_KEY,
    XAI_API_KEY,
    ELEVENLABS_API_KEY,
    ASSEMBLYAI_API_KEY,
    DEEPGRAM_API_KEY,
    LANGFUSE_SECRET_KEY,
    MISTRAL_API_KEY,
    AWS_BEDROCK_LONG_LIVED_KEY,
    AWS_BEDROCK_SHORT_LIVED_KEY,
    VERCEL_AI_GATEWAY_KEY,
    WEIGHTS_AND_BIASES_V1_KEY,
)
