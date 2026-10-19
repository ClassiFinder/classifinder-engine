"""
ClassiFinder — AI / LLM Provider Patterns

Patterns for OpenAI, Anthropic, and Cohere API keys.
AI service secrets increased 81% year-over-year in 2025 (GitGuardian report).
These are critical severity -- a leaked key gives direct access to billable
API usage and potentially sensitive model interactions.

Pattern design notes:
- OpenAI keys use sk- prefix. Legacy keys are alphanumeric; current project
  (sk-proj-), service-account (sk-svcacct-) and admin (sk-admin-) keys embed
  T3BlbkFJ and contain - and _ in the body. All formats are detected.
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
        "OpenAI API key starting with sk- prefix (legacy, sk-proj-, sk-svcacct-,"
        " sk-admin-). Grants access to GPT models, DALL-E, embeddings, and other"
        " OpenAI services; admin keys also manage org keys, users, and billing."
    ),
    provider="openai",
    severity="critical",
    # Independently authored — sk- prefix derived from OpenAI API documentation.
    # Branch 1: current keys embed the literal T3BlbkFJ (base64 "OpenAI") and use a
    # url-safe body ([A-Za-z0-9_-]), with optional proj-/svcacct-/admin- scope.
    # Format per https://github.com/gitleaks/gitleaks/blob/master/cmd/generate/config/rules/openai.go (MIT)
    # Branch 2: legacy alphanumeric sk- / sk-proj- keys.
    regex=re.compile(
        r"(?P<secret>sk-(?:(?:proj|svcacct|admin)-)?[A-Za-z0-9_-]{20,100}T3BlbkFJ"
        r"[A-Za-z0-9_-]{20,100}(?![A-Za-z0-9_-])"
        r"|sk-(?:proj-)?[a-zA-Z0-9]{32,}(?![a-zA-Z0-9]))",
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


# ===================================================
# LANGSMITH
# ===================================================

LANGSMITH_API_KEY = SecretPattern(
    id="langsmith_api_key",
    name="LangSmith API Key",
    description=(
        "LangSmith API key with lsv2_pt_ or lsv2_sk_ prefix (32 lowercase alphanumeric chars)."
        " Grants access to LangSmith LLM observability and tracing."
    ),
    provider="langsmith",
    severity="high",
    # Independently authored — lsv2_pt_/lsv2_sk_ vendor-published prefix per LangSmith
    # API key documentation (https://docs.smith.langchain.com/how_to_guides/setup/create_account_api_key).
    regex=re.compile(
        r"(?P<secret>lsv2_(?:pt|sk)_[a-z0-9]{32})"
        r"(?![a-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["langsmith", "LANGSMITH_API_KEY", "langchain", "lsv2"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the LangSmith Settings page under API Keys."
        " Generate a new key and update your tracing configuration."
    ),
    tags=["ai", "langsmith", "observability"],
)


# ===================================================
# CLARIFAI
# ===================================================

CLARIFAI_PAT = SecretPattern(
    id="clarifai_pat",
    name="Clarifai Personal Access Token",
    description=(
        "Clarifai Personal Access Token (PAT), a 32-character hex string."
        " Detected when preceded by Clarifai-specific context keywords."
        " Grants access to Clarifai computer vision and AI models."
    ),
    provider="clarifai",
    severity="high",
    # Independently authored — context-gated 32-char hex per Clarifai API documentation
    # (https://docs.clarifai.com/clarifai-basics/authentication/authorize).
    regex=re.compile(
        r"(?:"
        r"(?:CLARIFAI_PAT|CLARIFAI_API_KEY|clarifai.*token|clarifai.*key|clarifai.*pat)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[a-f0-9]{32})"
        r"(?![a-f0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=3.5,
    context_keywords=["clarifai", "CLARIFAI_PAT", "CLARIFAI_API_KEY"],
    known_test_values=set(),
    recommendation=(
        "Revoke this PAT at clarifai.com under Account Settings > Security > Personal Access Tokens."
        " Generate a new token with minimal required scopes."
    ),
    tags=["ai", "clarifai", "vision"],
)


# ===================================================
# OPENROUTER
# ===================================================

OPENROUTER_API_KEY = SecretPattern(
    id="openrouter_api_key",
    name="OpenRouter API Key",
    description=(
        "OpenRouter API key with sk-or-v1- prefix. Grants access to OpenRouter's"
        " unified inference API spanning 100+ models — leaked keys incur usage charges."
    ),
    provider="openrouter",
    severity="high",
    # Independently authored — sk-or-v1- vendor-published prefix per OpenRouter
    # authentication docs (https://openrouter.ai/docs/api/reference/authentication).
    # The hyphenated infix keeps it disjoint from openai_api_key (alphanumeric body).
    regex=re.compile(
        r"(?P<secret>sk-or-v1-[a-zA-Z0-9]{32,})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["openrouter", "OPENROUTER_API_KEY", "sk-or-v1"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the OpenRouter dashboard under Keys."
        " Generate a new key and update your configuration."
    ),
    tags=["ai", "openrouter", "inference"],
)


# ===================================================
# PERPLEXITY
# ===================================================

PERPLEXITY_API_KEY = SecretPattern(
    id="perplexity_api_key",
    name="Perplexity API Key",
    description=(
        "Perplexity API key with pplx- prefix. Grants access to Perplexity's"
        " search-augmented LLM API."
    ),
    provider="perplexity",
    severity="high",
    # Independently authored — pplx- vendor-published prefix per Perplexity
    # API key management docs (https://docs.perplexity.ai/docs/admin/api-key-management).
    regex=re.compile(
        r"(?P<secret>pplx-[a-zA-Z0-9]{32,})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["perplexity", "PERPLEXITY_API_KEY", "pplx"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Perplexity API settings."
        " Generate a new key and update your configuration."
    ),
    tags=["ai", "perplexity", "inference"],
)


# ===================================================
# ANYSCALE
# ===================================================

ANYSCALE_API_KEY = SecretPattern(
    id="anyscale_api_key",
    name="Anyscale API Key",
    description=(
        "Anyscale API key with esecret_ prefix. Grants access to Anyscale"
        " inference and compute services."
    ),
    provider="anyscale",
    severity="high",
    # Independently authored — esecret_ vendor-published prefix per Anyscale
    # authentication docs (https://docs.anyscale.com/endpoints/text-generation/authenticate/).
    # Distinct from notion_api_key (secret_ prefix; Notion regex carries a left boundary).
    regex=re.compile(
        r"(?P<secret>esecret_[a-zA-Z0-9]{16,})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["anyscale", "ANYSCALE_API_KEY", "esecret"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Anyscale console under API Keys."
        " Generate a new key and update your configuration."
    ),
    tags=["ai", "anyscale", "inference"],
)


# ===================================================
# BRAINTRUST
# ===================================================

BRAINTRUST_API_KEY = SecretPattern(
    id="braintrust_api_key",
    name="Braintrust Service Token",
    description=(
        "Braintrust service token with bt-st- prefix. Grants programmatic access"
        " to Braintrust LLM eval and observability. (User keys use the generic sk-"
        " prefix and surface as openai_api_key; only service tokens are matched here.)"
    ),
    provider="braintrust",
    severity="high",
    # Independently authored — bt-st- vendor-published service-token prefix per Braintrust
    # authentication docs (https://www.braintrust.dev/docs/reference/platform/authentication).
    regex=re.compile(
        r"(?P<secret>bt-st-[a-zA-Z0-9]{16,})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["braintrust", "BRAINTRUST_API_KEY", "bt-st"],
    known_test_values=set(),
    recommendation=(
        "Revoke this service token in the Braintrust settings under API Keys."
        " Generate a new token and update your configuration."
    ),
    tags=["ai", "braintrust", "observability"],
)


# ===================================================
# RUNPOD
# ===================================================

RUNPOD_API_KEY = SecretPattern(
    id="runpod_api_key",
    name="RunPod API Key",
    description=(
        "RunPod API key with rpa_ prefix. Grants access to RunPod GPU cloud"
        " resources — leaked keys can incur compute charges."
    ),
    provider="runpod",
    severity="high",
    # Independently authored — rpa_ vendor-published prefix per RunPod scoped-API-keys
    # announcement (https://www.runpod.io/blog/scoped-api-keys-runpod).
    regex=re.compile(
        r"(?P<secret>rpa_[A-Za-z0-9]{20,})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["runpod", "RUNPOD_API_KEY", "rpa_"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the RunPod console under Settings > API Keys."
        " Generate a new key and update your configuration."
    ),
    tags=["ai", "runpod", "inference"],
)



# ===================================================
# BAIDU (QIANFAN / BCE)
# ===================================================

BAIDU_QIANFAN_BCE_API_KEY = SecretPattern(
    id="baidu_qianfan_bce_api_key",
    name="Baidu Qianfan BCE API Key",
    description=(
        "Baidu Cloud Engine v3 API key, used as the bearer token for the Qianfan"
        " LLM platform and for AppBuilder. Shaped"
        " bce-v3/ALTAK-<21 alphanumerics>/<lowercase hex>, 75 characters in the"
        " observed form. Grants direct access to billable model inference and to"
        " whatever BCE services the issuing account can reach."
    ),
    provider="baidu",
    severity="high",
    # Three fixed segments carry the precision, which is why there is no entropy
    # gate: the literal `bce-v3/`, the literal `ALTAK-` sub-prefix, an
    # exactly-21-character key ID, a `/`, then a lowercase-hex secret. The
    # exactly-21 width is confirmed across four independent public samples; the
    # 40-character tail was measurable on only one unmasked sample, so the tail
    # bound is deliberately tolerant ({32,64}) rather than a hard {40} — the two
    # literal prefixes plus the fixed-width ID already make this a near-zero-FP
    # anchor, so widening the tail costs no precision but survives a re-widened
    # tail instead of silently missing it.
    #
    # Lowercase hex (not alphanumerics) for the tail is also deliberate: it
    # excludes the author-redacted `x`/`X` placeholders that dominate the public
    # corpus, and the exactly-21 requirement on segment 1 excludes Baidu's own
    # masked documentation values (`bce-v3/ALTAK-KZke********/f1d6ee***`).
    # Source: baidubce/bce-qianfan-sdk, python/qianfan/tests/chat_completion_v2_test.py
    #   https://github.com/baidubce/bce-qianfan-sdk
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>bce-v3/ALTAK-[A-Za-z0-9]{21}/[a-f0-9]{32,64})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=[
        "baidu",
        "qianfan",
        "bce-v3",
        "QIANFAN_BEARER_TOKEN",
        "APPBUILDER_TOKEN",
        "bce",
    ],
    # Baidu's own SDK test fixture, split so the literal never appears whole in
    # this file (these tokens are widely deployed and secret-scanning partners
    # match on the joined form).
    known_test_values={
        "bce-v3/ALTAK-" + "JZasis7GfnokSLLXykKHj" + "/"
        + "054c2e64c06db4d6019f0dbfc964e90aa3fc3ddd",
    },
    recommendation=(
        "Revoke this API key in the Baidu Cloud console under the Qianfan"
        " ModelBuilder API-key page, issue a replacement, and audit recent"
        " inference usage for unauthorized charges."
    ),
    tags=["ai", "baidu", "qianfan", "llm", "cloud"],
)


# ===================================================
# FIRECRAWL API KEY (2026-09-07)
# ===================================================

# The body width is not measured from sampled keys — it is derived from the
# vendor's own server code. Firecrawl's apps/api/src/lib/parseApi.ts strips a
# leading '^fc-' from the supplied key and then re-inserts UUID dashes with
# /(.{8})(.{4})(.{4})(.{4})(.{12})/ before looking it up, which only makes
# sense if what remains is exactly 32 hexadecimal characters: an undashed
# UUID. So 'fc-' + 32 hex is the vendor's own arithmetic, not an inference.
#
# confidence_base is 0.90 rather than the 0.95 prefix-anchored tier, on
# purpose. 'fc-' is three characters, which is a materially weaker anchor than
# the four-to-nine-character literals that earn 0.95, and 'fc-' followed by an
# MD5 is a plausible cache-filename shape. 0.90 still sits comfortably above
# the 0.85 FP-wordlist gate (scanner.py), so a real key next to the word "test"
# is not silently sunk; the masks are pinned as known_test_values instead.
#
# Severity high rather than critical: the key authenticates Firecrawl's
# scraping and crawling API for the owning account, so a leak is billable
# compute and access to the account's crawl history and stored results, but it
# is not a control-plane credential for anything outside Firecrawl.

FIRECRAWL_API_KEY = SecretPattern(
    id="firecrawl_api_key",
    name="Firecrawl API Key",
    description=(
        "Firecrawl API key — the literal 'fc-' prefix followed by exactly 32"
        " hexadecimal characters (an undashed UUID), 35 in total."
        " Authenticates Firecrawl's scrape, crawl and extract endpoints for the"
        " owning account, so a leaked key means billable compute on someone"
        " else's plan and access to that account's crawl jobs and results."
    ),
    provider="firecrawl",
    severity="high",
    # The 32-hex body is the vendor's own arithmetic: Firecrawl's API server
    # strips '^fc-' from the supplied key and re-inserts UUID dashes with
    # /(.{8})(.{4})(.{4})(.{4})(.{12})/, which pins what remains at exactly 32
    # hexadecimal characters. Guards, confidence and known_test_values are
    # ClassiFinder's own.
    # Source: https://github.com/firecrawl/firecrawl/blob/main/apps/api/src/lib/parseApi.ts
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"(?P<secret>fc-[a-f0-9]{32})"
        r"(?![0-9A-Za-z-])",
        re.ASCII,
    ),
    # 0.90 (structural tier), not 0.95: 'fc-' is a three-character anchor and
    # 'fc-' + 32 hex is a plausible cache-filename shape. Still above the 0.85
    # FP-wordlist gate so a real key in a *test* file is never priced down.
    confidence_base=0.90,
    entropy_threshold=0.0,  # masks are pinned below rather than gated on entropy
    context_keywords=[
        "firecrawl",
        "FIRECRAWL_API_KEY",
        "api_key",
        "crawl",
        "scrape",
    ],
    known_test_values={
        # The all-zero and all-f undashed UUIDs, which is how Firecrawl's docs,
        # SDK READMEs and tutorials render a redacted key.
        "fc-" + "0" * 32,
        "fc-" + "f" * 32,
        "fc-" + "a" * 32,
    },
    recommendation=(
        "Revoke this key in the Firecrawl dashboard under API Keys and issue a"
        " replacement. Then check the account's usage and job history for the"
        " exposure window — a leaked key is billable against your plan — and"
        " review any crawl results it could have read, since those may contain"
        " content from private or authenticated targets you crawled."
    ),
    tags=["ai", "firecrawl", "scraping"],
)


HELICONE_API_KEY = SecretPattern(
    id="helicone_api_key",
    name="Helicone API Key",
    description=(
        "Helicone API key — the literal 'sk-helicone' (secret) or 'pk-helicone'"
        " (write-only) prefix, optional '-eu' / '-cp' / '-rl' region and"
        " key-kind segments, then four dash-separated groups of exactly 7"
        " lowercase alphanumerics. Authenticates Helicone's LLM gateway and"
        " observability APIs for the owning organization, whose request logs"
        " hold full prompts and completions."
    ),
    provider="helicone",
    severity="high",
    # Helicone's own worker defines HELICONE_API_KEY_REGEX with explicit
    # sk-helicone-, pk-helicone-, sk-helicone-eu- and pk-helicone-eu- forms, a
    # generalized [sp]k(-helicone)?(-eu)?(-cp)? form, and a rate-limited list
    # with an -rl segment, each followed by 4 x 7 [a-z0-9]. The legacy bare
    # 'sk-' + 4 x 7 form has no anchor and is deliberately not matched.
    # Guards, confidence and known_test_values are ClassiFinder's own.
    # Source: https://github.com/Helicone/helicone/blob/main/worker/src/lib/util/apiKeyRegex.ts
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>[sp]k-helicone(?:-eu)?(?:-cp)?(?:-rl)?"
        r"-[a-z0-9]{7}-[a-z0-9]{7}-[a-z0-9]{7}-[a-z0-9]{7})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # masks are pinned below rather than gated on entropy
    context_keywords=[
        "helicone",
        "HELICONE_API_KEY",
        "Helicone-Auth",
        "api_key",
        "gateway",
    ],
    known_test_values={
        # Single-character masks as rendered in docs and tutorials.
        "sk-helicone-" + "-".join(["x" * 7] * 4),
        "pk-helicone-" + "-".join(["x" * 7] * 4),
        "sk-helicone-" + "-".join(["0" * 7] * 4),
        "pk-helicone-" + "-".join(["0" * 7] * 4),
    },
    recommendation=(
        "Delete this key in the Helicone dashboard under Settings > API Keys"
        " and issue a replacement. Then review the organization's request logs"
        " for the exposure window: a secret key can read logged prompts and"
        " completions, and any key can write requests and costs into your"
        " account. Also rotate any provider keys stored in Helicone's vault."
    ),
    tags=["ai", "helicone", "observability", "gateway"],
)

# ===================================================
# HACK CLUB AI API KEY (2026-10-05)
# ===================================================
# Hack Club AI (ai.hackclub.com) is an OpenAI-compatible LLM proxy. In the
# vendor's own server source (hackclub/ai src/routes/api.tsx — read for the
# format facts only; no code copied), a key is minted as
#   `sk-hc-v1-${crypto.randomUUID()}${crypto.randomUUID()}` with '-' removed,
# i.e. 'sk-hc-v1-' + two lowercase-hex UUIDv4s = exactly 64 lowercase hex.
# (The UUIDv4 version/variant nibbles are NOT enforced, so a future switch to
# plain random hex is still caught.)
#
# DISJOINT FROM OPENAI: openai_api_key needs 'sk-' followed by 32+
# alphanumerics, which stops at the '-' after 'hc', so 'sk-hc-v1-...' never
# satisfies it. BOTH GUARDS REFUSE [A-Za-z0-9_-], so a 65-hex run matches
# nothing.
#
# Severity high: the key spends the owner's quota on the proxy's models.

HACKCLUB_AI_API_KEY = SecretPattern(
    id="hackclub_ai_api_key",
    name="Hack Club AI API Key",
    description=(
        "Hack Club AI API key — the literal 'sk-hc-v1-' prefix followed by"
        " exactly 64 lowercase hex characters (two dash-stripped UUIDv4s). Used"
        " as an OpenAI-compatible Bearer key against ai.hackclub.com; whoever"
        " holds it spends the owner's model quota."
    ),
    provider="hackclub",
    severity="high",
    # Format per the vendor's own server source (hackclub/ai, api.tsx: the
    # 'sk-hc-v1-' prefix plus two crypto.randomUUID() with dashes removed),
    # read for format facts only. Guards, confidence and test values are ours.
    # Source: https://github.com/hackclub/ai/blob/main/src/routes/api.tsx
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>sk-hc-v1-[0-9a-f]{64})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # hex body is ~4.0 bits/char — the 9-char prefix carries the precision
    context_keywords=["hackclub", "ai.hackclub.com", "HACKCLUB_AI_API_KEY", "Bearer"],
    known_test_values={
        # Hex masks. confidence_base 0.95 sits above the 0.85 FP-wordlist gate,
        # so they are pinned here and land at ~0.15.
        "sk-" + "hc-v1-" + fill * 64
        for fill in ("0", "a", "f")
    },
    recommendation=(
        "Revoke this key on the Hack Club AI dashboard (ai.hackclub.com, API"
        " keys) and create a replacement, then update every client and CI"
        " secret that uses it. Review the key's usage for requests you did not"
        " make during the exposure window."
    ),
    tags=["ai", "hackclub", "llm"],
)


# ===================================================
# MINIMAX API KEY — 'sk-api-' pay-as-you-go key (2026-10-09)
# ===================================================

# MiniMax (MiniMax-M2 / abab / speech / video models, platform.minimax.io)
# authenticates its OpenAI- and Anthropic-compatible APIs with a Bearer API
# key. Pay-as-you-go keys start with 'sk-api-'; Token Plan (subscription)
# keys start with 'sk-cp-' and are NOT matched here (their width has not been
# measured yet).
#
# THE WIDTH IS NOT VENDOR-DOCUMENTED. MiniMax's own docs show the 'sk-cp-'
# Token Plan prefix only; the 'sk-api-' pay-as-you-go prefix is stated by
# secondary integrator docs. Exactly 119 [A-Za-z0-9_-] after the prefix is
# taken from the Betterleaks (MIT) rule 'minimax-api-key', corroborated by a
# narrow measurement of public values (the measured sources are deliberately
# not named because they hold live keys).
#
# Disjoint from openai_api_key: 'sk-(?:proj-)?[a-zA-Z0-9]{32,}' cannot cross
# the hyphen after 'sk-api'. Guards refuse [A-Za-z0-9_-] on both sides, so a
# 120th character matches nothing rather than being truncated. confidence
# 0.90 (not the 0.95 long-prefix tier: the width is third-party, the prefix
# short) with no entropy gate — still above the 0.85 FP-wordlist gate, so a
# random body that happens to contain 'test' / 'demo' is not sunk.

MINIMAX_API_KEY = SecretPattern(
    id="minimax_api_key",
    name="MiniMax API Key",
    description=(
        "MiniMax pay-as-you-go API key — 'sk-api-' followed by 119 base64url"
        " characters. Grants access to MiniMax's text, speech, image and video"
        " model APIs, billed to the account."
    ),
    provider="minimax",
    severity="high",
    # MiniMax's docs show the 'sk-cp-' Token Plan sibling; 'sk-api-' (pay-as-
    # you-go) per integrator docs; width 119 per the Betterleaks (MIT) rule
    # minimax-api-key. Guards, confidence and test values are ClassiFinder's.
    # Source: https://platform.minimax.io/docs/token-plan/other-tools
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>sk-api-[A-Za-z0-9_-]{119})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,  # 119-char random body — the prefix + fixed width carry the precision
    context_keywords=[
        "minimax",
        "MINIMAX_API_KEY",
        "api.minimax.io",
        "api.minimaxi.com",
        "minimax.chat",
    ],
    known_test_values={
        # Single-character masks — how docs and redacted configs render this
        # key. 0.90 sits above the 0.85 FP-wordlist gate, so they are pinned
        # here (~0.15). Built by concatenation: no contiguous key literal.
        "sk-" + "api-" + fill * 119
        for fill in ("x", "X", "0", "a")
    },
    recommendation=(
        "Delete this key in the MiniMax console (platform.minimax.io, Account >"
        " API Keys) and create a replacement, then update every client and CI"
        " secret that uses it. Review usage and billing for requests you did not"
        " make during the exposure window. Store the key in a secrets manager and"
        " never ship it to a browser or mobile client."
    ),
    tags=["ai", "minimax", "llm"],
)



# ===================================================
# TOGETHER AI API KEY — 'tgp_v1_' (2026-10-10)
# ===================================================
# Together AI (together.ai — hosted open-model inference, fine-tuning and GPU
# clusters behind an OpenAI-compatible API at api.together.xyz) API key: the
# literal 'tgp_v1_' prefix followed by exactly 43 base64url characters
# ([A-Za-z0-9_-]), 50 in total. 43 is unpadded base64url of 32 bytes.
#
# HIGH VERIFICATION BURDEN: an earlier Together pattern was removed as
# non-existent because its format was guessed. This one is not:
# - PREFIX, VENDOR-ATTESTED: Together's own Apache-2.0 SDK
#   (togethercomputer/together-py, src/together/lib/cli/_track_cli.py)
#   redacts r"tgp_[a-z0-9_-]+" from CLI telemetry, and its unit test
#   (tests/unit/test_cli_telemetry.py) asserts a 'tgp_v1_...' literal is
#   redacted. Read for the format fact only; no code copied.
# - WIDTH AND ALPHABET, THIRD-PARTY: the Betterleaks (MIT) rule
#   togetherai-api-key is tgp_v1_[A-Za-z0-9_-]{43}; its own false-positive
#   fixtures reject a 36-character body and a 'tgp_v2_' prefix. Together's
#   public docs still show only a placeholder, so the 43 is not a vendor
#   statement.
#
# 'tgp_v1_' is a 7-character literal with a version segment, so the pattern
# is structurally anchored: confidence 0.90 with no entropy gate (below the
# 0.95 long-prefix tier because the width is third-party; above the 0.85
# FP-wordlist gate). Guards refuse [A-Za-z0-9_-] on both sides: a 44th
# character matches nothing rather than being truncated.
#
# Severity high: the key spends the owner's billed inference, fine-tuning
# and dedicated-endpoint quota.

TOGETHER_API_KEY = SecretPattern(
    id="together_api_key",
    name="Together AI API Key",
    description=(
        "Together AI API key — the literal 'tgp_v1_' prefix followed by exactly"
        " 43 base64url characters. Sent as a Bearer key to api.together.xyz;"
        " whoever holds it spends the owner's inference and fine-tuning quota."
    ),
    provider="together",
    severity="high",
    # Prefix per Together's own SDK (together-py _track_cli.py redacts
    # 'tgp_...'; its unit test uses a 'tgp_v1_' literal). The 43-character
    # base64url width is from the Betterleaks (MIT) rule togetherai-api-key.
    # Guards, confidence and known_test_values are ClassiFinder's own.
    # Source: https://github.com/betterleaks/betterleaks/blob/main/cmd/generate/config/rules/togetherai.go
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>tgp_v1_[A-Za-z0-9_-]{43})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,  # base64url body ~5.4 bits/char — the versioned prefix carries the precision
    context_keywords=[
        "together",
        "together.ai",
        "together.xyz",
        "TOGETHER_API_KEY",
        "Together(",
        "Bearer",
    ],
    known_test_values={
        # Single-character masks — how docs and redacted configs render this
        # key. 0.90 sits above the 0.85 FP-wordlist gate, so they are pinned
        # (~0.15). Built by concatenation so no contiguous key-shaped literal
        # sits in source.
        "tg" + "p_v1_" + fill * 43
        for fill in ("x", "X", "0", "a")
    },
    recommendation=(
        "Revoke this key in the Together AI dashboard (Settings > API Keys)"
        " and create a replacement, then update every client, notebook and CI"
        " secret that sends it as TOGETHER_API_KEY. Review usage and billing"
        " for inference, fine-tuning jobs and dedicated endpoints you did not"
        " start during the exposure window."
    ),
    tags=["ai", "together", "llm", "inference"],
)


# ===================================================
# NVIDIA API KEY — 'nvapi-' (2026-10-16)
# ===================================================
# NVIDIA API key (build.nvidia.com / NGC / NIM): the literal 'nvapi-' prefix
# followed by exactly 64 base64url characters. Sent as a Bearer key to
# integrate.api.nvidia.com and other NVIDIA-hosted endpoints.
# - PREFIX, VENDOR-DOCUMENTED: NVIDIA's own NeMo Retriever docs state that
#   keys typically start with 'nvapi-' and show NVIDIA_API_KEY="nvapi-...";
#   keys are generated at build.nvidia.com.
# - WIDTH + ALPHABET, MEASURED: the vendor publishes only truncated
#   placeholders. Every public value in a narrow single-prefix measurement
#   (3 samples) was 64 characters of [A-Za-z0-9_-]; the measured sources are
#   not named because they hold live keys. Thin evidence: re-measure the
#   width if more samples turn up.
#
# The body may START with '-' or '_', so there is no \b after the prefix; the
# lookbehind/lookahead guards refuse [A-Za-z0-9_-] on both sides, so a 65th
# character matches nothing rather than being truncated. Confidence 0.90 with
# no entropy gate (6-character vendor prefix; width is measured, not vendor
# stated; above the 0.85 FP-wordlist gate). Severity high: the key spends the
# owner's NVIDIA-hosted inference quota.

NVIDIA_API_KEY = SecretPattern(
    id="nvidia_api_key",
    name="NVIDIA API Key",
    description=(
        "NVIDIA API key — the literal 'nvapi-' prefix followed by exactly 64"
        " base64url characters. Authenticates to NVIDIA-hosted NIM / build.nvidia.com"
        " endpoints; whoever holds it spends the owner's inference quota."
    ),
    provider="nvidia",
    severity="high",
    # Source: https://docs.nvidia.com/nemo/retriever/26.5.0/extraction/api-keys/
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>nvapi-[A-Za-z0-9_-]{64})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,  # base64url body ~5.4 bits/char — the vendor prefix carries the precision
    context_keywords=[
        "nvidia",
        "NVIDIA_API_KEY",
        "NGC_API_KEY",
        "build.nvidia.com",
        "integrate.api.nvidia.com",
    ],
    known_test_values={
        # Single-character masks — how docs and redacted configs render this
        # key. 0.90 sits above the 0.85 FP-wordlist gate, so they are pinned
        # (~0.15). Built by concatenation: no contiguous key literal sits in
        # source (GitHub push protection).
        "nv" + "api-" + fill * 64
        for fill in ("x", "X", "0", "a")
    },
    recommendation=(
        "Revoke this key at build.nvidia.com (profile > API Keys), generate a"
        " replacement, and update every deployment that uses it. Review recent"
        " usage for unexpected requests."
    ),
    tags=["ai", "nvidia", "llm"],
)

# ===================================================
# LLAMACLOUD / LLAMAPARSE API KEY — 'llx-' (2026-10-17)
# ===================================================
# LlamaCloud API key (LlamaParse, LlamaExtract, LlamaCloud indexes): the
# literal 'llx-' prefix followed by exactly 48 alphanumeric characters. Sent
# as a Bearer key to api.cloud.llamaindex.ai and read by the LlamaIndex SDKs
# from LLAMA_CLOUD_API_KEY.
# - PREFIX, VENDOR-DOCUMENTED: LlamaIndex's own LlamaParse API-key page and
#   SDK quickstart show LlamaCloud(api_key="llx-...") and
#   LLAMA_CLOUD_API_KEY="llx-...".
# - WIDTH + ALPHABET, MEASURED: the vendor publishes only truncated
#   placeholders. Every public value in a narrow single-prefix measurement
#   (10 samples) was 48 characters of [A-Za-z0-9]; the measured sources are
#   not named because they hold live keys.
#
# The lookbehind/lookahead guards refuse [A-Za-z0-9_-] on both sides, so a
# 49th character matches nothing rather than being truncated, and 'llx-' is
# never carved out of a longer identifier. Confidence 0.95 with no entropy
# gate (vendor prefix plus fixed-width body). Severity high: the key spends
# the owner's LlamaCloud parsing credits and reads every index and pipeline
# in the project.

LLAMACLOUD_API_KEY = SecretPattern(
    id="llamacloud_api_key",
    name="LlamaCloud / LlamaParse API Key",
    description=(
        "LlamaCloud API key (LlamaParse / LlamaExtract / LlamaIndex Cloud) — the"
        " literal 'llx-' prefix followed by exactly 48 alphanumeric characters."
        " Authenticates to api.cloud.llamaindex.ai; whoever holds it spends the"
        " owner's parsing credits and can read the project's indexes and pipelines."
    ),
    provider="llamacloud",
    severity="high",
    # Source: https://developers.llamaindex.ai/llamaparse/general/api_key
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>llx-[A-Za-z0-9]{48})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # base62 body ~5.3 bits/char — the vendor prefix carries the precision
    context_keywords=[
        "llamacloud",
        "llamaparse",
        "llamaindex",
        "LLAMA_CLOUD_API_KEY",
        "api.cloud.llamaindex.ai",
    ],
    known_test_values={
        # Single-character masks — how docs and redacted configs render this
        # key. 0.95 sits above the 0.85 FP-wordlist gate, so they are pinned
        # (~0.15). Built by concatenation: no contiguous key literal sits in
        # source (GitHub push protection).
        "ll" + "x-" + fill * 48
        for fill in ("x", "X", "0", "a")
    },
    recommendation=(
        "Revoke this key in LlamaCloud (cloud.llamaindex.ai > API Keys), generate a"
        " replacement, and update every deployment that uses it. Review recent"
        " LlamaParse / LlamaExtract usage for unexpected jobs."
    ),
    tags=["ai", "llamacloud", "llamaindex", "llm"],
)

# ===================================================
# CARTESIA API KEY — 'sk_car_' / 'sk_car_admin_' (2026-10-18)
# ===================================================
# Cartesia (Sonic text-to-speech / voice agents) API key: the literal
# 'sk_car_' prefix, optionally followed by 'admin_' for an organization
# admin key, then exactly 22 alphanumeric characters. Sent as X-API-Key or
# a Bearer token to api.cartesia.ai and read by the Cartesia SDKs from
# CARTESIA_API_KEY.
# - PREFIXES, VENDOR-DOCUMENTED: Cartesia's own API-keys reference documents
#   the admin key as 'sk_car_admin_...' (issued at play.cartesia.ai/keys/admin)
#   and states that key IDs never start with 'sk_'; every other endpoint's
#   Authorizations block reads "Cartesia API key (sk_car_...)".
# - WIDTH + ALPHABET, MEASURED: the vendor publishes only truncated
#   placeholders. Every public standard-key value in a narrow single-prefix
#   measurement (13 samples, plus one truncated) was 22 characters of
#   [A-Za-z0-9]; the measured sources are not named because they hold live
#   keys. The ADMIN body width is UNMEASURED and assumed equal: an admin key
#   of another width is missed (generic fallback at most), never mis-sliced,
#   because '_' is outside the body alphabet.
#
# The lookbehind/lookahead guards refuse [A-Za-z0-9_-] on both sides, so a
# 23rd character matches nothing rather than being truncated, and 'sk_car_'
# is never carved out of a longer snake_case identifier (sk_car_model_id).
# Confidence 0.95 with no entropy gate (vendor prefix plus fixed-width
# body). Severity high: a standard key spends the owner's TTS / voice
# credits; an admin key additionally manages every key in the organization.

CARTESIA_API_KEY = SecretPattern(
    id="cartesia_api_key",
    name="Cartesia API Key",
    description=(
        "Cartesia API key (Sonic text-to-speech / voice agents) — the literal"
        " 'sk_car_' prefix, optionally 'sk_car_admin_' for an organization admin"
        " key, followed by exactly 22 alphanumeric characters. Authenticates to"
        " api.cartesia.ai; whoever holds it spends the owner's TTS credits, and an"
        " admin key can create, list and revoke every API key in the organization."
    ),
    provider="cartesia",
    severity="high",
    # Source: https://docs.cartesia.ai/api-reference/api-keys/get
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>sk_car_(?:admin_)?[A-Za-z0-9]{22})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # base62 body ~4.4 bits/char at 22 wide — the vendor prefix carries the precision
    context_keywords=[
        "cartesia",
        "CARTESIA_API_KEY",
        "CARTESIA_ADMIN_API_KEY",
        "api.cartesia.ai",
        "sonic",
        "tts",
    ],
    known_test_values={
        # Single-character masks — how docs and redacted configs render this
        # key, for both prefixes. 0.95 sits above the 0.85 FP-wordlist gate,
        # so they are pinned (~0.15). Built by concatenation: no contiguous key
        # literal sits in source (GitHub push protection).
        "sk_" + "car_" + admin + fill * 22
        for admin in ("", "admin_")
        for fill in ("x", "X", "0", "a")
    },
    recommendation=(
        "Revoke this key in Cartesia (play.cartesia.ai > API Keys, or > Admin Keys"
        " for an sk_car_admin_ key), generate a replacement, and update every"
        " deployment that uses it. If it was an admin key, audit the organization's"
        " other API keys for ones you did not create."
    ),
    tags=["ai", "cartesia", "tts", "voice"],
)

# ===================================================
# BROWSERBASE API KEY — 'bb_live_' (2026-10-19)
# ===================================================
# Browserbase (headless cloud browsers for AI agents; Stagehand) API key:
# the literal 'bb_live_' prefix followed by exactly 27 base64url characters.
# Sent in the X-BB-API-Key header to api.browserbase.com and read by the
# Browserbase / Stagehand SDKs from BROWSERBASE_API_KEY.
# - PREFIX, VENDOR-DOCUMENTED: Browserbase's own docs (docs.browserbase.com
#   quickstarts) show BROWSERBASE_API_KEY="bb_live_..." and document the
#   X-BB-API-Key header.
# - WIDTH + ALPHABET, MEASURED: the vendor publishes only truncated
#   placeholders. Every public value in a narrow single-prefix measurement
#   (7 samples) was 27 characters of [A-Za-z0-9_-]; the measured sources are
#   not named because they hold live keys. No 'bb_test_' sibling is
#   corroborated, so none is matched.
#
# The lookbehind/lookahead guards refuse [A-Za-z0-9_-] on both sides, so a
# 28th character matches nothing rather than being truncated. Because '_' is
# in the body alphabet, a snake_case identifier of exactly the right width
# (bb_live_session_identifier_...) could fit the shape; the 3.9-bit entropy
# gate sinks those (English identifiers score ~3.5-3.9 over the whole
# value, random bodies >= ~4.0). Confidence 0.90 (vendor prefix, measured
# width; above the 0.85 FP-wordlist gate). Severity high: whoever holds it
# runs cloud browser sessions billed to the owner and can read their
# session recordings, logs and contexts.

BROWSERBASE_API_KEY = SecretPattern(
    id="browserbase_api_key",
    name="Browserbase API Key",
    description=(
        "Browserbase API key (headless cloud browsers for AI agents, Stagehand) —"
        " the literal 'bb_live_' prefix followed by exactly 27 base64url"
        " characters. Authenticates to api.browserbase.com via the X-BB-API-Key"
        " header; whoever holds it runs browser sessions billed to the owner and"
        " can read the project's session recordings, logs and stored contexts."
    ),
    provider="browserbase",
    severity="high",
    # Source: https://docs.browserbase.com/integrations/vercel/agent-browser/quickstart
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>bb_live_[A-Za-z0-9_-]{27})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=3.9,  # random 27-char base64url bodies score >= ~4.0; snake_case identifiers <= ~3.9
    context_keywords=[
        "browserbase",
        "BROWSERBASE_API_KEY",
        "BROWSERBASE_PROJECT_ID",
        "X-BB-API-Key",
        "api.browserbase.com",
        "stagehand",
    ],
    known_test_values={
        # Single-character masks — how docs and redacted configs render this
        # key. Pinned (~0.15). Built by concatenation: no contiguous key
        # literal sits in source (GitHub push protection).
        "bb_" + "live_" + fill * 27
        for fill in ("x", "X", "0", "a")
    },
    recommendation=(
        "Rotate this key in the Browserbase dashboard (Settings > API Keys),"
        " update every deployment that reads BROWSERBASE_API_KEY, and review the"
        " project's recent sessions for ones you did not start."
    ),
    tags=["ai", "browserbase", "browser", "agents"],
)

# ===================================================
# TAVILY API KEY — 'tvly-' / 'tvly-dev-' (2026-10-19)
# ===================================================
# Tavily (search / extract API for LLM agents) API key: the literal 'tvly-'
# prefix, optionally followed by 'dev-' for a development key, then exactly
# 32 alphanumeric characters. Sent as 'Authorization: Bearer tvly-...' to
# api.tavily.com and read by the Tavily SDKs and LangChain integration from
# TAVILY_API_KEY.
# - PREFIXES, VENDOR-DOCUMENTED: Tavily's own docs authenticate with
#   'Bearer tvly-YOUR_API_KEY', and its enterprise key-generation reference
#   returns development keys as 'tvly-dev-...' (key_type 'development' is
#   the default; the production key prefix is not shown and is not guessed
#   here beyond the bare 'tvly-').
# - WIDTH + ALPHABET, MEASURED: the vendor publishes only truncated values.
#   Every public value in a narrow single-prefix measurement was 32
#   [A-Za-z0-9] after the prefix; the measured sources are not named
#   because they hold live keys.
#
# Both guards refuse [A-Za-z0-9_-], so a 33rd character matches nothing
# rather than being truncated, and because '-' is outside the body alphabet
# a 'tvly-<other>-' key with an unknown infix is missed, never mis-sliced.
# Confidence 0.95, no entropy gate. Severity high: whoever holds the key
# spends the owner's search credits.

TAVILY_API_KEY = SecretPattern(
    id="tavily_api_key",
    name="Tavily API Key",
    description=(
        "Tavily API key (search / extract API for LLM agents) — the literal"
        " 'tvly-' prefix, optionally 'tvly-dev-' for a development key,"
        " followed by exactly 32 alphanumeric characters. Authenticates to"
        " api.tavily.com and spends the owner's search credits."
    ),
    provider="tavily",
    severity="high",
    # Source: https://docs.tavily.com/documentation/enterprise/generate-keys
    regex=re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"(?P<secret>tvly-(?:dev-)?[A-Za-z0-9]{32})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # vendor prefix plus fixed-width body carries the precision
    context_keywords=[
        "tavily",
        "TAVILY_API_KEY",
        "api.tavily.com",
        "TavilyClient",
        "search",
    ],
    known_test_values={
        # Single-character masks, both prefixes. Built by concatenation.
        "tv" + "ly-" + dev + fill * 32
        for dev in ("", "dev-")
        for fill in ("x", "X", "0", "a")
    },
    recommendation=(
        "Delete this key in the Tavily dashboard (app.tavily.com > API Keys),"
        " create a replacement and update TAVILY_API_KEY wherever it is set"
        " (agent configs, CI secrets, notebooks). Check the account's usage"
        " for searches you did not make."
    ),
    tags=["ai", "tavily", "search", "llm"],
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
    LANGSMITH_API_KEY,
    CLARIFAI_PAT,
    OPENROUTER_API_KEY,
    PERPLEXITY_API_KEY,
    ANYSCALE_API_KEY,
    BRAINTRUST_API_KEY,
    RUNPOD_API_KEY,
    BAIDU_QIANFAN_BCE_API_KEY,
    # 2026-09-07 — Firecrawl API key ('fc-' + exactly 32 hex, the width
    # pinned by the vendor's own parseApi.ts UUID re-dashing).
    FIRECRAWL_API_KEY,
    # 2026-09-19 — Helicone API key ('sk-helicone' / 'pk-helicone' + optional
    # -eu/-cp/-rl + 4 x 7 [a-z0-9], per the vendor's own apiKeyRegex.ts).
    HELICONE_API_KEY,
    # 2026-10-05 — Hack Club AI API key ('sk-hc-v1-' + 64 lowercase hex;
    # from the vendor's own key generator). Disjoint from openai_api_key.
    HACKCLUB_AI_API_KEY,
    # 2026-10-09 — MiniMax pay-as-you-go API key ('sk-api-' + 119
    # base64url; width per Betterleaks MIT). Disjoint from openai_api_key.
    MINIMAX_API_KEY,
    # 2026-10-10 — Together AI API key ('tgp_v1_' + 43 base64url; prefix per
    # the vendor's own SDK, width per the Betterleaks (MIT) rule).
    TOGETHER_API_KEY,
    # 2026-10-16 — NVIDIA API key ('nvapi-' + 64 base64url; prefix per
    # NVIDIA's own docs, width measured on public samples).
    NVIDIA_API_KEY,
    # 2026-10-17 — LlamaCloud / LlamaParse API key ('llx-' + 48 alphanumeric;
    # prefix per LlamaIndex's own docs, width measured on public samples).
    LLAMACLOUD_API_KEY,
    # 2026-10-18 — Cartesia API key ('sk_car_' / 'sk_car_admin_' + 22
    # alphanumeric; prefixes per Cartesia's own API reference, width measured
    # on public samples).
    CARTESIA_API_KEY,
    # 2026-10-19 — Browserbase API key ('bb_live_' + 27 base64url; prefix per
    # Browserbase's own docs, width measured on public samples).
    BROWSERBASE_API_KEY,
    # 2026-10-19 — Tavily API key ('tvly-' / 'tvly-dev-' + 32 alphanumeric;
    # prefixes per Tavily's own docs, width measured on public samples).
    TAVILY_API_KEY,
)
