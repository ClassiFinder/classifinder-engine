"""
ClassiFinder — Prompt Injection Markers (Phase 1: high-precision)

Patterns for structurally rare tokens that appear in prompt-injection attacks
against LLM applications. Phase 1 ships only the 4 high-precision patterns:
control-token role hijacks, agent tool-call tag injection, named jailbreak
personas, and Unicode bidirectional override smuggling (Trojan Source).

Phase 2 (instruction overrides, persona overrides, prompt extraction, etc.)
is gated on FP testing of these patterns and lives in a separate module.

Design notes:
- These are syntactic markers, not vendor-issued credentials. Severity caps
  at "high" — no "critical" — since the consequence is "block the input,"
  not "rotate this key."
- Confidence base is 0.85+ across the board because each pattern targets
  text that is structurally rare in legitimate user input (control tokens,
  literal tool tags, named personas with stable spellings, BiDi codepoints).
- Entropy threshold is 0.0 — entropy doesn't apply to natural language.
- The "secret" named group captures the matched marker text. value_preview
  in findings is the first 4 + last 4 chars, which is informative enough to
  identify what was caught (e.g., "<|im" ... "tem|>").
- ClassiFinder is layer 1: detect the structural marker. Semantic detection
  of indirect injections (benign-looking RAG docs that quietly redirect the
  model) requires LLM-in-the-loop and is left to LlamaGuard / PromptGuard.
"""

import re

from .registry import SecretPattern, register

# ===================================================
# 1. ROLE HIJACK — chat template control tokens
# ===================================================

ROLE_HIJACK_MARKER = SecretPattern(
    id="pi_role_hijack_marker",
    name="Role Hijack Token",
    description=(
        "Chat template control tokens (ChatML im_start/im_end, Llama [INST]"
        " / <<SYS>>, Llama 3 header tokens) appearing in user input. Used"
        " to fake a system or assistant turn and override the application's"
        " intended prompt structure."
    ),
    provider="prompt_injection",
    severity="high",
    # Independently authored — control tokens drawn from public OpenAI ChatML
    # (im_start/im_end/endoftext), Llama 2 instruction format ([INST]/<<SYS>>),
    # Llama 3 header tokens (begin_of_text/start_header_id/end_header_id/eot_id),
    # and Alpaca-style instruct format (### Instruction:/### Response:). The
    # (?<!`) / (?!`) lookarounds skip inline-code mentions in tech documentation.
    regex=re.compile(
        r"(?<!`)"
        r"(?P<secret>"
        r"<\|(?:im_start|im_end|endoftext|begin_of_text|start_header_id"
        r"|end_header_id|eot_id|system|user|assistant)\|>"
        r"|<<SYS>>|<</SYS>>"
        r"|\[INST\]|\[/INST\]"
        r"|^### (?:Instruction|Response|System)[: ]"
        r")"
        r"(?!`)",
        re.MULTILINE,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=[],
    known_test_values=set(),
    recommendation=(
        "Block this input or strip the control tokens before passing to the"
        " LLM. Chat template tokens in user-submitted text are diagnostic of"
        " a deliberate attempt to inject a fake system or assistant turn."
        " Note: this pattern is tuned for user-input deployment surfaces"
        " (LangChain guard, FastAPI middleware). For RAG pre-indexing of"
        " LLM-internals documentation (HuggingFace tokenizer docs, chat-"
        " template tutorials), expect over-firing inside fenced code blocks"
        " — opt out via the types= filter for those use cases."
    ),
    tags=["prompt-injection", "role-hijack", "high-precision"],
)


# ===================================================
# 2. TOOL CALL INJECTION — fake agent actions
# ===================================================

TOOL_CALL_INJECTION = SecretPattern(
    id="pi_tool_call_injection",
    name="Tool Call Tag Injection",
    description=(
        "Literal tool-use, function-call, or chain-of-thought tags in user"
        " input. Attempts to fake a model-emitted tool call or reasoning"
        " trace. High severity in agent pipelines that parse model output"
        " for tool dispatch."
    ),
    provider="prompt_injection",
    severity="high",
    # Independently authored — tag names from public Anthropic Messages API
    # documentation (tool_use, tool_result), OpenAI legacy function-calling
    # docs (function_call), and chain-of-thought wrapper conventions
    # (thinking, reasoning). User input containing these tags is an attempt
    # to fake a model-emitted tool call or reasoning trace.
    regex=re.compile(
        r"(?P<secret>"
        r"</?(?:tool_use|tool_call|tool_result|function_call|thinking|reasoning)"
        r"\b[^>]*>"
        r")",
        re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=[],
    known_test_values=set(),
    recommendation=(
        "Block or escape these tags before passing input to an agent loop."
        " Tool-call tags in user-submitted text are a known vector for"
        " prompt-injection attacks against tool-using agents. Note: this"
        " pattern over-fires on prompt-engineering documentation (e.g.,"
        " Anthropic's metaprompt tutorial) that contains literal tags as"
        " teaching examples — opt out via the types= filter when RAG-"
        " indexing such content."
    ),
    tags=["prompt-injection", "agent-attack", "high-precision"],
)


# ===================================================
# 3. JAILBREAK PERSONA — DAN, developer mode, etc.
# ===================================================

JAILBREAK_PERSONA = SecretPattern(
    id="pi_jailbreak_persona",
    name="Known Jailbreak Persona",
    description=(
        "References to canonical jailbreak personas (DAN, AIM, STAN,"
        " developer mode, god mode, evilGPT). High signal of intent to"
        " bypass model safety guardrails."
    ),
    provider="prompt_injection",
    severity="high",
    # Independently authored — persona names sourced from publicly disclosed
    # jailbreak corpora (HackAPrompt 2023, jailbreak_llms research dataset,
    # and the survey by Liu et al. 2024 "Jailbreaking ChatGPT via Prompt
    # Engineering"). Restricted to canonical persona names with stable
    # spellings: DAN, AIM, STAN, developer mode, god mode, evilGPT.
    regex=re.compile(
        r"(?P<secret>"
        r"\b(?:DAN|D\.A\.N\.)\s+(?:mode|prompt|persona)\b"
        r"|\bdo\s+anything\s+now\b"
        r"|\b(?:developer|god)\s+mode\s+(?:enabled|activated|on|engaged)\b"
        r"|\b(?:AIM|STAN|DUDE)\s+(?:mode|prompt|persona)\b"
        r"|\bevil[-_\s]?GPT\b"
        r"|\bjail[-\s]?broken\s+(?:mode|response|model|GPT|AI|version)\b"
        r")",
        re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=["roleplay", "pretend", "hypothetical", "uncensored"],
    known_test_values=set(),
    recommendation=(
        "Block or escalate. These persona names are well-known jailbreak"
        " triggers documented in published security research. Note that"
        " documents *about* jailbreaking (security research, this very"
        " pattern's docs) will also match — opt out via types= filter for"
        " those use cases."
    ),
    tags=["prompt-injection", "jailbreak", "high-precision"],
)


# ===================================================
# 4. BIDI OVERRIDE — Trojan Source (CVE-2021-42574)
# ===================================================

BIDI_OVERRIDE = SecretPattern(
    id="pi_bidi_override",
    name="Bidirectional Override Character",
    description=(
        "Unicode bidirectional override characters (LRE/RLE/PDF/LRO/RLO and"
        " LRI/RLI/FSI/PDI). The Trojan Source attack vector — text renders"
        " one way and parses another. Almost never legitimate in English-"
        " language pipelines."
    ),
    provider="prompt_injection",
    severity="high",
    # Source: Boucher & Anderson, 2021, "Trojan Source: Invisible
    # Vulnerabilities" (CVE-2021-42574). Codepoints per Unicode 15.1
    # General Category Cf (Format).
    regex=re.compile(
        r"(?P<secret>[\u202a-\u202e\u2066-\u2069]+)",
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=[],
    known_test_values=set(),
    recommendation=(
        "Strip BiDi control characters before passing input to the LLM."
        " For pipelines that legitimately handle right-to-left scripts"
        " (Arabic, Hebrew, Persian), opt out via the types= filter — this"
        " pattern is tuned for English-language deployment surfaces."
    ),
    tags=["prompt-injection", "encoding-attack", "trojan-source", "high-precision"],
)


register(
    ROLE_HIJACK_MARKER,
    TOOL_CALL_INJECTION,
    JAILBREAK_PERSONA,
    BIDI_OVERRIDE,
)
