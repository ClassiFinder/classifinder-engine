"""
ClassiFinder — Payment Provider Patterns

Patterns for Stripe, PayPal, and Square credentials.
Payment keys are critical severity -- a leaked Stripe live key gives direct
access to charge customers, issue refunds, and read payment data.

Pattern design notes:
- Stripe keys have extremely reliable prefixes: sk_live_, sk_test_, pk_live_,
  pk_test_, rk_live_, rk_test_, whsec_. This makes detection near-certain.
- We detect both live and test keys. Test keys are flagged with lower severity
  (medium) but still reported -- they often appear alongside live keys or
  reveal account structure.
- PayPal and Square have less distinctive formats, so we rely more on context.
"""

import re

from .registry import SecretPattern, register

# ===================================================
# STRIPE
# ===================================================

STRIPE_LIVE_SECRET_KEY = SecretPattern(
    id="stripe_live_secret_key",
    name="Stripe Live Secret Key",
    description=(
        "Stripe live-mode secret API key. Grants full access to"
        " a live Stripe account including charges, refunds,"
        " and customer data."
    ),
    provider="stripe",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>sk_live_[a-zA-Z0-9]{24,99})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.99,  # prefix is unique to Stripe
    entropy_threshold=0.0,
    context_keywords=[
        "stripe",
        "secret_key",
        "STRIPE_SECRET_KEY",
        "payment",
    ],
    known_test_values=set(),  # sk_live_ keys are never test values by definition
    recommendation=(
        "Immediately roll this key in the Stripe Dashboard"
        " under Developers > API Keys."
        " Audit recent charges and events in the Stripe log."
    ),
    tags=["payment", "stripe"],
)


STRIPE_TEST_SECRET_KEY = SecretPattern(
    id="stripe_test_secret_key",
    name="Stripe Test Secret Key",
    description=(
        "Stripe test-mode secret API key. Cannot process real"
        " payments but reveals account structure and test data."
    ),
    provider="stripe",
    severity="medium",
    regex=re.compile(
        r"(?P<secret>sk_test_[a-zA-Z0-9]{24,99})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.99,
    entropy_threshold=0.0,
    context_keywords=[
        "stripe",
        "secret_key",
        "test",
        "STRIPE_SECRET_KEY",
    ],
    known_test_values={
        "sk_test_4eC39HqLyjWDarjtT1zdp7dc",  # from Stripe docs
    },
    recommendation=(
        "Roll this test key in the Stripe Dashboard."
        " While it cannot process real payments, it exposes"
        " account configuration and test data."
    ),
    tags=["payment", "stripe"],
)


STRIPE_LIVE_PUBLISHABLE_KEY = SecretPattern(
    id="stripe_live_publishable_key",
    name="Stripe Live Publishable Key",
    description=(
        "Stripe live-mode publishable key. Intended for client-side"
        " use but should not appear in server-side code, logs,"
        " or configs."
    ),
    provider="stripe",
    severity="low",  # publishable keys are semi-public by design
    regex=re.compile(
        r"(?P<secret>pk_live_[a-zA-Z0-9]{24,99})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.99,
    entropy_threshold=0.0,
    context_keywords=[
        "stripe",
        "publishable",
        "STRIPE_PUBLISHABLE_KEY",
    ],
    known_test_values=set(),
    recommendation=(
        "Publishable keys are designed for client-side use,"
        " but their presence in server code or logs may indicate"
        " a configuration issue. Review whether this should be"
        " a secret key instead."
    ),
    tags=["payment", "stripe"],
)


STRIPE_WEBHOOK_SECRET = SecretPattern(
    id="stripe_webhook_secret",
    name="Stripe Webhook Signing Secret",
    description=("Stripe webhook endpoint signing secret, used to verify webhook payloads."),
    provider="stripe",
    severity="high",
    regex=re.compile(
        r"(?P<secret>whsec_[a-zA-Z0-9]{24,99})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.99,
    entropy_threshold=0.0,
    context_keywords=[
        "stripe",
        "webhook",
        "signing",
        "whsec",
        "endpoint",
    ],
    known_test_values=set(),
    recommendation=(
        "Rotate this webhook signing secret in the Stripe Dashboard"
        " under Developers > Webhooks."
        " An attacker with this secret can forge webhook events."
    ),
    tags=["payment", "stripe", "webhook"],
)


STRIPE_RESTRICTED_KEY = SecretPattern(
    id="stripe_restricted_key",
    name="Stripe Restricted API Key",
    description=(
        "Stripe restricted API key with limited permissions."
        " Still sensitive -- permissions may include read access"
        " to customer or payment data."
    ),
    provider="stripe",
    severity="high",
    regex=re.compile(
        r"(?P<secret>rk_live_[a-zA-Z0-9]{24,99})"
        r"(?![a-zA-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.99,
    entropy_threshold=0.0,
    context_keywords=["stripe", "restricted", "rk_live"],
    known_test_values=set(),
    recommendation=(
        "Rotate this restricted key in the Stripe Dashboard."
        " Audit its permission scope to understand exposure."
    ),
    tags=["payment", "stripe"],
)


# ===================================================
# PAYPAL
# ===================================================

PAYPAL_CLIENT_SECRET = SecretPattern(
    id="paypal_client_secret",
    name="PayPal Client Secret",
    description=("PayPal REST API client secret. Used with client ID for OAuth authentication."),
    provider="paypal",
    severity="critical",
    regex=re.compile(
        r"(?:"
        r"(?:PAYPAL_CLIENT_SECRET|paypal.*client.*secret|paypal.*secret)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>E[A-Za-z0-9\-]{50,80})"  # PayPal secrets typically start with E
        r"(?![A-Za-z0-9\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.75,  # format less distinctive, relies on context
    entropy_threshold=3.5,
    context_keywords=[
        "paypal",
        "client_secret",
        "client_id",
        "PAYPAL_CLIENT_ID",
        "sandbox",
        "payment",
    ],
    known_test_values=set(),
    recommendation=(
        "Rotate this secret in the PayPal Developer Dashboard."
        " Revoke the associated app credentials if compromised."
    ),
    tags=["payment", "paypal"],
)


# ===================================================
# SQUARE
# ===================================================

SQUARE_ACCESS_TOKEN = SecretPattern(
    id="square_access_token",
    name="Square Access Token",
    description=(
        "Square API access token. Format varies but typically"
        " a long alphanumeric string with the EAA prefix"
        " for sandbox or production."
    ),
    provider="square",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>EAA[a-zA-Z0-9\-_]{40,100})"
        r"(?![a-zA-Z0-9\-_])",
        re.ASCII,
    ),
    confidence_base=0.85,
    entropy_threshold=3.0,
    context_keywords=[
        "square",
        "access_token",
        "SQUARE_ACCESS_TOKEN",
        "squareup",
    ],
    known_test_values=set(),
    recommendation=("Revoke and regenerate this token in the Square Developer Dashboard."),
    tags=["payment", "square"],
)


# ===================================================
# CREDIT CARDS
# ===================================================


def _luhn_check(digits: str) -> bool:
    """Validate a credit card number using the Luhn algorithm.

    Pure function: digits in, bool out. Returns True if the number
    passes the Luhn checksum (i.e., is a structurally valid card number).
    """
    if not digits.isdigit() or len(digits) < 13:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


CREDIT_CARD_NUMBER = SecretPattern(
    id="credit_card_number",
    name="Credit Card Number",
    description=(
        "Credit card number (Visa, Mastercard, Amex, Discover)."
        " Validated with Luhn checksum to reduce false positives."
    ),
    provider="payment",
    severity="high",
    regex=re.compile(
        r"(?<![0-9])"  # negative lookbehind: not preceded by digit
        r"(?P<secret>"
        # Visa, MC, Amex, Discover prefixes
        r"(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))"
        r"[\s\-]?"
        r"[0-9]{4,6}"
        r"[\s\-]?"
        r"[0-9]{4,5}"
        r"(?:[\s\-]?[0-9]{4})?"
        r")"
        r"(?![0-9])",  # negative lookahead: not followed by digit
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,  # Luhn check handles validation instead of entropy
    context_keywords=[
        "card",
        "credit",
        "cc",
        "payment",
        "card_number",
        "pan",
        "visa",
        "mastercard",
        "amex",
    ],
    known_test_values={
        "4111111111111111",  # Visa test
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "5500000000000004",  # Mastercard test
        "340000000000009",  # Amex test
        "6011000000000004",  # Discover test
        "4242424242424242",  # Stripe test card
    },
    recommendation=(
        "This card number should be removed from code, logs,"
        " and configuration immediately. If this is a real card,"
        " notify the cardholder and your PCI compliance team."
    ),
    tags=["payment", "pci", "credit-card"],
)


# ===================================================
# SHOPIFY
# ===================================================

SHOPIFY_ACCESS_TOKEN = SecretPattern(
    id="shopify_access_token",
    name="Shopify Admin API Access Token",
    description=(
        "Shopify admin API access token with shpat_ prefix."
        " Grants access to a Shopify store's admin API."
    ),
    provider="shopify",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>shpat_[a-fA-F0-9]{32})"
        r"(?![a-fA-F0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "shopify",
        "SHOPIFY_ACCESS_TOKEN",
        "shopify_token",
        "shpat",
    ],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in the Shopify Partner Dashboard"
        " or store admin under Apps > Develop apps."
    ),
    tags=["payment", "shopify", "ecommerce"],
)


SHOPIFY_CUSTOM_TOKEN = SecretPattern(
    id="shopify_custom_token",
    name="Shopify Custom App Access Token",
    description=(
        "Shopify custom app access token with shpca_ prefix."
        " Grants custom app access to a Shopify store."
    ),
    provider="shopify",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>shpca_[a-fA-F0-9]{32})"
        r"(?![a-fA-F0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "shopify",
        "SHOPIFY_CUSTOM_TOKEN",
        "shpca",
    ],
    known_test_values=set(),
    recommendation=("Revoke this token in the Shopify store admin under Apps > Develop apps."),
    tags=["payment", "shopify", "ecommerce"],
)


SHOPIFY_PRIVATE_TOKEN = SecretPattern(
    id="shopify_private_token",
    name="Shopify Private App Access Token",
    description=(
        "Shopify private app access token with shppa_ prefix."
        " Grants private app access to a Shopify store."
    ),
    provider="shopify",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>shppa_[a-fA-F0-9]{32})"
        r"(?![a-fA-F0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=[
        "shopify",
        "SHOPIFY_PRIVATE_TOKEN",
        "shppa",
    ],
    known_test_values=set(),
    recommendation=(
        "Shopify deprecated private apps. Migrate to custom apps and revoke this token."
    ),
    tags=["payment", "shopify", "ecommerce"],
)


# ===================================================
# ETHEREUM
# ===================================================

ETHEREUM_PRIVATE_KEY = SecretPattern(
    id="ethereum_private_key",
    name="Ethereum Private Key",
    description=(
        "Ethereum private key — 0x followed by 64 hex characters (256 bits)."
        " Detected when preceded by Ethereum/wallet context keywords."
        " Controls an Ethereum wallet and all its assets."
    ),
    provider="ethereum",
    severity="critical",
    regex=re.compile(
        r"(?:"
        r"(?:ETH_PRIVATE_KEY|ETHEREUM_PRIVATE_KEY|ethereum.*private.*key|eth.*key|wallet.*key|private.*key.*eth)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>0x[a-fA-F0-9]{64})"
        r"(?![a-fA-F0-9])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=3.5,
    context_keywords=[
        "ethereum",
        "eth",
        "wallet",
        "ETH_PRIVATE_KEY",
        "web3",
        "metamask",
    ],
    known_test_values={
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",  # Hardhat #0
    },
    recommendation=(
        "Transfer all assets from this wallet immediately."
        " An attacker with this key has full control of the wallet"
        " and can drain all ETH and tokens."
    ),
    tags=["crypto", "ethereum", "wallet"],
)


# ===================================================
# BITCOIN
# ===================================================

BITCOIN_WIF_KEY = SecretPattern(
    id="bitcoin_wif_key",
    name="Bitcoin WIF Private Key",
    description=(
        "Bitcoin private key in Wallet Import Format (WIF)."
        " Starts with 5 (uncompressed), K, or L (compressed) followed by"
        " 50-51 Base58Check characters."
    ),
    provider="bitcoin",
    severity="critical",
    regex=re.compile(
        r"(?:"
        r"(?:BTC_PRIVATE_KEY|BITCOIN_PRIVATE_KEY|bitcoin.*private.*key|bitcoin.*wif|btc.*key|wallet.*wif)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[5KL][1-9A-HJ-NP-Za-km-z]{50,51})"
        r"(?![1-9A-HJ-NP-Za-km-z])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.80,
    entropy_threshold=3.5,
    context_keywords=[
        "bitcoin",
        "btc",
        "wallet",
        "wif",
        "BTC_PRIVATE_KEY",
        "private_key",
    ],
    known_test_values=set(),
    recommendation=(
        "Transfer all Bitcoin from this wallet immediately."
        " An attacker with a WIF private key has full control"
        " of the associated Bitcoin address."
    ),
    tags=["crypto", "bitcoin", "wallet"],
)


# ===================================================
# RAZORPAY
# ===================================================

RAZORPAY_KEY = SecretPattern(
    id="razorpay_key",
    name="Razorpay API Key",
    description=(
        "Razorpay API key with rzp_live_ or rzp_test_ prefix."
        " Grants access to Razorpay payment processing."
    ),
    provider="razorpay",
    severity="critical",
    regex=re.compile(
        r"(?P<secret>rzp_(?:live|test)_[A-Za-z0-9]{14,})"
        r"(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["razorpay", "RAZORPAY_KEY", "rzp"],
    known_test_values=set(),
    recommendation=(
        "Rotate this key in the Razorpay Dashboard under Settings > API Keys."
        " Audit recent transactions for unauthorized activity."
    ),
    tags=["payment", "razorpay"],
)


register(
    STRIPE_LIVE_SECRET_KEY,
    STRIPE_TEST_SECRET_KEY,
    STRIPE_LIVE_PUBLISHABLE_KEY,
    STRIPE_WEBHOOK_SECRET,
    STRIPE_RESTRICTED_KEY,
    PAYPAL_CLIENT_SECRET,
    SQUARE_ACCESS_TOKEN,
    CREDIT_CARD_NUMBER,
    SHOPIFY_ACCESS_TOKEN,
    SHOPIFY_CUSTOM_TOKEN,
    SHOPIFY_PRIVATE_TOKEN,
    ETHEREUM_PRIVATE_KEY,
    BITCOIN_WIF_KEY,
    RAZORPAY_KEY,
)
