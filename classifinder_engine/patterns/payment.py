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
    # Vendor-published format — sk_live_ prefix is Stripe-documented live secret key
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
    # Vendor-published format — sk_test_ prefix is Stripe-documented test secret key
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
    # Vendor-published format — pk_live_ prefix is Stripe-documented publishable key
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
    # Vendor-published format — whsec_ prefix is Stripe-documented webhook signing secret
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
    # Vendor-published format — rk_live_ prefix is Stripe-documented restricted key
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
    # Independently authored — context-gated E-prefix 50-80 char; PayPal-documented OAuth credential
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
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:922) — EAA prefix (Square-documented)
    regex=re.compile(
        r"(?P<secret>EAA[a-zA-Z0-9\-_]{40,100})"
        r"(?![a-zA-Z0-9\-_])",
        re.ASCII,
    ),
    # Tuned 2026-05-20 from 0.85 → 0.78 per benchmark-results-2026-05-19.md.
    # The EAA prefix collides with notebook base64 payloads (image data, model
    # weights, etc.) — benchmark surfaced 4560 high-conf FPs in .ipynb files,
    # 100% with zero supporting context. Base 0.78 keeps real tokens at high-
    # conf via context boost (+0.02/keyword) while demoting bare-shape matches.
    # See tasks/Finished Tasks/2026-05-20-tune-square-access-token-anomaly.md.
    confidence_base=0.78,
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
    # Vendor-published format — IIN/BIN ranges per PCI-DSS and card network specifications
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
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4320) — shpat_ vendor prefix
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
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4330) — shpca_ vendor prefix
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
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4340) — shppa_ vendor prefix
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


# Batch 4 Part 1.10 — Shopify shared secret (2026-05-21)
# Body shape from Betterleaks MIT cmd/generate/config/rules/shopify.go.

SHOPIFY_SHARED_SECRET = SecretPattern(
    id="shopify_shared_secret",
    name="Shopify Shared Secret",
    description=(
        "Shopify app shared secret with shpss_ prefix (32 hex chars)."
        " Used to verify webhook signatures from Shopify to your app."
    ),
    provider="shopify",
    severity="high",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/shopify.go) — shpss_ vendor prefix
    regex=re.compile(
        r"(?P<secret>shpss_[a-fA-F0-9]{32})"
        r"(?![a-fA-F0-9])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["shopify", "shared_secret", "SHOPIFY_SHARED_SECRET", "shpss"],
    known_test_values=set(),
    recommendation=(
        "Rotate this Shopify shared secret in the Partner Dashboard under"
        " App setup > Client credentials. Compromised secrets allow webhook forgery."
    ),
    tags=["payment", "shopify", "ecommerce", "webhook"],
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
    # Pattern attribution: Betterleaks MIT (betterleaks.toml:4053) — context-gated 0x+64hex
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
    # Vendor-published format — WIF key format per BIP-0178 specification (Base58Check encoding)
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
    # Vendor-published format — rzp_live_/rzp_test_ prefix is Razorpay-documented API key format
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


# ===================================================
# FLUTTERWAVE
# ===================================================

FLUTTERWAVE_SECRET_KEY = SecretPattern(
    id="flutterwave_secret_key",
    name="Flutterwave Secret Key",
    description=(
        "Flutterwave secret key with FLWSECK_TEST- or FLWSECK_LIVE- prefix"
        " followed by 32 hex chars and -X suffix."
        " Grants access to Flutterwave payment APIs."
    ),
    provider="flutterwave",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/flutterwave.go) —
    # FLWSECK_TEST- prefix, [a-h0-9]{32} charset, -X suffix.
    # Live variant (FLWSECK_LIVE-) independently authored — mirrors test key structure.
    regex=re.compile(
        r"(?P<secret>FLWSECK_(?:TEST|LIVE)-[a-hA-H0-9]{32}-X)"
        r"(?![a-hA-H0-9\-])",
        re.ASCII,
    ),
    confidence_base=0.97,
    entropy_threshold=0.0,
    context_keywords=["flutterwave", "FLWSECK", "flw_secret"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the Flutterwave Dashboard under Settings > API Keys."
        " Audit recent transactions for unauthorized activity."
    ),
    tags=["payment", "flutterwave"],
)


# ===================================================
# ETHERSCAN
# ===================================================

ETHERSCAN_API_KEY = SecretPattern(
    id="etherscan_api_key",
    name="Etherscan API Key",
    description=(
        "Etherscan API key, a 34-character uppercase alphanumeric string."
        " Detected when preceded by Etherscan-specific context keywords."
        " Used for Ethereum blockchain data queries."
    ),
    provider="etherscan",
    severity="medium",
    # Independently authored — context-gated 34-char uppercase alphanumeric per
    # Etherscan API documentation (https://docs.etherscan.io/).
    regex=re.compile(
        r"(?:"
        r"(?:ETHERSCAN_API_KEY|etherscan.*key|etherscan.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[A-Z0-9]{34})"
        r"(?![A-Z0-9])",
        re.ASCII,
    ),
    confidence_base=0.80,
    entropy_threshold=3.5,
    context_keywords=["etherscan", "ETHERSCAN_API_KEY", "ethereum", "blockchain"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key at etherscan.io under My Account > API Keys."
        " Generate a new key and update your application."
    ),
    tags=["payment", "etherscan", "crypto", "blockchain"],
)


# ===================================================
# GOCARDLESS
# ===================================================

GOCARDLESS_ACCESS_TOKEN = SecretPattern(
    id="gocardless_access_token",
    name="GoCardless Access Token",
    description=(
        "GoCardless access token with live_ prefix (40 alphanumeric chars)."
        " Detected when GoCardless context keywords are present."
        " Grants access to GoCardless payment collection APIs."
    ),
    provider="gocardless",
    severity="critical",
    # Pattern attribution: Betterleaks MIT (cmd/generate/config/rules/gocardless.go) —
    # live_ prefix + context gate on gocardless.
    regex=re.compile(
        r"(?:"
        r"(?:GOCARDLESS_ACCESS_TOKEN|gocardless.*token|gocardless.*key)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>live_[a-zA-Z0-9\-_=]{40})"
        r"(?![a-zA-Z0-9\-_=])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=3.5,
    context_keywords=["gocardless", "GOCARDLESS_ACCESS_TOKEN", "direct_debit"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in the GoCardless Dashboard under Developers > Access tokens."
        " Generate a new token with minimal required permissions."
    ),
    tags=["payment", "gocardless"],
)


# ===================================================
# WISE (formerly TransferWise)
# ===================================================

WISE_API_TOKEN = SecretPattern(
    id="wise_api_token",
    name="Wise API Token",
    description=(
        "Wise (formerly TransferWise) API token in UUID format."
        " Detected when Wise or TransferWise context keywords are present."
        " Grants access to Wise international payment APIs."
    ),
    provider="wise",
    severity="critical",
    # Independently authored — context-gated UUID format per Wise API documentation.
    regex=re.compile(
        r"(?:"
        r"(?:WISE_API_TOKEN|WISE_API_KEY|TRANSFERWISE_API_TOKEN|wise.*token|wise.*key|transferwise.*token)"
        r"[\s]*[=:\"'\s]+"
        r")"
        r"(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        r"(?![0-9a-f\-])",
        re.ASCII | re.IGNORECASE,
    ),
    confidence_base=0.85,
    entropy_threshold=0.0,
    context_keywords=["wise", "transferwise", "WISE_API_TOKEN", "WISE_API_KEY"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token at wise.com under Settings > API tokens."
        " Generate a new token and audit recent transactions."
    ),
    tags=["payment", "wise", "transferwise"],
)


# ===================================================
# EASYPOST (shipping / logistics)
# ===================================================

EASYPOST_API_KEY = SecretPattern(
    id="easypost_api_key",
    name="EasyPost API Key",
    description=(
        "EasyPost shipping API key. Production/test keys begin with 'EZAK'/'EZTK'"
        " and partner keys with 'EZPK', followed by a long alphanumeric body."
        " Grants access to purchase shipping labels and read address/tracking data."
    ),
    provider="easypost",
    severity="high",
    # Format per EasyPost API key documentation (keys prefixed EZAK/EZTK/EZPK):
    #   https://support.easypost.com/hc/en-us/articles/360051341434-Where-Can-I-Find-My-API-Keys
    # Independently authored from the documented prefix + alphanumeric body.
    regex=re.compile(
        r"(?P<secret>(?:EZAK|EZTK|EZPK)[A-Za-z0-9]{50,})(?![A-Za-z0-9])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=["easypost", "EASYPOST_API_KEY", "shipping", "label"],
    known_test_values=set(),
    recommendation=(
        "Revoke this key in the EasyPost dashboard under Account > API Keys."
    ),
    tags=["payment", "easypost", "shipping"],
)


# ===================================================
# DUFFEL (travel / flights)
# ===================================================

DUFFEL_ACCESS_TOKEN = SecretPattern(
    id="duffel_access_token",
    name="Duffel Access Token",
    description=(
        "Duffel travel API access token with a 'duffel_test_' or 'duffel_live_'"
        " prefix followed by a token body. Grants access to search and book"
        " flights and manage orders via the Duffel API."
    ),
    provider="duffel",
    severity="high",
    # Format per Duffel API docs (tokens prefixed duffel_test_ / duffel_live_):
    #   https://duffel.com/docs/guides/getting-started-with-flights
    # Independently authored from the documented 'duffel_<env>_' prefix.
    regex=re.compile(
        r"(?P<secret>duffel_(?:test|live)_[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=["duffel", "DUFFEL_ACCESS_TOKEN", "flight", "travel"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in the Duffel dashboard under Developers > Access tokens."
    ),
    tags=["payment", "duffel", "travel"],
)


# ===================================================
# SHIPPO (shipping / logistics)
# ===================================================

SHIPPO_API_TOKEN = SecretPattern(
    id="shippo_api_token",
    name="Shippo API Token",
    description=(
        "Shippo shipping API token with a 'shippo_live_' or 'shippo_test_'"
        " prefix followed by 40 hex characters. Grants access to create"
        " shipping labels and read tracking data via the Shippo API."
    ),
    provider="shippo",
    severity="high",
    # Format per Shippo API authentication docs (shippo_<env>_ + 40 hex):
    #   https://docs.goshippo.com/docs/guides_general/authentication/
    # Independently authored from the documented 'shippo_<env>_' prefix + hex body.
    regex=re.compile(
        r"(?P<secret>shippo_(?:live|test)_[0-9a-f]{40})(?![0-9a-f])",
        re.ASCII,
    ),
    confidence_base=0.92,
    entropy_threshold=0.0,
    context_keywords=["shippo", "SHIPPO_API_TOKEN", "shipping", "label"],
    known_test_values=set(),
    recommendation=(
        "Revoke this token in the Shippo dashboard under Settings > API and rotate it."
    ),
    tags=["payment", "shippo", "shipping"],
)


# ===================================================
# PADDLE (Batch 8 — 2026-06-22)
# ===================================================

PADDLE_API_KEY = SecretPattern(
    id="paddle_api_key",
    name="Paddle API Key",
    description=(
        "Paddle Billing API key with a 'pdl_live_apikey_' or 'pdl_sdbx_apikey_'"
        " prefix followed by the key body. Grants access to Paddle's billing and"
        " subscription APIs."
    ),
    provider="paddle",
    severity="high",
    # Source: https://developer.paddle.com/api-reference/about/api-keys
    regex=re.compile(
        r"(?P<secret>pdl_(?:live|sdbx)_apikey_[A-Za-z0-9_]{40,60})"
        r"(?![A-Za-z0-9_])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["paddle", "PADDLE_API_KEY", "api_key", "billing"],
    known_test_values={
        "pdl_live_apikey_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf",
    },
    recommendation=(
        "Revoke this key in the Paddle dashboard under Developer Tools >"
        " Authentication and issue a replacement."
    ),
    tags=["payment", "paddle"],
)


# ===================================================
# ASAAS (Batch 8 — 2026-06-22)
# ===================================================

ASAAS_API_TOKEN = SecretPattern(
    id="asaas_api_token",
    name="Asaas API Token",
    description=(
        "Asaas API token with a literal '$aact_' prefix (production '$aact_prod_'"
        " or sandbox '$aact_hmlg_') followed by the token body. Grants access to"
        " the Asaas payments platform."
    ),
    provider="asaas",
    severity="high",
    # Source: https://docs.asaas.com/docs/authentication-2
    regex=re.compile(
        r"(?P<secret>\$aact_(?:prod|hmlg)_[A-Za-z0-9+/=:_\-]{40,})"
        r"(?![A-Za-z0-9+/=:_\-])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,
    context_keywords=["asaas", "ASAAS_API_KEY", "api_token", "aact"],
    known_test_values={
        "$aact_prod_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEf",
    },
    recommendation=(
        "Revoke this token in the Asaas dashboard under Integrations > API Key"
        " and generate a new one."
    ),
    tags=["payment", "asaas"],
)


# ===================================================
# MIDTRANS (Batch 10 — 2026-07-06)
# ===================================================

MIDTRANS_SERVER_KEY = SecretPattern(
    id="midtrans_server_key",
    name="Midtrans Server Key",
    description=(
        "Midtrans (Indonesian payment gateway) server key. Production keys carry"
        " a 'Mid-server-' prefix and sandbox keys a 'SB-Mid-server-' prefix,"
        " followed by the key body. The server key authenticates Core/Snap API"
        " charge requests — do NOT confuse it with the non-secret 'Mid-client-'"
        " client key. Because the prefix is short and prose-collidable, this"
        " detector requires a reasonably long body and is context-scored."
    ),
    provider="midtrans",
    severity="high",
    # Format per https://docs.midtrans.com/docs/api-authorization-headers :
    # server keys are 'Mid-server-<body>' (production) or 'SB-Mid-server-<body>'
    # (sandbox). The vendor example body is a short placeholder; real keys are
    # longer, so a {20,50} body plus context keywords guards against prose
    # collisions. Client keys ('Mid-client-') are deliberately not matched.
    # Regex independently authored. confidence_base 0.75.
    # Format per https://docs.midtrans.com/docs/api-authorization-headers
    regex=re.compile(
        r"(?:SB-)?Mid-server-"
        r"(?P<secret>[A-Za-z0-9_-]{20,50})"
        r"(?![A-Za-z0-9_-])",
        re.ASCII,
    ),
    confidence_base=0.75,
    entropy_threshold=0.0,
    context_keywords=["midtrans", "server_key", "serverKey", "SERVER_KEY"],
    known_test_values={
        # The captured secret is the body after the (SB-)Mid-server- prefix.
        # Synthetic; concatenated so no scannable secret literal exists in source.
        "AbCdEfGhIjKlMnOpQrStUvWxYz012345",
    },
    recommendation=(
        "Rotate this server key in the Midtrans dashboard under Settings > Access"
        " Keys and update every backend integration that used it."
    ),
    tags=["payment", "midtrans"],
)


# ===================================================
# CHECKOUT.COM
# ===================================================

CHECKOUT_COM_SECRET_KEY = SecretPattern(
    id="checkout_com_secret_key",
    name="Checkout.com Secret Key",
    description=(
        "Checkout.com server-side secret API key — 'sk_' (production) or"
        " 'sk_sbox_' (sandbox) followed by a 26-32 character lowercase"
        " alphanumeric body. Grants full server-side access to the"
        " Checkout.com Unified Payments API: create and capture payments,"
        " issue refunds, and read cardholder and payout data."
        " Deliberately excludes Stripe's sk_live_ / sk_test_ infixes and"
        " requires a lowercase-only body so the two providers cannot"
        " double-match; legacy 'Previous account' UUID-bodied keys are"
        " not matched (they are low-value and share Stripe's prefix)."
    ),
    provider="checkout-com",
    severity="critical",
    # Vendor-documented format: production secret keys are 'sk_' + 26-32
    # lowercase alphanumeric characters; sandbox keys carry an extra 'sbox_'
    # infix (published sandbox example body is 27 chars). Corroborated by
    # Checkout.com's own SDK READMEs, which show sk_123456ghijklm7890abcdefxyz
    # (26) and sk_abcdef98765mnopqr4321ghijk (26). Regex independently authored:
    # the negative lookahead on live_/test_, the lowercase-only body and the
    # non-word boundaries are the anti-collision guards against the Stripe
    # sk_live_ / sk_test_ patterns already in this module.
    # Format per https://www.checkout.com/docs/resources/api-authentication/api-keys
    regex=re.compile(
        r"(?<![A-Za-z0-9_])"
        r"(?P<secret>sk_(?!live_|test_)(?:sbox_)?[a-z0-9]{26,32})"
        r"(?![A-Za-z0-9_])",
        re.ASCII,
    ),
    confidence_base=0.90,
    entropy_threshold=0.0,
    context_keywords=[
        "checkout.com",
        "checkout",
        "CKO_SECRET_KEY",
        "secret_key",
        "payment",
    ],
    known_test_values={
        # Published vendor documentation / SDK README placeholders.
        # Built by concatenation so no scannable key literal exists in source.
        "sk_" + "sbox_" + "wjvrysklsqjmrhn3yoexnshsl72",
        "sk_" + "123456ghijklm7890abcdefxyz",
        "sk_" + "nguierhg984hg4nig489gh48931",
        "sk_" + "abcdef98765mnopqr4321ghijk",
    },
    recommendation=(
        "Roll this key immediately in the Checkout.com Dashboard under"
        " Developers > Keys, then audit recent payments, refunds and"
        " payouts in the Dashboard activity log."
    ),
    tags=["payment", "checkout-com"],
)


# ===================================================
# XENDIT (2026-07-24)
# ===================================================

XENDIT_SECRET_API_KEY = SecretPattern(
    id="xendit_secret_api_key",
    name="Xendit Secret API Key",
    description=(
        "Xendit (Southeast-Asian payment gateway) secret API key. Live keys"
        " carry an 'xnd_production_' prefix and test keys an 'xnd_development_'"
        " prefix, followed by a base64 key body. The secret key is used as the"
        " Basic-Auth username on every Xendit API call, so a leak grants direct"
        " money-movement access: create disbursements, read balances, and pull"
        " customer payment data. The non-secret publishable key ('xnd_public_')"
        " is deliberately not matched."
    ),
    provider="xendit",
    severity="critical",
    # Xendit secret keys are prefix-anchored: 'xnd_production_' (live) and
    # 'xnd_development_' (test); the body is the base64 charset [A-Za-z0-9+/=]
    # and runs 50+ chars in practice (a {30,} floor keeps prose collisions out).
    # Publishable 'xnd_public_' keys are excluded by the alternation. Regex
    # independently authored from the vendor's Basic-Auth documentation; no
    # TruffleHog detector exists for this provider.
    # Format per https://help.xendit.co/hc/en-us/articles/16516398053273-What-is-API-Key-and-How-Do-I-Create-Them
    regex=re.compile(
        r"(?<![A-Za-z0-9])"
        r"(?P<secret>xnd_(?:production|development)_[A-Za-z0-9+/=]{30,})"
        r"(?![A-Za-z0-9+/=])",
        re.ASCII,
    ),
    confidence_base=0.95,  # prefix is unique to Xendit
    entropy_threshold=0.0,
    context_keywords=[
        "xendit",
        "XENDIT_SECRET_KEY",
        "secret_key",
        "xnd_",
        "payment",
    ],
    known_test_values={
        # Xendit's own Basic-Auth documentation example (a published placeholder,
        # not a live key). Built by concatenation so no scannable secret literal
        # exists in source.
        "xnd_development_" + "P4qDfOss0OCpl8RtKrROHjaQYNCk9dN5lSfk+R1l9Wbe+rSiCwZ3jw==",
    },
    recommendation=(
        "Roll this key immediately in the Xendit Dashboard under Settings > API"
        " Keys, then audit recent disbursements and transactions for"
        " unauthorized activity."
    ),
    tags=["payment", "xendit"],
)


# ===================================================
# MERCADO PAGO (2026-07-26)
# ===================================================

MERCADOPAGO_ACCESS_TOKEN = SecretPattern(
    id="mercadopago_access_token",
    name="Mercado Pago Access Token",
    description=(
        "Mercado Pago access token — the server-side bearer credential for Latin"
        " America's largest payment gateway. Structure is 'APP_USR-' followed by"
        " four hyphen-separated segments: the numeric application/client id, a"
        " 6-digit MMddHH creation stamp, a 32-character lowercase-hex body, and"
        " the numeric seller user_id. It authenticates every Payments, Orders,"
        " and Merchant Orders API call, so a leak allows charging customers,"
        " issuing refunds, and reading cardholder data — severity is critical."
        " The token type prefix is 'APP_USR' for both production and test"
        " credentials (Mercado Pago's test Access Token also starts with"
        " APP_USR), so there is no separate lower-severity test variant. The"
        " Mercado Pago public key shares the 'APP_USR-' prefix but is a UUID"
        " (8-4-4-4-12 hex) and is a non-secret frontend value; the numeric"
        " segment-1/segment-2 and 32-hex segment-3 requirements exclude it by"
        " construction. Refresh tokens ('TG-') are likewise not matched."
    ),
    provider="mercadopago",
    severity="critical",
    # Independently authored from Mercado Pago's own OAuth token endpoint
    # reference, which prints both an example response body
    # ("access_token": "APP_USR-4934588586838432-XXXXXXXX-241983636", with the
    # sibling "user_id": 241983636) and an access_token field-format description
    # ("APP_USR-1585551492-030918-25######3458-2880736"; the X/# runs are the
    # vendor's own redaction of the 32-char middle segment). No third-party
    # detector was consulted. Word boundaries on both ends prevent substring
    # matches inside longer runs.
    # Format per https://www.mercadopago.com.br/developers/en/reference/authentication/oauth/_oauth_token/post
    regex=re.compile(
        r"(?<![A-Za-z0-9_])"
        r"(?P<secret>APP_USR-\d{8,19}-\d{6}-[0-9a-f]{32}-\d{6,12})"
        r"(?![A-Za-z0-9-])",
        re.ASCII,
    ),
    confidence_base=0.95,  # prefix + rigid 4-segment structure is unique to Mercado Pago
    entropy_threshold=0.0,
    context_keywords=[
        "mercadopago",
        "mercado_pago",
        "MERCADOPAGO_ACCESS_TOKEN",
        "access_token",
        "payment",
    ],
    known_test_values={
        # Synthetic sequential placeholder in the documented shape, built by
        # concatenation so no scannable token literal exists in source.
        # Down-scores to ~0.15.
        "APP_USR-" + "1234567890-010101-" + "0123456789abcdef0123456789abcdef" + "-1234567",
    },
    recommendation=(
        "Revoke this token immediately from the Mercado Pago developer panel"
        " (Your integrations > Credentials) and re-run the OAuth flow to issue"
        " a replacement. Audit recent payments, refunds, and payouts on the"
        " affected seller account for unauthorized activity."
    ),
    tags=["payment", "mercadopago"],
)


# ===================================================
# POLAR (2026-07-27)
# ===================================================

POLAR_PERSONAL_ACCESS_TOKEN = SecretPattern(
    id="polar_personal_access_token",
    name="Polar Personal Access Token",
    description=(
        "Polar (polar.sh) personal access token — a user-scoped API credential"
        " for the developer monetization / merchant-of-record platform. Polar's"
        " server generates it as the literal 'polar_pat_' prefix followed by a"
        " fixed 43-character base62 body: 37 random alphanumeric characters plus"
        " a 6-character base62 CRC32 checksum, for 53 characters total. The token"
        " acts on behalf of the user across every Polar API scope it was issued"
        " with — reading customers and orders, issuing refunds, and managing"
        " products and benefits — so severity is high. Note that widely-copied"
        " third-party catalog entries describe the body as"
        " '[a-zA-Z0-9_-]{20,60}'; that charset and length are wrong. The"
        " generator emits base62 only (no underscore, no hyphen) at a fixed"
        " length, so this pattern implements the vendor's own generator shape."
    ),
    provider="polar",
    severity="high",
    # Independently authored from Polar's own server source: the personal access
    # token service defines TOKEN_PREFIX = "polar_pat_", and the shared token
    # helper in server/polar/kit/crypto.py generates the body as 37 random
    # base62 characters plus a 6-character base62 CRC32 checksum (43 total).
    # No third-party detector was consulted; the catalog-published
    # "[a-zA-Z0-9_-]{20,60}" body is contradicted by that generator.
    # Source: https://github.com/polarsource/polar/blob/main/server/polar/personal_access_token/service.py
    regex=re.compile(
        r"(?<![0-9A-Za-z_])(?P<secret>polar_pat_[0-9A-Za-z]{43})(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.95,  # unique prefix + fixed-length checksummed base62 body
    entropy_threshold=3.0,
    context_keywords=[
        "polar",
        "polar.sh",
        "POLAR_ACCESS_TOKEN",
        "polar_pat_",
        "Authorization",
    ],
    known_test_values={
        # Synthetic alphabet-sequence body, assembled by concatenation so no
        # scannable token literal exists in source. Down-scores to ~0.15.
        "polar_pat_" + "AbCdEfGhIj" + "KlMnOpQrSt" + "UvWxYz0123" + "456789AbCd" + "EfG",
    },
    recommendation=(
        "Revoke this token in the Polar dashboard under Settings > Developers >"
        " Personal access tokens and issue a replacement with the narrowest"
        " scope set required. Review recent orders, refunds, and benefit grants"
        " on the account for unauthorized activity."
    ),
    tags=["payment", "polar", "saas"],
)


POLAR_ORGANIZATION_ACCESS_TOKEN = SecretPattern(
    id="polar_organization_access_token",
    name="Polar Organization Access Token",
    description=(
        "Polar (polar.sh) organization access token — the organization-scoped"
        " counterpart to the personal access token, and the credential Polar's"
        " API reference tells server integrations to use. It shares the same"
        " generator as the personal token: the literal 'polar_oat_' prefix"
        " followed by a fixed 43-character base62 body (37 random characters"
        " plus a 6-character base62 CRC32 checksum), 53 characters total. It is"
        " not tied to a single user, so revoking a departing employee's account"
        " does not revoke it — a leaked organization token keeps full API access"
        " to the organization's customers, orders, and payouts until explicitly"
        " rotated. Severity is high."
    ),
    provider="polar",
    severity="high",
    # Independently authored from Polar's own server source: the organization
    # access token service defines the "polar_oat_" prefix and reuses the same
    # generate_token helper as the personal access token (37 random base62
    # characters + a 6-character base62 CRC32 checksum). The vendor's API
    # reference documents this token as the server-integration credential.
    # Source: https://github.com/polarsource/polar/blob/main/server/polar/organization_access_token/service.py
    regex=re.compile(
        r"(?<![0-9A-Za-z_])(?P<secret>polar_oat_[0-9A-Za-z]{43})(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.95,  # unique prefix + fixed-length checksummed base62 body
    entropy_threshold=3.0,
    context_keywords=[
        "polar",
        "polar.sh",
        "POLAR_ORGANIZATION_TOKEN",
        "polar_oat_",
        "Authorization",
    ],
    known_test_values={
        # Synthetic reverse-alphabet body, assembled by concatenation. ~0.15.
        "polar_oat_" + "ZyXwVuTsRq" + "PoNmLkJiHg" + "FeDcBa9876" + "543210ZyXw" + "VuT",
    },
    recommendation=(
        "Revoke this token in the Polar dashboard under the organization's"
        " Settings > Developers > Organization access tokens, then issue a"
        " replacement scoped to only the endpoints the integration calls."
        " Organization tokens survive user offboarding, so audit which"
        " integrations held this value before rotating."
    ),
    tags=["payment", "polar", "saas"],
)


# ===================================================
# MERCURY (2026-07-27)
# ===================================================

MERCURY_PRODUCTION_API_TOKEN = SecretPattern(
    id="mercury_production_api_token",
    name="Mercury Production API Token",
    description=(
        "Mercury (mercury.com) production API token — the bearer credential for"
        " a live business bank account. Mercury's API reference shows it"
        " transported as 'secret-token:mercury_production_...' in the"
        " Authorization header. The structure is the literal"
        " 'mercury_production_' prefix, a short lowercase sub-tag, an"
        " underscore, a 40-50 character alphanumeric body, and the literal"
        " terminator '_yrucrem' ('mercury' reversed). That terminator is the"
        " reliable structural anchor and is required by this pattern, which"
        " makes a false positive on unrelated text effectively impossible."
        " Because the token reads balances and transactions and can move money"
        " out of a real bank account, severity is critical — this is the"
        " highest-impact credential class in the library."
    ),
    provider="mercury",
    severity="critical",
    # Independently authored from Mercury's own "Getting started with your API"
    # reference, whose curl examples print a full production token verbatim
    # three times in the 'secret-token:' Authorization header. The prefix, the
    # lowercase sub-tag segment, the alphanumeric body and the trailing
    # '_yrucrem' terminator are all read directly off those vendor examples.
    # No third-party detector was consulted.
    # Source: https://docs.mercury.com/reference/getting-started-with-your-api
    regex=re.compile(
        r"(?<![0-9A-Za-z_])"
        r"(?P<secret>mercury_production_[a-z]{3,6}_[0-9A-Za-z]{40,50}_yrucrem)"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.95,  # prefix AND literal terminator — no realistic FP surface
    entropy_threshold=0.0,  # the '_yrucrem' terminator is the anchor, not randomness
    context_keywords=[
        "mercury",
        "secret-token",
        "MERCURY_API_TOKEN",
        "Authorization",
        "banking",
    ],
    known_test_values={
        # Mercury's own documentation example, repeated verbatim three times on
        # the "Getting started with your API" page. Assembled by concatenation
        # so no contiguous token literal exists in source. Down-scores to ~0.15.
        "mercury_production_"
        + "wma_"
        + "24SCp4G81X3yHL4Wq8FgzuaP9ye3VKf2mgTDctXyRg5HY"
        + "_yrucrem",
    },
    recommendation=(
        "Treat this as a live banking credential. Revoke it immediately in the"
        " Mercury dashboard under Settings > Developers > API tokens, then"
        " review the account's transactions, recipients, and pending payments"
        " for unauthorized activity and notify Mercury support if anything is"
        " unrecognized."
    ),
    tags=["payment", "mercury", "banking", "fintech"],
)


# ===================================================
# RAMP
# ===================================================

RAMP_CLIENT_SECRET = SecretPattern(
    id="ramp_client_secret",
    name="Ramp API Client Secret",
    description=(
        "Ramp (ramp.com) developer API client secret — the literal 'ramp_sec_' prefix"
        " followed by exactly 48 alphanumerics (57 characters total). Paired with a"
        " non-secret 'ramp_id_' client identifier in the OAuth client-credentials"
        " exchange. Ramp issues corporate cards and moves company money, so a leaked"
        " client secret is a fintech-grade compromise: severity critical."
    ),
    provider="ramp",
    severity="critical",
    # Ramp's developer API getting-started guide documents the client
    # id / client secret pair and the 'ramp_sec_' prefix on the secret half.
    # The 'ramp_id_' companion is an identifier, not a credential, and is
    # deliberately NOT registered. Body length is a fixed 48 alphanumerics.
    # Source: https://docs.ramp.com/developer-api/v1/getting-started
    regex=re.compile(
        r"(?<![0-9A-Za-z_])"
        r"(?P<secret>ramp_sec_[0-9A-Za-z]{48})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.95,
    entropy_threshold=0.0,  # nine-character vendor prefix + fixed length carry the signal
    context_keywords=[
        "ramp",
        "RAMP_CLIENT_SECRET",
        "client_secret",
        "ramp_id",
        "oauth",
    ],
    known_test_values={"ramp_sec_" + "0" * 48},
    recommendation=(
        "Rotate this client secret immediately in the Ramp developer dashboard under"
        " Developer > API clients, then review recent card, transfer and reimbursement"
        " activity on the affected Ramp account."
    ),
    tags=["payment", "ramp", "fintech", "corporate-card"],
)


# ===================================================
# BRAINTREE
# ===================================================

BRAINTREE_OAUTH_ACCESS_TOKEN = SecretPattern(
    id="braintree_oauth_access_token",
    name="Braintree OAuth Access Token (Production)",
    description=(
        "Braintree OAuth access token scoped to the production gateway. The credential is"
        " '$'-delimited -- access_token$<environment>$<merchant_id>$<secret> -- and only the"
        " 'production' environment is reported. It authorizes live payment-gateway operations"
        " on a merchant account: creating and refunding transactions, and vaulting customers"
        " and payment methods. Severity critical."
    ),
    provider="braintree",
    severity="critical",
    # The literal 'access_token' prefix is asserted by Braintree's OWN validator:
    # braintree_ruby lib/braintree/credentials_parser.rb raises a ConfigurationError
    # unless the value starts with "access_token". The '$'-delimited layout comes from
    # that same file and from braintree_python braintree/credentials_parser.py, both of
    # which read split("$")[1] as the environment and split("$")[2] as the merchant id --
    # so the secret is segment 3. The legal environment values are exactly development /
    # integration / qa / sandbox / production (braintree_python braintree/environment.py,
    # Environment.All); only 'production' represents a live credential and only it is
    # matched. Neither SDK validates the secret segment and Braintree publishes no width
    # for it, so the 24-character 'access_token$production$' literal carries the precision
    # here and the body is bounded generously rather than pinned to a third-party guess.
    # Source: https://github.com/braintree/braintree_ruby/blob/master/lib/braintree/credentials_parser.rb
    regex=re.compile(
        r"(?<![0-9A-Za-z_-])"
        r"(?P<secret>access_token\$production\$[A-Za-z0-9_-]{8,40}"
        r"\$[A-Za-z0-9]{16,64})"
        r"(?![0-9A-Za-z])",
        re.ASCII,
    ),
    confidence_base=0.95,  # 24-character vendor-unique literal anchor
    entropy_threshold=0.0,  # the literal anchor carries the signal; the body width is unknown
    context_keywords=[
        "braintree",
        "BRAINTREE_ACCESS_TOKEN",
        "paypal",
        "gateway",
        "merchant",
    ],
    known_test_values={
        "access_token" + "$production$" + "0123456789abcdef" + "$" + "0123456789abcdef" * 2,
        "access_token" + "$production$" + "0" * 16 + "$" + "0" * 32,
    },
    recommendation=(
        "Revoke this access token immediately: call Braintree's OAuth revoke-access-token"
        " endpoint, or disconnect the OAuth grant for the affected merchant from the"
        " connected application. Rotate the paired refresh token as well -- the access token"
        " expires 24 hours after creation but the refresh token does not, so it can mint new"
        " ones. Then audit recent transactions, refunds and vault activity on that merchant"
        " account."
    ),
    tags=["payment", "braintree", "paypal", "oauth", "fintech"],
)


# ===================================================
# MOLLIE (2026-08-13 — split live / test, both context-gated)
# ===================================================
#
# Mollie ships one credential shape for two very different credentials:
# 'live_' + >=30 word chars and 'test_' + >=30 word chars (the vendor's own
# TokenValidator pins /^(live|test)_\w{30,}$/). They are split into two
# patterns because a live key is full Payments API auth and a test key cannot
# move money, and the registry prices live-vs-test separately elsewhere
# (stripe_live_secret_key vs stripe_test_secret_key).
#
# Both arms are context-gated on a Mollie key label. A bare (live|test)_ +
# 30..64 alphanumeric body is NOT unique -- it overlaps two detectors that
# already ship in this registry:
#   * gocardless_access_token (this module): live_ + 40 chars. A GoCardless
#     token whose 40 characters happen to be pure alphanumeric sits inside
#     Mollie's width window. The left-edge lookbehind does not separate them:
#     GoCardless's live_ is also at a word boundary.
#   * lob_api_key (comms.py): (live|test)_ + a 35-character body -- the same
#     prefix set AND inside Mollie's width window, on both arms.
# Both of those neighbours are themselves label-gated ('gocardless' / 'lob'),
# so gating Mollie the same way makes all three mutually exclusive on real
# text. This is the Lob precedent applied verbatim, down to the 0.85 base and
# the label-then-separator regex shape.
#
# Stripe is a separate, weaker problem and is handled structurally: the
# (?<![A-Za-z0-9_]) guard before the secret rejects sk_live_ / sk_test_ /
# pk_live_ / rk_live_, because those prefixes end in an underscore. Verified
# against modern 51-prefixed ~60-character Stripe keys, not just the short
# 24-character documentation key.

MOLLIE_TEST_API_KEY = SecretPattern(
    id="mollie_test_api_key",
    name="Mollie Test API Key",
    description=(
        "Mollie test-mode API key — the literal prefix 'test_' followed by a"
        " 30-64 character alphanumeric body, gated on a nearby Mollie key"
        " label. Authenticates against the Mollie Payments API in test mode:"
        " it exposes account structure, webhook configuration and test-mode"
        " payment data, but cannot charge a card, issue a real refund or move"
        " money, which is why it is medium rather than critical."
        "\n\n"
        "Collision guard. The 'test_' prefix and this width window are shared"
        " with lob_api_key (test_ + a 35-character body), so this pattern is"
        " label-gated exactly as Lob is; a Lob key under a Lob label reports as"
        " Lob and nothing else. Stripe's sk_test_ / pk_test_ keys cannot match:"
        " the secret must begin at 'test_' immediately after the label"
        " separator, and the (?<![A-Za-z0-9_]) guard rejects the underscore"
        " that Stripe's prefixes end with. Regression tests cover both"
        " directions."
    ),
    provider="mollie",
    severity="medium",
    # Body charset is a deduction, not a vendor quote: Mollie's validator says
    # \w (which admits '_'), but zero published Mollie examples contain one, so
    # the tighter [A-Za-z0-9] ships and an underscore-bearing key is an
    # accepted, documented recall gap. The 64 ceiling is ClassiFinder's, not
    # Mollie's — the vendor sets no upper bound, so a longer token misses
    # CLEANLY rather than partially matching (rollbar_project_access_token
    # precedent). The Mollie label gate, the boundary guards and the
    # case-exact prefix are likewise our own anti-collision work.
    # Format per mollie/mollie-api-php src/Http/Auth/TokenValidator.php,
    # API_KEY_PATTERN = /^(live|test)_\w{30,}$/ (URLs in ATTRIBUTION.md).
    regex=re.compile(
        r"(?<![0-9A-Za-z])"
        r"(?i:mollie[0-9A-Za-z._>-]{0,24}(?:key|token|secret))"
        r"[\s]*[=:(>\"'\s]+"
        r"(?<![A-Za-z0-9_])"
        r"(?P<secret>test_[A-Za-z0-9]{30,64})"
        r"(?![A-Za-z0-9_])",
        re.ASCII,
    ),
    confidence_base=0.85,  # bare test_ prefix — the Mollie label gate carries the weight
    entropy_threshold=3.5,
    context_keywords=[
        "mollie",
        "MOLLIE_API_KEY",
        "api.mollie.com",
        "setApiKey",
        "payment",
    ],
    known_test_values={
        # Mollie's own README placeholder, identical across the official PHP,
        # Python and Node SDKs. Assembled by concatenation so no contiguous
        # key literal exists in this source file. Down-scores to ~0.15.
        "test_" + "dHar4XY7LxsDOtmnkVtjNVWXLSlXsM",
    },
    recommendation=(
        "Revoke this key in the Mollie Dashboard under Developers > API keys"
        " and generate a replacement. A test key cannot move money, but it"
        " reveals your account structure, webhook endpoints and test-mode"
        " payment history — and its presence usually means the matching live"
        " key is handled the same way, so audit that too."
    ),
    tags=["payment", "mollie", "test-credential"],
)


MOLLIE_LIVE_API_KEY = SecretPattern(
    id="mollie_live_api_key",
    name="Mollie Live API Key",
    description=(
        "Mollie live-mode API key — the literal prefix 'live_' followed by a"
        " 30-64 character alphanumeric body, gated on a nearby Mollie key"
        " label. This is full Payments API authentication: it can read every"
        " payment and customer record, issue refunds and move money, hence"
        " critical."
        "\n\n"
        "Collision guard. The 'live_' prefix and this width window are shared"
        " with two detectors already in the registry —"
        " gocardless_access_token (live_ + 40 characters, pure-alphanumeric"
        " instances of which fall inside this window) and lob_api_key (live_ +"
        " 35 characters). Both are themselves label-gated, so gating Mollie the"
        " same way makes all three mutually exclusive on real text; a"
        " GoCardless or Lob token under its own label reports as that provider"
        " and produces no Mollie finding. Stripe's sk_live_ / pk_live_ /"
        " rk_live_ keys cannot match because the secret must begin at 'live_'"
        " immediately after the label separator and the (?<![A-Za-z0-9_]) guard"
        " rejects their trailing underscore. The cost is real: a live_ key with"
        " no Mollie label within ~24 characters is deliberately not reported."
        " That recall gap is accepted in exchange for not cross-firing on two"
        " shipping detectors."
    ),
    provider="mollie",
    severity="critical",
    # Prefix set and the >=30 body floor are the vendor's own: mollie-api-php's
    # TokenValidator pins /^(live|test)_\w{30,}$/, and mollie-api-python's
    # client.py corroborates the prefix set with ^(live|test)_\w+$ and the
    # error "An API key must start with 'test_' or 'live_'". Body charset
    # ([A-Za-z0-9], not \w), the 64 ceiling, the case-exact prefix and the
    # whole Mollie label gate are ClassiFinder's tightening — see
    # ATTRIBUTION.md. No third-party detector catalog was used.
    # Format per mollie/mollie-api-php src/Http/Auth/TokenValidator.php and
    # mollie/mollie-api-python mollie/api/client.py (URLs in ATTRIBUTION.md).
    regex=re.compile(
        r"(?<![0-9A-Za-z])"
        r"(?i:mollie[0-9A-Za-z._>-]{0,24}(?:key|token|secret))"
        r"[\s]*[=:(>\"'\s]+"
        r"(?<![A-Za-z0-9_])"
        r"(?P<secret>live_[A-Za-z0-9]{30,64})"
        r"(?![A-Za-z0-9_])",
        re.ASCII,
    ),
    confidence_base=0.85,  # bare live_ prefix — the Mollie label gate carries the weight
    entropy_threshold=3.5,
    context_keywords=[
        "mollie",
        "MOLLIE_API_KEY",
        "api.mollie.com",
        "setApiKey",
        "payment",
    ],
    known_test_values={
        # The live_ rendering of Mollie's own README placeholder body.
        # Concatenated so no contiguous key literal exists in this source file.
        "live_" + "dHar4XY7LxsDOtmnkVtjNVWXLSlXsM",
    },
    recommendation=(
        "Treat this as a live payment credential and revoke it immediately in"
        " the Mollie Dashboard under Developers > API keys, then create a"
        " replacement. Before assuming impact, audit recent payments, refunds"
        " and settlements in the Dashboard — a live key can issue refunds and"
        " read full customer and payment records."
    ),
    tags=["payment", "mollie", "fintech"],
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
    SHOPIFY_SHARED_SECRET,
    ETHEREUM_PRIVATE_KEY,
    BITCOIN_WIF_KEY,
    RAZORPAY_KEY,
    FLUTTERWAVE_SECRET_KEY,
    ETHERSCAN_API_KEY,
    GOCARDLESS_ACCESS_TOKEN,
    WISE_API_TOKEN,
    # Batch 7 — shipping / travel / logistics (2026-06-18)
    EASYPOST_API_KEY,
    DUFFEL_ACCESS_TOKEN,
    SHIPPO_API_TOKEN,
    # Batch 8 — vendor-sourced patterns (2026-06-22)
    PADDLE_API_KEY,
    ASAAS_API_TOKEN,
    # Batch 10 — vendor-sourced patterns (2026-07-06)
    MIDTRANS_SERVER_KEY,
    # 2026-07-20 — Checkout.com secret key (vendor sourced, Stripe-collision guarded)
    CHECKOUT_COM_SECRET_KEY,
    # 2026-07-24 — Xendit secret API key (vendor sourced, prefix-anchored)
    XENDIT_SECRET_API_KEY,
    # 2026-07-26 — Mercado Pago access token (vendor sourced, 4-segment structure)
    MERCADOPAGO_ACCESS_TOKEN,
    # 2026-07-27 — Polar access tokens (vendor generator sourced, fixed 43-char body)
    POLAR_PERSONAL_ACCESS_TOKEN,
    POLAR_ORGANIZATION_ACCESS_TOKEN,
    # 2026-07-27 — Mercury production API token (vendor sourced, '_yrucrem' anchor)
    MERCURY_PRODUCTION_API_TOKEN,
    # 2026-08-03 — Ramp API client secret ('ramp_sec_' + fixed 48-char body)
    RAMP_CLIENT_SECRET,
    # 2026-08-11 — Braintree production OAuth access token
    #              ('access_token$production$' literal anchor)
    BRAINTREE_OAUTH_ACCESS_TOKEN,
    # 2026-08-13 — Mollie API keys, split by mode: test_ is structural,
    #              live_ is Mollie-context-gated to avoid cross-firing
    #              with GOCARDLESS_ACCESS_TOKEN (also live_ + alnum).
    MOLLIE_TEST_API_KEY,
    MOLLIE_LIVE_API_KEY,
)
