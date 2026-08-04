# Attribution & Third-Party Notices

ClassiFinder is built with respect for the open-source community. This file documents the third-party projects whose work has informed, inspired, or contributed to ClassiFinder's pattern library and engine design.

If you believe an attribution is missing or incorrect, please open an issue.

---

## Pattern Library Sources

ClassiFinder's secret-detection pattern library has multiple lineages. Each pattern in `patterns/*.py` carries an inline `# Source:` or `# Format per ...` comment identifying its provenance. This file collects the upstream license notices.

### Betterleaks (MIT)

**Project:** https://github.com/betterleaks/betterleaks
**License:** MIT
**Use in ClassiFinder:** Approximately 49 detection patterns in ClassiFinder were ported from or modeled on rules in `betterleaks.toml` (v1.0.0) and `cmd/generate/config/rules/*.go`. Each ported pattern carries an inline comment citing the source file.

**Batch 5 additions (2026-05-28):** The following 5 patterns were added citing Betterleaks Go rule files:

| ClassiFinder Pattern | Betterleaks Source |
|---|---|
| `flutterwave_secret_key` | `cmd/generate/config/rules/flutterwave.go` |
| `gocardless_access_token` | `cmd/generate/config/rules/gocardless.go` |
| `intercom_access_token` | `cmd/generate/config/rules/intercom.go` |
| `messagebird_api_key` | `cmd/generate/config/rules/messagebird.go` |
| `sendbird_token` | `cmd/generate/config/rules/sendbird.go` |

> MIT License
>
> Copyright (c) Betterleaks contributors
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

### SAFE-MCP (CC-BY-4.0)

**Project:** https://github.com/safe-mcp/safe-mcp
**License:** Creative Commons Attribution 4.0 International (CC-BY-4.0) for technique documentation; Apache-2.0 for code
**Use in ClassiFinder:** SAFE-MCP is a MITRE-ATT&CK-style threat-technique catalog for the Model Context Protocol ecosystem. ClassiFinder uses SAFE-MCP as a **threat-class reference**, not as a source of detection strings:

1. **Cross-referencing:** Each prompt-injection pattern in `patterns/prompt_injection.py` carries a `safe_mcp_ids: list[str]` field mapping it to the SAFE-T technique IDs it detects. This is pure classification (reference to public identifiers like CVE numbers) and not a derivative work.
2. **Four patterns inspired by the technique catalog:** `pi_html_comment_directive`, `pi_data_boundary_manipulation`, `pi_line_jumping_marker`, and `pi_system_tag_injection` were authored independently from the **prose narrative** of their respective SAFE-T README files. The regex implementations were NOT translated from the upstream Sigma `detection-rule.yml` files — that distinction is enforced by ClassiFinder's cleanroom authoring discipline. Each pattern carries a two-line inline provenance comment naming the technique URL and stating the cleanroom posture.

| ClassiFinder Pattern | SAFE-MCP Technique |
|---|---|
| `pi_html_comment_directive` | https://github.com/safe-mcp/safe-mcp/tree/main/techniques/SAFE-T1001, https://github.com/safe-mcp/safe-mcp/tree/main/techniques/SAFE-T1402 |
| `pi_data_boundary_manipulation` | https://github.com/safe-mcp/safe-mcp/tree/main/techniques/SAFE-T1102 |
| `pi_line_jumping_marker` | https://github.com/safe-mcp/safe-mcp/tree/main/techniques/SAFE-T1401 |
| `pi_system_tag_injection` | https://github.com/safe-mcp/safe-mcp/tree/main/techniques/SAFE-T1102, https://github.com/safe-mcp/safe-mcp/tree/main/techniques/SAFE-T1603 |

CC-BY-4.0 requires attribution. By using ClassiFinder you acknowledge SAFE-MCP as the source threat catalog informing these four patterns and the SAFE-T cross-reference field on all prompt-injection findings. ClassiFinder regexes are independently authored.

Full license text: https://creativecommons.org/licenses/by/4.0/legalcode

### secrets-patterns-db (CC-BY-4.0)

**Project:** https://github.com/mazen160/secrets-patterns-db
**Maintainer:** Mazin Ahmed
**License:** Creative Commons Attribution 4.0 International (CC-BY-4.0)
**Use in ClassiFinder:** The following patterns were re-attributed to secrets-patterns-db, which is the earliest known publication of each regex under a permissive license:

| ClassiFinder Pattern | SPDB Entry |
|---|---|
| `notion_api_key` | db/rules-stable.yml:2250 |
| `pagerduty_api_key` | db/rules-stable.yml:2338 |
| `newrelic_admin_api_key` | db/rules-stable.yml:2194 |
| `nuget_api_key` | db/rules-stable.yml:5280 |
| `figma_pat` | db/rules-stable.yml:1068 |
| `ibm_cloud_api_key` | db/rules-stable.yml:1740 |
| `amazon_mws_auth_token` | datasets/high-confidence.yml ("Amazon MWS Auth Token") |

CC-BY-4.0 requires attribution. Each affected pattern carries an inline comment pointing to the SPDB source line. By using ClassiFinder you acknowledge this attribution.

Full license text: https://creativecommons.org/licenses/by/4.0/legalcode

---

## Vendor Documentation (Independently Derived Patterns)

The following patterns were independently derived from official vendor documentation. They are not derivative works of any third-party scanner. These citations are recorded for transparency and as a paper trail of independent provenance.

| Pattern | Vendor Source |
|---|---|
| `terraform_cloud_token` | https://developer.hashicorp.com/terraform/cloud-docs/api-docs/user-tokens, https://developer.hashicorp.com/terraform/cloud-docs/api-docs/agent-tokens |
| `buildkite_token` | https://buildkite.com/docs/apis/managing-api-tokens, https://buildkite.com/docs/platform/security/tokens |
| `airtable_api_key` | https://airtable.com/developers/web/guides/personal-access-tokens, https://support.airtable.com/docs/creating-personal-access-tokens |
| `netlify_token` | https://answers.netlify.com/t/change-to-the-netlify-authentication-token-format/106146 |
| `mongodb_connection_string` | https://www.mongodb.com/docs/manual/reference/connection-string-formats/ |
| `redis_connection_string` | https://www.iana.org/assignments/uri-schemes/prov/redis, https://www.iana.org/assignments/uri-schemes/prov/rediss |
| `discord_bot_token` | https://docs.discord.com/developers/reference |
| `onesignal_rest_api_key` | https://documentation.onesignal.com/docs/en/keys-and-ids, https://documentation.onesignal.com/reference/quick-start-api-guide |
| `cloudinary_url` | https://cloudinary.com/documentation/node_quickstart |
| `ngrok_authtoken` | https://ngrok.com/docs/agent/ |
| `opsgenie_api_key` | https://support.atlassian.com/opsgenie/docs/api-key-management/ |
| `yandex_cloud_iam_token` | https://yandex.cloud/en/docs/security/standard/authentication |
| `clojars_deploy_token` | https://github.com/clojars/clojars-web/blob/main/src/clojars/db.clj |
| `neon_api_key` | https://neon.com/docs/manage/api-keys |
| `midtrans_server_key` | https://docs.midtrans.com/docs/api-authorization-headers |
| `frameio_developer_token` | https://github.com/Frameio/python-frameio-client (official Frame.io Python SDK — documents the `fio-u-` developer-token prefix) |
| `cisco_meraki_api_key` | https://developer.cisco.com/meraki/api-v1/authorization/ (Meraki Dashboard API — 40-char hex key via `X-Cisco-Meraki-API-Key` / `Authorization: Bearer`) |
| `inngest_signing_key` | https://github.com/inngest/inngest/blob/main/pkg/authn/signing_key_strategy.go (Inngest server — defines the `signkey-` prefix set and the `^signkey-\\w+-` validation regex), https://github.com/inngest/inngest-js/blob/main/packages/inngest/src/helpers/strings.ts (JS SDK — decodes the post-prefix body as hex), https://github.com/inngest/inngest-py/blob/main/.env.example (64-hex example key) |
| `render_api_key` | https://github.com/openai/skills/blob/main/skills/.curated/render-deploy/SKILL.md (OpenAI curated render-deploy skill — `export RENDER_API_KEY="rnd_xxxxx"`), cross-referenced with Render's official API docs (render.com/docs/api, api-docs.render.com) |
| `xata_api_key` | https://github.com/xataio/xata/blob/main/internal/api/key/key.go (Xata's own Go source — defines `UserKeyPrefix = "xau"`, `OrganizationKeyPrefix = "xao"`, `MaxLength = 40`, and a base62 body of 20 random bytes plus a 4-byte CRC32; sibling `key_test.go` bounds the body length) |
| `wakatime_api_key` | https://github.com/wakatime/wakatime-cli/blob/develop/pkg/params/params.go (official WakaTime CLI, BSD 3-Clause — validates keys with `^(waka_)?[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`; the `waka_` prefix, optional in the vendor regex, is made required here as the anti-FP anchor) |
| `checkout_com_secret_key` | https://www.checkout.com/docs/resources/api-authentication/api-keys and https://www.checkout.com/docs/developer-resources/api/manage-api-keys/api-keys (Checkout.com — server-side secret keys are `sk_` for production and `sk_sbox_` for sandbox, followed by a 26-32 character lowercase alphanumeric body); corroborated by Checkout.com's own official SDK READMEs, which use the same shape in their configuration examples: https://github.com/checkout/checkout-sdk-java, https://github.com/checkout/checkout-sdk-php, https://github.com/checkout/checkout-sdk-python. Regex independently authored; the Stripe `sk_live_`/`sk_test_` negative lookahead and lowercase-only body are our own anti-collision guards. |
| `mercadopago_access_token` | https://www.mercadopago.com.br/developers/en/reference/authentication/oauth/_oauth_token/post (Mercado Pago's own OAuth token endpoint reference — prints an example response body `"access_token": "APP_USR-4934588586838432-XXXXXXXX-241983636"` alongside the sibling `"user_id": 241983636`, plus an access_token field-format description `APP_USR-1585551492-030918-25######3458-2880736` naming the `APP_USR` token type, the client id, and the MMddHH creation date; the X/# runs are the vendor's own redaction of the 32-char hex segment). Regex independently authored from that reference; no third-party detector was consulted. The public key (`APP_USR-` + UUID) and refresh token (`TG-`) are deliberately excluded. |
| `zoho_oauth_token` | https://www.zoho.com/accounts/protocol/oauth/web-apps/access-token-expiry.html and https://www.zoho.com/accounts/protocol/oauth/web-apps/access-token.html (Zoho's own OAuth documentation — prints concrete example values rather than placeholders: `access_token` `1000.<32 lowercase hex>.<32 lowercase hex>` and `refresh_token` in the identical shape, pinning the literal `1000.` leading segment, the lowercase-hex charset, and the exact 32-character length of both segments); the non-secret `client_id` shape used as the anti-collision negative comes from https://www.zoho.com/accounts/protocol/oauth/web-apps/authorization.html. Regex independently authored from those references; no third-party detector was consulted. |
| `supabase_secret_key` | https://github.com/supabase/supabase/blob/master/docker/utils/rotate-new-api-keys.sh (Supabase's own self-hosting key-rotation script — contains the generator verbatim: `generateOpaqueKey(prefix)` = prefix + `base64url(randomBytes(17)).slice(0, 22)` + `"_"` + `base64url(sha256(PROJECT_REF + "|" + intermediate)).slice(0, 8)`, and defines the `sb_secret_` / `sb_publishable_` prefixes; this pins the base64url charset and the exact 22 + `_` + 8 body). Corroborated by the vendor CLI's local-development default key in https://github.com/supabase/cli/blob/main/apps/cli-go/pkg/config/apikeys.go, which is exactly 22 + `_` + 8 and is registered here as a `known_test_value`. Regex independently authored from those sources; no third-party detector was consulted. The sibling `sb_publishable_` (client-safe) and `sb_temp_` (platform) keys share the generator but are excluded by the literal prefix. |
| `cockroachdb_cloud_api_key` | https://github.com/cockroachdb/terraform-provider-cockroach/blob/main/examples/resources/cockroach_api_key/import.sh (CockroachDB's own Terraform provider repo — publishes a full-length example service-account API key, `CCDB1_` + 22 alphanumerics + `_` + 40 alphanumerics, 69 characters total; the same example is repeated in that repo's `docs/resources/api_key.md`), corroborated by https://github.com/cockroachdb/docs (`src/current/cockroachcloud/ccloud-reference.md` — shows `ccloud service-account api-key create` emitting `Secret: CCDB1_...`, confirming the prefix), with product context at https://www.cockroachlabs.com/docs/cockroachcloud/service-accounts. Regex independently authored from those vendor sources; no third-party detector was consulted. No entropy threshold — the 6-character vendor-unique prefix and the fixed 69-character length carry the signal. |
| `trigger_dev_secret_key` | https://github.com/triggerdotdev/trigger.dev/blob/main/apps/webapp/app/utils/apiKeys.ts (Trigger.dev's own key generator — `customAlphabet("1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 24)` fixes the body at exactly 24 characters from the 62-character alphanumeric alphabet; `apiKeyPrefix()` returns `tr_dev_` / `tr_stg_` / `tr_prod_` / `tr_preview_`; `generateAdditionalApiKey()` inserts a literal `sk_` between prefix and body, which root keys omit), corroborated by the vendor's own unit test https://github.com/triggerdotdev/trigger.dev/blob/main/apps/webapp/app/utils/apiKeys.test.ts (asserts `^{prefix}[A-Za-z0-9]{24}$` and `^{prefix}sk_[A-Za-z0-9]{24}$` across all four environments). The secret-vs-publishable split comes from https://github.com/triggerdotdev/trigger.dev/blob/main/packages/cli-v3/src/utilities/getApiKeyType.ts, which types `tr_*` as "server" and `pk_*` as "public" — the publishable `pk_dev_` / `pk_prod_` keys and the `tr_pat_` personal access token are deliberately excluded. Regex independently authored from those vendor sources; no third-party detector was consulted. No entropy threshold — the multi-segment vendor prefix and the generator-fixed 24-character body carry the signal. |
| `infisical_service_token` | https://github.com/Infisical/infisical/blob/main/backend/src/services/service-token/service-token-service.ts (Infisical's own service-token generator — `const secret = crypto.randomBytes(16).toString("hex")` fixes the secret segment at exactly 32 lowercase hex characters, and `const token = \`st.${serviceToken.id.toString()}.${secret}\`` gives the `st.` prefix and the three-segment layout; the same file parses with `token.split(".", 3)`, which is why a 4th segment can be present and is ignored). The middle segment is pinned to a canonical UUID by the table DDL in https://github.com/Infisical/infisical/blob/main/backend/src/db/migrations/20231225072545_service-token.ts (`t.string("id", 36).primary().defaultTo(knex.fn.uuid())` — a 36-character column defaulting to a generated UUID), corroborated by the vendor's own Go test fixture `"st." + uuid.New().String() + "."` in https://github.com/Infisical/infisical/blob/main/backend-go/tests/platform/auth/apiauthenticator_test.go . The prefix is the vendor's routing anchor per https://github.com/Infisical/infisical/blob/main/backend-go/internal/services/auth/apiauth/classify.go (`strings.HasPrefix(token, "st.")` -> `AuthModeServiceToken`; every other three-part dotted token is routed to `AuthModeJWT`), and the optional trailing hex segment is documented in https://github.com/Infisical/infisical/blob/main/docs/internals/service-tokens.mdx (the token `st.abc.def.ghi`, where `st.abc.def` is the Bearer credential and `ghi` is "a hex-string" used to decrypt the project key). Regex independently authored from those vendor sources; no third-party detector was consulted. No entropy threshold — both variable segments are lowercase hex (max 4.0 bits/char), so the UUID plus fixed-32-hex structure carries the signal instead. |
| `polar_personal_access_token` | https://github.com/polarsource/polar/blob/main/server/polar/personal_access_token/service.py (Polar's own server — defines the `polar_pat_` TOKEN_PREFIX) and https://github.com/polarsource/polar/blob/main/server/polar/kit/crypto.py (the shared generate_token helper — 37 random base62 characters plus a 6-character base62 CRC32 checksum, so the body is exactly 43 base62 characters). Regex independently authored from that source. Note that third-party detector catalogs publish this token as `polar_(at|oat|rt)_[a-zA-Z0-9_-]{20,60}`; that charset and length are contradicted by the vendor generator and were deliberately NOT used. |
| `polar_organization_access_token` | https://github.com/polarsource/polar/blob/main/server/polar/organization_access_token/service.py (Polar's own server — defines the `polar_oat_` prefix and reuses the same generate_token helper as the personal access token) and https://polar.sh/docs/api-reference/introduction (vendor API reference — documents the organization access token as the server-integration credential). Regex independently authored; same catalog-format caveat as `polar_personal_access_token`. |
| `mercury_production_api_token` | https://docs.mercury.com/reference/getting-started-with-your-api (Mercury's own "Getting started with your API" reference — its curl examples print a full production token verbatim three times in the `secret-token:` Authorization header, pinning the `mercury_production_` prefix, the lowercase sub-tag segment, the alphanumeric body, and the literal `_yrucrem` terminator). Regex independently authored from those vendor examples; no third-party detector was consulted. The published example is registered as a `known_test_value`. |
| `zuplo_consumer_api_key` | https://zuplo.com/docs/articles/api-key-leak-detection (Zuplo's own leak-detection article — publishes the key shape, `zpka_` + a 32-character alphanumeric body + `_` + an 8-character CRC32 checksum, 46 characters total, expressly so that leak-detection services can recognize it). Regex independently authored from that article. |
| `authress_service_client_access_key` | https://authress.io/knowledge-base/docs/authorization/service-clients/access-keys (Authress's own service-client access-key documentation — describes the access key as the `sc_`-prefixed service client id, the key id, the `acc`-prefixed account id, and a base64 PKCS#8 private key, joined with `.` separators). Regex independently authored; the full four-segment structure including the literal `acc` marker is required on purpose, because a bare `sc_` prefix is far too generic to detect on. |
| `databento_api_key` | https://github.com/databento/databento-rs/blob/main/src/lib.rs (Databento's own Rust client — `ApiKey::new` rejects any key whose length is not 32 with the message "expected to be 32-characters long", and documents the `db-` prefix; that fixes the body at exactly 29 characters). Regex independently authored from that source. |
| `cfxre_server_key` | https://github.com/citizenfx/txAdmin/blob/master/shared/consts.ts (txAdmin — Cfx.re's own first-party server admin tool; its `regexSvLicenseNew` defines the `cfxk_` prefix, the body, and the trailing base62 CRC32B checksum segment) and https://forum.cfx.re/t/introducing-a-new-server-key-format/3598425 (Cfx.re forum announcement of the new server-key format). Regex independently authored. The vendor's own `{1,60}_{1,20}` bounds were deliberately NOT shipped verbatim — they would accept `cfxk_a_b`; the body is tightened to 20-40 characters and the checksum to 4-10. |
| `lob_api_key` | https://help.lob.com/account-management/api-keys (Lob's own API-keys help article — "Test API keys are always prefixed with `test_` and production API keys with `live_`"). The vendor publishes the prefixes but not the body length; the 35-character body used here is corroborated by community detector catalogs and was re-derived and re-stated independently, and the mandatory `lob` label gate is ClassiFinder's own anti-collision guard against `gocardless_access_token` (bare `live_` + a 40-character body) and Stripe's `sk_live_`/`pk_live_`/`rk_live_` keys. No TruffleHog detector code was read or copied; TruffleHog is AGPL-3.0 and is never a source for engine code. |
| `contentful_management_personal_access_token` | https://github.com/contentful/experience-design-system-sdk-public/blob/main/packages/experience-design-system-cli/src/lib/debug-logger.ts (Contentful's own CLI debug-output redaction regex, `/CFPAT-[A-Za-z0-9_-]{20,}/` — pins the `CFPAT-` prefix and the base64url body charset) and https://github.com/contentful/contentful-management.php/blob/master/tests/Recordings/e2e_personal_access_token_create_get_revoke.json (Contentful's own PHP SDK end-to-end HTTP recording — contains a real, long-since-revoked token whose body is exactly 64 lowercase hex characters; the recorded payload timestamps are 2018-04-16, which is why that shape is treated here as the LEGACY format and the real value is deliberately NOT registered as a `known_test_value`). The current 43-character body — 32 random bytes in unpadded base64url, the same shape as Contentful's existing delivery token — was fixed empirically rather than from a vendor statement: every `CFPAT-` occurrence harvested across 60 public repositories has a 43-character body (length histogram 43:15, 42:2, 20:1, the short ones being truncated placeholders). Note that Contentful's published CMA access-token docs state neither length nor charset. Regex independently authored from those vendor sources and that corpus survey; several public detector catalogs publish a compatible 43-character rule, but no third-party detector code was consulted or ported, and none of them covers the legacy 64-hex form. Additive to `contentful_delivery_api_token`, which is a different (read-only, prefix-less, context-gated) credential. |
| `hcaptcha_siteverify_secret_key` | https://docs.hcaptcha.com/ (hCaptcha's own Developer Guide — documents the `secret` parameter POSTed to the `/siteverify` endpoint, publishes the all-zero dummy secret `0x` + forty zeros that is registered here as a `known_test_value`, and references the enterprise `ES_…` sitekey secret). The vendor guide does not state the body length or charset of either shape, so both branches were pinned against two independent third-party integrations that validate exactly the same alternation: https://github.com/AlfredoRamos/phpbb-ext-hcaptcha (`captcha/plugins/hcaptcha.php` — `#\A(0x[a-fA-F0-9]{40}\|ES_[a-fA-F0-9]{32})\z#`) and https://github.com/bgord/bgord-bun (`src/hcaptcha-secret-key.vo.ts` — `/^(0x[a-fA-F0-9]{40}\|ES_[a-fA-F0-9]{32})$/`). Those two were read as corroborating evidence for the format only; the shipped regex is independently authored and differs materially from both — they are whole-string validators, whereas this is a context-gated scanner rule. The mandatory `hcaptcha` / `siteverify` context gate, the 60-character window, the `(?<![A-Za-z0-9_])` left boundary and the entropy threshold are ClassiFinder's own anti-false-positive guards, added because `0x` + 40 hex is byte-identical to a public Ethereum address. No third-party secret-detector code was consulted or ported. |

Vendor-published token formats (e.g. `AKIA...`, `sk_live_...`, `AIza...`, PEM markers, JWT structure, Bitcoin WIF, credit-card IINs) are facts and not subject to copyright.

---

## Research Sources (No Code Used)

The following projects were studied for research, methodology, and competitive analysis. **No source code or copyrighted regex strings from these projects have been incorporated into ClassiFinder.** They are listed for intellectual honesty.

### TruffleHog (AGPL-3.0)

**Project:** https://github.com/trufflesecurity/trufflehog
**License:** AGPL-3.0
**Use in ClassiFinder:** Research only. ClassiFinder studied TruffleHog's detector taxonomy, false-positive reduction techniques, entropy thresholds, and decoder architecture. No regex strings, wordlists, or code were copied. Every pattern that shares structural similarity with a TruffleHog detector has been audited and its independent provenance documented inline in the source.

### Gitleaks (MIT)

**Project:** https://github.com/gitleaks/gitleaks
**License:** MIT
**Use in ClassiFinder:** Competitive context only. ClassiFinder is intentionally not a Git-history scanner; Gitleaks served as a positioning baseline.

---

## Python Dependencies

ClassiFinder's runtime dependencies and their licenses are tracked in each subproject's `pyproject.toml` / `requirements.lock`. Notable:

- **FastAPI** (MIT) — https://github.com/tiangolo/fastapi
- **Pydantic** (MIT) — https://github.com/pydantic/pydantic
- **Uvicorn** (BSD-3-Clause) — https://github.com/encode/uvicorn
- **httpx** (BSD-3-Clause) — https://github.com/encode/httpx

Run `pip-licenses` against any subproject's lockfile for the exhaustive list.

---

*Last updated: 2026-05-28* (Batch 5: 5 Betterleaks Go rule sources added)
