# Attribution & Third-Party Notices

ClassiFinder is built with respect for the open-source community. This file documents the third-party projects whose work has informed, inspired, or contributed to ClassiFinder's pattern library and engine design.

If you believe an attribution is missing or incorrect, please open an issue.

---

## Pattern Library Sources

ClassiFinder's secret-detection pattern library has multiple lineages. Each pattern in `patterns/*.py` carries an inline `# Source:` or `# Format per ...` comment identifying its provenance. This file collects the upstream license notices.

### Betterleaks (MIT)

**Project:** https://github.com/betterleaks/betterleaks
**License:** MIT
**Use in ClassiFinder:** Approximately 44 detection patterns in ClassiFinder were ported from or modeled on rules in `betterleaks.toml` (v1.0.0). Each ported pattern carries an inline comment citing the source TOML line.

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

*Last updated: 2026-05-15* (SAFE-MCP attribution added in [2026-05-15-safe-mcp-incorporation-decisions.md](../classifinder-knowledge/2026-05-15-safe-mcp-incorporation-decisions.md))
