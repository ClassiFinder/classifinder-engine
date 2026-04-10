---
name: require-pattern-source-comment
enabled: true
event: file
action: warn
conditions:
  - field: file_path
    operator: regex_match
    pattern: patterns/[^/]+\.py$
  - field: new_text
    operator: regex_match
    pattern: re\.compile\(
---

## Pattern Provenance Check

You are writing a `re.compile()` to a patterns file. Before saving, confirm every new pattern entry has a source comment within 5 lines above it.

**Accepted comment formats (pick one):**
- `# Source: <URL to vendor doc or upstream file>`
- `# Format per <vendor doc URL>`
- `# Pattern attribution: Betterleaks MIT` or `SPDB CC-BY-4.0`
- `# Independently authored — <brief rationale>`
- `# Vendor-published format (prefix is public spec)`

**Rules:**
- TruffleHog (AGPL-3.0) must NEVER be the source — rewrite from vendor docs instead
- Betterleaks (MIT) and secrets-patterns-db (CC-BY-4.0) are safe with attribution
- If sourced from Betterleaks or SPDB, also update `ATTRIBUTION.md`

The pre-commit hook will block the commit if any `re.compile()` lacks a nearby source comment.
