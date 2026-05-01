# Threat Intelligence Model

## Purpose

The threat intelligence layer provides a normalized advisory and testing-knowledge store for adaptive pack generation.

It is not an exploit fetcher. It is a structured relevance input.

## Stored record shape

Each `threat_intel_record` stores:

- `source`
- `advisory_id`
- `title`
- `summary`
- `affected_products_json`
- `affected_versions_json`
- `product_match_hints_json`
- `architecture_hints_json`
- `attack_surface_type`
- `suggested_test_patterns_json`
- `confidence_score`
- `severity`
- `references_json`
- `published_at`
- `updated_at`
- `normalization_status`
- `metadata_json`

## Source model

The ingestion layer is designed for approved feeds and curated knowledge such as:

- CVE and advisory summaries
- vendor advisories
- curated internal testing notes
- approved rule/template references
- vetted testing patterns for relevant product classes

## Local approved-feed cache

The feed-cache foundation keeps assessment-time matching local. Operators or supervised build-lane jobs can import already-approved feed payloads through:

- `POST /api/v1/threat-intel/feed-cache/import`

Supported initial feed types:

- `cisa_kev`: local copies of CISA Known Exploited Vulnerabilities records, normalized into `source = cisa-kev` records with `kev` badge metadata.
- `mitre_attack`: local ATT&CK technique records, normalized into `source = mitre-attack` records with `attack` badge metadata.
- `cve_cvss`: local CVE/CVSS metadata, normalized into `source = cve-cvss` records with `cvss` badge metadata.

The import path accepts records in the request body. It does not fetch a remote URL, download exploit code, or perform any scan-time external lookup. The request schema intentionally rejects a `source_url` fetch shape; feed acquisition remains an operator/build-lane responsibility outside active assessment analysis.

## Normalization rules

Normalization keeps the data useful for matching instead of treating every feed as a special case.

Important normalized dimensions:

- product names
- version ranges or version hints
- architecture hints
- attack surface type such as `web`, `api`, `auth`, `tls`, or `code`
- suggested test patterns such as `nuclei`, `zap`, `playwright`, `semgrep`, or `scanner-profile`

## How it is used

Threat intelligence records are matched against:

- normalized inventory terms
- scope and attack surface hints
- prior findings for the same engagement
- Prompt 1 methodology metadata reused through the existing methodology layer

The output is not automatic execution. The output is a relevance decision that can drive pack generation.

Finding Theater now also exposes local-cache threat-intel badges when a finding matches stored approved-feed data. Badge matching uses only fields already present in local `threat_intel_records`, including advisory ids, CVE ids, ATT&CK technique ids, product hints, CWE ids, and source references. Badge output is source-linked and non-attributional:

- KEV badges show known-exploited catalog context when a local CISA KEV record matches.
- CVSS badges show locally cached score/severity context when a local CVE/CVSS record matches.
- ATT&CK badges show technique context when a local ATT&CK technique record matches.

Badge output does not mutate findings, auto-escalate severity, claim threat-actor attribution, or perform external network calls during finding analysis.

## Stale and sparse behavior

Each feed-cache import records `feed_cached_at` and `stale_after_days` in `metadata_json`.

- Fresh records are labeled `fresh` while the cache age is within the threshold.
- Old records are labeled `stale` with the cache age and stale threshold.
- Records without a parseable cache timestamp are labeled `unknown`.
- Findings with no local match return an explicit no-badge reason instead of fabricated intelligence.

## Non-goals

This layer does not:

- download or run exploits
- fetch remote feed URLs during finding analysis
- claim threat-actor attribution
- change finding severity
- bypass the approval model
- change the closed runtime during an active engagement
