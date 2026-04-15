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

## Non-goals

This layer does not:

- download or run exploits
- bypass the approval model
- change the closed runtime during an active engagement

