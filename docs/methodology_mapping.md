# Methodology Mapping for AegisPT

## 1. Purpose

This document defines the additive methodology layer for AegisPT.

The intent is to make the existing platform easier to position in enterprise assessments without changing its core architecture. AegisPT remains:

- evidence-first
- tool-orchestrated
- operator-controlled
- replay-oriented
- approval-gated for higher-impact validation

The methodology layer exists to answer four practical questions:

1. Which framework governs the assessment lifecycle?
2. Which framework governs web and API technical test coverage?
3. Which framework governs structured technical execution, evidence handling, and reporting discipline?
4. Which framework can optionally be used to reference application security controls in findings?

## 2. Framework Roles

### 2.1 PTES

PTES is the assessment lifecycle model.

In AegisPT, PTES governs:

- engagement framing
- workflow language behind the operator UX
- the distinction between discovery, analysis, controlled exploitation, reporting, and retest
- how internal validation sessions are positioned as controlled adversary simulation rather than free-form exploitation

PTES is the primary answer to: "Where are we in the assessment?"

### 2.2 OWASP WSTG

OWASP WSTG is the primary web and API technical coverage model.

In AegisPT, WSTG governs:

- how dynamic web/API findings are categorized
- how test areas are described in coverage summaries
- how findings reference recognizable web testing domains
- how operator workflows map web validation evidence to known testing areas

WSTG is the primary answer to: "What web or API security area did this test or finding cover?"

### 2.3 NIST SP 800-115

NIST SP 800-115 is the structured technical testing and reporting discipline.

In AegisPT, NIST SP 800-115 governs:

- planning and rules-of-engagement discipline
- discovery versus attack distinctions
- evidence handling and structured reporting expectations
- remediation and retest framing

NIST is the primary answer to: "How was this assessment planned, executed, analyzed, and reported in a disciplined way?"

### 2.4 OWASP ASVS (Optional Reference Layer)

OWASP ASVS is an optional control-verification and requirement-reference layer.

In AegisPT, ASVS is not the main testing workflow. It is used only when helpful to:

- map a finding to an application security control requirement
- support secure SDLC and remediation conversations
- provide a control-oriented reference in technical reporting

ASVS is the primary answer to: "Which secure application control expectation does this finding relate to, if we want to say so precisely?"

## 3. Product Mapping Table

| AegisPT Component | Governing Framework | Implementation Notes |
| --- | --- | --- |
| Engagement definition, scope, ROE reference | PTES, NIST SP 800-115 | Maps to pre-engagement and planning discipline. |
| Passive reconnaissance and discovery runs | PTES, NIST SP 800-115, WSTG | Operator workflow labels stay simple, but passive runs map to intelligence gathering / discovery. |
| Approval-gated active validation runs | PTES, NIST SP 800-115, WSTG | Active and intrusive run classes map to controlled exploitation / verification and NIST attack discipline. |
| Internal validation sessions | PTES, NIST SP 800-115 | Treated as controlled, stepwise adversary validation with approvals and replayable evidence. |
| ZAP-based web validation | OWASP WSTG | Primary web testing coverage source for dynamic web findings. |
| Nuclei-based validation | NIST SP 800-115, WSTG where applicable | Template-driven validation contributes evidence and may map to WSTG when the finding is clearly web/API relevant. |
| Semgrep-based code validation | PTES, NIST SP 800-115, optional ASVS | Code findings may not always have a direct WSTG reference; WSTG remains web/API-first. |
| Finding normalization | WSTG, PTES, NIST SP 800-115, optional ASVS | Findings now persist methodology metadata alongside evidence links. |
| Report generation | NIST SP 800-115, PTES, WSTG | Reports include scope, ROE summary, methodology, coverage, confirmed findings, evidence, remediation, and verification status. |
| Remediation and retest workflow | PTES, NIST SP 800-115 | Existing finding status model remains the verification-state carrier. |

## 4. Lifecycle Mapping

The operator-facing workflow stays simple, but it now maps cleanly to PTES phases.

| Product Workflow Label | PTES Phase | AegisPT Mapping |
| --- | --- | --- |
| Pre-Engagement | Pre-Engagement | Engagement creation, scope definition, ROE reference, approvals model. |
| Intelligence Gathering | Intelligence Gathering | Discovery and passive reconnaissance through tools such as httpx, nmap, ffuf, feroxbuster, and early ZAP exploration. |
| Analysis / Validation | Threat Modeling and Vulnerability Analysis | Passive validation, template-based checks, code review findings, and evidence-backed issue confirmation. |
| Controlled Exploitation / Verification | Exploitation and Post-Exploitation where applicable | Approval-gated active ZAP steps, controlled internal validation, and approved validation of exploitability. |
| Reporting | Reporting | Evidence-backed executive and technical report generation. |
| Retest | Retest | Repeat execution after remediation and finding status updates such as resolved or reopened. |

Notes:

- AegisPT does not expose PTES jargon everywhere in the product UI.
- PTES remains the internal lifecycle reference.
- Internal validation does not imply unrestricted exploitation. It remains human-governed and stepwise.

## 5. Technical Coverage Mapping

OWASP WSTG is the primary technical coverage model for web and API testing.

| WSTG Area | Typical AegisPT Coverage |
| --- | --- |
| Information Gathering | httpx, nmap, ffuf, feroxbuster, early ZAP spidering, passive target discovery. |
| Configuration and Deployment Management Testing | HTTP methods, headers, exposed admin paths, content discovery, default exposure checks, selected Nuclei validations. |
| Identity Management Testing | Manual and future assisted checks; first-pass finding metadata support exists. |
| Authentication Testing | ZAP/manual validation, selective mapping from normalized auth findings. |
| Authorization Testing | ZAP/manual validation, internal validation scenarios, IDOR/BOLA and broken authorization mappings. |
| Session Management Testing | ZAP/manual validation, cookie, CSRF, timeout, and session handling mappings. |
| Input Validation Testing | ZAP findings, Nuclei patterns, Semgrep patterns where relevant, injection-class mapping. |
| Error Handling Testing | ZAP/manual validation, stack trace and verbose error mappings. |
| Weak Cryptography Testing | TLS and crypto-related checks from testssl.sh, Nuclei, ZAP, or manual validation. |
| Business Logic Testing | Primarily controlled manual or internal validation support; evidence model already supports it. |
| Client-side Testing | Security header findings, clickjacking, DOM/client-side issues, Playwright-assisted coverage when used. |
| API Testing | Partial today through existing HTTP, ZAP, and validation tooling; planned for deeper dedicated API workflows. |

Version handling:

- AegisPT stores both `wstg_id` and `wstg_version`.
- The current default stable reference is `v4.2`.
- If the platform later adopts a newer WSTG release, existing findings remain unambiguous because the version is persisted with the reference.
- API-specific coverage may continue to use broader WSTG categories until dedicated, version-specific API mappings are added.

## 6. Reporting and Evidence Mapping

NIST SP 800-115 provides the structured discipline around planning, execution, evidence handling, and reporting.

| AegisPT Capability | NIST Relevance | Implementation Notes |
| --- | --- | --- |
| Engagement, scope, ROE reference | Planning | Establishes what is authorized and how the work should be conducted. |
| Approval-gated execution | Planning, Attack | Reinforces deliberate execution and reduces uncontrolled impact. |
| Passive and active task execution | Discovery, Attack | Passive runs align more closely to discovery; active validation aligns more closely to attack. |
| Artifact capture and hashing | Execution, Data Handling | Preserves evidence integrity and supports replay. |
| Linked finding evidence | Analysis, Reporting | Findings remain tied to artifacts and execution details. |
| Markdown and HTML reporting | Reporting | Executive and technical outputs remain evidence-first and structured. |
| Finding status updates and retest flow | Post-Testing | Supports remediation tracking, verification, and reopened findings. |

## 7. Finding Metadata Standard

The methodology layer defines a broader finding metadata standard than the current persistence model.

### Persisted Finding Fields in the Current Alignment Patch

These fields are now persisted directly on findings:

- `title`
- `severity`
- `target_id`
- `evidence_ref`
- `status`
- `summary`
- `methodology_tags`
- `ptes_phase`
- `nist_phase`
- `wstg_id`
- `wstg_version`
- `asvs_reference`
- `control_family`

### Standard Report/Finding Package Fields

These fields should exist in the technical reporting model, even when some are analyst-supplied rather than auto-derived today:

- `title`
- `severity`
- `confidence`
- `exploitability`
- `affected_assets`
- `business_impact`
- `technical_impact`
- `evidence_references`
- `replay_status`
- `methodology_references`
- `wstg_id`
- `wstg_version`
- `ptes_phase`
- `nist_phase`
- `asvs_reference`
- `remediation_summary`
- `remediation_detail`
- `verification_status`

Implementation guidance:

- `wstg_id` should be populated only when the mapping is reasonably defensible.
- `wstg_version` must travel with `wstg_id`.
- `asvs_reference` should only be populated with a precise control reference, not guessed.
- `verification_status` currently maps to the existing finding status model.
- `replay_status` is currently derived from evidence linkage in reports rather than persisted as a dedicated database field.

## 8. Non-Goals

This methodology layer does not change:

- the core architecture
- the evidence-first philosophy
- the controlled internal validation model
- the existing tool-first execution model
- the approval-gated design for higher-impact actions
- the prohibition on autonomous self-propagation or worming

It is an alignment patch, not a re-architecture.
