# TIBER-EU Alignment Guide

Last updated: 2026-04-28

This guide explains how AegisPT evidence can support a TIBER-EU-style programme. It does not make AegisPT a TIBER-certified provider and does not turn an AegisPT scan into a formal TIBER-EU test.

## Boundary Statement

A full TIBER-EU assessment requires the appropriate governance, control team, threat-intelligence provider, red-team provider, target organisation participation, legal authorization, and regulator or authority alignment where applicable.

AegisPT can support parts of the evidence trail when approved by the programme stakeholders, but:

- AegisPT does not replace the TIBER control team;
- AegisPT does not replace an independent threat-intelligence provider;
- AegisPT does not replace an independent red-team provider;
- AegisPT output is not a TIBER-EU certification, attestation, or supervisory submission on its own.

## Where AegisPT Can Help

| TIBER-EU Area | AegisPT Support | Boundary |
| --- | --- | --- |
| Scoping and preparation | store authorized scope, rules of engagement, run configuration, approvals, and audit events | final TIBER scope and governance remain programme-controlled |
| Intelligence-led planning | provide discovery inventory, service exposure, local threat-intel matching, CVE intelligence, and advisory attack paths | threat-intelligence provider retains responsibility for the threat intelligence report |
| Controlled red-team testing preparation | provide evidence-backed findings, exploitation-readiness boundaries, and controlled validation outputs where explicitly authorized | execution must remain within TIBER governance, safety rules, and approval constraints |
| Evidence and replay | retain artifacts, hashes where available, task output, report exports, and audit events | evidence may support but does not replace formal TIBER deliverables |
| Remediation tracking | track findings, retests, accepted risk, and proof-of-resolution outputs | remediation programme ownership remains with the tested entity |

## AegisPT Evidence To Preserve

- authorization document and rules of engagement
- approved target scope and denied targets
- run profile, configuration, and approval events
- task execution metadata and evidence artifacts
- inventory snapshots and exposure summaries
- findings, severity, status, evidence refs, and remediation state
- reports generated for NIS2, DORA, assurance, technical, and evidence appendix variants
- audit events for export, cleanup, purge, and major operator actions

## DORA / TLPT Relationship

DORA may require advanced testing, including threat-led penetration testing for selected financial entities. AegisPT can support technical evidence collection and preparation, but a DORA TLPT programme requires governance, independence, scope, reporting, and authority expectations beyond a normal tool-generated report.

Use the AegisPT `dora` report variant to:

- summarize which ICT-risk evidence areas were technically exercised;
- identify unresolved findings and residual risk;
- separate routine technical testing from TLPT evidence;
- highlight what still requires formal governance, independent providers, and supervisory process evidence.

## Recommended Operating Pattern

1. Create the authorization document before any assessment activity.
2. Record scope, allowed test depth, emergency contacts, and stop conditions.
3. Run discovery and safe validation within AegisPT.
4. Export technical, evidence, NIS2, DORA, and assurance reports as supporting evidence.
5. Review findings with the programme control team before treating any result as TIBER-relevant evidence.
6. Keep formal TIBER threat-intelligence, test plan, execution logs, closure reports, and attestations outside AegisPT unless explicitly approved for storage.

## Unsupported Claims

Do not state that:

- AegisPT is a TIBER-EU-certified provider;
- an AegisPT report is a full TIBER-EU test;
- routine AegisPT scanning satisfies DORA TLPT by itself;
- technical findings alone prove NIS2 or DORA compliance;
- absence of AegisPT findings proves operational resilience.

## References

- ECB TIBER-EU Framework
- Regulation (EU) 2022/2554, Digital Operational Resilience Act
- Directive (EU) 2022/2555, NIS2
- NCSC NL Cyberbeveiligingswet / NIS2 zorgplicht guidance
