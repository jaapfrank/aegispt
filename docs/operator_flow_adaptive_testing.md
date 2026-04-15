# Operator Flow for Adaptive Testing

## Goal

The operator flow stays simple even though the platform now supports customer-specific adaptive packs.

## Current implementation

The current repository includes an initial operator console at `/app` that follows this flow directly. It reuses the existing backend models and exposes the wizard, mission control, drilldowns, reporting, evidence access, and Codex build-lane visibility without introducing a second backend architecture.

## Workflow

1. Create engagement
2. Define scope
3. Run inventory
4. Review inventory summary
5. Run AI research and relevance analysis
6. Generate customer-specific capability pack
7. Validate pack
8. Approve and promote pack
9. Start active validation with that pack
10. Review findings and reports

## Screen requirements

### Inventory summary

Show:

- hosts
- services
- endpoints
- technologies
- auth signals
- API signals
- TLS posture
- detection confidence

### Relevance summary

Show:

- relevant advisories
- informational advisories
- suppressed advisories
- proposed extra checks
- methodology tags
- justification and evidence basis

### Pack review

Show:

- pack name and version
- artifact list
- inventory snapshot source
- threat intel references
- methodology tags
- generation provenance

### Validation and promotion

Show:

- validation pass/fail
- blocking issues
- approval history
- deployment readiness

### Runtime binding

Show:

- currently bound pack version
- deployment target
- rollback state where relevant

### Findings and reporting

Show:

- finding origin: standard or adaptive pack
- pack version when applicable
- inherited methodology metadata
- evidence and reproduction links

## UX note

The operator should feel like they are approving an assessment plan extension, not managing a generic CI/CD system.
