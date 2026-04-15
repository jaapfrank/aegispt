# Promotion Pipeline

## Purpose

Generated packs must pass through a controlled release lane before the runtime can use them.

## Validation stages

The current pipeline performs:

1. artifact structure checks
2. syntax-oriented checks where practical
3. safe dry-run style validation for JSON-defined artifacts
4. validation artifact recording
5. promotion blocking on failure

## State diagram

```text
generated
  |
  v
validate
  |
  +--> validation_failed
  |
  v
validated
  |
  v
approved
  |
  v
deployed
  |
  +--> superseded
  |
  +--> retired
```

## Approval gate

Approval happens after successful validation.

This preserves the existing evidence-first, operator-controlled execution posture:

- generation is reviewable
- validation is recorded
- approval is explicit
- deployment is explicit
- runtime use is deterministic

## Recorded artifacts

Each validation result stores:

- validator identity
- executor identity
- pass/fail summary
- per-artifact results
- blocking issues
- validation artifact metadata

