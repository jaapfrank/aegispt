# Codex Build Lane

## Purpose

The Codex build lane is the supervised generation and refinement path for customer-specific adaptive packs.

It assumes operators may use Codex through:

- Codex CLI
- Codex IDE extension
- Codex app workflows where supported

with ChatGPT/Codex sign-in handled in those supported clients.

## Operating model

Codex is used after inventory completes and before runtime deployment.

Codex may help:

- refine generated nuclei templates
- refine Playwright flows
- refine Semgrep rules
- adjust scanner profiles
- improve pack metadata and workflow definitions

## Required guardrails

- no hidden self-editing of the live runtime
- no pack changes during an active assessment run
- all generated output must go through validation and approval
- all artifacts must remain versioned and reviewable

## Practical workflow

1. inventory completes
2. relevance analysis identifies capability gaps
3. a pack is generated with initial artifacts
4. Codex refines those artifacts in the supervised build lane
5. validation runs
6. operator approval occurs
7. the approved pack is deployed
8. a run binds to that deployed pack

## Evidence requirements

The build lane should preserve:

- which inventory snapshot drove the work
- which threat intel references influenced the pack
- which artifacts were generated or refined
- which validation result approved the pack for promotion

