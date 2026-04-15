# Identity Model

## Purpose

This document prepares AegisPT for identity-aware testing and future internal validation paths.

## Future concepts

- users
- roles
- permissions
- auth context mapping
- privilege boundaries

## Placeholder schemas

Prompt 3 adds placeholder schemas for:

- subjects
- roles
- permissions
- auth context

These placeholders are additive only and do not introduce full directory integration.

## Later use cases

- model which identities can reach which assets
- map privilege escalation opportunities
- support internal validation scenarios that reason about access level transitions

## Out of scope

- AD integration
- LDAP integration
- identity graph storage
- live privilege collection
