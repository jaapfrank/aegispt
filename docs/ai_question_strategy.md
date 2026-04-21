# AI Question Strategy

## Core rules

- ask one useful question at a time
- ask broad intent first, specifics second
- only ask for information that still changes the mission shape
- prefer safe inference over noisy over-questioning
- never broaden scope from vague language

## Question order

The intake generally resolves in this order:

1. what is being tested
2. what the main goal is
3. what exact targets are authorized
4. whether authenticated access is needed
5. how conservative or thorough the run should be
6. what exclusions or internal boundary rules apply
7. whether the confirmation summary is acceptable

The order may compress when a safe inference is already good enough.

## Recommendation behavior

The intake may recommend:

- inventory-first when the operator asks for visibility or per-item reporting
- authenticated review when the operator mentions a portal account or role-based behavior
- conservative posture when the mission is clearly inventory-led
- adaptive coverage when the operator explicitly wants customer-specific follow-up checks

## Safety behavior

- access is not assumed just because a portal or API exists
- public scope is never broadened implicitly
- internal lateral discovery is always framed as bounded and approval-aware
- risky or ambiguous language produces clarification or rejection rather than silent expansion

## Operator experience

- the live summary always shows what is confirmed, inferred, and still needed
- the advanced drawer is available without forcing novice users into low-level toggles too early
- the confirmation summary reads like an operator handoff, not a raw schema dump
