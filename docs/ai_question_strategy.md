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

## Optional LLM intake intelligence

When enabled, the LLM intake layer is a review aid around the existing deterministic intake. It may translate ambiguous operator text into warnings, safe inferences, methodology or pack context, and follow-up questions. It does not replace the deterministic parser and it does not create a second run-configuration model.

The layer is disabled by default. Disabled, unsupported, or provider-failure paths preserve the normal deterministic intake behavior and may only attach failure metadata when the backend is explicitly configured to store interpretation context.

Allowed interpretation output is bounded:

- scope, targets, allowlists, denylists, and exclusions cannot be broadened from LLM output
- authenticated access cannot be inferred unless credentials or access context are explicitly present in operator input or configuration
- methodology and pack suggestions are advisory until the operator confirms them
- pack suggestions cannot approve, deploy, bind, auto-bind, or dispatch work
- follow-up questions always require operator confirmation before they affect the run

## Safety behavior

- access is not assumed just because a portal or API exists
- public scope is never broadened implicitly
- internal lateral discovery is always framed as bounded and approval-aware
- risky or ambiguous language produces clarification or rejection rather than silent expansion

## Operator experience

- the live summary always shows what is confirmed, inferred, and still needed
- the advanced drawer is available without forcing novice users into low-level toggles too early
- the confirmation summary reads like an operator handoff, not a raw schema dump
