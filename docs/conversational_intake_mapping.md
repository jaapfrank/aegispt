# Conversational Intake Mapping

## Purpose

The conversational intake translates plain-language operator answers into the existing deterministic run configuration. It does not create a second config model.

Optional LLM intake intelligence can attach advisory interpretation metadata under `intake.llm_interpretation` when explicitly enabled. That metadata is not authoritative configuration: it cannot add targets, widen allowlists, assume credentials, approve packs, deploy packs, bind packs, dispatch tasks, or bypass the existing deterministic intake and run gates.

## Mapping model

| Conversation topic | Primary run fields | Notes |
| --- | --- | --- |
| Intent | `assessment_type`, `intake_preferences.mission_intent` | intent may infer a target type when the language is clear enough |
| Goal | `test_profile`, `intake_preferences.primary_goal`, module/safety presets | goal drives the recommended profile and execution depth unless advanced overrides are already active |
| Scope | `targets` | only explicit authorized URLs, domains, IPs, CIDRs, or API roots are accepted |
| Access | `access.accounts`, `access.manual_auth_steps`, `intake_preferences.auth_strategy` | auth questions appear only when access materially changes the run |
| Safety | `safety`, `intake_preferences.safety_posture` | conservative defaults may be inferred for low-risk inventory-first missions |
| Boundaries | `exclusions`, `intake_preferences.boundary_handling`, `intake_preferences.lateral_discovery` | boundary notes and denylist values stay visible in scope/report context |
| Output preference | `intake_preferences.output_style` | affects summary/report framing, not runtime safety |
| Optional LLM interpretation | `intake.llm_interpretation` | advisory warnings, safe inferences, blocked suggestions, and follow-up questions only; no runtime or scope mutation |

## Inference rules

- broad target type can be inferred from phrases such as `LAN network`, `API`, `domain`, or `customer portal`
- mixed-surface phrasing such as `mixed`, `hybrid`, or `web and API` now resolves before pure API wording so mixed missions do not silently collapse into API-only runs
- goal can be inferred only when the operator explicitly signals it through phrases like `inventory first`, `deep test`, or `adaptive`
- auth is not inferred early if the mission shape may still require credentials
- conservative safety may be inferred for internal inventory-first and TLS-only style missions
- boundary handling may default to standard scope only when no exclusions or lateral-discovery hints were provided
- scope parsing may refine a broad generic target type, but it does not downshift deliberate specialist mission types such as `SSL/TLS Only` or `Authenticated App` just because the approved target is expressed as a domain or URL

## Confirmation rules

The intake must confirm or surface as still-needed anything that materially changes:

- authorized scope
- authenticated access
- validation aggressiveness
- exclusions or boundary handling

## Ambiguity handling

- vague public-target expansion is rejected
- `look around`, `anything reachable`, or similar phrasing does not become authorization
- if the operator wants internal adjacency or lateral discovery, the summary phrases it as:
  - within the authorized internal environment
  - subject to configured limits
  - report-only unless explicit follow-up approval exists
- LLM-produced scope expansion, unconfirmed access assumptions, and pack approval or deployment language are recorded as blocked suggestions rather than being mapped into run fields

## Advanced synchronization

The advanced drawer remains authoritative for power-user tuning. When it changes:

- the same run fields are updated
- the conversational summary marks the affected section as an advanced override
- confirmation text and mission summary update immediately
