# Operator Console Phase 1 Checklist

## Purpose

This document is the working checklist for Phase 1 of the operator-console stabilization side project.

Phase 1 exists to make the conversational intake fully completable, understandable, and trustworthy across every supported mission type before the broader execution-truth and LAN follow-through slices continue.

## Phase focus

- complete every assessment-type intake path
- verify the right questions appear at the right time
- ensure the confirmation summary matches the real deterministic run model
- keep advanced overrides synchronized with the conversational summary
- keep advanced overrides synchronized with the currently active question so stale prompts do not linger after the mission model changes
- keep advanced invalid-input states truthful so the wizard never shows `Confirmation Ready` while step validation is still blocking mission creation
- keep the natural-language confirmation handoff visible after mission creation so operators can compare the intake promise against the created dossier
- keep the existing-engagement reuse route explicit so operators can tell when a mission will attach to the selected dossier instead of creating a new one
- keep new-dossier creation explicit too, and never overwrite a hand-entered dossier name with later conversational inference
- keep hand-entered dossier names locked even when advanced scope or advanced profile changes happen later in the same intake
- keep auto-generated new-dossier names truthful too, so advanced scope and profile overrides continue to refresh the suggested dossier name until the operator explicitly types their own replacement
- keep authorization context (`Customer`, `ROE Reference`) aligned across confirmation, Explorer, and the persisted run dossier for both engagement routes
- keep scope guardrails (`Exclusions`, `Boundary Notes`, `Boundary Handling`, `Output Style`) aligned across advanced overrides, confirmation, and the persisted run dossier
- keep richer mixed/auth/adaptive routes truthful so `Boundaries` is still explicitly confirmed before launch instead of silently defaulting to `Standard Scope Only`
- keep scope revisions truthful so moving from a simpler web/auth route into a boundary-sensitive route such as an internal CIDR clears any earlier generic boundary confirmation and re-prompts `Boundaries`
- keep scope revisions truthful so internal-only lateral guardrails such as `Report Adjacent Ranges Only` do not linger after the operator revises the mission onto a non-internal web scope
- keep scope revisions truthful so an API mission revised onto a plain website URL no longer persists that new scope as `api base urls` or keeps the mission type stuck on `API`
- keep boundary copy truthful so non-internal web/app/API routes do not still ask about `adjacent internal ranges` or show internal-only quick replies in either the conversational question or Advanced Configuration
- keep auth-default behavior truthful so `Domain / Domains` deep routes do not suddenly ask for credentials just because the generic `Deep` profile would normally enable `auth_flows` on auth-capable app routes
- keep confirmation wording human-readable, including exact singular/plural guardrail phrasing when exclusions are present
- keep notes-only boundary guidance distinct from true structured exclusions across confirmation and Explorer
- keep boundary-topic revision truthful so `No extra exclusions` and notes-only revisions clear or replace older advanced scope payload instead of leaving contradictory stale guardrails behind
- keep goal/assessment compatibility truthful so `Internal Validation` cannot survive onto non-LAN scope and scope revisions do not silently fall back to a lighter profile than the direct supported route
- keep internal credentialed mission staging truthful so `Authenticated Review` on a LAN/CIDR target does not pretend the first run is already an authenticated app lane when the real execution still starts with discovery
- keep suggested-answer chip paths truthful so representative click-driven intake routes create the same deterministic run dossiers as the typed-answer path
- keep the `What Still Needs Confirmation` card calm and honest so it does not repeat the already-active topic or echo the same remaining item through multiple competing affordances
- keep the opening intent screen calm and honest so it does not claim downstream `Access` or `Output` requirements before the mission state actually makes those topics relevant
- keep common portal-language intent truthful so examples like `Our customer portal` actually enter the authenticated-app path instead of drifting into the generic web-app route
- keep assessment-type wording truthful so public-edge `External IP / WAN` intent does not briefly ask for internal hosts, passive lanes do not claim active validation in the same confirmation handoff, and mixed-surface copy does not duplicate `assessment`
- keep WAN perimeter rich-goal staging truthful so explicit IP/CIDR perimeter missions do not promise a `Deep` or `Adaptive` first run while the created mission still starts in passive discovery
- keep WAN perimeter authenticated-review staging truthful so protected-access perimeter missions do not claim an `Authenticated Only` first run while the created mission still starts in passive discovery
- keep TLS-only goal selection truthful so a pure certificate/protocol mission does not offer or persist impossible deep/adaptive goal promises
- keep the inline `Mission Progress` note calm and honest so it does not repeat the already-active topic family while that question is already on screen
- keep revision controls calm and truthful so `Revise Captured Topic` stays hidden until there is a real earlier answer to revise, and never lists unanswered later topics as fake `Change ...` actions
- keep advanced-settings access handoff truthful so choosing that route does not silently loop or hide that `Access` is still pending
- keep authenticated-app unauthenticated choices truthful so explicit `Keep it unauthenticated` answers do not bounce back into an access-detail dead end
- keep repeated prior-topic answers truthful so if access is already resolved and the operator repeats `Unauthenticated` while the wizard is asking `Safety`, the response explains the current missing topic instead of feeling like a loop
- keep repeated prior-topic answers truthful so if safety is already resolved and the operator repeats `Balanced` or another standalone safety answer while the wizard is asking `Boundaries`, the response explains the current missing boundary topic instead of silently recording nonsense boundary notes
- keep repeated prior-topic answers truthful so if access is already resolved and the operator repeats `Unauthenticated` while the wizard is asking `Boundaries`, the response explains the current missing boundary topic instead of silently recording nonsense boundary notes
- keep the opening summary truthful so the untouched intake does not show a stale default `Website / Web App` / `Standard` / `passive-web-nuclei-audit` mission before the operator has actually shaped the run
- keep forward scope transitions calm so a valid `Goal` answer does not immediately surface the untouched empty-state error `Add at least one target in scope.` on the newly active `Scope` question
- keep advanced-scope validation truthful at the same time, so real invalid scope data still remains visible when the wizard returns focus to `Scope`
- prove that each supported assessment type creates a run dossier whose type, profile, lane, and scope still match the wizard handoff after mission creation
- keep narrow/mobile wizard layout truthful so phase-specific workspace rules do not squeeze the intake beside the rail or push the confirmation handoff into an unreadable oversized card
- keep narrow/mobile confirmation geometry truthful after resize/reload so the recent thread, current question, planned-mission summary, and `Create Mission` CTA are measured in their settled final state instead of a transient scroll frame
- prove the coverage in browser automation, not only in static docs

## Validation status

- prepared on 2026-04-17
- automation source of truth:
  - `ui/tests/test_operator_console_e2e.py`
  - `ui/tests/test_product_feature_matrix_e2e.py`
  - `codex/tasks/ui_acceptance_matrix.json`
- manual operator review:
  - supported assessment-type baseline completed on 2026-04-19 through `codex/results/live-host-wizard-operator-review-matrix-20260419.json`
  - periodic calmness/copy review is still recommended after future major wizard changes

## 1. Assessment-Type Checklist

| Assessment Type | Intent Example | Required Prompt Shape | Auth Branch Expected | Confirmation Must Clarify | Browser Status | Manual Review |
| --- | --- | --- | --- | --- | --- | --- |
| Website / Web App | `Our website` | exact targets, safety, boundaries | optional only if later requested | web assessment, target URL, chosen profile/lane | covered | covered |
| Domain / Domains | `Our external domain` | exact targets, safety, boundaries | no by default | domain assessment, domain scope, external-surface lane | covered | covered |
| External IP / WAN | `Our internet-facing IP range` | exact IPs/CIDRs, safety, boundaries | no by default | WAN assessment, exact public IP/CIDR scope, passive network lane | covered | covered |
| Internal Range / LAN | `My LAN network` | exact CIDR/hosts, safety, boundaries | optional, must allow unauthenticated flow | internal discovery-first mission and approved internal scope handling | covered | covered |
| API | `Our API` | API/application targets, auth, safety, boundaries | yes for token/account-aware flows | API scope, access strategy, adaptive/profile lane if selected | covered | covered |
| SSL/TLS Only | `TLS posture for our public site` | TLS scope targets, safety, boundaries | no by default | TLS-only intent, passive lane, no active exploitation wording | covered | covered |
| Authenticated App | `Our customer portal` | exact targets, auth, safety, boundaries | yes | authenticated review, protected access context, chosen lane | covered | covered |
| Mixed Assessment | `Our mixed web and API estate` | exact targets, auth, safety, boundaries | yes | mixed scope, adaptive/customer-specific posture, pack-aware lane | covered | covered |

## 2. Profile and Lane Checklist

| Profile | Expected Lane / Behavior | Current Status |
| --- | --- | --- |
| Light | low-impact passive baseline | covered |
| Standard | balanced baseline lane | covered |
| Deep | broader guarded/active validation lane | covered |
| Deep override while a prior question is active | if an advanced profile/safety change makes access the next required topic, the conversational question must realign immediately instead of leaving the stale prior prompt visible | covered |
| Invalid advanced scope while later topics are answered | if advanced scope input is invalid, the wizard must fall back to `Scope`, keep `Create Mission` hidden, and show the blocking validation message instead of surfacing a fake confirmation state | covered |
| Internal Validation -> non-LAN scope normalization | incompatible internal-validation intent on web/API scope must normalize to a compatible deep-assessment plan, and revising a valid LAN internal-validation mission onto web scope must land on the same normalized `Deep` / `active-web-safe` route as the direct conversational path | covered |
| Authenticated Review -> internal discovery-first staging | credentialed internal-range authenticated-review missions must keep the access context but stage the first run as `Standard` / `passive-network-discovery`, and revising a credentialed authenticated web mission onto LAN scope must land on that same discovery-first internal plan | covered |
| Authenticated Review -> external WAN discovery-first staging | explicit WAN IP/CIDR missions with protected access must keep that access context but stage the first run as `External Surface Only` / `passive-network-discovery` instead of claiming an `Authenticated Only` first run | covered |
| Deep / Adaptive -> external WAN discovery-first staging | explicit WAN IP/CIDR missions that ask for deep or adaptive coverage must stage the first run as `External Surface Only` / `passive-network-discovery`, move straight to `Safety`, and keep `active_checks = passive-only` in the created run dossier | covered |
| External Surface Only | perimeter-first passive lane | covered |
| Authenticated Only | authenticated guarded lane | covered |
| SSL/TLS Only | transport-only passive lane | covered |
| Internal Validation | staged discovery-first internal path | covered |
| Adaptive Customer-Specific Mode | adaptive / pack-aware lane | covered |

## 3. Access and Authentication Checklist

| Scenario | Expected Behavior | Current Status |
| --- | --- | --- |
| Unauthenticated | must not force credential details later | covered |
| Literal `Keep it unauthenticated` phrasing | must advance cleanly to the next required safety question on internal-validation flows | covered |
| Repeating `Unauthenticated` at `Safety` | must keep the wizard on `Safety` and explain that access is already resolved instead of returning a loop-like generic error | covered |
| Repeating `Balanced` at `Boundaries` | must keep the wizard on `Boundaries` and explain that safety is already resolved instead of silently storing `Balanced` as a boundary note | covered |
| Repeating `Unauthenticated` at `Boundaries` | must keep the wizard on `Boundaries` and explain that access is already resolved instead of silently storing `Unauthenticated` as a boundary note | covered |
| Initial summary honesty before intake context exists | `Current Essentials`, `Coverage & Safety`, and `Execution Lane & ETA` must not show a stale default mission before enough conversational context exists, but explicit advanced planning choices must still appear immediately | covered |
| Goal -> Scope transition error hygiene | after a valid `Goal` answer advances to `Scope`, the wizard must not show `Add at least one target in scope.` before the operator has interacted with that new question, while real invalid advanced-scope data must still surface as blocking feedback | covered |
| Suggested-answer chips | representative web, LAN, and API chip-driven routes must complete through real mission creation and land in the same deterministic run dossier as typed intake | covered |
| Still-needed summary actions | current-question topics and linked same-question topics must not be repeated as redundant jump actions or leftover badges | covered |
| Initial intent still-needed horizon | before the operator answers the opening intent question, the wizard must not prematurely claim `Access` or `Output` as blocking topics unless the mission state already makes them relevant | covered |
| Customer-portal authenticated classification | plain-language intent such as `Our customer portal` must enter the `Authenticated App` path, surface auth-aware goal options, and persist the authenticated profile/lane in the created run dossier | covered |
| TLS-only goal guardrails | `SSL/TLS Only` missions must limit quick replies to TLS-safe goals and normalize unsupported typed goals such as `Deep assessment` into a truthful standard TLS-only dossier | covered |
| TLS-only explicit guardrails after scope | `SSL/TLS Only` missions must still ask `Safety` and `Boundaries` after scope instead of skipping straight to confirmation with silent defaults | covered |
| Current-question progress note | the inline `Mission Progress` note must suppress the currently active topic family, including `Goal` / `Output` and `Access` / `Access Detail` | covered |
| Advanced-settings access handoff | `I will add access in advanced settings` must keep `Access` visibly pending, open the drawer on the access step, and realign to `Safety` once access detail is added | covered |
| Credentialed portal/app access | requires access-context follow-up before confirmation | covered |
| Deep domain route auth default | `Domain / Domains` + `Deep assessment` must move from `Scope` to `Safety` instead of prompting `Access` by default, and the stored run must stay `unauthenticated` with `auth_flows = false` | covered |
| Rich generic web route auth default | `Website / Web App` + `Deep assessment` or `Adaptive customer-specific testing` must move from `Scope` to `Safety` instead of prompting `Access` by default, and the stored run must stay `unauthenticated` with `auth_flows = false` | covered |
| API token / key access | requires token-aware access-context capture | covered |
| Session / cookie access | supported through the existing access model and advanced drawer, then preserved into the created run dossier as protected access metadata | covered |
| Auth revision back to unauthenticated | revising an authenticated mission to `Keep it unauthenticated` must clear stale account/session state and downgrade the handoff away from `Authenticated Review` / `Authenticated Only` | covered |
| Authenticated-app unauthenticated route | an `Authenticated App` mission that explicitly stays unauthenticated must move on to the next real topic and persist `auth_strategy = unauthenticated` without forcing access-detail capture | covered |
| Advanced drawer access handoff | summary must reflect that access will be finalized in Advanced Configuration | covered |
| Confirmation-summary handoff | the natural-language planned mission must survive run creation and remain visible in Explorer as part of the run dossier | covered |
| Existing engagement reuse | reusing the selected engagement must not create a duplicate dossier and the Explorer handoff must keep that route visible after mission creation | covered |
| New engagement creation | creating a fresh dossier must create exactly one engagement, keep the chosen dossier name intact, and keep that route visible after mission creation | covered |
| Hand-entered dossier name preservation | once the operator types their own dossier name, later advanced scope and profile overrides must not replace it with a refreshed suggestion | covered |
| Auto-generated dossier name sync | when the operator has not typed their own dossier name, advanced scope and profile overrides must keep the generated name aligned with the effective target and goal instead of freezing on an earlier default | covered |
| Authorization context persistence | reused and newly created dossier routes must keep `Customer` and `ROE Reference` aligned in confirmation, Explorer, and the stored `configuration_json.intake.engagement_context` | covered |
| Scope-guardrail persistence | advanced scope exclusions and boundary notes must stay aligned in confirmation, Explorer, and stored `configuration_json.intake.preferences.boundary_handling` | covered |
| Rich-route boundary confirmation | mixed/adaptive and credentialed/API access routes must ask `Boundaries` before confirmation instead of silently inheriting `Standard Scope Only` | covered |
| Supported standard/deep routes require explicit boundaries | standard website/domain/WAN routes plus unauthenticated deep website/domain routes must stop on `Boundaries` after `Safety` before confirmation instead of silently inheriting `Standard Scope Only` | covered |
| Scope revision re-prompts required boundaries | revising from a simpler web/auth route onto a boundary-sensitive route such as an internal CIDR must clear any earlier generic `No extra exclusions` answer and re-ask `Boundaries` | covered |
| Scope revision clears stale internal lateral guardrails | revising a LAN mission that was using `Report Adjacent Ranges Only` onto a non-internal web scope must drop the old internal lateral-discovery copy instead of carrying it into the revised web confirmation and stored run dossier | covered |
| API scope revision reclassifies plain web URLs truthfully | revising an API mission onto a plain website URL must reclassify the mission to `Website / Web App`, move the target into `urls`, and re-ask `Boundaries` when preserved token access keeps the route access-aware | covered |
| Empty auth detail for authenticated run | must block with explicit feedback | covered |
| Revision of an earlier topic | must show that the flow is revisiting an earlier answer and then return to the recalculated main path | covered |

## 4. Safety and Boundary Checklist

Additional covered wording-truth checks:

- public-edge `External IP / WAN` phrasing now keeps external IP/CIDR wording at the scope step instead of briefly asking for `internal hosts`
- passive execution lanes such as `passive-web-nuclei-audit` no longer claim that guarded active validation is enabled in the same confirmation handoff
- mixed-surface confirmation copy now uses a single `mixed assessment` phrase instead of `mixed assessment assessment`
- WAN perimeter deep/adaptive routes now rename the rich-goal quick replies to staged follow-up wording, skip the premature access question after scope, and keep the created run in passive-only discovery mode
- WAN perimeter authenticated-review routes now keep the protected access context attached but no longer pair `Authenticated Only` wording with a passive discovery first run

| Scenario | Expected Behavior | Current Status |
| --- | --- | --- |
| Passive only | active checks disabled and summary reflects it | covered |
| Conservative | light guarded posture with lower pace | covered |
| Internal LAN inventory via chip-driven intake | `Visibility with clear per-item detail` must still ask the operator for safety before boundaries and confirmation | covered |
| Balanced | standard guarded posture | covered |
| Thorough | deeper guarded posture | covered |
| Aggressive with approval | explicit approval-aware wording | covered |
| No extra exclusions | standard scope-only confirmation | covered |
| Adjacent internal ranges reported only | report-only lateral wording | covered |
| Scope revision clears report-only lateral wording on web scope | revising a LAN report-only mission onto website scope must remove the stale adjacent-range copy and fall back to the compatible web boundary default | covered |
| API-to-web scope revision re-prompts boundary confirmation | revising an access-aware API mission onto a plain website URL must hide confirmation until `Boundaries` is re-confirmed for the revised route | covered |
| Non-internal boundary copy stays generic after scope revision | once a revised route is no longer internal, the conversational `Boundaries` card and advanced boundary-notes placeholder must drop internal-range wording and hide the `Report adjacent internal ranges only` quick reply | covered |
| Boundary revision clears prior exclusions | revising `Boundaries` to `No extra exclusions` must remove older denylist entries and boundary notes from confirmation and Explorer | covered |
| Boundary revision replaces explicit denylist with notes-only guidance | revising `Boundaries` to a notes-only answer must replace the older explicit-exclusion payload instead of showing both at once | covered |
| Unauthorized public expansion request | blocked clearly and safely | covered |

## 5. Commands Used For Phase 1 Validation

```bash
./.venv/bin/pytest -q -s api/tests/test_runs.py -k 'engagement_route_metadata or new_engagement_route_metadata or confirmation_summary'
./.venv/bin/pytest -q -s ui/tests/test_operator_console_e2e.py
./.venv/bin/pytest -q -s ui/tests/test_product_feature_matrix_e2e.py
./.venv/bin/python scripts/run_product_e2e_matrix.py --lane ui
```

Independent live-host proof for the current authorization-context slice:

- `codex/results/live-host-wizard-authorization-context-20260418-225146.json`
- `codex/results/live-host-wizard-scope-guardrails-20260418-230804.json`
- `codex/results/live-host-wizard-scope-guardrail-copy-20260418-232414.json`
- `codex/results/live-host-wizard-notes-only-guardrails-20260418-233446.json`
- `codex/results/live-host-boundary-revision-clear-20260418.json`
- `codex/results/live-host-auth-revision-unauthenticated-downgrade-20260418.json`
- `codex/results/live-host-wizard-goal-compatibility-20260419.json`
- `codex/results/live-host-wizard-internal-auth-discovery-20260419.json`
- `codex/results/live-host-wizard-internal-rich-goal-discovery-20260419.json`
- `codex/results/live-host-wizard-assessment-type-parity-20260419.json`
- `codex/results/live-host-wizard-validation-aware-profile-parity-20260419.json`
- `codex/results/live-host-wizard-mobile-confirmation-layout-20260419.json`
- `codex/results/live-host-wizard-mobile-confirmation-post-settle-20260419.json`
- `codex/results/live-host-wizard-quick-reply-matrix-20260419.json`
- `codex/results/live-host-wizard-needed-summary-dedup-20260419.json`
- `codex/results/live-host-wizard-linked-badge-dedup-20260419.json`
- `codex/results/live-host-wizard-path-note-dedup-20260419.json`
- `codex/results/live-host-wizard-advanced-access-bridge-20260419.json`
- `codex/results/live-host-wizard-initial-topic-visibility-20260419.json`
- `codex/results/live-host-wizard-customer-portal-authenticated-app-20260419.json`
- `codex/results/live-host-wizard-external-wan-discovery-first-20260419.json`
- `codex/results/live-host-wizard-external-wan-authenticated-review-20260419.json`
- `codex/results/live-host-wizard-assessment-wording-truth-20260419.json`
- `codex/results/live-host-wizard-tls-goal-guardrails-20260419.json`
- `codex/results/live-host-wizard-tls-safety-boundaries-20260419.json`
- `codex/results/live-host-wizard-revision-calmness-20260419.json`
- `codex/results/live-host-wizard-rich-boundary-confirmation-20260419.json`
- `codex/results/live-host-wizard-internal-lateral-scope-revision-20260419.json`
- `codex/results/live-host-wizard-api-scope-revision-20260419.json`
- `codex/results/live-host-wizard-non-internal-boundary-copy-20260419.json`
- `codex/results/live-host-wizard-domain-deep-no-auth-default-20260419.json`
- `codex/results/live-host-wizard-web-rich-profile-no-auth-default-20260419.json`
- `codex/results/live-host-wizard-supported-boundaries-20260419.json`
- `codex/results/live-host-wizard-advanced-realignment-20260419.json`
- `codex/results/live-host-wizard-safety-auth-repeat-guidance-20260419.json`
- `codex/results/live-host-wizard-safety-auth-repeat-guidance-20260419.png`
- `codex/results/live-host-wizard-boundaries-safety-repeat-guidance-20260419.json`
- `codex/results/live-host-wizard-boundaries-safety-repeat-guidance-20260419.png`
- `codex/results/live-host-wizard-boundaries-access-repeat-guidance-20260419.json`
- `codex/results/live-host-wizard-boundaries-access-repeat-guidance-20260419.png`
- `codex/results/live-host-wizard-current-essentials-truth-20260419.json`
- `codex/results/live-host-wizard-current-essentials-truth-20260419.png`
- `codex/results/live-host-wizard-composite-revalidation-20260419.json`
- `codex/results/live-host-wizard-composite-revalidation-20260419.png`
- `codex/results/live-host-wizard-operator-review-matrix-20260419.json`
- `codex/results/live-host-wizard-operator-review-matrix-20260419/`

## 6. Exit Criteria For This Phase

Phase 1 can only be considered complete when:

1. every assessment type is completable through the conversational path
2. no required question path dead-ends
3. the confirmation summary stays aligned with the created run
4. advanced overrides remain synchronized
5. browser validation proves the above and the repo truth files are updated

## 7. Remaining caution even after browser coverage

Even with the expanded browser matrix and the completed supported assessment-type manual review baseline, Phase 1 still benefits from periodic human review for:

- copy calmness
- answer clarity
- operator confidence on when a run is truly ready
- broader day-to-day narrow-screen comfort beyond the currently repaired supported-path confirmation layout
