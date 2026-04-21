# UI Assessment Wizard

## Purpose

The wizard is now a conversational mission intake. It still remains the mandatory start of the product flow, but it no longer asks the operator to march through a rigid visible seven-step form before anything makes sense.

## Final intake model

The operator experiences:

1. a single active AI-guided question
2. a live mission summary that separates confirmed, inferred, and still-needed items
3. an advanced configuration drawer for full deterministic control
4. a natural-language confirmation summary before run creation

The underlying run model still stores the same core configuration:

- assessment type
- targets
- exclusions / boundary notes
- access context
- test profile
- enabled modules
- safety limits
- execution lane
- ETA estimate

## Final UX behavior

- the first screen asks what the operator wants to test in plain language
- the intake asks one focused question at a time
- the intake can safely infer defaults, but does not hide those inferences
- common portal phrasing now maps to the right authenticated lane:
  - plain-language intent such as `our customer portal` now resolves to `Authenticated App` instead of quietly falling back to a generic web-app mission
  - the very next goal step now offers auth-aware quick replies such as `Authenticated review`
  - the live still-needed horizon also reflects that access is now a real upcoming topic for that mission type
- public-edge wording now stays in the public-edge route:
  - plain-language intent such as `our internet-facing IP range` now stays in the `External IP / WAN` path through the scope step instead of briefly switching to internal-host language
  - the scope question therefore keeps exact public IP/CIDR wording instead of asking for `internal hosts`
- TLS-only missions now keep the goal step truthful and bounded:
  - once intent resolves to `SSL/TLS Only`, the goal step now offers only TLS-safe choices such as `Quick overview` and `Standard assessment`
  - unsupported typed goals such as `Deep assessment` are normalized immediately into a standard TLS-only mission with an explicit explanation instead of leaving the wizard in a half-open contradictory state
  - the created run dossier now persists that normalized TLS-only goal/profile/lane combination instead of carrying an impossible deep or adaptive TLS promise
  - after TLS scope is recorded, the wizard no longer jumps straight to confirmation with silent defaults; it now stops for explicit `Safety` and `Boundaries` answers before mission creation so the passive transport-only lane still has visible guardrails
- the opening intake state now defers downstream `Access` and `Output` obligations until they are actually relevant:
  - before the operator has even answered the first intent question, the still-needed card and inline mission-progress note no longer claim that auth/access or reporting-output choices are already blocking topics
  - the first-screen horizon now stays on the real near-term flow: `Target Type`, `Goal`, `Scope`, and `Safety`
  - once access or output becomes relevant through mission type, goal, or operator input, those topics appear again in the still-needed model instead of being removed from the product
- the opening intake summary now stays equally honest about deterministic defaults:
  - before the operator has answered the first intent question, `Current Essentials` no longer shows a stale default mission such as `Website / Web App`, `Standard profile`, or `passive-web-nuclei-audit`
  - the collapsed `Coverage & Safety` and `Execution Lane & ETA` sections now stay on `Waiting for mission shape` until the intake has enough confirmed or safely inferred mission context
  - once the operator deliberately shapes the mission through conversation or advanced planning overrides, those summaries surface the real deterministic profile/lane details again instead of staying blank
- the scope transition now stays calm without hiding real blocking data:
  - after a valid conversational `Goal` answer advances the intake to `Scope`, the wizard no longer surfaces the empty-state error `Add at least one target in scope.` before the operator has touched the scope question
  - if Advanced Configuration already contains genuinely invalid scope data, the wizard still returns focus to `Scope` and keeps the exact blocking validation visible instead of masking that defect
- suggested-answer chips are now an explicitly supported intake path instead of a cosmetic shortcut:
  - the current question now tells the operator they can click a suggested reply or type their own wording
  - representative chip-driven web, LAN, and API flows are now browser- and live-host-validated through real mission creation
- the current question card now makes progress explicit:
  - on the main path it shows which mission topics still need confirmation
  - it no longer repeats the topic family the operator is already answering, so `Goal` / `Output` and `Access` / `Access Detail` do not compete with the active question
  - in revision mode it explains that AegisPT will recalculate the next required topic after the edited answer is applied
- the visible thread stays concise:
  - the newest turns remain visible inline
  - older context moves into `Earlier Intake Context`
  - revision controls move into `Revise Captured Topic`
  - those revision controls now stay hidden until the operator has actually locked a topic into the deterministic run dossier
  - unanswered later topics no longer appear there as premature `Change ...` actions, which keeps the opening wizard calmer and more truthful
- inferred items stay visible in the summary until the operator confirms or overrides them
- authenticated, API, and mixed flows ask for access context when that materially changes the run
- external domain/perimeter routes no longer become credential-aware by accident:
  - `Domain / Domains` missions that use a richer profile such as `Deep` no longer ask `Should this stay unauthenticated...` just because that profile would normally enable `auth_flows` for auth-capable app routes
  - those domain missions now stay unauthenticated by default unless the operator explicitly chooses an auth-driven route instead of inheriting an access branch from a generic profile preset
- richer generic web routes now keep that same auth-default truth:
  - `Website / Web App` missions using richer goals such as `Deep assessment` or `Adaptive customer-specific testing` now move from `Scope` to `Safety`, not `Access`, unless the operator explicitly chooses an auth-aware route
  - the created run dossier for those generic web paths now persists `auth_strategy = unauthenticated` with `auth_flows = false` instead of silently inheriting web-auth coverage from a richer profile preset
- supported web-facing routes now also keep boundary confirmation explicit after `Safety` instead of silently inferring `Standard Scope Only`:
  - `Website / Web App`, `Domain / Domains`, and `External IP / WAN` standard routes now stop on `Boundaries` before confirmation
  - unauthenticated `API` standard routes and unauthenticated `Authenticated App` standard routes now do the same instead of jumping straight from `Safety` to confirmation
  - the richer unauthenticated `Deep assessment` defaults for generic web and domain routes now also stop on `Boundaries` after `Safety`, so those routes no longer skip the final guardrail confirmation just because they correctly stayed off the auth branch
- richer mixed/auth/adaptive routes now also keep boundary confirmation explicit:
  - `Mixed Assessment` no longer jumps from `Safety` straight to `Confirmation Ready` with an implied `Standard Scope Only` guardrail
  - credentialed portal/app routes, API token/key routes, and adaptive mixed/API routes now surface the boundary question before confirmation so the operator explicitly confirms exclusions or scope-only handling
  - if the operator revises scope from a simpler web/auth route into a boundary-sensitive route such as an internal CIDR, the old generic `No extra exclusions` answer is no longer silently reused; the wizard re-asks `Boundaries` when the new scope requires it
  - if the operator revises a LAN route that was carrying `Report Adjacent Ranges Only` over to a non-internal scope such as a website, the old internal lateral-discovery copy is cleared instead of following the revised web mission into confirmation
  - if the operator revises an API mission onto a plain website URL while reviewing `Scope`, the wizard no longer stores that target as an `api base url`; it reclassifies the mission to `Website / Web App`, asks `Boundaries` again because the token-bearing route is still access-aware, and persists the revised web scope truthfully
  - when the revised route is no longer internal, the `Boundaries` question and the Advanced Configuration boundary-notes placeholder now switch to generic scope wording instead of still talking about `adjacent internal ranges`
  - the internal-only quick reply `Report adjacent internal ranges only` is now offered only on true `Internal Range / LAN` routes instead of appearing on revised web/app/API missions
- if the operator explicitly chooses to finalize access later in Advanced Configuration:
  - the wizard now keeps `Access` visibly pending instead of implying that only later topics remain
  - the `Access` action in the still-needed summary now opens Advanced Configuration directly on the access step
  - the auth-details quick reply for advanced settings now opens that same drawer instead of silently looping on the same question
  - once the operator adds the required account, token, or session reference in the drawer, the conversation realigns to the next topic such as `Safety`
- internal LAN missions now keep the conversation moving even when the operator explicitly chooses an unauthenticated path
- the literal phrase `Keep it unauthenticated` is now browser-covered on the internal-validation path so a common human answer still advances visibly to the safety question
- if the operator then accidentally repeats `Unauthenticated` while the current question is already `Safety`, the wizard now answers contextually instead of feeling stuck:
  - it says access is already set to unauthenticated
  - it tells the operator that the next needed answer is a safety choice such as `Conservative`, `Balanced`, `Thorough`, `Passive only`, or `Aggressive with approval`
- if the operator then reaches `Boundaries` and accidentally repeats the previous safety answer such as `Balanced`, the wizard now keeps `Boundaries` active instead of silently storing that as a boundary note:
  - it says safety is already set
  - it tells the operator that the next needed answer is boundary guidance such as `No extra exclusions`, `Report adjacent internal ranges only`, or custom exclusions / boundary notes
- if the operator reaches `Boundaries` and accidentally repeats the previous access answer such as `Unauthenticated`, the wizard now also keeps `Boundaries` active instead of silently storing that as a boundary note:
  - it says access is already set
  - it tells the operator that the next needed answer is boundary guidance such as `No extra exclusions`, `Report adjacent internal ranges only`, or custom exclusions / boundary notes
- revising an authenticated flow back to `Keep it unauthenticated` now clears stale account/session details and downgrades the mission handoff from `Authenticated Review` / `Authenticated Only` to a compatible unauthenticated plan instead of leaving contradictory copy behind
- that same authenticated-app route can now remain honestly unauthenticated without dropping back into an access-detail dead end:
  - after `Keep it unauthenticated`, the wizard now moves on to the next real topic such as `Safety`
  - the created run dossier persists `auth_strategy = unauthenticated`, no access accounts, and the compatible `Standard` / `active-web-safe` plan
- `Internal Validation` remains reserved for approved LAN/CIDR missions:
  - if the operator asks for internal validation on a website or API mission, the handoff is normalized to a compatible `Deep Assessment` plan instead of pretending a non-LAN mission is still an internal-validation run
  - if the operator starts on a valid LAN internal-validation route and later revises the scope to a website, the wizard now realigns the profile, lane, and suggested dossier name to the same deep web plan as the direct route
- credentialed internal-range missions now stay discovery-first instead of pretending the first run is already an authenticated app/API lane:
  - if the operator asks for `Authenticated Review` against a LAN/CIDR target and supplies credentials or planned protected access, the mission keeps that operator intent but stages the first run as `Standard` + `passive-network-discovery`
  - the confirmation handoff now explains that AegisPT will keep the access context attached and surface credential-aware follow-up options after reachable services are confirmed
  - if a credentialed web authenticated-review mission is later revised onto LAN scope, the wizard now realigns to that same discovery-first internal plan instead of leaving `Authenticated Only` next to a passive network-discovery lane
- rich-goal internal-range missions now stay discovery-first too:
  - if the operator asks for `Deep Assessment` against a LAN/CIDR target, the mission keeps that goal but stages the first run as `Standard` + `passive-network-discovery`
  - if the operator asks for `Adaptive Customer-Specific Testing` against a LAN/CIDR target, the mission likewise keeps the adaptive intent but stages the first run as `Standard` + `passive-network-discovery`
  - the confirmation handoff now explains that deeper or adaptive follow-up coverage happens after reachable hosts and services are confirmed instead of falsely implying that the first passive discovery run is already the deep/adaptive lane
  - if an adaptive web mission is later revised onto LAN scope, the wizard now realigns to that same discovery-first internal plan instead of leaving `Adaptive Customer-Specific Mode` beside a passive network-discovery lane
- rich-goal WAN perimeter missions now stay discovery-first too:
  - `External IP / WAN` goal quick replies now use staged wording such as `Deep follow-up after discovery` and `Adaptive follow-up after discovery` instead of implying that the first perimeter run is already deep/adaptive
  - if the operator still types `Deep Assessment` or `Adaptive Customer-Specific Testing` for an explicit WAN IP/CIDR mission, the mission keeps that operator goal but stages the first run as `External Surface Only` + `passive-network-discovery`
  - if the operator asks for `Authenticated Review` on an explicit WAN IP/CIDR mission and supplies protected access, the mission now keeps that access context attached but still stages the first run as `External Surface Only` + `passive-network-discovery`
  - after explicit WAN scope is recorded on those staged routes, the conversation now moves straight to `Safety` instead of asking for premature access context
  - the confirmation handoff now explains that passive perimeter discovery happens first and that deeper, adaptive, or access-aware follow-up only appears once reachable hosts and services are confirmed
- internal LAN missions always surface safety and boundary/lateral-intent questions before confirmation so the operator can explicitly shape how cautious or exploratory the run should be
  - this now also holds on the chip-driven `Visibility with clear per-item detail` route, which no longer skips directly from CIDR scope to boundaries with an implied safety posture
  - the same explicit-boundary model now also applies to richer mixed/auth/adaptive routes where a silent default would hide an important guardrail choice
- explicit specialist mission types such as `SSL/TLS Only` and `Authenticated App` are preserved through scope entry instead of being silently downgraded to a generic domain or web assessment
- advanced controls remain available at any point through the drawer
- advanced changes immediately synchronize back into the conversational summary
- advanced changes now also realign the live conversation when they change the next required topic:
  - if an advanced profile or safety override resolves the currently visible question
  - or changes which topic must be asked next
  - the conversational intake moves to that next required topic instead of leaving a stale pre-override question on screen
- advanced scope validation now uses that same truth model:
  - if the advanced drawer contains invalid scope data, the wizard no longer surfaces a fake `Confirmation Ready` state
  - instead it returns the operator to the scope topic, keeps `Create Mission` hidden, and shows the exact blocking validation message
  - this is now explicitly covered for the `SSL/TLS Only` path where a hostname entered into the IP-only field must not create a half-confirm dead end
- editing only engagement metadata in Advanced Configuration no longer skips the opening intent question:
  - dossier name, customer, and ROE edits stay as mission-context changes
  - they do not falsely mark the mission intent as answered
- when the operator chooses `Use the selected engagement dossier` in Advanced Configuration:
  - the mission brief now makes that reuse route explicit instead of leaving it implicit
  - the confirmation summary says the run will be attached to the existing engagement dossier
  - the confirmation card now also shows the reused dossier's `Customer` and `ROE Reference`
  - Explorer preserves that engagement-route handoff after mission creation so reuse versus new-dossier creation remains auditable
- when the operator keeps the default new-dossier route:
  - the confirmation summary now explicitly says a new engagement dossier will be created before the run begins
  - the confirmation card keeps the chosen `Customer` and `ROE Reference` visible before launch
  - the created run dossier keeps that route visible in Explorer after creation
  - a hand-entered dossier name is no longer overwritten later by conversational intent, goal, or scope answers
  - that same hand-entered dossier name now stays locked even if the operator changes advanced scope and advanced profile afterward
  - if the operator keeps the suggested dossier name, advanced scope and profile overrides now keep that auto-generated name aligned with the effective target and mission goal instead of freezing on an earlier default
  - the run-create API now normalizes `intake.engagement_context` against the actual engagement at creation time, so direct API calls and the browser wizard persist the same authorization context
- exclusions and boundary notes are available in advanced scope controls and remain visible in summary/report context
- the right-side summary now leads with:
  - `Current Essentials`
  - `What Still Needs Confirmation`
  - `Mission Brief`
  and keeps the heavier target/access, coverage, and ETA detail collapsed until needed
- the `What Still Needs Confirmation` card is now actionable:
  - missing topics render as direct jump controls
  - operators can jump ahead to a later missing topic without losing the main intake path
  - when they do, the wizard now says `Reviewing Another Topic` instead of incorrectly implying that only an earlier answer is being revised
  - the card no longer repeats the topic the wizard is already asking about as another quick action
  - linked topics that resolve through the same question, such as `Goal` and `Output`, no longer render as duplicate quick actions while that question is already active
  - linked same-question topics also no longer linger as leftover badges after those quick actions are suppressed
  - remaining quick actions are now the only repeated affordance; duplicate badges for the same remaining items are suppressed
- the intake shell itself is now calmer during the Intake phase:
  - only the essential mission-context badges stay expanded above the wizard
  - secondary run, lane, module, ETA, and AI-planning detail moves behind `More Mission Context`
  - the top phase strip compresses non-active phases so the wizard is not competing with large cross-phase summaries
  - the mission-progress note inside the current question uses a lighter inline note instead of another heavy card
  - on narrow/mobile viewports the intake workspace now collapses into one readable column, keeps the left rail below the wizard, and preserves a visible confirmation CTA instead of shrinking the wizard beside persistent rail chrome
- the confirmation card explains:
  - what will be tested
  - what profile and execution lane will be used
  - whether active checks are enabled
  - what the ETA looks like
  - which explicit exclusions and boundary notes are recorded
  - which output style and boundary-handling posture will be carried into the run dossier
  - scope-guardrail wording now stays human-readable for both one exclusion and multiple exclusions instead of leaking awkward singular/plural copy into the operator handoff
  - passive execution lanes such as `passive-web-nuclei-audit` now say explicitly that active exploitation-style checks are not enabled in that run instead of contradicting the passive lane with guarded-active copy
  - mixed-surface handoff copy now uses a single `mixed assessment` phrase instead of the duplicated `mixed assessment assessment` wording
  - on narrow/mobile viewports the confirmation summary now stays capped and scrollable inside the question card so the operator can still read the handoff and use `Create Mission` without hunting through an oversized card
- advanced scope overrides now keep structured exclusions truthful in the deterministic run model:
  - if an operator adds denylist targets or boundary notes in Advanced Configuration
  - notes-only boundary guidance now stays distinct from true structured exclusions
  - the stored `boundary_handling` is updated in place instead of silently remaining on a stale default such as `Standard Scope Only`
  - notes-only guardrails no longer collapse into `Custom Exclusions Recorded` in the confirmation handoff or Explorer dossier
  - revising `Boundaries` back to `No extra exclusions` now clears the prior denylist and boundary-note payload instead of leaving contradictory stale exclusions behind
  - revising `Boundaries` from explicit exclusions to notes-only guidance now replaces the old denylist instead of stacking both meanings at once
- that same natural-language confirmation summary is now carried into the created run dossier as a stored mission handoff:
  - operators can reopen it later in Explorer
  - this makes the intake promise auditable against the real run configuration instead of leaving it as a transient pre-launch card only
- when the operator chooses deep internal validation against a LAN/CIDR target, the confirmation card now explains that the mission starts with live discovery first and only then exposes deeper follow-up validation paths
- after confirmation, the operator lands in Mission Control with the run already created and queued
- conversational completion is now browser-regression-tested across every supported assessment type:
  - Website / Web App
  - Domain / Domains
  - External IP / WAN
  - Internal Range / LAN
  - API
  - SSL/TLS Only
  - Authenticated App
  - Mixed Assessment
- representative advanced profile routes are now also validated through real run creation, not only summary text:
  - each supported profile matrix path is checked for persisted assessment type
  - persisted profile
  - persisted execution lane
  - and persisted approved scope

## Advanced drawer rules

- hidden by default
- always available during intake
- uses the existing deterministic controls instead of a second config model
- supports:
  - mission / engagement setup
  - scope and exclusions
  - credentials / sessions / token references
  - profile selection
  - module toggles
  - safety limits
- advanced overrides are surfaced back into the summary as explicit overrides
- mission-mode changes in the advanced drawer can reuse the currently selected engagement without creating a duplicate dossier

## Source of truth

The conversational intake does not create a parallel backend model.

On confirmation, it still:

- creates or reuses the engagement
- records allowlist and denylist scope through the existing scope endpoint
- seeds inventory from reviewed wizard input
- creates the run through the existing run model with `configuration_json`
- opens Mission Control where the operator can explicitly start validation

## Phase 1 stabilization note

The intake remains part of the operator-console stabilization side project.

The current Phase 1 control documents are:

- `docs/operator_console_phase1_checklist.md`
- `docs/operator_console_phase6_checklist.md`
- `docs/ui_browser_validation.md`
- `docs/product_test_matrix.md`

## Security note

Conversation history is used for UX, but run creation persists structured configuration, not a raw secret-heavy transcript. Access values still flow through the existing protected-secret baseline where applicable.
