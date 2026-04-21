# UI Browser Validation

## Purpose

The operator console now has browser-level validation through Playwright so the conversational mission intake, Mission Control flow, drilldowns, and report workflows are checked in a real Chromium session instead of only through static/API tests.

## Scope

The current browser suite covers:

- app load at `/app/`
- conversational intake rendering
- suggested-answer helper copy and chip-driven intake paths
- opening-intake horizon truth:
  - before the operator answers the first intent question, the wizard no longer claims that `Access` or `Output` are already missing mission topics
  - the initial still-needed horizon now stays on `Goal`, `Scope`, and `Safety` while `Target Type` remains implicit in the active intent step
- opening-summary truth:
  - before the operator answers the first intent question, `Current Essentials` no longer shows a stale default assessment type, profile, execution lane, or ETA
  - the collapsed `Coverage & Safety` and `Execution Lane & ETA` disclosures now stay on `Waiting for mission shape` until the intake has enough confirmed or safely inferred mission context
  - deliberate advanced planning overrides still surface the deterministic lane/profile summary immediately instead of hiding explicit operator choices
- advanced-confirmation realignment truth:
  - if Advanced Configuration clears the already-confirmed scope, the wizard now exits the confirmation card, returns focus to `Scope`, and shows the blocking `Add at least one target in scope.` validation instead of leaving a silent fake-ready state
  - if Advanced Configuration switches a previously ready mission onto `Authenticated Only`, the wizard now exits the confirmation card and returns focus to `Access` so the missing auth context is resolved before mission creation
- goal-to-scope transition truth:
  - after a valid conversational `Goal` answer advances the wizard to `Scope`, the wizard no longer shows the untouched empty-state error `Add at least one target in scope.` before the operator has interacted with the scope question
  - real advanced-scope validation defects still remain visible; only the untouched empty-state prompt is suppressed on that forward transition
- portal-intent classification truth:
  - plain-language intent such as `Our customer portal` now resolves to the `Authenticated App` mission type instead of silently falling back to the generic web-app path
  - the next goal step therefore offers auth-aware quick replies such as `Authenticated review` and surfaces `Access` in the remaining mission horizon
  - creating that mission persists `Authenticated App`, `Authenticated Only`, and `active-web-safe` in the run dossier
- TLS-only goal-guardrail truth:
  - once intent resolves to `SSL/TLS Only`, the goal step now offers only TLS-safe choices instead of generic deep/adaptive quick replies
  - unsupported typed goals such as `Deep assessment` now normalize immediately into a standard TLS-only mission with explicit operator-facing explanation
  - creating that mission persists `SSL/TLS Only`, `SSL/TLS Only`, and `passive-web-baseline` with the normalized `standard-assessment` goal in the run dossier
- assessment-type wording truth:
  - public-edge phrasing such as `Our internet-facing IP range` now stays in the `External IP / WAN` path through the scope step instead of briefly falling back to internal-host copy
  - passive execution lanes such as `passive-web-nuclei-audit` no longer claim that guarded active validation is enabled in the same confirmation handoff
  - `Mixed Assessment` confirmation copy now uses a single `mixed assessment` phrase instead of the duplicated `mixed assessment assessment` wording
- conversational completion across every supported assessment type
- intent -> goal -> scope translation into deterministic run creation
- inline conversational validation feedback
- natural-language revision commands:
  - typed `change that` now reopens the last answered topic instead of leaving the operator on the current question
  - typed `go back`, `undo`, and `previous` now reopen the last answered topic with an editable draft instead of leaving the operator on the current question
  - back-command wrappers such as `please go back?`, `UNDO!`, `please change that?`, and `PREVIOUS!` now have browser proof that they normalize into that same last-answer parser path
  - typed `change goal` now reopens the goal question with the captured goal draft, and typed aliases such as `edit goal`, `revise goal`, `change profile`, `change depth`, `edit profile`, `revise profile`, `edit depth`, and `revise depth` follow that same goal-revision path
  - typed `change scope`, `change target`, `change access`, `change auth`, `change credential`, `change token`, `change session`, `change safety`, and `change boundary` now reopen editable source drafts for those already-captured topics instead of dropping the operator onto a lossy summary
  - polite wrappers such as `please change scope?` and `change target please.` now have browser proof that they normalize into that same topic-jump parser path instead of needing separate canonical command entries
  - case and spacing variants such as `CHANGE   SCOPE!` and `edit   targets` now have browser proof that they normalize into that same topic-jump parser path
  - parser-supported `edit` / `revise` topic jumps are now also explicitly covered for representative routes such as `edit scope`, `edit target`, `edit access`, `edit auth`, `edit credential`, `edit token`, `edit safety`, `edit boundary`, `edit session`, `revise access`, `revise auth`, `revise goal`, `revise profile`, `revise safety`, `revise scope`, `revise target`, `revise token`, `revise credential`, `revise session`, and `revise boundary`
  - once the wizard is already on the confirmation card, disclosure-driven revision actions such as `Change Boundaries` reopen the same editable source draft without reintroducing input clutter into confirmation itself
- access-detail revision truth:
  - the `Access Detail` question can now also accept an access-strategy change such as `Keep it unauthenticated` instead of behaving like a one-way detail-only prompt
  - this keeps `Change Access` usable even after advanced/session routes have already moved the operator into a captured `Access Detail` topic
  - withdrawing access from that point clears stored account/session/manual-auth context and returns the intake to the next deterministic required topic
  - token-bearing secret refs such as `vault://.../updated-token` now stay inside the access-detail parser instead of being misread as a high-level auth-strategy phrase and leaving the intake stuck on `Access Detail`
  - direct session-reference routes now keep `auth_strategy = session-access` after detail capture instead of drifting to `credentialed`, and `change session` / `edit session` / `revise session` reopen a truthful editable draft that preserves the operator-facing session label
  - the visible `Previous Topic` button now also routes through that same truthful access-topic resolver:
    - when Advanced Configuration captured an account-backed access detail, `Previous Topic` reopens the exact stored `Access Detail` draft instead of falling back to the coarser auth-strategy question
    - when Advanced Configuration captured only shared manual-auth guidance or only shared session guidance with no account rows, `Previous Topic` reopens the exact stored note text and returns to `Safety` after the revision is applied
  - once the wizard is already back on the confirmation card, the disclosure/button route now also has explicit proof for shared no-account access contexts: `Change Access` reopens the stored shared manual-auth or shared session note, accepts the revision, and returns directly to confirmation without fabricating an account row or re-asking already-confirmed `Safety` / `Boundaries`
  - the older inline history route now also has explicit proof for those same shared no-account access contexts: when Advanced Configuration captures only a shared manual-auth note or only a shared session note, the intake creates a truthful revisable history turn in `Earlier Intake Context`, and that turn-level `Change` button reopens the exact stored note text instead of dropping back to the high-level auth-strategy question
  - the top progress-stepper `Access` route now also has explicit proof for those same shared no-account access contexts: clicking the `Access` step reopens the exact stored shared manual-auth or shared session note instead of dropping back to the high-level auth-strategy question
- exact common auth phrasing coverage, including `Keep it unauthenticated`
- repeated access-answer guidance:
  - if access is already resolved and the operator types `Unauthenticated` again while the current question is `Safety`, the wizard now keeps focus on `Safety` and explains that access is already set instead of returning a loop-like generic error
- repeated safety-answer guidance at boundaries:
  - if safety is already resolved and the operator types a standalone safety answer such as `Balanced` again while the current question is `Boundaries`, the wizard now keeps focus on `Boundaries` and explains that safety is already set instead of silently storing that text as a boundary note
- repeated access-answer guidance at boundaries:
  - if access is already resolved and the operator types an access answer such as `Unauthenticated` again while the current question is `Boundaries`, the wizard now keeps focus on `Boundaries` and explains that access is already set instead of silently storing that text as a boundary note
- summary behavior for confirmed, inferred, and advanced-override states
- confirmation-summary persistence:
  - the natural-language planned mission text survives run creation
  - Explorer now shows that stored mission handoff inside the run dossier
  - explicit denylist targets, boundary notes, and output-style / boundary-handling context remain visible in both the confirmation card and Explorer dossier after mission creation
- existing-engagement reuse persistence:
  - the advanced mission-mode route can reuse the selected engagement dossier without creating a duplicate engagement
  - the mission handoff and Explorer dossier both keep the reuse-route context visible after mission creation
  - the confirmation card, Explorer dossier, and stored run configuration all keep the selected dossier's `Customer` and `ROE Reference` aligned
- new-engagement creation persistence:
  - a hand-entered dossier name in the advanced mission context survives later conversational answers
  - a hand-entered dossier name also survives later advanced scope and profile overrides instead of being replaced by a refreshed suggestion
  - an auto-generated dossier name now keeps tracking advanced scope and profile overrides until the operator explicitly replaces it
  - creating a new dossier increments engagement count by exactly one
  - the mission handoff and Explorer dossier both keep the create-new route visible after mission creation
  - the created run keeps the chosen `Customer` and `ROE Reference` visible in the confirmation card, Explorer dossier, and stored run configuration
- still-needed summary actions can jump directly to a requested missing topic without losing the main required intake path
- still-needed summary deduplication:
  - the currently active topic is no longer repeated as another jump action in the `What Still Needs Confirmation` card
  - linked topics that resolve through the already-active question, such as `Goal` / `Output`, no longer repeat there as duplicate jump actions
  - linked same-question topics also no longer linger there as leftover badges once those jump actions are suppressed
  - the card now keeps only genuinely remaining quick actions instead of echoing the same items again as both actions and badges
- current-question progress-note deduplication:
  - the inline `Mission Progress` note now suppresses the topic family the operator is already answering instead of repeating `Goal` / `Output` or `Access` while those questions are on screen
  - the auth-details path now reduces cleanly to `Safety` instead of claiming `Access` is still missing while the operator is entering that access context
- advanced-access bridge truth:
  - when the operator says access will be finalized in Advanced Configuration, the still-needed state now keeps `Access` visibly pending instead of pretending only `Safety` remains
  - the `Access` action in the still-needed summary now opens the Advanced Configuration drawer directly on the access step
  - the auth-details quick reply for advanced settings now opens that same drawer instead of silently looping on the same conversational question
  - filling the access detail in the drawer realigns the live question to `Safety`
  - once that advanced access detail exists, later `change access` / `edit access` / `change auth` / `edit auth` / `revise auth` / `change credential` / `edit credential` / `revise credential` / `change token` / `edit token` / `revise token` / `change session` / `edit session` / `revise session` revisions now reopen the exact stored access-detail draft instead of dropping back to the older high-level auth-strategy question
  - shared `Manual Auth` or `Session Notes` without any account row now also count as a real access context, so the wizard, Mission Control, and Explorer no longer falsely claim that access is still missing on those supported no-account routes
  - those same shared no-account routes now also keep revision truth: `change access` reopens shared manual-auth guidance as raw note text, and `change session` reopens shared session guidance as raw note text instead of fabricating an account row
- rich-route boundary-confirmation truth:
  - mixed/adaptive, credentialed app, and API token routes no longer jump from `Safety` straight to `Confirmation Ready` with an implied `Standard Scope Only` guardrail
  - revising from a simpler authenticated web route into an internal CIDR now clears the old generic boundary confirmation and re-prompts `Boundaries` before confirmation
- session / cookie access handoff from the advanced drawer into the real run dossier, including protected-access binding visibility
- shared manual-auth guidance without account rows from advanced override through Mission Control and Explorer dossier review
- shared session/cookie guidance without account rows from advanced override through Mission Control and Explorer dossier review
- revision-mode clarity:
  - revisiting an earlier topic shows a clear return-to-flow note
  - the primary answer button changes to `Apply Answer & Return`
  - jumping ahead to a later missing topic now shows `Reviewing Another Topic` instead of incorrectly calling it an earlier-topic revision
- calmer intake hierarchy:
  - older conversation context behind disclosure
  - revision controls behind disclosure
  - the `Revise Captured Topic` disclosure now stays hidden until a topic is actually locked into the run dossier, and it only shows already-captured topics instead of surfacing premature `Change ...` actions for unanswered later steps
  - summary led by still-needed and mission-brief cards
  - intake-shell focus mode keeps only essential mission context expanded while secondary mission metadata moves behind disclosure
  - non-active phase cards stay quieter during intake instead of competing with the active wizard
  - the current-question progress note stays visible without consuming another heavy card-sized block
  - narrow/mobile intake layout now collapses to a true single-column workspace instead of leaving the wizard squeezed beside the rail through phase-specific CSS overrides
  - the mobile confirmation card now keeps the confirmation summary capped and in-view while preserving a visible enabled `Create Mission` button
  - the narrow/mobile confirmation geometry is now checked only after the settle-scroll completes, so the recent thread, current question, confirmation summary, and create-mission CTA are validated in the same final operator view instead of an in-flight transition frame
- quick-reply completion truth:
  - representative suggested-answer web, LAN, and API flows now create real runs instead of only relying on typed-answer paths in the browser suite
  - the internal LAN `Visibility with clear per-item detail` route now still asks the operator for safety before boundaries and confirmation instead of silently inferring a safety posture
- advanced drawer synchronization
- advanced scope-guardrail synchronization:
  - adding structured exclusions in the Advanced Drawer now updates the stored `boundary_handling` instead of leaving a stale default in the run dossier
  - the confirmation card and Explorer dossier both show the resulting exclusion summary and boundary-note context
  - the confirmation summary now keeps singular/plural exclusion wording readable for both one explicit exclusion and multiple explicit exclusions
  - notes-only boundary guidance now keeps `Boundary Notes Recorded` instead of collapsing into `Custom Exclusions Recorded`
  - the confirmation summary now uses a dedicated notes-only guardrail sentence instead of the broken `Boundary notes only remain outside this mission` wording
  - missing or older notes-only boundary metadata now still falls back to `Boundary Notes Recorded` in both the confirmation card and Explorer dossier instead of misclassifying those runs as structured exclusions
  - revising `Boundaries` to `No extra exclusions` now clears prior advanced denylist entries and boundary notes instead of leaving a contradictory `Standard Scope Only` label beside stale exclusions
  - revising `Boundaries` from explicit exclusions to notes-only guidance now replaces the old denylist payload in both the confirmation card and Explorer dossier
- advanced override realignment:
  - if an advanced change changes the next required topic, the live conversational question now updates to that topic immediately
  - this prevents stale questions from lingering after profile or safety overrides changed the real run model
  - the current representative web route now proves that a `Deep` profile plus active/deep safety override realigns from the stale safety question to `Boundaries`, not to an auth prompt
  - on the supported live host that same route then persists a `Deep` run with the `active-web-zap-active` execution lane, while the separate internal-validation-to-web scope-revision route still lands on `active-web-safe`
- validation-aware advanced override truth:
  - if advanced scope/profile changes would otherwise make the wizard look confirmation-ready while step validation is still failing, the live conversation now falls back to the blocking topic instead of showing a fake confirm state
  - the regression is explicitly covered for the `SSL/TLS Only` path where a hostname is mistakenly entered into the advanced `IP Addresses` field
  - the blocking validation message is now visible in the wizard error rail and the summary keeps `Scope` in the still-needed bucket until the operator corrects it
- auth-revision downgrade truth:
  - revising an authenticated mission back to `Keep it unauthenticated` now clears stale account/session payload instead of silently carrying it into the created run
  - the confirmation card, Mission Control summary, Explorer dossier, and stored run configuration now downgrade from `Authenticated Review` / `Authenticated Only` to a compatible unauthenticated plan instead of leaving contradictory auth-only copy behind
  - authenticated-app missions can now also stay unauthenticated on the direct route without falling back into `What access context should I record?`; after explicit unauthenticated choice they move on to the next real topic and persist `auth_strategy = unauthenticated` with no stored accounts
- goal/scope compatibility truth:
  - `Internal Validation` now stays reserved for approved internal CIDR/LAN missions instead of surviving onto web/API missions as a contradictory goal
  - if a valid LAN internal-validation mission is later revised onto a website scope, the confirmation handoff now realigns to the same `Deep` / `active-web-safe` web plan as the direct conversational route instead of keeping the lighter assessment-type preset
- credentialed internal-range discovery-first truth:
  - `Authenticated Review` against a LAN/CIDR mission no longer claims an `Authenticated Only` first run while the execution lane is still passive network discovery
  - once protected access is supplied for an internal-range mission, the confirmation handoff now explains that the first run stays discovery-first under `Standard` and keeps the access context attached for later credential-aware follow-up
  - revising a credentialed authenticated web mission onto LAN scope now realigns to that same discovery-first internal plan instead of leaving `Authenticated Only` beside `passive-network-discovery`
- external WAN discovery-first truth:
  - `External IP / WAN` quick replies now label rich goals as staged follow-up work (`Deep follow-up after discovery`, `Adaptive follow-up after discovery`) instead of implying that the first run is already deep/adaptive
  - typed `Deep assessment` and `Adaptive customer-specific testing` answers on an explicit WAN IP/CIDR mission now stage the first run as `External Surface Only` + `passive-network-discovery`
  - typed `Authenticated review` with supplied protected access on an explicit WAN IP/CIDR mission now keeps the access context attached but still stages the first run as `External Surface Only` + `passive-network-discovery`
  - after explicit WAN scope is recorded on those staged routes, the next question is now `Safety` instead of a premature access prompt, and the created run keeps `active_checks = passive-only`
- multi-role authenticated context from intake through dossier review
  - advanced multi-role access now keeps both roles visible in the confirmation card, stores two protected secret bindings in the created run, and exposes a safe `Access Contexts` dossier block plus per-role protected-binding detail in Explorer
  - the same Explorer dossier path is now separately proven for multi-role manual-auth / SSO context, including zero protected secret bindings, shared manual-auth handoff notes, and per-role MFA notes under the persisted `credentialed` strategy
  - that route is now also separately proven when the operator supplies only per-role MFA/manual-auth notes plus shared handoff guidance, with no usernames and no secret references at all; the created dossier keeps both roles visible, shows `0 secret bindings`, and renders `Username: Not recorded` instead of dropping those access contexts
  - the same Explorer dossier path is now separately proven for multi-role API access, including mixed `api_key` and `bearer_token` protected-binding types under the persisted `api-access` strategy
  - the same Explorer dossier path is now separately proven for multi-role session/cookie access, including locally protected `session` bindings plus persisted session-note visibility in the dossier summary
- assessment-type preset coverage across all supported wizard assessment types
- profile preset coverage across representative profile/lane combinations
- profile preset dossier parity across representative profile/lane combinations, including real mission creation and persisted run-config verification instead of summary-only checks
- module toggle rendering and summary synchronization
- run creation with representative conversational operator data
- Mission Control landing after wizard completion
- Mission Control task-focus truth before and after dispatch
- explicit manual-dispatch browser coverage so `Start Validation` cannot silently look like a dead button when a host is still configured without inline or worker execution
- queued-web dispatch truth:
  - when a standard website mission lands in Mission Control with queued nuclei work, only one visible dispatch CTA remains on screen
  - once the run is observed beyond `queued`, Mission Control no longer stays pinned to `Validation is starting`
  - thin-output web runs now also surface an explicit review-warning block inside Run Activity instead of only in the top Current Activity card
- blocked pending-approval and failed completed-with-errors mission states
  - approval-gated active profiles now show `Run launch is blocked pending approval`, an approval-count block in Run Activity, and no misleading `Start Validation` action before approval exists
- deployed adaptive-pack visibility across Mission Control, Pack Forge, Report Center, Explorer, and History
- Codex Pack Forge prepared-task lifecycle visibility, including workspace export commands and the `validation-result.json` handoff path
- artifact-specific Codex build-lane validation cues for `playwright_flow` and `zap_job`, including the exact expected checks surfaced in Pack Forge and prepared-task handoff output
- discovery-to-follow-up continuity for internal/LAN runs, including service-identification launch and completed follow-up context
- Surface Map search/filter behavior for discovery-driven inventories
- navigation to Findings Theater, Evidence Replay, Pack Forge, Report Center, Explorer, and History
- run-level Evidence Replay context for zero-finding discovery and follow-up runs
- follow-up lineage visibility in Explorer, History, and Report Center
- Explorer dossier-summary behavior for completed follow-up runs
- History search plus finding/inventory delta comparison behavior
- phase-feed visibility rules and grouped Mission Control support panels
- report preview actions
- real browser downloads for markdown, HTML, and PDF report exports
- empty-state rendering for major screens
- compact rail and status-feed hierarchy behavior

## Matrix relationship

The browser suite is the executable companion to:

- `docs/product_test_matrix.md`
- `codex/tasks/ui_acceptance_matrix.json`

## Latest focused proof

The newest conversational-alias and token-detail slice is currently proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_depth_alias_reopens_goal_question_with_editable_goal_draft or undo_alias_reopens_last_answered_scope_topic_and_returns_to_safety or previous_alias_reopens_last_answered_access_topic_and_returns_to_safety or change_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or change_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or test_api_token_route_requires_boundary_confirmation_before_confirmation'`
- surrounding revision-cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_goal_command_reopens_goal_question_and_realigns_to_auth or change_profile_alias_reopens_goal_question_with_editable_goal_draft or change_depth_alias_reopens_goal_question_with_editable_goal_draft or change_that_reopens_last_answered_topic_and_returns_to_main_path or go_back_reopens_last_answered_access_topic_and_returns_to_safety or undo_alias_reopens_last_answered_scope_topic_and_returns_to_safety or previous_alias_reopens_last_answered_access_topic_and_returns_to_safety or change_scope_command_reopens_scope_with_editable_draft_and_returns_to_confirmation or change_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or change_access_command_reopens_editable_access_details_and_returns_to_safety or change_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or change_safety_command_reopens_existing_safety_choice_and_returns_to_confirmation or change_boundaries_button_reopens_editable_boundary_draft_and_returns_to_confirmation or test_api_token_route_requires_boundary_confirmation_before_confirmation or auth_details_question_can_switch_back_to_unauthenticated_without_dead_end or revising_authenticated_access_to_unauthenticated_clears_access_context_and_downgrades_plan'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-conversation-alias-proof-20260420-023033.json`
  - `codex/results/live-host-conversation-alias-proof-20260420-023033.png`

The follow-on access-family alias and direct-session slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_auth_alias_can_withdraw_access_and_persist_unauthenticated_run or change_credential_alias_reopens_credential_detail_and_persists_updated_role or direct_session_reference_route_and_change_session_alias_keep_session_access_truth or session_reference_in_advanced_drawer_reaches_run_dossier or revising_authenticated_access_to_unauthenticated_clears_access_context_and_downgrades_plan'`
- surrounding revision/auth cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_auth_alias_can_withdraw_access_and_persist_unauthenticated_run or change_credential_alias_reopens_credential_detail_and_persists_updated_role or direct_session_reference_route_and_change_session_alias_keep_session_access_truth or change_goal_command_reopens_goal_question_and_realigns_to_auth or change_profile_alias_reopens_goal_question_with_editable_goal_draft or change_depth_alias_reopens_goal_question_with_editable_goal_draft or change_that_reopens_last_answered_topic_and_returns_to_main_path or go_back_reopens_last_answered_access_topic_and_returns_to_safety or undo_alias_reopens_last_answered_scope_topic_and_returns_to_safety or previous_alias_reopens_last_answered_access_topic_and_returns_to_safety or change_scope_command_reopens_scope_with_editable_draft_and_returns_to_confirmation or change_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or change_access_command_reopens_editable_access_details_and_returns_to_safety or change_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or change_safety_command_reopens_existing_safety_choice_and_returns_to_confirmation or change_boundaries_button_reopens_editable_boundary_draft_and_returns_to_confirmation or auth_details_question_can_switch_back_to_unauthenticated_without_dead_end or revising_authenticated_access_to_unauthenticated_clears_access_context_and_downgrades_plan or session_reference_in_advanced_drawer_reaches_run_dossier or test_api_token_route_requires_boundary_confirmation_before_confirmation'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-access-alias-proof-20260420-024118.json`
  - `codex/results/live-host-access-alias-proof-20260420-024118.png`

The next edit/revise verb-family slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'edit_profile_alias_reopens_goal_question_with_editable_goal_draft or revise_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or edit_auth_alias_can_withdraw_access_and_persist_unauthenticated_run or revise_token_alias_reopens_api_access_details_and_persists_updated_secret_reference'`
- surrounding revision/auth cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_goal_command_reopens_goal_question_and_realigns_to_auth or change_profile_alias_reopens_goal_question_with_editable_goal_draft or edit_profile_alias_reopens_goal_question_with_editable_goal_draft or change_depth_alias_reopens_goal_question_with_editable_goal_draft or change_that_reopens_last_answered_topic_and_returns_to_main_path or go_back_reopens_last_answered_access_topic_and_returns_to_safety or undo_alias_reopens_last_answered_scope_topic_and_returns_to_safety or previous_alias_reopens_last_answered_access_topic_and_returns_to_safety or change_scope_command_reopens_scope_with_editable_draft_and_returns_to_confirmation or change_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or revise_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or change_access_command_reopens_editable_access_details_and_returns_to_safety or change_auth_alias_can_withdraw_access_and_persist_unauthenticated_run or edit_auth_alias_can_withdraw_access_and_persist_unauthenticated_run or change_credential_alias_reopens_credential_detail_and_persists_updated_role or change_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or revise_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or direct_session_reference_route_and_change_session_alias_keep_session_access_truth or change_safety_command_reopens_existing_safety_choice_and_returns_to_confirmation or change_boundaries_button_reopens_editable_boundary_draft_and_returns_to_confirmation or auth_details_question_can_switch_back_to_unauthenticated_without_dead_end or revising_authenticated_access_to_unauthenticated_clears_access_context_and_downgrades_plan or session_reference_in_advanced_drawer_reaches_run_dossier or test_api_token_route_requires_boundary_confirmation_before_confirmation'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-edit-revise-proof-20260420-025415.json`
  - `codex/results/live-host-edit-revise-proof-edit-profile-20260420-025415.png`
  - `codex/results/live-host-edit-revise-proof-edit-auth-20260420-025415.png`
  - `codex/results/live-host-edit-revise-proof-revise-token-20260420-025415.png`

The next advanced-access revision-sync slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_access_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or change_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or change_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or change_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access'`
- supporting API regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'test_run_configuration_materializes_secret_references or test_static_operator_console_is_served or test_ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding advanced/revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'advanced_access_placeholder_opens_drawer_and_realigns_to_safety or auth_details_advanced_settings_reply_opens_access_drawer or auth_details_question_can_switch_back_to_unauthenticated_without_dead_end or advanced_drawer_overrides_stay_synchronized or change_access_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or change_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or change_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or change_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or session_reference_in_advanced_drawer_reaches_run_dossier'`
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'advanced_access_placeholder_opens_drawer_and_realigns_to_safety or multi_role_advanced_access_persists_into_run_and_dossier_context'`
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'multi_role_advanced_access_persists_into_run_and_dossier_context or multi_role_api_access_persists_into_run_and_dossier_context'`
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'multi_role_advanced_access_persists_into_run_and_dossier_context or multi_role_api_access_persists_into_run_and_dossier_context or multi_role_session_access_persists_into_run_and_dossier_context or multi_role_manual_auth_access_persists_into_run_and_dossier_context'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-advanced-access-revision-proof-20260420-030404.json`
  - `codex/results/live-host-advanced-access-revision-detail-20260420-030404.png`
  - `codex/results/live-host-advanced-access-revision-session-20260420-030404.png`
  - `codex/results/live-host-advanced-access-alias-proof-20260420-011348.json`
  - `codex/results/live-host-advanced-access-alias-credential-20260420-011348.png`
  - `codex/results/live-host-advanced-access-alias-session-20260420-011348.png`
  - `codex/results/live-host-multi-role-manual-auth-proof-20260420.json`
  - `codex/results/live-host-multi-role-manual-auth-proof-20260420.png`
  - `codex/results/live-host-manual-note-only-access-proof-20260420.json`
  - `codex/results/live-host-manual-note-only-access-proof-20260420.png`

The adjacent advanced-access edit/revise alias slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'test_edit_access_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or test_edit_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or test_revise_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or test_revise_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or test_edit_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or test_change_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access or test_edit_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access'`
- supporting API regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'test_run_configuration_materializes_secret_references or test_static_operator_console_is_served or test_ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding advanced/revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'advanced_access_placeholder_opens_drawer_and_realigns_to_safety or change_access_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or edit_access_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or previous_topic_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or change_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or edit_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or revise_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or auth_details_advanced_settings_reply_opens_access_drawer or change_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or revise_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or change_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or edit_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or change_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access or edit_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access or advanced_drawer_overrides_stay_synchronized or session_reference_in_advanced_drawer_reaches_run_dossier'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-advanced-access-edit-revise-proof-20260420.json`
  - `codex/results/live-host-advanced-edit-access-20260420.png`
  - `codex/results/live-host-advanced-edit-credential-20260420.png`
  - `codex/results/live-host-advanced-revise-credential-20260420.png`
  - `codex/results/live-host-advanced-revise-auth-session-20260420.png`
  - `codex/results/live-host-advanced-edit-session-20260420.png`
  - `codex/results/live-host-advanced-change-token-20260420.png`
  - `codex/results/live-host-advanced-edit-token-20260420.png`

The adjacent advanced-access auth/session/token symmetry slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'test_change_auth_after_advanced_credential_detail_reopens_detail_draft_and_persists_updated_role or test_edit_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or test_revise_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or test_revise_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access'`
- supporting API regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'test_run_configuration_materializes_secret_references or test_static_operator_console_is_served or test_ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding advanced/revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'advanced_access_placeholder_opens_drawer_and_realigns_to_safety or change_access_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or edit_access_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or previous_topic_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or change_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or change_auth_after_advanced_credential_detail_reopens_detail_draft_and_persists_updated_role or edit_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or revise_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or auth_details_advanced_settings_reply_opens_access_drawer or change_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or revise_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or edit_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or change_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or edit_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or revise_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or change_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access or edit_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access or revise_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access or advanced_drawer_overrides_stay_synchronized or session_reference_in_advanced_drawer_reaches_run_dossier'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-advanced-access-auth-symmetry-proof-20260420.json`
  - `codex/results/live-host-advanced-change-auth-credential-20260420.png`
  - `codex/results/live-host-advanced-edit-auth-session-20260420.png`
  - `codex/results/live-host-advanced-revise-session-20260420.png`
  - `codex/results/live-host-advanced-revise-token-20260420.png`

The next advanced-credential auth alias symmetry slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'test_edit_auth_after_advanced_credential_detail_reopens_detail_draft_and_persists_updated_role or test_revise_auth_after_advanced_credential_detail_reopens_detail_draft_and_persists_updated_role'`
- supporting API regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'test_run_configuration_materializes_secret_references or test_static_operator_console_is_served or test_ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding advanced/revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'advanced_access_placeholder_opens_drawer_and_realigns_to_safety or change_access_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or edit_access_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or previous_topic_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or change_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or change_auth_after_advanced_credential_detail_reopens_detail_draft_and_persists_updated_role or edit_auth_after_advanced_credential_detail_reopens_detail_draft_and_persists_updated_role or revise_auth_after_advanced_credential_detail_reopens_detail_draft_and_persists_updated_role or edit_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or revise_credential_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or auth_details_advanced_settings_reply_opens_access_drawer or change_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or revise_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or edit_auth_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or change_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or edit_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or revise_session_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or change_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access or edit_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access or revise_token_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access or advanced_drawer_overrides_stay_synchronized or session_reference_in_advanced_drawer_reaches_run_dossier'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-advanced-credential-auth-alias-proof-20260420.json`
  - `codex/results/live-host-advanced-edit-auth-credential-20260420.png`
  - `codex/results/live-host-advanced-revise-auth-credential-20260420.png`

The adjacent safety/boundary alias slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'edit_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries or change_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump'`
- supporting API regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'test_run_configuration_materializes_secret_references or test_static_operator_console_is_served or test_ui_support_list_endpoints_reuse_existing_contracts'`

The next shared no-account inline-history access-revision slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'inline_change_from_history_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or inline_change_from_history_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supporting API/static regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts or static_operator_console_is_served or ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding no-account access cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'shared_manual_auth_note_without_accounts_persists_into_run_and_dossier_context or shared_session_note_without_accounts_persists_into_run_and_dossier_context or change_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_access_button_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or inline_change_from_history_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or change_access_button_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or inline_change_from_history_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-access-inline-history-change-20260420.json`
  - `codex/results/live-host-shared-manual-auth-inline-history-change-20260420.png`
  - `codex/results/live-host-shared-session-inline-history-change-20260420.png`

The next shared no-account stepper access-revision slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'access_stepper_button_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or access_stepper_button_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supporting API/static regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts or static_operator_console_is_served or ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding no-account access cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'shared_manual_auth_note_without_accounts_persists_into_run_and_dossier_context or shared_session_note_without_accounts_persists_into_run_and_dossier_context or change_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_access_button_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or inline_change_from_history_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or access_stepper_button_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or change_access_button_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or inline_change_from_history_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or access_stepper_button_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-access-stepper-change-20260420.json`
  - `codex/results/live-host-shared-manual-auth-stepper-change-20260420.png`
  - `codex/results/live-host-shared-session-stepper-change-20260420.png`

The next visible `Previous Topic` access-revision slice is now also proven by:

- targeted browser regression:
  - `PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" .venv/bin/python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'go_back_reopens_last_answered_access_topic_and_returns_to_safety or previous_topic_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or previous_topic_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or access_stepper_button_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or previous_topic_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or access_stepper_button_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supporting API/static regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts or static_operator_console_is_served or ui_support_list_endpoints_reuse_existing_contracts'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-previous-topic-access-20260420.json`
  - `codex/results/live-host-previous-topic-account-20260420.png`
  - `codex/results/live-host-previous-topic-shared-manual-20260420.png`
  - `codex/results/live-host-previous-topic-shared-session-20260420.png`

The adjacent account-backed `Previous Topic` advanced-access symmetry slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'test_previous_topic_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or test_previous_topic_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or test_previous_topic_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access'`
- supporting API/static regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'test_run_configuration_materializes_secret_references or test_static_operator_console_is_served or test_ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding previous-topic cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'go_back_reopens_last_answered_access_topic_and_returns_to_safety or previous_topic_after_advanced_drawer_detail_reopens_detail_draft_and_persists_updated_role or previous_topic_after_advanced_session_detail_reopens_detail_draft_and_preserves_session_access or previous_topic_after_advanced_api_detail_reopens_detail_draft_and_preserves_api_access or previous_topic_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or access_stepper_button_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or previous_topic_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or access_stepper_button_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-previous-topic-advanced-access-proof-20260420.json`
  - `codex/results/live-host-previous-topic-advanced-credential-20260420.png`
  - `codex/results/live-host-previous-topic-advanced-session-20260420.png`
  - `codex/results/live-host-previous-topic-advanced-api-20260420.png`

The next shared no-account last-answer command slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_that_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or previous_alias_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or undo_alias_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or go_back_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- surrounding shared no-account last-answer cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_that_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or undo_alias_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or previous_alias_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or go_back_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supporting API/static regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-access-last-answer-commands-20260420.json`
  - `codex/results/live-host-shared-manual-change-that-20260420.png`
  - `codex/results/live-host-shared-session-previous-20260420.png`
  - `codex/results/live-host-shared-access-undo-go-back-20260420.json`
  - `codex/results/live-host-shared-manual-undo-20260420.png`
  - `codex/results/live-host-shared-session-go-back-20260420.png`
- surrounding revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_safety_command_reopens_existing_safety_choice_and_returns_to_confirmation or edit_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries or change_boundaries_button_reopens_editable_boundary_draft_and_returns_to_confirmation or change_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_that_reopens_last_answered_topic_and_returns_to_main_path or go_back_reopens_last_answered_access_topic_and_returns_to_safety or undo_alias_reopens_last_answered_scope_topic_and_returns_to_safety or previous_alias_reopens_last_answered_access_topic_and_returns_to_safety'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-safety-boundary-alias-proof-20260420-011921.json`
  - `codex/results/live-host-safety-boundary-alias-edit-safety-20260420-011921.png`
  - `codex/results/live-host-safety-boundary-alias-change-boundary-20260420-011921.png`

The next shared no-account edit/revise alias slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'edit_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or revise_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supporting API/static regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-access-edit-revise-20260420.json`
  - `codex/results/live-host-shared-manual-edit-access-20260420.png`
  - `codex/results/live-host-shared-session-revise-session-20260420.png`

The next shared no-account secondary edit/revise alias slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'revise_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or edit_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- surrounding shared no-account access cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or edit_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or revise_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or edit_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or revise_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supporting API/static regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts or static_operator_console_is_served or ui_support_list_endpoints_reuse_existing_contracts'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-access-secondary-edit-revise-20260420.json`
  - `codex/results/live-host-shared-manual-revise-access-20260420.png`
  - `codex/results/live-host-shared-session-edit-session-20260420.png`

The adjacent shared no-account access/session-prefix parser-truth slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'test_revise_access_after_shared_manual_auth_note_without_accounts_accepts_prefix_style_longer_note_text or test_edit_session_after_shared_session_note_without_accounts_accepts_prefix_style_longer_note_text'`
- surrounding shared no-account access/session cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'test_change_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or test_edit_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or test_revise_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or test_revise_access_after_shared_manual_auth_note_without_accounts_accepts_prefix_style_longer_note_text or test_change_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or test_edit_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or test_edit_session_after_shared_session_note_without_accounts_accepts_prefix_style_longer_note_text or test_revise_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supporting API/static regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts or static_operator_console_is_served or ui_support_list_endpoints_reuse_existing_contracts'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-access-prefix-parser-truth-20260420.json`
  - `codex/results/live-host-shared-manual-revise-access-prefix-20260420.png`
  - `codex/results/live-host-shared-session-edit-session-prefix-20260420.png`

The next shared no-account auth-alias slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or edit_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or revise_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or edit_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or revise_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- surrounding shared no-account access cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or edit_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or revise_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or edit_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or revise_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or edit_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or revise_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or change_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or edit_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or revise_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supporting API/static regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts or static_operator_console_is_served or ui_support_list_endpoints_reuse_existing_contracts'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-auth-alias-no-account-20260420.json`
  - `codex/results/live-host-shared-manual-change-auth-20260420.png`
  - `codex/results/live-host-shared-manual-edit-auth-20260420.png`
  - `codex/results/live-host-shared-manual-revise-auth-20260420.png`
  - `codex/results/live-host-shared-session-change-auth-20260420.png`
  - `codex/results/live-host-shared-session-edit-auth-20260420.png`
  - `codex/results/live-host-shared-session-revise-auth-20260420.png`

The adjacent shared no-account auth-phrase parser-truth slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'test_change_auth_after_shared_manual_auth_note_without_accounts_accepts_longer_note_text_containing_change_auth_phrase or test_edit_auth_after_shared_session_note_without_accounts_accepts_longer_note_text_containing_edit_auth_phrase'`
- surrounding shared no-account auth cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'test_change_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or test_edit_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or test_revise_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or test_change_auth_after_shared_manual_auth_note_without_accounts_accepts_longer_note_text_containing_change_auth_phrase or test_change_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or test_edit_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or test_revise_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or test_edit_auth_after_shared_session_note_without_accounts_accepts_longer_note_text_containing_edit_auth_phrase'`
- supporting API/static regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts or static_operator_console_is_served or ui_support_list_endpoints_reuse_existing_contracts'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-auth-phrase-parser-truth-20260420.json`
  - `codex/results/live-host-shared-manual-change-auth-phrase-20260420.png`
  - `codex/results/live-host-shared-session-edit-auth-phrase-20260420.png`

The adjacent shared no-account auth-prefix parser-truth slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'test_revise_auth_after_shared_manual_auth_note_without_accounts_accepts_prefix_style_longer_note_text or test_change_auth_after_shared_session_note_without_accounts_accepts_prefix_style_longer_note_text'`
- surrounding shared no-account auth cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'test_change_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or test_edit_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or test_revise_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or test_change_auth_after_shared_manual_auth_note_without_accounts_accepts_longer_note_text_containing_change_auth_phrase or test_revise_auth_after_shared_manual_auth_note_without_accounts_accepts_prefix_style_longer_note_text or test_change_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or test_edit_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or test_revise_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or test_edit_auth_after_shared_session_note_without_accounts_accepts_longer_note_text_containing_edit_auth_phrase or test_change_auth_after_shared_session_note_without_accounts_accepts_prefix_style_longer_note_text'`
- supporting API/static regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts or static_operator_console_is_served or ui_support_list_endpoints_reuse_existing_contracts'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-auth-prefix-parser-truth-20260420.json`
  - `codex/results/live-host-shared-manual-revise-auth-prefix-20260420.png`
  - `codex/results/live-host-shared-session-change-auth-prefix-20260420.png`

The adjacent shared no-account edit-auth-prefix parser-truth slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'test_edit_auth_after_shared_manual_auth_note_without_accounts_accepts_prefix_style_longer_note_text or test_edit_auth_after_shared_session_note_without_accounts_accepts_prefix_style_longer_note_text'`
- surrounding shared no-account auth cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'test_change_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or test_edit_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or test_revise_auth_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or test_change_auth_after_shared_manual_auth_note_without_accounts_accepts_longer_note_text_containing_change_auth_phrase or test_revise_auth_after_shared_manual_auth_note_without_accounts_accepts_prefix_style_longer_note_text or test_edit_auth_after_shared_manual_auth_note_without_accounts_accepts_prefix_style_longer_note_text or test_change_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or test_edit_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or test_revise_auth_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or test_edit_auth_after_shared_session_note_without_accounts_accepts_longer_note_text_containing_edit_auth_phrase or test_change_auth_after_shared_session_note_without_accounts_accepts_prefix_style_longer_note_text or test_edit_auth_after_shared_session_note_without_accounts_accepts_prefix_style_longer_note_text'`
- supporting API/static regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts or static_operator_console_is_served or ui_support_list_endpoints_reuse_existing_contracts'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-edit-auth-prefix-parser-truth-20260420.json`
  - `codex/results/live-host-shared-manual-edit-auth-prefix-20260420.png`
  - `codex/results/live-host-shared-session-edit-auth-prefix-20260420.png`

The adjacent scope/access edit-revise slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'edit_scope_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or revise_access_alias_reopens_editable_access_details_and_persists_updated_role'`
- supporting API regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'test_run_configuration_materializes_secret_references or test_static_operator_console_is_served or test_ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding scope/access revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_scope_command_reopens_scope_with_editable_draft_and_returns_to_confirmation or change_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or revise_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or edit_scope_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or change_access_command_reopens_editable_access_details_and_returns_to_safety or change_auth_alias_can_withdraw_access_and_persist_unauthenticated_run or edit_auth_alias_can_withdraw_access_and_persist_unauthenticated_run or revise_access_alias_reopens_editable_access_details_and_persists_updated_role or change_credential_alias_reopens_credential_detail_and_persists_updated_role'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-scope-access-alias-proof-20260420-012517.json`
  - `codex/results/live-host-scope-access-alias-edit-scope-20260420-012517.png`
  - `codex/results/live-host-scope-access-alias-revise-access-20260420-012517.png`

The adjacent safety/boundary edit-revise slice is now also proven by:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'revise_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries or edit_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump'`
- supporting API regression:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'test_run_configuration_materializes_secret_references or test_static_operator_console_is_served or test_ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding safety/boundary revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_safety_command_reopens_existing_safety_choice_and_returns_to_confirmation or edit_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries or revise_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries or change_boundaries_button_reopens_editable_boundary_draft_and_returns_to_confirmation or edit_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_that_reopens_last_answered_topic_and_returns_to_main_path or go_back_reopens_last_answered_access_topic_and_returns_to_safety or undo_alias_reopens_last_answered_scope_topic_and_returns_to_safety or previous_alias_reopens_last_answered_access_topic_and_returns_to_safety'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-safety-boundary-edit-revise-proof-20260420-013019.json`
  - `codex/results/live-host-safety-boundary-edit-revise-safety-20260420-013019.png`
  - `codex/results/live-host-safety-boundary-edit-revise-boundary-20260420-013019.png`

Real-run safe lab validation remains a separate acceptance lane and is not replaced by browser-only checks.

The Pack Forge artifact-specific validation cues are also cross-checked outside the browser through:

- `api/tests/test_codex_tasks.py::test_codex_workspace_scripts_export_bundle_and_capture_validation_against_live_host`
- `codex/results/live-host-codex-validation-hooks-20260420-014016.json`

The natural-language revision-command slice is also cross-checked on the supported live host through:

- normalized command browser regressions:
  - `test_back_command_normalization_reopens_last_answered_access_topic`
  - `test_polite_revision_command_wrappers_reopen_scope_with_editable_draft`
  - `test_revision_command_case_and_spacing_normalization_reopens_scope_draft`
- output-style revision browser regressions:
  - `test_change_output_command_reopens_output_question_and_updates_style`
  - `test_edit_output_alias_reopens_output_question_with_editable_style_draft`
  - `test_revise_output_alias_reopens_output_question_with_editable_style_draft`
  - `test_reporting_aliases_reopen_output_question_with_editable_style_draft`
  - `test_output_revision_command_normalization_reopens_output_style_draft`
- `codex/results/live-host-wizard-natural-revision-20260420-015137.json`
- `codex/results/live-host-wizard-topic-revisions-20260420-020259.json`
- `codex/results/live-host-auth-detail-unauth-revision-20260420-021145.json`
- `codex/results/live-host-goal-revision-commands-20260420-021627.json`

## Test structure

- tests live under `ui/tests/`
- `ui/tests/conftest.py` starts a temporary FastAPI instance backed by SQLite
- that browser fixture now also injects deterministic fake `nmap` and `nuclei` binaries so the operator-flow suite stays reproducible instead of depending on host tool timing
- `ui/tests/test_operator_console_e2e.py` covers the primary operator flow
- `ui/tests/test_product_feature_matrix_e2e.py` covers the broader feature/options matrix
- Playwright traces and screenshots are written to `ui/test-results/` on failure

The wizard completion matrix is also tracked in:

- `docs/operator_console_phase1_checklist.md`
- `codex/tasks/ui_acceptance_matrix.json`

The Phase 1 authorization-context alignment is also validated through the API lane and an independent live-host browser proof:

- `api/tests/test_runs.py`
- `codex/results/live-host-wizard-authorization-context-20260418-225146.json`

The Phase 1 goal-compatibility normalization slice is also validated through targeted browser/API assertions plus an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `codex/results/live-host-wizard-goal-compatibility-20260419.json`

The Phase 1 internal authenticated-review discovery-first slice is also validated through targeted browser/API assertions plus an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `codex/results/live-host-wizard-internal-auth-discovery-20260419.json`

The Phase 1 internal rich-goal discovery-first slice is also validated through targeted browser/API assertions plus an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `codex/results/live-host-wizard-internal-rich-goal-discovery-20260419.json`

The Phase 1 assessment-type dossier-parity slice is also validated through targeted browser/API assertions plus an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `codex/results/live-host-wizard-assessment-type-parity-20260419.json`

The supported assessment-type manual operator review baseline is also captured through an independent live-host browser matrix:

- `codex/results/live-host-wizard-operator-review-matrix-20260419.json`

The approval-gated Mission Control blocked-state slice is also validated through targeted browser/API assertions plus an independent live-host browser proof:

- `ui/tests/test_product_feature_matrix_e2e.py`
- `api/tests/test_runs.py`
- `codex/results/live-host-pending-approval-run-activity-20260419.json`

The queued-web dispatch and thin-output Mission Control slice is also validated through targeted browser/API assertions plus an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_nuclei_dispatch.py`
- `api/tests/test_task_dispatch.py`
- `codex/results/live-host-web-dispatch-truth-20260419.json`

The broader Phase 2 execution-truth signoff is now also backed by the composite product matrix plus a second independent live-host browser proof that covers both approval-gated blocking and real queued-dispatch completion on the supported `127.0.0.1:8000` host path:

- `scripts/run_product_e2e_matrix.py --lane all`
- `codex/results/live-host-phase2-run-execution-signoff-20260419.json`
- `codex/results/live-host-phase2-run-execution-blocked-20260419.png`
- `codex/results/live-host-phase2-run-execution-dispatch-20260419.png`

The next Phase 1 advanced-validation/profile-parity slice is also validated through targeted browser/API assertions plus an independent live-host browser proof:

- `ui/tests/test_product_feature_matrix_e2e.py`
- `api/tests/test_runs.py`
- `codex/results/live-host-wizard-validation-aware-profile-parity-20260419.json`

The next Phase 1 narrow-screen confirmation-layout slice is also validated through targeted browser assertions, API/static-asset checks, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-mobile-confirmation-layout-20260419.json`
- `codex/results/live-host-wizard-mobile-confirmation-post-settle-20260419.json`

The next Phase 1 quick-reply trust slice is also validated through targeted browser assertions, API/static-asset checks, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-quick-reply-matrix-20260419.json`

The next Phase 1 still-needed-summary dedup slice is also validated through targeted browser assertions, API/static-asset checks, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-needed-summary-dedup-20260419.json`

The follow-on linked-badge dedup slice is also validated through targeted browser assertions, API/static-asset checks, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-linked-badge-dedup-20260419.json`

The follow-on current-question progress-note dedup slice is also validated through targeted browser assertions, API/static-asset checks, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-path-note-dedup-20260419.json`

The follow-on repeated-access-answer guidance slice is also validated through targeted browser assertions, API/static-asset checks, the broader UI matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-safety-auth-repeat-guidance-20260419.json`
- `codex/results/live-host-wizard-safety-auth-repeat-guidance-20260419.png`

The follow-on repeated-safety-answer-at-boundaries guidance slice is also validated through targeted browser assertions, API/static-asset checks, the broader UI matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-boundaries-safety-repeat-guidance-20260419.json`
- `codex/results/live-host-wizard-boundaries-safety-repeat-guidance-20260419.png`

The follow-on repeated-access-answer-at-boundaries guidance slice is also validated through targeted browser assertions, API/static-asset checks, the broader UI matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-boundaries-access-repeat-guidance-20260419.json`
- `codex/results/live-host-wizard-boundaries-access-repeat-guidance-20260419.png`

The follow-on opening-summary truth slice is also validated through targeted browser assertions, API/static-asset checks, the broader UI matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `ui/tests/test_product_feature_matrix_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-current-essentials-truth-20260419.json`
- `codex/results/live-host-wizard-current-essentials-truth-20260419.png`

The follow-on goal-to-scope transition truth slice is validated through targeted browser assertions, repeated isolation checks for the previously flaky matrix cases, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `ui/tests/test_product_feature_matrix_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-scope-transition-truth-20260419.json`
- `codex/results/live-host-wizard-scope-transition-truth-20260419.png`

That same scope now also has a clean composite UI-matrix rerun plus a fresh end-to-end live-host revalidation:

- `TMPDIR=/var/tmp ./.venv/bin/python scripts/run_product_e2e_matrix.py --lane ui`
- `codex/results/live-host-wizard-composite-revalidation-20260419.json`
- `codex/results/live-host-wizard-composite-revalidation-20260419.png`

The next Phase 1 non-internal boundary-copy truth slice is also validated through targeted browser assertions, API/static-asset checks, the broader feature/options matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `ui/tests/test_product_feature_matrix_e2e.py`
- `codex/results/live-host-wizard-non-internal-boundary-copy-20260419.json`
- `codex/results/live-host-wizard-non-internal-boundary-copy-20260419.png`

The next Phase 1 external-domain auth-default truth slice is also validated through targeted browser assertions, API/static-asset checks, the broader feature/options matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `ui/tests/test_product_feature_matrix_e2e.py`
- `codex/results/live-host-wizard-domain-deep-no-auth-default-20260419.json`
- `codex/results/live-host-wizard-domain-deep-no-auth-default-20260419.png`

The follow-on generic-web rich-profile auth-default truth slice is also validated through targeted browser assertions, API/static-asset checks, the broader feature/options matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `ui/tests/test_product_feature_matrix_e2e.py`
- `codex/results/live-host-wizard-web-rich-profile-no-auth-default-20260419.json`
- `codex/results/live-host-wizard-web-rich-profile-no-auth-default-20260419.png`

The adjacent supported-route explicit-boundaries slice is also validated through targeted browser assertions, API/static-asset checks, the broader feature/options matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `ui/tests/test_product_feature_matrix_e2e.py`
- `codex/results/live-host-wizard-supported-boundaries-20260419.json`
- `codex/results/live-host-wizard-supported-boundaries-20260419.png`

The follow-on external WAN discovery-first slice is also validated through targeted browser assertions, API/static-asset checks, the broader UI matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `ui/tests/test_product_feature_matrix_e2e.py`
- `codex/results/live-host-wizard-external-wan-discovery-first-20260419.json`
- `codex/results/live-host-wizard-external-wan-discovery-first-20260419.png`
- `codex/results/live-host-wizard-external-wan-authenticated-review-20260419.json`
- `codex/results/live-host-wizard-external-wan-authenticated-review-20260419.png`

The follow-on rich-route boundary-confirmation slice is also validated through targeted browser assertions, run-config/API checks, the broader UI matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_runs.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-rich-boundary-confirmation-20260419.json`
- `codex/results/live-host-wizard-rich-boundary-confirmation-20260419.png`

The adjacent internal-lateral scope-revision slice is also validated through targeted browser assertions, API/static-asset checks, the broader UI matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `ui/tests/test_product_feature_matrix_e2e.py`
- `codex/results/live-host-wizard-internal-lateral-scope-revision-20260419.json`
- `codex/results/live-host-wizard-internal-lateral-scope-revision-20260419.png`

The adjacent API scope-revision reclassification slice is also validated through targeted browser assertions, API/static-asset checks, the broader UI matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `ui/tests/test_product_feature_matrix_e2e.py`
- `codex/results/live-host-wizard-api-scope-revision-20260419.json`
- `codex/results/live-host-wizard-api-scope-revision-20260419.png`

The follow-on auto-generated dossier-name sync slice is also validated through targeted browser assertions, run-config/API checks, the broader UI matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_runs.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-auto-dossier-name-sync-20260419.json`
- `codex/results/live-host-wizard-auto-dossier-name-sync-20260419.png`

The adjacent manual-dossier-name preservation route is also validated through targeted browser assertions, run-config/API checks, the broader UI matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_runs.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-manual-dossier-name-preserved-20260419.json`
- `codex/results/live-host-wizard-manual-dossier-name-preserved-20260419.png`

The follow-on advanced-override realignment truth slice is also validated through targeted browser assertions, the full product matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `scripts/run_product_e2e_matrix.py --lane all`
- `codex/results/live-host-wizard-advanced-realignment-20260419.json`
- `codex/results/live-host-wizard-advanced-realignment-20260419.png`

The follow-on advanced-access bridge slice is also validated through targeted browser assertions, API/static-asset checks, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-advanced-access-bridge-20260419.json`

The follow-on initial-topic-visibility slice is also validated through targeted browser assertions, API/static-asset checks, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-initial-topic-visibility-20260419.json`

The follow-on customer-portal authenticated-classification slice is also validated through targeted browser assertions, API/static-asset checks, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-customer-portal-authenticated-app-20260419.json`

The follow-on TLS-only goal-guardrail slice is also validated through targeted browser assertions, API/static-asset checks, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-tls-goal-guardrails-20260419.json`

The follow-on TLS-only safety-and-boundaries truth slice is also validated through targeted browser assertions, API/static-asset checks, the broader feature/options matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `ui/tests/test_product_feature_matrix_e2e.py`
- `codex/results/live-host-wizard-tls-safety-boundaries-20260419.json`
- `codex/results/live-host-wizard-tls-safety-boundaries-20260419.png`

The follow-on calm revision-controls plus authenticated-app unauthenticated-path slice is also validated through targeted browser assertions, API/static-asset checks, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `codex/results/live-host-wizard-revision-calmness-20260419.json`

The follow-on assessment-type wording-truth slice is also validated through targeted browser assertions, API/static-asset checks, the broader UI matrix, and an independent live-host browser proof:

- `ui/tests/test_operator_console_e2e.py`
- `api/tests/test_ui_support.py`
- `ui/tests/test_product_feature_matrix_e2e.py`
- `codex/results/live-host-wizard-assessment-wording-truth-20260419.json`

The next secondary revision-alias slice is also validated through targeted browser assertions, API/static-asset checks, a broader surrounding revision cluster, and an independent live-host browser proof:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'edit_access_alias_reopens_editable_access_details_and_persists_updated_role or revise_auth_alias_can_withdraw_access_and_persist_unauthenticated_run or direct_session_reference_route_and_revise_session_alias_keep_session_access_truth or revise_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump'`
- API/static check:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'test_run_configuration_materializes_secret_references or test_static_operator_console_is_served or test_ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_access_command_reopens_editable_access_details_and_returns_to_safety or revise_access_alias_reopens_editable_access_details_and_persists_updated_role or edit_access_alias_reopens_editable_access_details_and_persists_updated_role or change_auth_alias_can_withdraw_access_and_persist_unauthenticated_run or edit_auth_alias_can_withdraw_access_and_persist_unauthenticated_run or revise_auth_alias_can_withdraw_access_and_persist_unauthenticated_run or change_credential_alias_reopens_credential_detail_and_persists_updated_role or direct_session_reference_route_and_change_session_alias_keep_session_access_truth or direct_session_reference_route_and_revise_session_alias_keep_session_access_truth or edit_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries or revise_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries or edit_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-secondary-revision-alias-proof-20260420-034015.json`
  - `codex/results/live-host-secondary-revision-alias-edit-access-20260420-034015.png`
  - `codex/results/live-host-secondary-revision-alias-revise-auth-20260420-034015.png`
  - `codex/results/live-host-secondary-revision-alias-revise-session-20260420-034015.png`
  - `codex/results/live-host-secondary-revision-alias-revise-boundary-20260420-034015.png`

The adjacent plural-boundary revision-alias slice is also validated through targeted browser assertions and a broader surrounding revision cluster:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'edit_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump'`
- surrounding revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_safety_command_reopens_existing_safety_choice_and_returns_to_confirmation or edit_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries or revise_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries or change_boundaries_button_reopens_editable_boundary_draft_and_returns_to_confirmation or edit_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump'`

The adjacent safety-synonym revision-alias slice is also validated through targeted browser assertions and a broader surrounding safety/boundary revision cluster:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_careful_alias_reopens_existing_safety_choice_and_returns_to_boundaries or edit_careful_alias_reopens_existing_safety_choice_and_returns_to_boundaries or revise_careful_alias_reopens_existing_safety_choice_and_returns_to_boundaries or change_conservative_alias_reopens_existing_safety_choice_and_returns_to_boundaries or edit_conservative_alias_reopens_existing_safety_choice_and_returns_to_boundaries or revise_conservative_alias_reopens_existing_safety_choice_and_returns_to_boundaries or change_aggressive_alias_reopens_existing_safety_choice_and_returns_to_boundaries or edit_aggressive_alias_reopens_existing_safety_choice_and_returns_to_boundaries or revise_aggressive_alias_reopens_existing_safety_choice_and_returns_to_boundaries or change_thorough_alias_reopens_existing_safety_choice_and_returns_to_boundaries or edit_thorough_alias_reopens_existing_safety_choice_and_returns_to_boundaries or revise_thorough_alias_reopens_existing_safety_choice_and_returns_to_boundaries'`
- surrounding revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_safety_command_reopens_existing_safety_choice_and_returns_to_confirmation or edit_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries or revise_safety_alias_reopens_existing_safety_choice_and_returns_to_boundaries or change_careful_alias_reopens_existing_safety_choice_and_returns_to_boundaries or edit_careful_alias_reopens_existing_safety_choice_and_returns_to_boundaries or revise_careful_alias_reopens_existing_safety_choice_and_returns_to_boundaries or change_conservative_alias_reopens_existing_safety_choice_and_returns_to_boundaries or edit_conservative_alias_reopens_existing_safety_choice_and_returns_to_boundaries or revise_conservative_alias_reopens_existing_safety_choice_and_returns_to_boundaries or change_aggressive_alias_reopens_existing_safety_choice_and_returns_to_boundaries or edit_aggressive_alias_reopens_existing_safety_choice_and_returns_to_boundaries or revise_aggressive_alias_reopens_existing_safety_choice_and_returns_to_boundaries or change_thorough_alias_reopens_existing_safety_choice_and_returns_to_boundaries or edit_thorough_alias_reopens_existing_safety_choice_and_returns_to_boundaries or revise_thorough_alias_reopens_existing_safety_choice_and_returns_to_boundaries or change_boundaries_button_reopens_editable_boundary_draft_and_returns_to_confirmation or edit_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump'`

The adjacent plural-target revision-alias slice is also validated through targeted browser assertions and a broader surrounding revision cluster:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_targets_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or edit_targets_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or revise_targets_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation'`
- surrounding revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_scope_command_reopens_scope_with_editable_draft_and_returns_to_confirmation or change_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or revise_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or edit_scope_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or revise_scope_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or edit_target_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or change_targets_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or edit_targets_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or revise_targets_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation'`

The adjacent plural auth-detail revision-alias slice is also validated through targeted browser assertions and a broader surrounding revision cluster:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_credentials_alias_reopens_credential_detail_and_persists_updated_role or edit_credentials_alias_reopens_credential_detail_and_persists_updated_role or revise_credentials_alias_reopens_credential_detail_and_persists_updated_role'`
- surrounding revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_credential_alias_reopens_credential_detail_and_persists_updated_role or edit_credential_alias_reopens_credential_detail_and_persists_updated_role or revise_credential_alias_reopens_credential_detail_and_persists_updated_role or change_credentials_alias_reopens_credential_detail_and_persists_updated_role or edit_credentials_alias_reopens_credential_detail_and_persists_updated_role or revise_credentials_alias_reopens_credential_detail_and_persists_updated_role or change_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or edit_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or revise_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or edit_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference or direct_session_reference_route_and_change_session_alias_keep_session_access_truth or direct_session_reference_route_and_edit_session_alias_keep_session_access_truth or direct_session_reference_route_and_revise_session_alias_keep_session_access_truth or direct_session_reference_route_and_revise_sessions_alias_keep_session_access_truth'`

The remaining plural-token revision-alias slice is also validated through targeted browser assertions and a broader surrounding revision cluster:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference or edit_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference or revise_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference'`
- surrounding revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_credential_alias_reopens_credential_detail_and_persists_updated_role or edit_credential_alias_reopens_credential_detail_and_persists_updated_role or revise_credential_alias_reopens_credential_detail_and_persists_updated_role or change_credentials_alias_reopens_credential_detail_and_persists_updated_role or edit_credentials_alias_reopens_credential_detail_and_persists_updated_role or revise_credentials_alias_reopens_credential_detail_and_persists_updated_role or change_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or edit_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or revise_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or change_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference or edit_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference or revise_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference or direct_session_reference_route_and_change_session_alias_keep_session_access_truth or direct_session_reference_route_and_edit_session_alias_keep_session_access_truth or direct_session_reference_route_and_revise_session_alias_keep_session_access_truth or direct_session_reference_route_and_revise_sessions_alias_keep_session_access_truth'`

The remaining plural-session revision-alias slice is also validated through targeted browser assertions and a broader surrounding revision cluster:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'direct_session_reference_route_and_change_sessions_alias_keep_session_access_truth or direct_session_reference_route_and_edit_sessions_alias_keep_session_access_truth or direct_session_reference_route_and_revise_sessions_alias_keep_session_access_truth'`
- surrounding revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_credential_alias_reopens_credential_detail_and_persists_updated_role or edit_credential_alias_reopens_credential_detail_and_persists_updated_role or revise_credential_alias_reopens_credential_detail_and_persists_updated_role or change_credentials_alias_reopens_credential_detail_and_persists_updated_role or edit_credentials_alias_reopens_credential_detail_and_persists_updated_role or revise_credentials_alias_reopens_credential_detail_and_persists_updated_role or change_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or edit_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or revise_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or change_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference or edit_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference or revise_tokens_alias_reopens_api_access_details_and_persists_updated_secret_reference or direct_session_reference_route_and_change_session_alias_keep_session_access_truth or direct_session_reference_route_and_change_sessions_alias_keep_session_access_truth or direct_session_reference_route_and_edit_session_alias_keep_session_access_truth or direct_session_reference_route_and_edit_sessions_alias_keep_session_access_truth or direct_session_reference_route_and_revise_session_alias_keep_session_access_truth or direct_session_reference_route_and_revise_sessions_alias_keep_session_access_truth'`

The adjacent boundary-synonym revision-alias slice is also validated through targeted browser assertions and a broader surrounding revision cluster:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_lateral_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_lateral_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_lateral_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_exclusions_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_exclusions_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_exclusions_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_excludes_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_excludes_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_excludes_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_exclusion_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_exclusion_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_exclusion_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_avoid_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_avoid_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_avoid_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_exclude_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_exclude_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_exclude_alias_reopens_existing_boundary_draft_after_safety_revision_jump'`
- surrounding revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_boundaries_button_reopens_editable_boundary_draft_and_returns_to_confirmation or edit_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_boundary_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_boundaries_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_lateral_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_lateral_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_lateral_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_exclusions_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_exclusions_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_exclusions_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_excludes_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_excludes_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_excludes_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_exclusion_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_exclusion_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_exclusion_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_avoid_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_avoid_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_avoid_alias_reopens_existing_boundary_draft_after_safety_revision_jump or change_exclude_alias_reopens_existing_boundary_draft_after_safety_revision_jump or edit_exclude_alias_reopens_existing_boundary_draft_after_safety_revision_jump or revise_exclude_alias_reopens_existing_boundary_draft_after_safety_revision_jump'`

The next tertiary revision-alias slice is also validated through targeted browser assertions, API/static-asset checks, a broader surrounding revision cluster, and an independent live-host browser proof:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'revise_profile_alias_reopens_goal_question_with_editable_goal_draft or edit_target_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or edit_credential_alias_reopens_credential_detail_and_persists_updated_role or direct_session_reference_route_and_edit_session_alias_keep_session_access_truth'`
- API/static check:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'test_run_configuration_materializes_secret_references or test_static_operator_console_is_served or test_ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_profile_alias_reopens_goal_question_with_editable_goal_draft or edit_profile_alias_reopens_goal_question_with_editable_goal_draft or revise_profile_alias_reopens_goal_question_with_editable_goal_draft or change_depth_alias_reopens_goal_question_with_editable_goal_draft or change_scope_command_reopens_scope_with_editable_draft_and_returns_to_confirmation or change_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or revise_target_alias_reopens_scope_with_editable_draft_and_returns_to_confirmation or edit_scope_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or edit_target_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or change_credential_alias_reopens_credential_detail_and_persists_updated_role or edit_credential_alias_reopens_credential_detail_and_persists_updated_role or direct_session_reference_route_and_change_session_alias_keep_session_access_truth or direct_session_reference_route_and_edit_session_alias_keep_session_access_truth or direct_session_reference_route_and_revise_session_alias_keep_session_access_truth'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-tertiary-revision-alias-proof-20260420-034757.json`
  - `codex/results/live-host-tertiary-revision-alias-revise-profile-20260420-034757.png`
  - `codex/results/live-host-tertiary-revision-alias-edit-target-20260420-034757.png`
  - `codex/results/live-host-tertiary-revision-alias-edit-credential-20260420-034757.png`
  - `codex/results/live-host-tertiary-revision-alias-edit-session-20260420-034757.png`

The next quaternary revision-alias slice is also validated through targeted browser assertions, API/static-asset checks, a broader surrounding revision cluster, and an independent live-host browser proof:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'edit_goal_alias_reopens_goal_question_with_editable_goal_draft or revise_goal_alias_reopens_goal_question_with_editable_goal_draft or revise_scope_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or revise_credential_alias_reopens_credential_detail_and_persists_updated_role or edit_token_alias_reopens_api_access_details_and_persists_updated_secret_reference'`
- API/static check:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'test_run_configuration_materializes_secret_references or test_static_operator_console_is_served or test_ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding revision cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_goal_command_reopens_goal_question_and_realigns_to_auth or edit_goal_alias_reopens_goal_question_with_editable_goal_draft or revise_goal_alias_reopens_goal_question_with_editable_goal_draft or change_profile_alias_reopens_goal_question_with_editable_goal_draft or edit_profile_alias_reopens_goal_question_with_editable_goal_draft or revise_profile_alias_reopens_goal_question_with_editable_goal_draft or change_depth_alias_reopens_goal_question_with_editable_goal_draft or change_scope_command_reopens_scope_with_editable_draft_and_returns_to_confirmation or revise_scope_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or edit_scope_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or edit_target_alias_reopens_scope_with_editable_draft_and_persists_updated_scope or change_credential_alias_reopens_credential_detail_and_persists_updated_role or edit_credential_alias_reopens_credential_detail_and_persists_updated_role or revise_credential_alias_reopens_credential_detail_and_persists_updated_role or change_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or edit_token_alias_reopens_api_access_details_and_persists_updated_secret_reference or revise_token_alias_reopens_api_access_details_and_persists_updated_secret_reference'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-quaternary-revision-alias-proof-20260420-035919.json`
  - `codex/results/live-host-quaternary-revision-alias-edit-goal-20260420-035919.png`
  - `codex/results/live-host-quaternary-revision-alias-revise-goal-20260420-035919.png`
  - `codex/results/live-host-quaternary-revision-alias-revise-scope-20260420-035919.png`
  - `codex/results/live-host-quaternary-revision-alias-revise-credential-20260420-035919.png`
  - `codex/results/live-host-quaternary-revision-alias-edit-token-20260420-035919.png`

The advanced-confirmation realignment slice is also validated through targeted browser assertions, API/static-asset checks, a broader surrounding advanced-override cluster, and an independent live-host browser proof:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'clearing_advanced_scope_from_confirmation_returns_to_scope_with_visible_validation_feedback or authenticated_only_advanced_profile_from_confirmation_reopens_access_before_confirm'`
- API/static check:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_ui_support.py -k 'test_static_operator_console_is_served or test_ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding advanced-override cluster replay:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'advanced_drawer_overrides_stay_synchronized or automatic_new_dossier_name_tracks_advanced_scope_and_profile_overrides or manual_dossier_name_survives_advanced_scope_and_profile_overrides or clearing_advanced_scope_from_confirmation_returns_to_scope_with_visible_validation_feedback or authenticated_only_advanced_profile_from_confirmation_reopens_access_before_confirm'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-advanced-confirmation-realignment-proof-20260420-040923.json`
  - `codex/results/live-host-advanced-confirmation-realignment-scope-error-20260420-040923.png`
  - `codex/results/live-host-advanced-confirmation-realignment-access-required-20260420-040923.png`

The shared no-account access-context slice is also validated through targeted API/browser assertions and independent live-host browser proof:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'shared_manual_auth_note_without_accounts_persists_into_run_and_dossier_context or shared_session_note_without_accounts_persists_into_run_and_dossier_context or manual_note_only_roles_persist_into_run_and_dossier_context'`
- API check:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts or manual_note_only_roles_without_secret_bindings or manual_multi_role_access_without_secret_bindings'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-manual-auth-no-account-20260420.json`
  - `codex/results/live-host-shared-manual-auth-no-account-20260420.png`
  - `codex/results/live-host-shared-session-note-no-account-20260420.json`
  - `codex/results/live-host-shared-session-note-no-account-20260420.png`

The shared no-account access-revision slice is also validated through targeted browser coverage, supporting API checks, and independent live-host browser proof:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supporting API/static check:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts or static_operator_console_is_served or ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding browser cluster:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'shared_manual_auth_note_without_accounts_persists_into_run_and_dossier_context or shared_session_note_without_accounts_persists_into_run_and_dossier_context or change_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or direct_session_reference_route_and_change_session_alias_keep_session_access_truth or direct_session_reference_route_and_revise_session_alias_keep_session_access_truth'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-access-revision-no-account-20260420.json`
  - `codex/results/live-host-shared-manual-auth-revision-no-account-20260420.png`
  - `codex/results/live-host-shared-session-note-revision-no-account-20260420.png`

The shared no-account confirmation-button revision slice is also validated through targeted browser coverage, supporting API checks, and independent live-host browser proof:

- targeted browser regression:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'change_access_button_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_access_button_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supporting API/static check:
  - `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_runs.py api/tests/test_ui_support.py -k 'shared_manual_auth_notes_without_accounts or shared_session_notes_without_accounts or static_operator_console_is_served or ui_support_list_endpoints_reuse_existing_contracts'`
- surrounding browser cluster:
  - `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH=\"$PWD/.playwright-browsers\" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py -k 'shared_manual_auth_note_without_accounts_persists_into_run_and_dossier_context or shared_session_note_without_accounts_persists_into_run_and_dossier_context or change_access_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_session_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance or change_access_button_after_shared_manual_auth_note_without_accounts_reopens_note_and_persists_updated_guidance or change_access_button_after_shared_session_note_without_accounts_reopens_note_and_persists_updated_guidance'`
- supported-host proof on `http://127.0.0.1:8000`:
  - `codex/results/live-host-shared-access-confirmation-change-access-20260420.json`
  - `codex/results/live-host-shared-manual-auth-confirmation-change-access-20260420.png`
  - `codex/results/live-host-shared-session-note-confirmation-change-access-20260420.png`

The LAN/internal follow-through slice is also tracked in:

- `docs/operator_console_phase3_checklist.md`

The findings/evidence/report-integrity slice is also tracked in:

- `docs/operator_console_phase4_checklist.md`

The surface/explorer/history-usability slice is also tracked in:

- `docs/operator_console_phase5_checklist.md`

The calmness/hierarchy/readability slice is also tracked in:

- `docs/operator_console_phase6_checklist.md`

The broader acceptance-matrix slice is also tracked in:

- `docs/operator_console_phase7_checklist.md`

## How to run

1. Activate the repo virtual environment.
2. Install the browser runtime once:

```bash
./.venv/bin/python -m playwright install chromium
```

3. Run the browser suite:

```bash
./.venv/bin/pytest -q -s ui/tests/test_operator_console_e2e.py ui/tests/test_product_feature_matrix_e2e.py
```

4. Run the repo-owned UI matrix wrapper:

```bash
./.venv/bin/python scripts/run_product_e2e_matrix.py --lane ui
```

## Selector policy

- prefer `data-testid` selectors for cross-screen actions and key workflow elements
- use stable IDs for advanced-drawer fields where the DOM is already explicit
- avoid brittle selectors tied only to decorative text or panel order

## Current renderer assumptions

- Chromium is the required first browser
- the test server uses the same FastAPI app served in development
- the runtime remains deterministic; browser tests do not mutate active assessment logic beyond the normal operator flows they exercise
- report download validation now asserts browser-created files with the correct markdown, HTML, and PDF content signatures instead of only checking link wiring
