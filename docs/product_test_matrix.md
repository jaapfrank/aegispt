# Product Test Matrix

## Purpose

The product test matrix defines how AegisPT is validated as a working operator product, not only as a set of isolated API endpoints.

## Test lanes

The matrix is split into three additive lanes:

| Lane | Goal | Source of truth |
| --- | --- | --- |
| UI browser | Validate the operator flow in Chromium | `ui/tests/` and `codex/tasks/ui_acceptance_matrix.json` |
| API regression | Validate evidence, report, secret, and run contracts | `api/tests/` |
| Real run | Validate end-to-end safe runs against approved targets | `scripts/run_acceptance_matrix.py` and `codex/tasks/target_lab_matrix.json` |

## Coverage areas

| Area | What must be covered | Current status |
| --- | --- | --- |
| Conversational intake | intent handling, goal mapping, goal/assessment compatibility normalization, credentialed internal-range discovery-first normalization, deep/adaptive internal-range discovery-first normalization, scope safety, auth prompts, exact common auth phrasing, suggested-answer chip flows, advanced overrides, advanced-question realignment, review handoff, still-needed topic jump actions, confirmation-summary persistence, explicit existing-engagement reuse, explicit new-dossier creation, authorization-context persistence, scope-guardrail persistence, manual mission-name preservation, assessment-type wording truth across public-edge, passive-lane, and mixed-surface copy, completion across all supported assessment types, and created-run dossier parity for every supported assessment type | implemented |
| Intake calmness | concise visible thread, disclosure-based older context, disclosure-based revision controls that only surface already-captured topics, compact summary hierarchy, deduplicated still-needed actions, linked-topic badges, and current-question progress notes, a quieter intake shell with secondary mission context behind disclosure, and a true one-column narrow/mobile layout whose post-settle confirmation state keeps the thread, summary, and create-mission CTA readable together | implemented |
| Access-mode matrix | unauthenticated, credential reference, API key, bearer token, session reference, shared manual-auth notes with no account rows, shared session/cookie notes with no account rows, manual-auth-only note paths including note-only per-role MFA context without usernames or secret refs, advanced-settings access handoff, authenticated-to-unauthenticated revision downgrades, and authenticated-app unauthenticated routes that continue cleanly without access-detail dead ends stay synchronized in the wizard summary and created dossier | implemented |
| Multi-role authenticated context | dual-role credentialed with protected secrets, dual-role manual-auth / SSO without protected secret bindings, API-token/bearer, and session/cookie runs keep role context visible from intake through Mission Control and Explorer dossier review, including a safe dossier access-context block and per-role protected-binding metadata without raw secret disclosure; shared no-account manual/session guidance is also proven to remain visible as a truthful single access context | implemented |
| Wizard feature matrix | assessment-type presets, profile presets, validation-aware advanced override truth, profile-to-run dossier parity, module toggles, report download actions | implemented |
| Safety-cluster matrix | passive/light, guarded/standard, deep/guarded, and active-approved guardrail combinations stay visible and lane-aligned | implemented |
| Execution-outcome matrix | blocked `pending_approval` runs and failed `completed_with_errors` runs surface honest mission and status-board state | implemented |
| Adaptive-pack visibility matrix | deployed pack state, runtime binding, and adaptive report context stay synchronized across Mission Control, Pack Forge, Report Center, Explorer, and History | implemented |
| Codex build-lane lifecycle | repo-backed Codex tasks expose truthful prepare output, workspace export expectations, validation-result handoff, artifact-specific Playwright/ZAP validation cues, and shell-script reproducibility against a live host | implemented |
| Mission Control | current activity, ETA, run activity, grouped operational snapshot, grouped supporting context, selected task truth before and after dispatch, queued-web dispatch truth, thin-output warning continuity, and discovery-to-follow-up continuity | implemented |
| Drilldowns | findings, evidence, packs, reports, explorer, history, follow-up lineage visibility, searchable surface/history review, inventory delta visibility, and zero-finding run-level evidence posture | implemented |
| Error and empty states | setup, loading, failed fetch, no findings, no reports | implemented |
| Reporting | markdown, HTML, PDF preview/export behavior | implemented |
| Secret handling | protected secret bindings instead of raw run echo | implemented |
| Desktop / thick-client static assessment | authorized Windows/Electron-style artifact intake, extracted config and secret-signal review without raw secret echo, updater/code-signing posture signals, local storage/log exposure, IPC/local-helper metadata exposure, embedded URL/API endpoint inventory, and explicit unsupported boundaries for kernel drivers, process injection, malware triage, memory-corruption exploit development, and live helper probing | implemented / bounded |
| Acceptance harness | safe target selection, run creation, evidence/report/result capture | implemented |
| Nmap discovery regression | inline discovery dispatch, inventory ordering, and follow-up service enumeration remain covered in the composite API lane | implemented |
| Lab scenarios | local smoke plus documented training-lab scenarios, including active-safe WebGoat/crAPI prerequisite checks | implemented |

## Machine-readable inputs

The repo keeps the acceptance plan in JSON so Codex can execute it consistently:

- `codex/tasks/product_acceptance_matrix.json`
- `codex/tasks/ui_acceptance_matrix.json`
- `codex/tasks/target_lab_matrix.json`

These files are marked `catalog_only` so they are available to the controlled build and acceptance lane without polluting the visible Codex task queue.

The `wizard_revision_alias_matrix` scenario records these expected-output anchors for drift-resistant revision coverage: `editable_revision_draft_reopen`, `return_to_main_intake_path`, `output_style_revision_truth`, `output_style_phrase_alias_truth`, `output_style_normalization_truth`, `output_style_reporting_alias_truth`, `output_style_format_alias_truth`, `output_style_scope_preservation_truth`, `output_style_safety_lane_preservation_truth`, `output_style_confirmation_button_boundary_truth`, `output_style_mid_intake_button_truth`, `output_style_run_config_truth`, `output_style_mid_intake_run_config_truth`, `api_token_detail_truth`, `session_access_detail_truth`, `advanced_access_detail_revision_truth`, `shared_no_account_access_revision_truth`, `confirmation_button_access_revision_truth`, `shared_no_account_history_revision_truth`, `shared_no_account_stepper_revision_truth`, `previous_topic_access_revision_truth`, `back_command_normalization_truth`, `shared_no_account_last_answer_commands_truth`, `shared_no_account_edit_revise_alias_truth`, `shared_no_account_auth_alias_truth`, `shared_no_account_auth_phrase_parser_truth`, `polite_revision_command_wrapper_truth`, `case_whitespace_revision_command_normalization_truth`, and `safety_boundary_revision_truth`.

## Required scenario groups

### UI browser

- conversational internal-inventory flow
- conversational authenticated webapp flow
- conversational API / adaptive flow
- conversational completion matrix across all supported assessment types
- assessment-type dossier parity across all supported conversational flows so Mission Control and `configuration_json` stay aligned with the wizard promise
- internal-validation unauthenticated wording coverage using the literal phrase `Keep it unauthenticated`
- if an internal/LAN operator repeats `Unauthenticated` after access is already resolved and the current question has advanced to `Safety`, the wizard must keep focus on `Safety` and explain that access is already set instead of looking stuck
- if an operator reaches `Boundaries` and repeats the previous safety answer such as `Balanced`, the wizard must keep focus on `Boundaries` and explain that safety is already set instead of silently persisting that text as a boundary note
- if an operator reaches `Boundaries` and repeats the previous access answer such as `Unauthenticated`, the wizard must keep focus on `Boundaries` and explain that access is already set instead of silently persisting that text as a boundary note
- before the operator answers the first intent question, the intake summary must not overclaim a stale default target type, profile, execution lane, or ETA; those details may only appear once enough conversational or advanced-override context exists
- when the operator deliberately changes mission/profile/module/safety settings in Advanced Configuration, the summary must immediately reflect those deterministic choices instead of staying blank
- after a valid conversational `Goal` answer advances the wizard to `Scope`, the wizard must not immediately surface the untouched empty-state error `Add at least one target in scope.` before the operator has interacted with that scope question
- genuine advanced-scope validation defects must still remain visible when the wizard returns focus to `Scope`; the empty-state suppression above must not hide real invalid data such as a hostname entered into an IP-only field
- incompatible `Internal Validation` intent on web/API scope normalizes to the same deep web plan as the direct supported route, and scope revision from a valid LAN internal-validation mission to web scope keeps that same normalized plan instead of drifting back to the lighter assessment-type preset
- credentialed `Authenticated Review` on an internal range keeps the operator intent but stages the first run as discovery-first `Standard` / `passive-network-discovery`, and the same normalization holds when a credentialed authenticated web mission is later revised onto LAN scope
- `Deep Assessment` and `Adaptive Customer-Specific Testing` on an internal range keep the operator goal but stage the first run as discovery-first `Standard` / `passive-network-discovery`, and adaptive web scope revised onto LAN keeps that same staged internal plan instead of leaving a contradictory adaptive lane beside passive discovery
- `Deep Assessment` and `Adaptive Customer-Specific Testing` on an explicit WAN IP/CIDR mission now keep the operator goal but stage the first run as `External Surface Only` / `passive-network-discovery`, skip the premature access question, and keep the created run in `passive-only` mode
- `Authenticated Review` with supplied protected access on an explicit WAN IP/CIDR mission now keeps the access context attached but still stages the first run as `External Surface Only` / `passive-network-discovery`, with `active_checks = passive-only`
- revising an authenticated mission back to `Keep it unauthenticated` clears prior access/session payload and downgrades the created run from `Authenticated Review` / `Authenticated Only` to a compatible unauthenticated plan
- advanced-drawer override synchronization
- advanced override can change the next required topic and realign the current question without leaving a stale prompt behind
- invalidating a previously confirmation-ready mission through Advanced Configuration must drop the wizard back onto the blocking topic with visible feedback instead of leaving a fake-ready confirmation card
- revision-mode clarity when the operator reopens an earlier topic and returns to the main intake flow
- typed natural-language revision commands such as `change that` and `go back` reopen the last answered topic instead of leaving the operator on the current question, and access-detail revision drafts remain editable rather than collapsing into a lossy summary
- polite, case, spacing, and punctuation variants around back commands, such as `please go back?`, `UNDO!`, `please change that?`, and `PREVIOUS!`, must normalize into the same last-answer revision path without becoming separate canonical matrix commands
- the visible `Previous Topic` button must use that same truthful access-topic routing, including advanced drawer account detail and shared no-account manual/session guidance that reopens as editable note text and returns to `Safety` after revision
- that visible account-backed `Previous Topic` route is now explicitly proven across advanced credential, session, and API-token detail instead of only a single credential example
- typed last-answer aliases such as `undo` and `previous` must follow that same last-topic revision path, including reopening the editable captured draft instead of a collapsed summary
- typed goal-revision commands such as `change goal`, plus aliases such as `edit goal`, `revise goal`, `change profile`, `change depth`, `edit profile`, `revise profile`, `edit depth`, or `revise depth`, must reopen the goal question with the captured goal draft and then realign the next required topic from the updated deterministic run state
- typed output-style revision commands such as `change output`, `edit output`, and `revise output` must reopen a dedicated reporting-style draft, update only `intake_preferences.output_style`, and then return to the next deterministic intake topic without changing scope, safety, or execution lane
- multiword output-style aliases such as `change output style`, `edit output style`, `revise output style`, `change reporting style`, `edit reporting style`, `revise reporting style`, `change report style`, `edit report style`, and `revise report style` must route to that same output-style draft without introducing a separate style workflow
- report/format/reporting-worded output aliases such as `change report`, `edit report`, `revise report`, `change format`, `edit format`, `revise format`, `change reporting`, `edit reporting`, and `revise reporting` must route to that same output-style draft without introducing a separate reporting workflow
- output-style alias revisions must keep the locked target type, goal, scope detail, safety posture, and execution-lane context visible while only the output-style summary changes
- in-progress `Change Output` controls must reopen the same output-style draft from the safety question, then return to that safety question without changing target type, goal, or exact scope detail
- in-progress `Change Output` controls must also prove the created run's `configuration_json` stores the revised output style while preserving standard boundary handling and approved CIDR scope
- confirmation-ready `Change Output` controls must reopen the same output-style draft and keep boundary notes plus scope guardrails visible while only the output-style summary changes
- confirmation-ready `Change Output` controls must also prove the created run's `configuration_json` stores the revised output style while preserving boundary handling, boundary notes, and approved CIDR scope
- normalized output-style variants such as `please change output?` and `EDIT   OUTPUT!` must resolve to that same canonical output-style revision path without becoming separate matrix commands
- direct typed topic-jump commands such as `change scope`, `change target`, `change targets`, `change access`, `change auth`, `change credential`, `change credentials`, `change token`, `change tokens`, `change session`, `change sessions`, `change safety`, `change careful`, `change conservative`, `change aggressive`, `change thorough`, `change boundary`, `change boundaries`, `change exclusions`, `change excludes`, `change exclusion`, `change lateral`, `change avoid`, and `change exclude` must reopen the editable source draft for that captured topic and then return to the next required main-path question after the revision is applied
- polite wrappers around direct topic-jump commands, such as `please change scope?` and `change target please.`, must normalize into the same captured-topic revision path without becoming separate canonical matrix commands
- case and whitespace variants around direct topic-jump commands, such as `CHANGE   SCOPE!` and `edit   targets`, must normalize into that same captured-topic revision path without becoming separate canonical matrix commands
- if access detail was first captured through Advanced Configuration, later `change access`, `change auth`, `change credential`, `change session`, `edit access`, `edit auth`, `edit credential`, `edit token`, `edit session`, `revise auth`, `revise credential`, `revise session`, and `revise token` commands must still reopen that exact stored detail draft rather than a stale high-level auth-choice prompt
- advanced credential detail must now also stay truthful across `change auth`, `edit auth`, and `revise auth`, so auth-worded revisions against a stored username-plus-secret draft keep the operator on the exact credential detail instead of downgrading to the coarser auth-strategy topic
- if that advanced access detail is a shared no-account manual-auth or session note, later `change access`, `change auth`, `edit auth`, `revise auth`, or `change session` must reopen the raw note text and keep the route note-only unless the operator explicitly switches to a structured credential/session reference
- the same supported topic-jump path must also stay truthful for parser-supported `edit` / `revise` phrasing, including representative routes such as `edit scope`, `edit target`, `edit targets`, `edit access`, `edit auth`, `edit credential`, `edit credentials`, `edit token`, `edit tokens`, `edit safety`, `edit careful`, `edit conservative`, `edit aggressive`, `edit thorough`, `edit boundary`, `edit boundaries`, `edit exclusions`, `edit exclusion`, `edit excludes`, `edit lateral`, `edit avoid`, `edit exclude`, `edit session`, `edit sessions`, `revise access`, `revise auth`, `revise goal`, `revise profile`, `revise safety`, `revise careful`, `revise conservative`, `revise aggressive`, `revise thorough`, `revise scope`, `revise target`, `revise targets`, `revise token`, `revise tokens`, `revise credential`, `revise credentials`, `revise session`, `revise sessions`, `revise boundary`, `revise boundaries`, `revise exclusions`, `revise excludes`, `revise exclusion`, `revise lateral`, `revise avoid`, and `revise exclude`
- when the wizard is already on the confirmation card, disclosure-based revision controls such as `Change Boundaries` must reopen the same editable boundary draft instead of a synthesized summary
- when the wizard is already on the confirmation card, disclosure-based `Change Access` must also reopen shared no-account manual/session guidance as raw note text and return directly to confirmation after the revision if no other topic became invalid
- once the operator is already on `Access Detail`, answers such as `Keep it unauthenticated` must still be accepted as a real access-strategy change, clearing stored access/session/manual-auth context and returning to the next deterministic topic instead of leaving the operator trapped in a detail-only loop
- once the operator is already on `Access Detail`, token-bearing secret refs such as `vault://.../updated-token` must still be parsed as access detail instead of being mistaken for a high-level auth-strategy change and leaving the intake stuck on `Access Detail`
- direct session-reference routes must preserve `auth_strategy = session-access` after detail capture, and later `change session`, `edit session`, or `revise session` revisions must reopen a truthful editable draft that preserves the operator-facing session label instead of degrading into a lossy reconstruction
- confirmation summary remains readable after mission creation through the Explorer dossier handoff card
- existing-engagement reuse keeps the selected dossier, does not create a duplicate engagement, and remains visible in the Explorer handoff context
- new-engagement creation keeps a hand-entered dossier name stable, creates exactly one new engagement, and remains visible in the Explorer handoff context
- a hand-entered new-dossier name stays locked even if the operator later changes advanced scope and advanced profile before confirming the mission
- auto-generated new-dossier naming keeps tracking advanced scope and profile overrides until the operator explicitly replaces the suggested name, and that refreshed name persists into the created engagement and run dossier
- dossier authorization context stays aligned across the confirmation card, Explorer dossier, and stored run configuration for both reuse-existing and create-new routes
- advanced scope exclusions and boundary notes stay aligned across the confirmation card, Explorer dossier, and stored `boundary_handling` metadata
- richer mixed/auth/adaptive routes must stop for an explicit boundary answer before confirmation instead of silently inheriting `Standard Scope Only`
- supported standard and unauthenticated deep web-facing routes must also stop for an explicit boundary answer after `Safety` instead of silently inheriting `Standard Scope Only`
- revising scope into a boundary-sensitive route such as an internal CIDR must clear an older generic boundary confirmation and re-ask `Boundaries`
- revising a LAN route that was carrying `Report Adjacent Ranges Only` onto a non-internal web scope must clear that stale lateral-discovery copy and fall back to a normal web-boundary default instead of keeping internal expansion wording on the revised mission
- revising an API mission onto a plain website URL while reviewing `Scope` must reclassify the run to `Website / Web App`, move the target into `urls` instead of `api_base_urls`, and re-ask `Boundaries` when the preserved token-bearing access context still makes the route access-aware
- once a revised route is no longer internal, the `Boundaries` question and Advanced Configuration boundary-notes placeholder must also switch to generic scope wording and must not keep the internal-only `Report adjacent internal ranges only` quick reply
- `Domain / Domains` missions that choose `Deep assessment` must stay unauthenticated by default after scope instead of surfacing an access question just because the generic `Deep` profile would otherwise enable `auth_flows`
- `Website / Web App` missions that choose richer non-auth goals such as `Deep assessment` or `Adaptive customer-specific testing` must also stay unauthenticated by default after scope instead of surfacing an access question just because the richer profile preset would otherwise enable `auth_flows`
- confirmation copy keeps exact scope-guardrail wording readable for both one exclusion and multiple exclusions
- notes-only boundary guidance stays distinct from structured exclusions across the confirmation card and Explorer dossier
- notes-only boundary fallback remains truthful even when older/missing metadata does not explicitly carry `boundary_handling`
- revising `Boundaries` to `No extra exclusions` clears previously entered advanced exclusions and notes across confirmation and Explorer instead of leaving stale contradictory guardrails behind
- revising `Boundaries` from explicit exclusions to notes-only guidance replaces the denylist payload instead of merging both meanings
- still-needed summary actions that jump into a later missing topic and then return to the next required main-path question
- still-needed summary cards that suppress redundant jump actions for the already-active topic, suppress linked same-question leftover badges, and do not echo the same remaining item in both actions and badges
- current-question progress notes that suppress the already-active topic family so `Goal` / `Output` and `Access` / `Access Detail` do not compete with the question currently on screen
- the initial intent screen must keep a truthful still-needed horizon: before intent is answered it may not prematurely claim `Access` or `Output` as blocking topics unless the operator has already made them relevant through advanced overrides or a mission type that genuinely requires them
- common natural-language portal phrasing such as `Our customer portal` must classify into the authenticated-app route instead of degrading to the generic web-app path, and the resulting run dossier must persist the authenticated profile/lane combination
- TLS-only intent must keep goal selection bounded: only TLS-safe quick replies should appear, and unsupported typed goals such as `Deep assessment` must normalize into a truthful standard TLS-only dossier instead of leaving a contradictory deep/adaptive TLS run promise
- TLS-only missions must still stop for explicit `Safety` and `Boundaries` confirmation after scope instead of silently inferring those guardrails and jumping straight to mission creation
- advanced-settings access routes where `Access` remains visibly pending, opens the advanced drawer directly from the still-needed summary, and realigns to the next topic once access detail is actually present
- once advanced access detail has been captured, later revision commands such as `change access`, `edit access`, `change auth`, `edit auth`, `revise auth`, `change credential`, `edit credential`, `revise credential`, `change token`, `edit token`, `revise token`, `change session`, `edit session`, or `revise session` must reopen the exact stored access-detail draft instead of dropping back to the older high-level auth-strategy question
- assessment-type preset matrix across all supported intake types
- profile-to-lane matrix across representative operator profiles
- profile-to-run dossier parity across representative operator profiles, including persisted `assessment_type`, `test_profile`, `execution_profile`, and approved scope
- invalid advanced scope/profile combinations must never surface a fake confirmation-ready state; they must return focus to the blocking topic with visible validation feedback
- module toggle rendering and summary synchronization
- Pack Forge Codex task preparation, including the displayed export command, validation handoff command, and `validation-result.json` output path
- calmer intake hierarchy and revision/context disclosures
- revision controls that stay hidden until a real earlier topic is captured, then only expose the topics already locked into the run dossier
- intake focus-shell behavior with secondary mission context collapsed by default
- narrow/mobile intake layout that keeps the rail below the wizard, preserves readable wizard width, and keeps the confirmation summary plus `Create Mission` CTA visible together after the settle-scroll completes
- access-mode matrix across supported auth-entry styles
- authenticated-app routes that explicitly stay unauthenticated and continue directly to the next real topic instead of forcing access-detail capture
- session/cookie access from advanced override through Mission Control and Explorer dossier review
- shared manual-auth guidance without account rows across wizard, Mission Control, and Explorer dossier review
- shared session/cookie guidance without account rows across wizard, Mission Control, and Explorer dossier review
- revision of shared manual-auth/session guidance without account rows, preserving truthful no-account access contexts after the note is edited
- confirmation-card `Change Access` revision of shared manual-auth/session guidance without account rows, preserving truthful no-account access contexts after the note is edited
- `Earlier Intake Context` inline `Change` revision of shared manual-auth/session guidance without account rows, reopening the exact stored note text and preserving truthful no-account access contexts after the note is edited
- top progress-stepper `Access` revision of shared manual-auth/session guidance without account rows, reopening the exact stored note text and preserving truthful no-account access contexts after the note is edited
- visible `Previous Topic` revision of advanced access detail plus shared manual-auth/session guidance without account rows, reopening the exact stored draft/note text and returning to `Safety` after the revision is applied
- typed last-answer commands on shared manual-auth/session guidance without account rows, including `change that`, `undo`, `previous`, and `go back`, reopening the exact stored note text and preserving truthful no-account access contexts after the note is edited
- edit/revise alias commands on shared manual-auth/session guidance without account rows, including `edit access`, `revise access`, `edit session`, and `revise session`, reopening the exact stored note text and preserving truthful no-account access contexts after the note is edited
- longer free-text updates on shared manual-auth/session guidance without account rows, including note text that merely contains or begins with phrases such as `revise access`, `edit session`, `change auth`, `edit auth`, or `revise auth`, staying stored as note text instead of being hijacked as parser commands
- multi-role authenticated context across wizard, mission, and dossier views
- multi-role manual-auth / SSO context across wizard, mission, and dossier views, including zero-binding access review with shared handoff notes and per-role MFA notes
- note-only per-role MFA/manual-auth context across wizard, mission, and dossier views, including `Username: Not recorded` plus `0 secret bindings`
- representative chip-driven web, LAN, and API intake flows, including the internal LAN route where safety must still be asked explicitly before boundaries and confirmation
- assessment-type wording truth across the wizard and confirmation handoff:
  - public-edge `External IP / WAN` routes must keep public IP/CIDR language instead of internal-host language
  - passive execution lanes must not claim that guarded active validation is enabled in the same confirmation card
  - mixed-surface confirmation copy must not duplicate the word `assessment`
- external WAN rich-goal truth across the wizard and confirmation handoff:
  - WAN goal quick replies must flag staged follow-up language instead of implying an immediate deep/adaptive perimeter run
  - typed `Deep Assessment` and `Adaptive Customer-Specific Testing` answers must stage the created run as `External Surface Only` / `passive-network-discovery`
  - once WAN scope is recorded on those staged routes, the next question must be `Safety`, not `Access`
- safety-cluster matrix across supported guardrail styles
- adaptive-pack visibility across mission, pack, report, dossier, and history surfaces
- end-to-end intake to Mission Control flow
- blocked and failed execution-outcome visibility
- queued-web dispatch truth where explicit URL targets win over derived host/IP duplicates, the dispatch mask falls away once the run is observed beyond `queued`, and thin-output review warnings stay visible in Run Activity
- end-to-end LAN discovery to follow-up service-identification flow
- phase isolation plus grouped Mission Control support-panel behavior
- searchable Surface Map review after LAN discovery
- Explorer dossier-summary review for selected runs
- History search and inventory-delta comparison behavior
- navigation across all major product areas
- zero-finding Evidence Replay behavior for discovery and follow-up runs
- follow-up lineage visibility in Explorer, Report Center, and History
- report preview and real browser download validation
- empty and blocked states
- safe rejection of unauthorized public target expansion

### API regression

- run creation and dispatch
- engagement-context normalization on run creation so dossier `Customer` / `ROE Reference` metadata matches the real engagement truth
- report catalog and export
- discovery-only and follow-up report integrity
- secret sanitization
- pack and provenance contract stability
- acceptance-harness helper coverage

### Real run

- local smoke run
- safe web training lab
- approval-gated authenticated lab
- adaptive pack-aware lab

## Pass criteria

A matrix scenario is considered passed when:

- the expected product surface exists
- the expected outputs are produced
- no unauthorized target was used
- evidence/report/history context is still linked back to the run
- discovery-derived follow-up runs remain linked back to the source run and source inventory snapshot where applicable

## Evidence produced by the matrix

Depending on the lane, validation should leave behind:

- pytest output
- Playwright traces/screenshots on failure
- acceptance result JSON under `codex/results/`
- run/report links for the validated scenario

## Composite runner

Use the repo-owned wrapper when you want one deterministic command instead of running the suites manually:

```bash
./.venv/bin/python scripts/run_product_e2e_matrix.py --lane all
```

This executes:

- the acceptance-harness and inline-`nmap` API regressions
- the API/product regression lane
- the operator-console browser lane
- the broader feature/options browser matrix

Latest full rerun evidence for the current supported-path contract:

- composite repo matrix passed again on 2026-04-19 through `scripts/run_product_e2e_matrix.py --lane all`
- Phase 2 execution-truth host signoff was independently re-proven on `127.0.0.1:8000` through:
  - `codex/results/live-host-phase2-run-execution-signoff-20260419.json`
  - `codex/results/live-host-phase2-run-execution-blocked-20260419.png`
  - `codex/results/live-host-phase2-run-execution-dispatch-20260419.png`

## Current explicit non-blockers

The supported-path matrix is now signed off, but the acceptance story is still not exhaustive. Current explicit non-blockers include:

- broader multi-account / multi-role browser flows across every comparison outcome and every remaining auth family beyond the currently proven credentialed-login with protected secrets, manual-auth / SSO without secret bindings, shared no-account manual/session guidance, API-token/bearer, and session/cookie paths
- broader blocked/failed-state coverage across every assessment/profile family
- deeper adaptive-pack permutations beyond the current mission/pack/report/dossier/history contract
- any additional future real-run scenario beyond the currently proven local smoke, Juice Shop, WebGoat, and crAPI paths when that extra lab stack is not yet live where the harness is executed
