# UI Conversational Intake

## Layout

- left column: conversation history plus one active question
- right column: live mission summary
- inline toolbar: advanced configuration toggle plus restart
- advanced drawer: synchronized deterministic controls

## Main behaviors

- the operator answers through free text or quick reply chips
- prior answers remain visible in the thread
- each conversational answer updates the same run model used for mission creation
- natural-language revision commands are supported:
  - `go back`, `undo`, or `previous` reopen the last answered topic
    - back-command casing, spacing, polite prefixes, and trailing punctuation normalize before routing too, with browser proof for `please go back?`, `UNDO!`, `please change that?`, and `PREVIOUS!`
  - the visible `Previous Topic` button now has that same truthful access-detail behavior on the supported advanced-access routes:
    - if an access account/role was captured through Advanced Configuration, `Previous Topic` from `Safety` reopens the exact stored `Access Detail` draft instead of falling back to the coarser auth-strategy question
      - that account-backed route is now explicitly proven for credential, session, and API-token detail instead of only the earlier credential example
    - if Advanced Configuration captured only shared manual-auth guidance or only shared session guidance with no account rows, `Previous Topic` reopens that exact stored note text and returns to `Safety` after the revised note is applied
  - `change that` now also reopens the last answered topic instead of only refocusing the current question
  - that same last-answer command family is now explicitly proven for shared no-account advanced-access routes too:
    - typed `change that` reopens shared manual-auth guidance as editable note text and returns to `Safety` after the revised note is applied
    - typed `undo` reopens shared manual-auth guidance as editable note text and returns to `Safety` after the revised note is applied
    - typed `previous` reopens shared session guidance as editable note text and returns to `Safety` after the revised note is applied
    - typed `go back` reopens shared session guidance as editable note text and returns to `Safety` after the revised note is applied
  - typed `change goal` reopens the goal question with the captured goal draft, and the same route is now explicitly proven for `edit goal`, `revise goal`, `edit profile`, `revise profile`, `edit depth`, `revise depth`, and typed aliases such as `change profile` or `change depth`
  - typed `change output`, `edit output`, and `revise output` reopen a dedicated reporting-style draft, update only `intake_preferences.output_style`, and then return to the next deterministic intake topic without changing scope, safety, or execution lane
    - multiword output-style aliases `change output style`, `edit output style`, `revise output style`, `change reporting style`, `edit reporting style`, `revise reporting style`, `change report style`, `edit report style`, and `revise report style` follow that same output-style route instead of creating a separate style workflow
    - report/format/reporting-worded aliases `change report`, `edit report`, `revise report`, `change format`, `edit format`, `revise format`, `change reporting`, `edit reporting`, and `revise reporting` follow that same output-style route instead of creating a separate reporting workflow
    - those output-style alias routes are browser-guarded to keep the locked target type, goal, scope detail, safety posture, and execution-lane context visible while only the output-style summary changes
    - confirmed output-style choices also expose `Change Output` in the captured-topic revision controls, including from an in-progress safety question and from a confirmation-ready mission; browser proof returns to the correct next intake topic and keeps boundary notes, scope detail, or scope guardrails visible while only the output-style summary changes
    - after confirmation, that same button path is API-verified against the created run's `configuration_json` so `intake.preferences.output_style`, boundary handling, boundary notes, and approved CIDR scope stay aligned with the revised mission summary
    - the in-progress safety-question `Change Output` path is also API-verified after mission creation, so the revised output style, standard boundary handling, and original CIDR scope land in the deterministic run dossier
    - output-style command normalization uses that same parser path too, with browser proof for `please change output?` and `EDIT   OUTPUT!`
  - while a live question input is on screen, typed commands such as `change scope`, `change target`, `change targets`, `change access`, `change auth`, `change credential`, `change credentials`, `change token`, `change tokens`, `change session`, `change sessions`, `change safety`, `change careful`, `change conservative`, `change aggressive`, `change thorough`, `change boundary`, `change boundaries`, `change exclusions`, `change excludes`, `change exclusion`, `change lateral`, `change avoid`, and `change exclude` jump straight to that captured topic with an editable source draft
  - polite command wrappers use that same parser path: a single leading or trailing `please` plus trailing `.`, `!`, or `?` is normalized before routing, with browser proof for `please change scope?` and `change target please.`
  - command casing and spacing are normalized before routing too, with browser proof for `CHANGE   SCOPE!` and `edit   targets`
  - the same parser-supported verb family is now evidence-backed for supported topic jumps such as `edit scope`, `edit target`, `edit targets`, `edit access`, `edit auth`, `edit credential`, `edit credentials`, `edit token`, `edit tokens`, `edit safety`, `edit careful`, `edit conservative`, `edit aggressive`, `edit thorough`, `edit boundary`, `edit boundaries`, `edit exclusions`, `edit exclusion`, `edit excludes`, `edit lateral`, `edit avoid`, `edit exclude`, `edit session`, `edit sessions`, `revise access`, `revise auth`, `revise goal`, `revise profile`, `revise safety`, `revise careful`, `revise conservative`, `revise aggressive`, `revise thorough`, `revise scope`, `revise target`, `revise targets`, `revise token`, `revise tokens`, `revise credential`, `revise credentials`, `revise session`, `revise sessions`, `revise boundary`, `revise boundaries`, `revise exclusions`, `revise excludes`, `revise exclusion`, `revise lateral`, `revise avoid`, and `revise exclude`
  - safety synonyms are now explicitly proven too: the `careful` family (`change careful`, `edit careful`, and `revise careful`), `conservative` family (`change conservative`, `edit conservative`, and `revise conservative`), `aggressive` family (`change aggressive`, `edit aggressive`, and `revise aggressive`), and `thorough` family (`change thorough`, `edit thorough`, and `revise thorough`) reopen the same exact stored safety draft instead of relying only on the `safety` noun by implication
  - representative plural auth-detail nouns are now explicitly proven too: `change credentials`, `edit credentials`, `revise credentials`, `change tokens`, `edit tokens`, `revise tokens`, `change sessions`, `edit sessions`, and `revise sessions` reopen the same exact stored access-detail drafts instead of relying on the singular examples by implication
  - representative boundary synonyms are now explicitly proven too: the `lateral` family (`change lateral`, `edit lateral`, and `revise lateral`), the `exclusions` family (`change exclusions`, `edit exclusions`, and `revise exclusions`), the `excludes` family (`change excludes`, `edit excludes`, and `revise excludes`), the `exclusion` family (`change exclusion`, `edit exclusion`, and `revise exclusion`), the `avoid` family (`change avoid`, `edit avoid`, and `revise avoid`), and the `exclude` family (`change exclude`, `edit exclude`, and `revise exclude`) reopen the same stored boundary draft instead of relying only on the `boundary` / `boundaries` wording
  - if access detail was captured through Advanced Configuration, later `change access`, `change auth`, `change credential`, `change session`, `edit access`, `edit auth`, `edit credential`, `edit token`, `edit session`, `revise auth`, `revise credential`, `revise session`, or `revise token` revisions reopen the exact stored access-detail draft instead of falling back to the older high-level auth-strategy question
    - advanced credential detail now also has explicit `change auth` / `edit auth` / `revise auth` symmetry proof, so auth-worded revisions on a stored username-plus-secret route reopen the exact credential draft instead of drifting back to the coarse auth-strategy prompt
  - that same advanced-detail revision path is now explicitly proven for shared no-account access contexts too:
    - `change access`, `edit access`, and `revise access` reopen shared manual-auth guidance as editable note text instead of fabricating a fake account row
    - `change session`, `edit session`, and `revise session` reopen shared session guidance as editable note text instead of fabricating a fake account row
    - `change auth`, `edit auth`, and `revise auth` also reopen the same shared manual-auth/session note text instead of dropping back to the coarse auth-strategy question or silently withdrawing the note-only access context
    - longer free-text note updates that merely contain phrases such as `revise access`, `edit session`, `change auth`, `edit auth`, or `revise auth` are now stored as note text instead of being hijacked as topic-jump commands, even when those phrases appear at the start of the replacement note text
  - once the intake is already on the confirmation card, the same earlier-topic revisions stay available through `Revise Captured Topic` disclosure buttons such as `Change Boundaries`
  - that confirmation-layer click path is now also explicitly proven for shared no-account access contexts: `Change Access` reopens the stored shared manual-auth note or shared session note and returns directly to confirmation after the revised note is applied
  - the older inline `Change` button path is now also explicitly proven for those same shared no-account advanced-access routes:
    - once shared manual-auth guidance or shared session guidance is captured through Advanced Configuration, the intake now syncs a truthful revisable history turn into `Earlier Intake Context`
    - clicking that inline `Change` button reopens the exact stored note text instead of dropping the operator back onto a lossy auth-strategy summary
    - after revision, the created run still preserves the truthful no-account access context (`accounts = []`) while updating only `manual_auth_steps` or `cookie_notes`
  - the top progress-stepper `Access` button is now also explicitly proven for those same shared no-account advanced-access routes:
    - once shared manual-auth guidance or shared session guidance is captured through Advanced Configuration, clicking the `Access` step reopens the exact stored note text instead of the coarse auth-strategy question
    - after revision, the operator returns cleanly to confirmation and the created run still preserves the truthful no-account access context (`accounts = []`) while updating only `manual_auth_steps` or `cookie_notes`
- the `Access Detail` question is not a one-way dead end:
  - it still accepts direct access detail such as usernames, token refs, session refs, or secret refs
  - it also accepts access-strategy changes such as `Keep it unauthenticated`, which immediately withdraw access and returns the intake to the next real required topic
  - token/session wording inside the secret reference itself no longer causes that answer to be misread as a strategy-only change; detail refs such as `vault://.../updated-token` remain editable access detail
  - direct session-reference routes now stay labeled truthfully as `session-access`, and session-only revise drafts such as `change session`, `edit session`, or `revise session` preserve the operator label instead of collapsing into a lossy `role ... session role` reconstruction
- Advanced Configuration can also invalidate a previously ready confirmation state:
  - if the operator clears required scope in the drawer after reaching `Confirm`, the intake immediately returns to `Scope`, hides the confirmation card, and now shows visible validation feedback instead of leaving a silent fake-ready state
  - if the operator switches the profile to an auth-required route such as `Authenticated Only`, the intake immediately returns to `Access` before confirmation and requires real access context instead of pretending the mission is still ready
  - if the operator records multiple authenticated roles in the drawer, the confirmation summary now keeps the combined role labels visible and the created Explorer dossier now exposes a safe `Access Contexts` block with auth strategy, protected-binding count, manual-auth notes, and per-role metadata without revealing raw secret material
  - that safe dossier path is now evidence-backed for:
    - multi-role credentialed login with protected secrets
    - multi-role manual-auth / SSO context without protected secret bindings
    - per-role manual-auth / MFA note-only context without usernames or secret refs
    - multi-role API token/bearer context
    - multi-role session/cookie context
    - shared manual-auth guidance with no account rows at all
    - shared session/cookie guidance with no account rows at all
  - this means operators can review multiple access roles after run creation even when a run depends on shared SSO choreography or per-role MFA notes instead of stored secret material
  - the same advanced access drawer no longer treats shared `Manual Auth` or `Session Notes` as second-class metadata:
    - shared manual-auth guidance without account rows now completes the auth path as a truthful `Credentialed Login` access context
    - shared session/cookie guidance without account rows now completes the auth path as a truthful `Session / Cookie` access context
    - Mission Control and Explorer keep those routes visible as `1 access context` instead of collapsing them to `No access context recorded`
    - later conversational revisions keep those no-account routes truthful as well, so updated shared manual/session guidance stays note-only unless the operator intentionally switches to a structured credential or session reference
- the summary panel separates:
  - confirmed
  - inferred
  - still needed

## Confirmation

Before run creation, the UI presents:

- a natural-language mission summary
- active-check / safety phrasing
- ETA
- visible advanced overrides if any exist
- exact target detail remains visible in the `Targets & Access` disclosure so scope revisions can be verified before mission creation
- revision disclosures reopen editable source drafts instead of collapsed summaries, including:
  - exact CIDR or target text for scope
  - exact access-detail lines for credentialed access context
  - the current safety posture wording
  - the stored boundary reply or note text

The operator can then:

- confirm
- edit a prior topic
- open advanced controls
- restart intake

## Design rules

- conversation should feel calm and guided, not like a toy chatbot
- important information must remain visible without dumping every low-level field into the main thread
- power-user control stays available, but hidden by default
