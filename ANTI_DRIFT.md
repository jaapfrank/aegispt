# Anti-Drift Contract

**Waarom dit bestaat:** sprint mythos-foundation (2026-05-19 t/m 2026-05-20) leverde 10 commits, 24 claude_picks, 6 high+critical findings — maar **0 daadwerkelijke penetraties en `chain_findings` bleef nul op alle 5 targets**. Code was "structurally correct" en alle unit tests waren groen, zonder dat het system end-to-end één extra exploit uitvoerde. Plumbing zonder capability. Dit document is het structurele tegengewicht.

ANTI_DRIFT.md staat naast [SESSION_PROMPT.md](SESSION_PROMPT.md):
- **SESSION_PROMPT.md** = HOE een sessie te starten (operationeel)
- **ANTI_DRIFT.md** = WELKE code je mag toevoegen (technische discipline)

Beide MOETEN geladen worden bij elke sessie. Memory regel `feedback-anti-drift-contract` verwijst hier ook naar.

---

## De 5 hard rules

### Rule 1 — User-value metrics, geen code-structural metrics

**DONE wordt gemeten aan:**

- XBOW benchmark score (% van 104 challenges solved)
- `exec_plan_successful` count op real targets
- `chain_findings` count op real targets
- `captured_value` entities emitted
- time-to-first-proof per target
- penetration depth (foothold-state transitions)
- backlog-419 release gate predicates

**DONE wordt NIET gemeten aan:**

- lines of code added
- unit tests passing
- ruff clean / compileall clean / git diff --check clean
- "function exists in module"
- "class is importable"
- "structurally correct"
- "sentinel test passes"

De technische checks zijn **voorwaarden**, geen bewijs. Bewijs = de user-value metric is meetbaar bewogen, geverifieerd via observability of DB-query.

### Rule 2 — No dead code

Elke functie, class, module, kwarg of constant toegevoegd in een task MOET binnen DEZELFDE task aangeroepen worden door production code dat een externe API request kan triggeren. Aantoonbaar via:

- `git grep` voor call sites laat ≥1 production caller zien
- Trace van API endpoint → service → jouw code is opvraagbaar
- Live test waarin jouw code daadwerkelijk runtime loopt (gelogd of via metric)

**Als je iets toevoegt dat een latere task pas gaat aanroepen: dat is uit-scope.** Verplaats het toevoegen naar de latere task. Niet vooruitwerken "voor de zekerheid".

### Rule 3 — Geen silent backward-compat creep

Vervang je oude code met nieuwe? **Verwijder de oude in dezelfde commit.** Geen `stack_hints` kwarg die no-op wordt "voor één release". Geen ongebruikte parameters met `# noqa F841` comments. Geen "deprecated maar geldig" markeringen die nooit removal-datum krijgen.

**Uitzondering**: als breaking change risico onbekend is, maak een EXPLICIETE deprecation commit met:
- Removal-datum in code-comment
- Failing-test die alle huidige callers vindt
- Plan voor migratie

Géén "voor de zekerheid bewaard" code. Géén "misschien later weer nodig" code.

### Rule 4 — Geen mocked-live equivalence claims

Unit tests met mocked dependencies bewijzen NIET dat code in productie werkt. Capability tasks (target_intel emit, exec_plan, validator, multi-agent coordinator, etc.) zijn pas DONE wanneer:

- Live integration tegen real target draait
- Delta-metric is meetbaar bewogen (cite specifieke meting)
- Bij twijfel of dit haalbaar is: per `feedback-self-validation` — agent voert live test zelf uit voordat DONE claim

Geen "structureel correct, live validatie deferred" — die zin betekent NOT DONE.

### Rule 5 — Geen "subsumed by next task" closures zonder bewijs

Closing task B als SUBSUMED-BY-task-A vereist:

- Task A's empirische delta dekt B's intended delta aantoonbaar
- B's success criteria zijn één-voor-één afgetekend tegen A's evidence
- B's queue entry krijgt `[CLOSED-SUBSUMED-BY-A — VERIFIED yyyy-mm-dd]` annotatie
- DONE_LOG entry citeert specifiek welke A-evidence welk B-criterium dekt

Niet: "vermoedelijk dekt A dit ook, sluit B".

---

## Pre-commit checklist (verplicht in commit message)

Voor elke commit die een task afsluit als DONE, vul deze checklist in:

```markdown
## Pre-commit drift check (per ANTI_DRIFT.md)

- [ ] Mijn code is INVOKED in production path (call site: <file:line> of API endpoint trace)
- [ ] Delta-metric bewoog: <metric> van <baseline> naar <new> op <target(s)>
- [ ] Removed code I replaced: <git diff line count voor deletions OR expliciete "no removal needed because additive">
- [ ] Geen scope creep: alle changes vallen binnen task package scope
- [ ] Follow-ups gefiled voor blocked items: <backlog-NNN refs OR "none, all in scope">
- [ ] Live test geslaagd (niet alleen unit): <link to validation report OR expliciete "structural-only task: <reden>">
```

**Commits zonder ingevulde checklist tellen NIET als DONE.** Operator kan `git log --grep="drift check"` draaien om te zien welke commits de discipline volgden.

---

## DONE-definitie strenger (vervangt SESSION_PROMPT §5)

Een capability-task is DONE wanneer ALLE van:

1. Required checks pass (per SESSION_PROMPT §3)
2. Live acceptance per task package criteria (per SESSION_PROMPT §4)
3. **Pre-commit checklist hierboven volledig ingevuld in commit message**
4. **Delta-metric op user-value metric bewoog meetbaar** (Rule 1)
5. **Geen dead code toegevoegd** (Rule 2)
6. **Geen silent backward-compat creep** (Rule 3)
7. **Live test gepasseerd, niet mocked-only** (Rule 4)
8. DONE_LOG entry citeert specifieke metric movement met before/after numbers
9. TASK_QUEUE.md annotatie is consistent (DONE / SUBSUMED-BY met bewijs)

Als ÉÉN van deze 9 false is: NIET DONE. STOP en surface aan operator.

---

## Stop-gates uitgebreid (naast SESSION_PROMPT §6)

Stop en vraag, niet doorgaan, zodra:

- **Drift gedetecteerd**: tijdens task implementatie merk je dat de delta-doelstelling niet aantoonbaar haalbaar is binnen scope → STOP
- **"Plumbing zonder capability"**: tijdens implementatie ontdek je dat je code plumbing toevoegt zonder eind-effect → STOP, herzie scope
- **Twijfel over "subsumed"**: voordat je een task als SUBSUMED markeert → STOP, vraag operator om verifiable success-criteria mapping
- **Dead code temptation**: je staat op het punt iets toe te voegen dat pas later wordt gebruikt → STOP, verplaats naar latere task
- **Backward-compat aanmoediging**: je overweegt een no-op kwarg te bewaren "voor de zekerheid" → STOP, vraag of het echt nodig is

---

## Wat ANTI_DRIFT NIET vervangt

- SESSION_PROMPT.md (operationeel — orientatie / required checks / promote next)
- Per-task `success_criteria` in JSON pakket (specifieke verwachte deliverables)
- Memory rules (behavioral): `feedback-live-proof-before-done`, `feedback-live-proof-must-be-diverse-real-targets`, `feedback-no-prescriptive-recipes`, `feedback-deferred-capability-followup`

ANTI_DRIFT.md is de TECHNISCHE concretisering van die memory rules in code-discipline.

---

## Geldigheid

Dit contract geldt vanaf commit dat ANTI_DRIFT.md aan repo toevoegt. Geldt voor ELKE task die DONE wordt geclaimd. Geen retroactief — vorige sprint mythos-foundation blijft historisch.

Aanvulling/wijziging vereist:
- Operator approval
- Memory entry update (`feedback-anti-drift-contract`)
- Commit "ANTI_DRIFT.md: rule X gewijzigd — reden Y"

---

## Aangemaakt 2026-05-20 na sprint mythos-foundation review

Direct gevolg van empirische drift: sprint leverde 10 commits + 0 chain_findings. Sprint mythos-exploitation-foundation start onder dit contract.
