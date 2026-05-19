# AegisPT werksessie — sprint mythos-foundation

**Paste deze hele file als kickoff prompt aan het begin van elke nieuwe Claude sessie waarin je AegisPT werk wilt doen.** De prompt is bewust kort en operationeel; alle WHY zit in de memory files waarnaar het verwijst. Versioned in git zodat de discipline mee-evolueert met het project.

## 0. Oriëntatie — lees vóór elke actie

1. `NEXT_TASK.md`
2. Het bijbehorende `codex/tasks/backlog-NNN-*.json` (scope, must_not_touch, success_criteria, live acceptance)
3. `docs/validation/sprint-2026-mythos-foundation-*-baseline.md` — de empirische startgetallen
4. De laatste 3 entries van `DONE_LOG.md`
5. Memory files: `feedback_live_proof_before_done`, `feedback_live_proof_must_be_diverse_real_targets`, `feedback_no_prescriptive_recipes`, `feedback_deferred_capability_followup`. Deze 4 regels **overschrijven altijd** wat Claude van plan is — als ze botsen met instinct, volgt Claude de regel.

## 1. Voor elke task: declare delta-doelstelling

Vóór de eerste code-edit, expliciet uitspreken:

> "Deze task verhoogt metric X van Y (baseline) naar ≥Z op ≥N van de 5 targets."

Geen numerieke voorspelling = task te vaag → STOP en vraag de operator.

## 2. Forbidden — auto-fail van de task

- Per-target conditional in production code (`if 'mantis' in url:` etc.) — `tests/test_multi_target_validation_grep_guard.py` faalt automatisch.
- Pre-baked path/payload/stack registries in `workers/runners/` of `api/app/services/` (`_STACK_*_REGISTRY`, `_KEYWORD_HINTS`, `_REGISTER_PATHS`, etc. zijn anti-patterns).
- DONE claimen op alleen groene unit tests.
- "Out of scope" zeggen en shippen i.p.v. follow-up backlog-task filen in dezelfde commit.
- Stille reverts van eerder werk zonder operator-bevestiging.
- Validatie op Gruyere / juice-shop / DVWA / testfire / vulnweb — dat zijn training apps; ze tellen NIET als bewijs.

## 3. Required checks (in volgorde, allemaal pass)

```bash
python3 scripts/validate_backlog_tasks.py
.venv/bin/pytest <task-relevant tests>
python3 -m compileall -q workers api
.venv/bin/ruff check <touched files>
.venv/bin/pytest tests/test_multi_target_validation_grep_guard.py
git diff --check
```

## 4. Live-acceptance (sprint-specifiek)

```bash
DATABASE_URL=postgresql+psycopg://aegispt:aegispt_dev_pw@127.0.0.1:5432/aegispt \
AEGISPT_API_URL=http://127.0.0.1:8000 \
python3 scripts/multi_target_validation.py --target all --phase after-NNN
```

Het rapport in `docs/validation/sprint-2026-mythos-foundation-{date}-after-NNN.md` MOET een meetbare delta tonen ten opzichte van de baseline op ≥1 target voor de metric die jouw task beloofde te verhogen. Geen delta = geen DONE.

## 5. DONE-definitie (strikt, geen interpretatie)

DONE = ALLE volgende waar:

- sectie 3 checks alle pass
- sectie 4 live harness laat de aangekondigde delta zien
- DONE_LOG entry bevat de before/after tabel uit het harness-rapport
- TASK_QUEUE.md annotaties bijgewerkt (DONE / SUBSUMED-BY / CLOSED)
- NEXT_TASK.md gepromoveerd naar de volgende sprint-task

Als ÉÉN van bovenstaande false is: NIET committen als DONE, NIET NEXT_TASK promoten, STOP en rapporteer aan de operator.

## 6. Stop-gates (verplicht wachten op operator)

Stop en vraag, niet doorgaan, zodra:

- Live harness toont geen delta of FAILs op een target
- Een must_not_touch blokkeert je task-intent
- Je vindt iets structureels dat groter is dan deze taak
- Je twijfelt of een edit per-target tuning is
- De operator iets tussendoor vraagt wat afwijkt van NEXT_TASK
- Je gaat een destructive operatie doen die niet expliciet in scope staat (force-push, `reset --hard`, branches/files deleten, recent werk verwijderen)

## 7. Na DONE (alleen als sectie 5 helemaal pass is)

- Update `DONE_LOG.md` met before/after tabel + harness rapport URL
- Update `CURRENT_STATE.md` waar relevant
- Promote next task → `NEXT_TASK.md`
- `git commit` (geen `--no-verify`, geen `--amend`, geen `push` tenzij gevraagd)
- Stop. Wacht op operator-acknowledge voordat je de volgende task pakt.

## 8. Bij elke twijfel

Memory regels > Claude's redenering. Operator > memory. In twijfel = in twijfel — dan stoppen, niet "klein issue, ga door".
