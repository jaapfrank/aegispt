# AegisPT werksessie — sprint mythos-foundation

**Paste deze hele file als kickoff prompt aan het begin van elke nieuwe Claude sessie waarin je AegisPT werk wilt doen.** De prompt is bewust kort en operationeel; alle WHY zit in de memory files waarnaar het verwijst. Versioned in git zodat de discipline mee-evolueert met het project.

## 0. Oriëntatie — lees vóór elke actie

1. **`ANTI_DRIFT.md`** (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Vanaf 2026-05-20 verplicht voor ELKE capability-task. **Overschrijft sectie 5 van deze prompt.**
2. **`STATE.md`** (repo root) — huidige staat, scope, live blocker, volgende lever (single source of truth sinds clean-slate 2026-06-11).
3. **`docs/validation/EVIDENCE_LEDGER.md`** + `evidence_ledger.jsonl` — de canonieke score.
4. De laatste 5 commits (`git log --oneline -5`) voor wat er net is aangeraakt.
6. Memory files: `feedback_live_proof_before_done`, `feedback_live_proof_must_be_diverse_real_targets`, `feedback_no_prescriptive_recipes`, `feedback_deferred_capability_followup`, **`feedback_anti_drift_contract`**. Deze 5 regels **overschrijven altijd** wat Claude van plan is — als ze botsen met instinct, volgt Claude de regel.

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

## 5. DONE-definitie — zie ANTI_DRIFT.md

**Vanaf 2026-05-20**: DONE-definitie staat in `ANTI_DRIFT.md` (9 criteria, strenger dan voorheen). De originele §5 hier (5 criteria) was te zwak — sprint mythos-foundation passeerde alle 5 zonder dat het system iets extra exploiteerde.

Quick-reference: een capability-task is alleen DONE wanneer een **user-value metric** (XBOW score / exec_plan_ok / chain_findings / captured_values) meetbaar bewoog op een real-world target, PLUS de pre-commit checklist uit ANTI_DRIFT.md is ingevuld in de commit message. Unit tests passing telt NIET als bewijs.

Bij ontbreken van ANY criterium: NIET committen als DONE, NIET NEXT_TASK promoten, STOP en rapporteer aan operator.

## 6. Stop-gates (verplicht wachten op operator)

Stop en vraag, niet doorgaan, zodra:

- Live harness toont geen delta of FAILs op een target
- Een must_not_touch blokkeert je task-intent
- Je vindt iets structureels dat groter is dan deze taak
- Je twijfelt of een edit per-target tuning is
- De operator iets tussendoor vraagt wat afwijkt van NEXT_TASK
- Je gaat een destructive operatie doen die niet expliciet in scope staat (force-push, `reset --hard`, branches/files deleten, recent werk verwijderen)

## 7. Na DONE (alleen als sectie 5 helemaal pass is)

- Regenereer de evidence ledger (`scripts/validation/build_evidence_ledger.py`) — de enige score
- Houd `STATE.md` kort + actueel (spiegelt de ledger; geen dagboek)
- `git commit` (geen `--no-verify`, geen `--amend`, geen `push` tenzij gevraagd)
- Stop. Wacht op operator-acknowledge voordat je de volgende task pakt.

## 8. Bij elke twijfel

Memory regels > Claude's redenering. Operator > memory. In twijfel = in twijfel — dan stoppen, niet "klein issue, ga door".
