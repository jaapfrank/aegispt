# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Sprint hand-off — pick next sprint (`mythos-exploitation-parity` / `domain-coverage` / `continuous-improvement`) **after** sprint `mythos-exploitation-foundation` CLOSED 15/15

## Goal

Sprint `mythos-exploitation-foundation` is gesloten met empirisch GO/NO-GO (release gate report + 6 live proposals). Volgende stap: operator kiest welke sprint als volgende NEXT_TASK promotet. Kandidaten staan in [`TASK_QUEUE.md`](TASK_QUEUE.md):

- **`mythos-exploitation-parity`** (gap-closure): `420` Neo4j+Graphiti knowledge graph, `421` OWASP Nettacker port (SMB+SSH).
- **`mythos-exploitation-domain-coverage`** (`424`-`430`): CLI/TUI, crypto / reversing / pwn / priv-esc / mobile capability runners, Nettacker rest.
- **`mythos-continuous-improvement`** (`431`): permanent XBOW score-climb — gevoed door `scripts/xbow_score_climb.py` + de 6 actieve proposals onder [`prompts/proposals/`](prompts/proposals/).
- **Operator-flagged session-2026-05-20 follow-ups** (`432` + `433` + `434`): scope/port discipline, runner failure-feedback contract, forensic run journal.

## Sprint context

Sprint `mythos-exploitation-foundation` is afgesloten 15/15 met 23 commits + 169 cross-module tests + empirisch 0/25 XBOW baseline. Release-gate report ([`docs/validation/release-gate-mythos-exploitation-foundation.md`](docs/validation/release-gate-mythos-exploitation-foundation.md)) noemt 8 specifieke gap items die de parity + continuous-improvement sprints drijven. De eerste batch van 6 versioned prompt proposals staat klaar voor operator review onder `prompts/proposals/`.

## Delta-doelstelling

> Operator beslist welke task package uit de queue als volgende NEXT_TASK promotet wordt. Wanneer beslist, kopieer dat task package's velden hierin en run `python3 scripts/validate_backlog_tasks.py` om de single-active-task invariant te herstellen.

## Scope

Geen code in deze tussenstap. Pure NEXT_TASK promotion housekeeping.

## Validation

- [ ] `python3 scripts/validate_backlog_tasks.py` returns "queued + active = 1:1".
- [ ] DONE_LOG entry for the previous task references the promotion.
