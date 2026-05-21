# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Release gate + cross-system capability comparison (XBOW / PentestGPT / PentAGI / OWASP Nettacker) — **Sprint mythos-exploitation-foundation, task 13 of 15**

## Goal

Per Codex Layer 5 + 'zonder metriek geen beter'. Formal release-gate die AegisPT (post-foundation sprint) evalueert tegen XBOW score, PentestGPT capabilities (publieke benchmarks), PentAGI features (backlog-418 report), OWASP Nettacker scanner coverage. Deliverable: gate-decision report + GO/NO-GO voor parity sprint.

## Sprint context

Task 13 van 15. Alle foundation modules zijn nu in production (407-417). De 25-challenge XBOW batch is geland — empirische score in. Tijd om dit formeel als release gate te toetsen.

## Delta-doelstelling

> Deze task levert `docs/validation/release-gate-mythos-exploitation-foundation.md` met: actuele XBOW score, exec_plan_successful avg, chain_findings avg, verified-exploited count, vergelijking tegen XBOW 84.6% target, PentestGPT/PentAGI/Nettacker feature-coverage tabel, en een expliciete GO / NO-GO beslissing met named gap-items.

## Scope

(1) Lees `/tmp/xbow-baseline-final/xbow-2026-05-21-baseline.{md,json}` (geland van de in-flight batch).
(2) Bereken metrics: solved/N, exec_plan ok/total avg, tools/run avg, findings/run avg, verified-exploited (validator verdict) count.
(3) Compare tegen public benchmarks (XBOW 84.6% on cleaned challenges; PentestGPT ~26-40% on various; Shannon Lite 96.15% on cleaned XBOW).
(4) Compare AegisPT module coverage tegen PentAGI specialist set (per backlog-418 report) + Nettacker scanner modules.
(5) Write report met GO/NO-GO + gap-items.

NO code changes — investigation + report only.

## Constraints (per ANTI_DRIFT.md)

- Per Rule 1: this IS the user-value metric ritual. Verdict moet expliciet GO of NO-GO zeggen, niet "we made progress".
- Per Rule 4: numbers come from the live `/tmp/xbow-baseline-final/` report, not retrofitted estimates.

## Source Package

`codex/tasks/backlog-419-release-gate-cross-system-compare.json`
