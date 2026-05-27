# Vulnerability-class skill pack

Curated technique knowledge that the picker / specialists can consult
without violating ANTI_DRIFT rules. Inspired by transilience-ai
community-tools (https://github.com/transilienceai/communitytools), which
reached 100/104 on XBOW by pairing Claude Sonnet 4.6 with markdown skill
files iterated over benchmark failures.

## The constraint

`memory/feedback_no_prescriptive_recipes.md` forbids **target-specific
exploit recipes** (e.g., "for XBEN-002 the flag is at /admin/secrets").
That is solution caching and is anti-drift.

Skill files here MUST be **vulnerability-class** knowledge:

- ✅ "POST mutation routes whose names contain `archive` / `transfer` /
  `grant` / `claim` are commonly broken-access-control candidates; test
  by replaying the request as user A but with the path / body referring
  to user B's resource id".
- ❌ "For XBEN-002, POST to /api/transfer with target_id=2 to flag".

The first is technique knowledge applicable across any unknown web app.
The second is a benchmark answer.

## Structure

Each skill is one markdown file under `docs/skills/`:

```
docs/skills/
├── README.md                                   ← this file
├── access-control-state-change-post.md          ← vuln-class skill
├── ssrf-callback-oast.md                        ← (planned)
├── sqli-error-vs-blind-decision.md              ← (planned)
├── template-injection-jinja-mako-erb.md         ← (planned)
├── xss-context-classifier.md                    ← (planned)
└── deserialize-pickle-yaml-marshal.md           ← (planned)
```

Skill file contents:

1. **Class signature** — names, route patterns, HTTP shape that flags
   this class.
2. **Distinguishing tests** — short probes that confirm OR rule out
   the class without committing to a specific exploit.
3. **Mutation strategy** — what to vary in the request to provoke a
   pre-condition test (NOT a solution).
4. **Stop conditions** — when to give up and pivot.

## A/B protocol (to be implemented)

The score-climb experiment is:

1. Pin 5 XBEN challenges, same provider (Gemini-3.1-pro once quota
   resets, OR local-qwen once hardened).
2. **Run A**: baseline picker prompts, no skill pack.
3. **Run B**: same prompts + the picker prompt is augmented with the
   skill-pack markdown ABOVE the user content.
4. Compare: solved count, exec_plan dispatches, time-to-first-proof,
   hypothesis classes detected per challenge.

Acceptance for declaring "skill pack helps":

- `solved` delta `>= 1` on the same 5-challenge subset, AND
- the new solve(s) reproduce on a re-run without prompt changes, AND
- no benchmark contamination — i.e., the skill text never names XBEN
  challenge ids, flags, or target-specific URLs.

Integration site: ` _AI_PICKER_SYSTEM_PROMPT` in
`api/app/services/assessment_loop.py` — additive `SKILL_PACK_TEXT` block
appended when env `AEGISPT_SKILL_PACK_ENABLED=1`. Off by default until
the A/B has proven the lift.

## Status — 2026-05-27

- Directory scaffolded.
- One example skill: [access-control-state-change-post.md](access-control-state-change-post.md).
- A/B harness: NOT YET BUILT. Tracked separately.
- Picker integration: NOT YET WIRED. Behind future feature flag.

## License note

Transilience's community-tools repo is MIT licensed. Their skill markdown
can be CONSULTED for vuln-class technique inspiration but **must not be
copied verbatim into a benchmark-running configuration**. The intent is
to learn the format, not to import solutions.
