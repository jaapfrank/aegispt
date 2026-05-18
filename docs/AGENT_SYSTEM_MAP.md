# Agent System Map — AegisPT

**Purpose**: cross-session continuity for AI development sessions. Before starting any task on AegisPT, read this. Before proposing a "new" feature, **check whether it already exists below**. Goal: prevent duplicate code and rediscovery work.

**Maintenance**: when you BUILD or REFACTOR something that changes the map, update this file in the same commit. Every section has a `last_verified` date — if you touch a section, refresh it.

---

## 1. Repository layout (canonical paths)

| Concern | Path |
|---|---|
| FastAPI control plane | `api/app/` |
| API routers | `api/app/routers/` |
| Service layer (business logic) | `api/app/services/` (101 modules) |
| SQLAlchemy models | `api/app/models/` |
| Alembic migrations | `migrations/versions/` |
| Worker orchestration (dramatiq) | `workers/orchestration/` |
| Runner implementations | `workers/runners/<name>/runner.py` (75 dirs) |
| Runner contracts | `workers/runners/base/contracts.py` |
| Runner capability registry | `workers/runners/capabilities.json` |
| Frontend (React v2) | `ui-v2/src/` |
| Scripts (install, validate, tests) | `scripts/` |
| Codex task packages | `codex/tasks/backlog-NNN-slug.json` |
| Codex results | `codex/results/` |
| Docs | `docs/` |
| Project state | `CURRENT_STATE.md`, `DONE_LOG.md`, `NEXT_TASK.md`, `TASK_QUEUE.md`, `DECISIONS.md` |
| Agents guide | `AGENTS.md` |
| **This file** | `docs/AGENT_SYSTEM_MAP.md` |

last_verified: 2026-05-15

---

## 2. The AI loop (picker) — how it works today

**Entry point**: `api/app/services/assessment_loop.py`

| Function / constant | Role |
|---|---|
| `_AI_PICKER_SYSTEM_PROMPT` (line 16-301) | 13.8 KB system prompt with evidence-first principle, phase model, exec_plan grammar, http_fetch + memory tool descriptions |
| `_claude_select_next_action()` (line 452) | The picker. Calls Claude Opus 4.7, hop-loop up to 12 hops, processes tool_use (memory + http_fetch), parses JSON decision |
| `_tolerant_json_fix()` (line 1139) | Best-effort JSON repair — strips trailing commas, escapes raw newlines/tabs inside strings. **Fails on unescaped quotes** (known gap). |
| `advance_assessment_loop()` | Outer per-iteration entry. Loads state, calls picker, applies decision, writes back to DB. |

**Tools Claude has during picker call**:
- `memory_20250818` (Anthropic-managed memory tool) → backed by `api/app/services/memory_backend.py`
- `http_fetch` (custom client-side) → backed by `api/app/services/http_fetch_backend.py` (94 lines, scope-allowlist enforced)

**Prompt caching**: `cache_control: {type: "ephemeral"}` on system prompt as of 2026-05-15. Tools auto-cached due to render order. Logged via `AI loop: hop=N usage input=X cache_read=Y cache_creation=Z output=W` per hop.

**Structured outputs (#330, 2026-05-16)**: `output_config={"format": {"type": "json_schema", "schema": _PICKER_OUTPUT_SCHEMA}}` on the picker call. Schema is a 5-variant `anyOf` (pick / level_up / level_up+plan / stop / exec_plan) with `additionalProperties: false` on every variant. The `plan` field is a stringified JSON body (strict-mode workaround for freeform inner objects); `_decode_picker_plan()` json.loads it client-side. `_tolerant_json_fix` retained as defensive fallback but path is deprecated — engagement logs a warning if it fires.

**Model**: `claude-opus-4-7`. Picker outputs 4 action types: `pick`, `level_up`, `stop`, `exec_plan`.

**Known issues**:
- ~~JSON parse failures on complex `exec_plan` outputs~~ — **resolved by #330** via structured outputs; the SDK now constrains the response shape server-side.
- ~~Memory file `/memories/run-progress.md` grows unbounded~~ — **resolved by #332**: `memory_backend.execute("view", ...)` is capped at 2 KB with a truncation marker; `rotate_run_progress()` helper trims the file to 6 KB when it exceeds 8 KB.
- ~~Loop stops hard on first parse failure, no soft retry~~ — **resolved by #331** via `_call_picker_with_retries` wrapper (1 initial + 2 retries = 3 total attempts; distinct `picker_retry_exhausted` stop reason when retries are spent).

last_verified: 2026-05-17 (post Phase 3 days 1-3; Phase 3 review checkpoint is #333)

---

## 3. Runners — what exists, generic vs Gruyere-specific

**Total**: 75 runner directories. Registered in `workers/orchestration/tasks.py` as `SUPPORTED_TOOLS` set. Findings extracted via `workers/orchestration/findings.py`. Capabilities (triggers, blockers, tiers) declared in `workers/runners/capabilities.json`.

### Verified generic (work on multiple stacks)
External-tool wrappers — generic by virtue of being thin layers on mature tools:
- `nmap`, `nuclei`, `sqlmap` (via web_depth), `zap`, `burp`, `nikto`, `httpx`
- `bloodhound`, `impacket`, `netexec`, `ldap_enum`, `responder`, `metasploit`
- `semgrep`, `aws_inventory`, `cloud_native`, `easm`
- `playwright_web`, `nmap`, `mdns_ssdp`, `snmp_enum`, `wifi_survey`
- `target_intel` (AI-driven, generic by design — see file)
- `smart_web_probe` (Claude Sonnet 4.6 reasoning per app)
- `xss_proof` (uses `_try_register_with_ai` for app-agnostic auth — important reference implementation)
- `lan_intel` (Claude Haiku, generic LAN analysis)
- **`info_disclosure_probe`** (migrated #328 — generic catalog only, `.gtl` paths stripped)
- **`stored_xss_probe`** (migrated #328 — uses `auth_discoverer.acquire_session()` for emergent auth)
- **`file_upload_probe`** (migrated #328 — uses `auth_discoverer.acquire_session()`)
- **`param_pollution_probe`** (migrated #328 — uses `auth_discoverer.fetch_auth_pages` + `fingerprint_application` for endpoint discovery; mass-assignment attack stays custom)
- **`cookie_tamper_probe`** (migrated #328 — uses `auth_discoverer.fetch_auth_pages` + `fingerprint_application` for endpoint discovery; crafted-username register stays custom)

**Empirical test 2026-05-16 (post-#328 generality run)**: `scripts/test_probe_generality.py` against juice-shop + demo.testfire.net + testasp.vulnweb.com confirms all 5 probes reach the testing stage (`attempts > 0`) on all 3 non-Gruyere targets, satisfying the no-regression-on-non-Gruyere acceptance criterion. Gruyere parity verified via 15/15 mock-based parity tests in `workers/tests/test_*_probe.py`.

**Operator-credentialed strategy (#345, 2026-05-18)**: `auth_discoverer.acquire_session()` now supports two strategies. When `session` + `run` kwargs are passed, the function consults `run_credential_vault` for a `password`-kind secret whose `metadata['target']` host matches `base_url`. On hit, dispatch goes to `acquire_session_with_credentials(base_url, username=..., password=...)` which strips `register_form` from the fingerprint, builds a login-only recipe via the existing `build_recipe`, and replays it with operator credentials. On miss (or no kwargs), the existing emergent-registration path runs unchanged — the #328 probe contract is preserved (probes that call `acquire_session(base_url, scope_allowlist=...)` see no behavior change). Credentials never appear in the returned session dict, graph entities, or audit logs: full values stay encrypted at rest in the vault, only the username and server-issued cookies surface. This closes the structural gap surfaced after #328/#329 — login-only targets (DVWA, customer staging, internal corporate apps) silently no-op'd under emergent registration; now they succeed when operator credentials are pre-staged in the vault.

### (no longer present) Verified Gruyere-specific
This category was empty after #328. The 5 probes formerly listed here have been migrated and moved to "Verified generic" above. The reference history is kept in `DONE_LOG.md` under the #328 entry.

### The exec_plan engine (the existing primitive composer)
`workers/runners/exec_plan/runner.py` (391 lines, 9 functions). **This is the closest thing to "Mythos-stijl" we already have.** Claude generates multi-step HTTP plans with capture/expect/on_success.create_finding. Used via `action: "exec_plan"` from picker. Grammar documented in `_AI_PICKER_SYSTEM_PROMPT` lines 210-300.

last_verified: 2026-05-18 (post-#345 operator-credentialed strategy)

---

## 4. Evidence model — what exists, post Phase-1 reality

| Component | Path | Status |
|---|---|---|
| Findings model | `api/app/models/control.py` | Used everywhere |
| Tasks model | `api/app/models/control.py` | Used everywhere |
| **EvidenceObservation model** | `api/app/models/control.py` (added #322) | Runner-emitted structured entities (asset, api, identity, credential_ref, etc.) — table `evidence_observations`, migration `20260515_0033` |
| Audit events (append-only) | DB table `audit_events` | Active. Narrator panels stored here. |
| `build_assessment_graph()` | `api/app/services/assessment_graph.py` | Source graph from run/task/finding tables |
| `build_normalized_evidence_graph()` | `api/app/services/assessment_graph.py:371` | Normalized graph; now also merges EvidenceObservation rows via `_runner_observation_nodes()` |
| **`project_graph_for_picker()`** | `api/app/services/assessment_graph.py` (added #323) | Token-bounded compact text projection. Default 3500-token budget. Per-group cap 25, per-line cap 200 chars, char-budget `max_tokens*4`. Returns empty string for sparse graphs. |
| **`evidence_ingest.py`** | `api/app/services/evidence_ingest.py` (added #322) | Runner-side `make_observation()` + orchestrator-side `persist_runner_observations()` + graph-side `load_run_observations()` |
| Evidence integrity service | `api/app/services/evidence_integrity.py` | Hash chain + signatures |
| Next-evidence-action recommender | `api/app/services/next_evidence_action.py` | Picker hint generator (used alongside graph projection) |
| Hypothesis confidence | `api/app/services/hypothesis_confidence.py` | Scoring of finding hypotheses |
| SaaS identity trust | `api/app/services/saas_identity_trust.py` | SaaS-specific evidence trust |
| Docs | `docs/evidence_graph_normalizer.md`, `docs/evidence_graph_adoption_plan.md` | Schema + adoption plan |
| **Picker integration** | `assessment_loop.py` `_claude_select_next_action` (#323) | Picker inserts graph projection block between outcomes and target-intel plan. Falls back to empty when graph sparse. Confirmed on live Gruyere/juice-shop/testfire runs 2026-05-15. |

**Phase 1 status (closed 2026-05-15 via checkpoint #324):**

- 4 pilot runners migrated to emit observations: `target_intel`, `smart_web_probe`, `xss_proof`, `web_depth.content_discovery`.
- On the three contrasting target stacks tested at the checkpoint (Gruyere/Python, juice-shop/Node SPA, testfire/Java JSP), `target_intel` + `smart_web_probe` emit assets+apis universally. `xss_proof` emits identity+credential_ref on Gruyere and testfire (form-based auth) but not juice-shop (REST API auth — Phase 2 #325-#329 will add this).
- Graph projection produces 994-3,870 chars per run on real data — well under the 4 KB soft target. See `docs/checkpoints/2026-mythos-phase1-review.md`.

**Remaining underuse (Phase 2+ scope):** the 5 Gruyere-specific vulnerability probes (info_disclosure_probe, param_pollution_probe, stored_xss_probe, cookie_tamper_probe, file_upload_probe) do not yet emit observations and remain hardcoded to Gruyere's `saveprofile?action=new` auth pattern. Their migration is Phase 2 work (#325-#328).

last_verified: 2026-05-15 (post Phase-1 review #324)

---

## 5. AI integration surface — what models, what calls, what cost

| Caller | Model | System prompt size | Frequency observed (24h) | Notes |
|---|---|---|---|---|
| Picker (`assessment_loop.py:750`) | `claude-opus-4-7` | ~3,500 tokens | 493 advances | Hop loop, multi-turn. **Cached as of 2026-05-15.** Confirmed cache_read > 0. |
| Narrator (`api/app/services/narrator.py:209`) | `claude-opus-4-7` (fallback only) | ~500-700 tokens | Primary path ChatGPT OAuth; 14 Opus fallbacks | Below 4K min cacheable; **caching skipped intentionally** |
| `target_intel/runner.py:149` | `claude-haiku-4-5-20251001` | ~3.4 KB | Once per run (recon) | Site analysis JSON |
| `smart_web_probe/runner.py:343` | `claude-sonnet-4-6` | ~7.7 KB | Once per smart-web invocation | App-aware attack synthesis |
| `xss_proof/runner.py:272` | `claude-haiku-4-5-20251001` | ~8 KB | Per xss-proof run | Auth-flow analysis (reference impl for generic auth!) |
| `lan_intel/runner.py:123` | `claude-haiku-4-5-20251001` | ~3.1 KB | Per LAN scan | Service analysis |
| `ai_pentest_agent/runner.py:197` | `claude-sonnet-4-6` | ~2.9 KB | Per agentic run | Multi-round conversation, grows quadratically |
| `runs.py:1690` (briefing) | `claude-haiku-4-5-20251001` | small | Per report request | Executive briefing |
| ChatGPT OAuth narrator | OAuth-backed | n/a | ~225 panels/day | Primary narrator path |

**Cost data 2026-05-15** (logs `/tmp/aegispt-api.log`): ~$300/day total estimated. Picker ~$300, narrator-Opus ~$18. After prompt caching: estimated $60-90/day reduction on picker = projected ~$210-240/day. **Memory tool truncation** is next biggest lever (avg 11 KB per call × 922 calls/day).

**Post-Phase-3 empirical (2026-05-17, 11 hops on testfire+juice-shop after `aegispt-api.service` restart onto commit be788d7):** per-hop usage avg input=5,662 / cache_read=8,169 (was 11,657 = **-30%** from #332 memory truncation) / cache_creation=2,323 / output=232. Cost/hop $0.1582 vs $0.1700 baseline = **-7%** on this small sample. 2 parse-fail-class events, 1 caught by `_call_picker_with_retries` (#331), 0 `picker_retry_exhausted`. Memory-truncation lower bound confirmed (~3,488 cache_read tokens/hop saved). Full day-level cost projection still requires bigger sample; the structural savings are real. **Follow-up surfaced**: `max_tokens=1024` on picker call too small for long `level_up` decisions — picker hits the cap mid-string, truncated grammar bypasses #330 structured outputs and lands on #331 retry; raise to 4096 for a quick win (separate task).

last_verified: 2026-05-17

---

## 6. Memory tool integration

**Backend**: `api/app/services/memory_backend.py` (224 lines). Implements view/create/str_replace/insert/delete/rename for Anthropic memory_20250818 tool.

**Storage path**: per-engagement under `/memories/`. Was historically unbounded — `/memories/run-progress.md` observed at ~77 KB.

**Truncation (#332, 2026-05-17)**: `memory_backend.execute("view", ...)` payloads are now capped at `VIEW_MAX_BYTES=2048` with a trailing `[...truncated, N more bytes ...]` marker (UTF-8-safe boundary; logs activity). Writes are NOT capped — full content stays on disk. `rotate_run_progress(threshold_bytes=8192, keep_bytes=6144)` is an opt-in maintenance helper that trims `/memories/run-progress.md` to the most-recent 6 KB when it exceeds 8 KB and inserts a small rotation header. Caller (assessment loop) can invoke it between advances. Expected ~$30/day saving (deferred to operator validation via live logged `cache_read_input_tokens` per picker hop).

**Use today**: per-run scratchpad. Knowledge does NOT persist usefully across engagements (single user has been writing to the same store, but the contents are mostly transient log entries, not patterns).

**Use in plan**: tasks **#325-#329** introduce pattern-level recipes under `/memories/auth-recipes/<fingerprint-hash>.json`.

last_verified: 2026-05-17

---

## 7. Scope, ROE, intrusive-tier governance

| Component | Path | What it does |
|---|---|---|
| Scope model | `api/app/models/control.py` (Scope) | host + path allowlist per engagement |
| Scope check helper | `api/app/services/runs.py` (`web_target_value_is_allowed_with_path`) | Used in every runner before sending traffic |
| ROE policy | `api/app/services/roe_policy.py` | Rules of engagement enforcement |
| Tier system (passive/active/intrusive) | Multiple — see `assessment_loop.py` `intrusive_block` | Operator approves intrusive tier per run |
| Per-run intrusive flag | `Run.autonomous_intrusive_allowed` | Auto-derived from `test_profile = "Full Pentest"` |
| Approvals | `api/app/services/approvals.py` | Operator approval workflow |
| Kill switch | API endpoint + scheduled checks | Halts runs immediately |
| Credential vault | `api/app/services/run_credential_vault.py` | Per-run captured credentials |

last_verified: 2026-05-15

---

## 8. Frontend (React v2) — Mission Control

**Path**: `ui-v2/src/`. Key components:
- `screens/MissionControl.tsx` — primary dashboard
- `components/CinemaMode.tsx` — 3D AI chain visualization for ai_loop runs
- `components/Intake.tsx` — engagement intake / target selection
- `components/MissionControlV3.tsx` (active) — story/technical dual view

**Narrator panels** stream via GET `/api/v1/runs/{run_id}/narrative-panels` (polling). Data lives in `audit_events` (append-only, race-safe).

**Build**: `bash scripts/build_ui_v2.sh`. Tests: `bash scripts/run_ui_fast_tests.sh`.

**Recent UI work** (parked per user): comic-strip narrative view styling.

last_verified: 2026-05-15

---

## 9. Project-state conventions (DO NOT skip)

Per `AGENTS.md`:
1. **Before any work**: read `NEXT_TASK.md`, `CURRENT_STATE.md`, `DECISIONS.md`.
2. **Single active task**: only ONE task may be in `NEXT_TASK.md` at a time.
3. **After work**: update `DONE_LOG.md` and `CURRENT_STATE.md`. If the active task completes, promote next from `TASK_QUEUE.md` into `NEXT_TASK.md`.
4. **Task packages** under `codex/tasks/backlog-NNN-slug.json` follow strict schema. Validate with `python3 scripts/validate_backlog_tasks.py`.
5. **Queue indexes** in TASK_QUEUE.md must be sequential 1..N. Each maps to exactly one `codex/tasks/backlog-NNN-*.json` (queue_index field inside must match position).
6. **Don't bypass** capability pack registry, validation pipeline, approval, runtime binding.
7. **Don't change** finding schema fields without explicit task scope.

last_verified: 2026-05-15

---

## 10. Mythos convergence plan (active strategic context)

**Goal**: take AegisPT from "AI orchestrates a runner catalog" to "AI reasons over evidence graph and composes attacks from primitives", without rebuilding the platform.

**Honest delta** (2026-05-15 analysis):
- ~30-40% of Mythos-vision already exists (exec_plan engine, evidence_graph, memory tool, evidence-first principle in system prompt, intrusive-tier governance, verifier mechanic in exec_plan.expect)
- Real gaps: (a) cross-engagement learning (cache), (b) non-HTTP primitives in exec_plan, (c) consistent evidence-graph ingestion + picker consumption, (d) cross-target provenance, (e) cross-runner verifier

**Five work blocks** (queued as tasks #321-#337 with review checkpoints):

1. **Phase 1: Evidence-graph as first-class** (#321-#324) — audit, ingestion helpers, picker consumption, review.
2. **Phase 2: Universal auth + pattern cache** (#325-#329) — form detection, AI recipe builder, memory-backed cache, migrate 5 Gruyere-specific probes, review.
3. **Phase 3: Picker hardening** (#330-#333) — structured outputs schema, soft-retry on parse fail, memory truncation, review.
4. **Phase 4: Cross-target + verifier** (#334-#337) — provenance, cross-runner verifier, non-HTTP primitives (SMB+LDAP) in exec_plan, final demo review.

**Expected duration at AI tempo**: 3 weeks focused (vs 3 months human-pace).

**Anti-rebuild promise**: every task additively extends existing code paths. Nothing in this plan throws away current runners. The 5 Gruyere-probes from prior work get refactored (auth flow extracted), not replaced.

last_verified: 2026-05-15

---

## 11. Quick-start for new sessions

1. `git status` — see what's in-flight (currently many WIP files on `codex/aegispt-repo-state-update-20260501`)
2. `cat NEXT_TASK.md` — what's currently active
3. `head -30 CURRENT_STATE.md` — top of state file has most-recent updates
4. `tail -30 DONE_LOG.md` — what was completed last
5. Skim this file's "Mythos convergence plan" (section 10) for strategic context
6. Run `python3 scripts/validate_backlog_tasks.py` to ensure queue + task packages are still valid before any changes
7. Look at `workers/runners/capabilities.json` for runner inventory
8. **Before writing any new runner or service**: check section 3 (runner inventory) and section 4 (evidence model) to confirm it doesn't exist yet.

last_verified: 2026-05-15

---

## 12. Known anti-patterns to avoid (lessons learned)

- **Don't add Gruyere-specific patterns** to runners. The 5 probes in section 3.2 are the cautionary tale.
- **Don't bypass scope/ROE/tier system** — operator approval flows exist for a reason.
- **Don't write new evidence storage** — use the existing graph + audit_events + findings.
- **Don't add unbounded loops** without per-iteration cost/time caps. The picker hop-loop is capped at 12 for a reason.
- **Don't put dynamic content** (timestamps, request IDs, random tokens) in the picker system prompt — it invalidates the prompt cache.
- **Don't seed prescriptive exploit recipes** — emergent discovery only. (Per `feedback_no_prescriptive_recipes` memory.)
- **Don't auto-resume runs** after `stop_reason` is set without explicit reset — caused infinite credit burn previously.
- **Don't write to `/memories/run-progress.md`** unbounded — keep recipe files small and patterns dense.

last_verified: 2026-05-15
