# PentAGI deep-dive — reusable components report

**Backlog task:** [backlog-418](../../codex/tasks/backlog-418-pentagi-deep-dive-reusable-components.json)
**Date:** 2026-05-21
**Investigator:** AegisPT build agent (Codex/Claude Opus 4.7)
**Source:** [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi) — 17,087 stars, MIT, Go, 50 MB, last update 2026-05-21.

## TL;DR

PentAGI is a Go monolith that mirrors many of the same architectural ideas we already shipped in AegisPT through backlog-407..417, with one structural difference: PentAGI commits to a hard multi-agent specialist roster from day 1 (Pentester / Coder / Adviser / Enricher / Generator / Installer / Memorist / Reflector / Reporter / Searcher / Task Planner / Image Chooser / Language Chooser / Refiner / Question* counterparts), whereas AegisPT is converging on the same pattern via backlog-415 (coordinator + 6 specialists). The directly portable artifacts are the **prompt templates** (Go `text/template` files, MIT licensed) and the **container/image selection heuristics**. The agent runtime itself is Go-native and not portable. Multi-LLM provider abstraction is already independently implemented in both projects (PentAGI under `backend/pkg/providers/*`, AegisPT under [`api/app/services/llm_provider.py`](../../api/app/services/llm_provider.py) from backlog-417).

## Architecture summary

PentAGI's structure (`backend/pkg/`) maps to AegisPT modules as follows:

| PentAGI package | Purpose | AegisPT equivalent | Status |
|---|---|---|---|
| `pkg/providers/{anthropic,openai,gemini,bedrock,ollama,deepseek,glm,kimi,custom}` | Per-vendor LLM clients | [`api/app/services/llm_provider.py`](../../api/app/services/llm_provider.py) | Equivalent (backlog-417) |
| `pkg/templates/prompts/*.tmpl` | Specialist prompt files (Go template) | [`api/app/services/assessment_loop.py`](../../api/app/services/assessment_loop.py) `_AI_PICKER_SYSTEM_PROMPT` + [`api/app/services/exploit_developer.py`](../../api/app/services/exploit_developer.py) `_EXPLOIT_DEVELOPER_SYSTEM_PROMPT` + `prompts/active/` from backlog-415 | Portable text — extract + translate |
| `pkg/controller` | Run loop / dispatch | [`api/app/services/assessment_loop.py`](../../api/app/services/assessment_loop.py) | Equivalent design, different language |
| `pkg/queue` | Task queue | `workers/orchestration/tasks.py` + dramatiq | Equivalent |
| `pkg/docker` | Container management for tool execution | [`workers/orchestration/sandbox_runner.py`](../../workers/orchestration/sandbox_runner.py) from backlog-409 | Equivalent (less mature in AegisPT — only exec_plan sandboxed so far) |
| `pkg/graphiti` | Graphiti knowledge-graph integration | (not yet — backlog-420 scope) | TODO upstream |
| `pkg/observability` | OTEL / Langfuse wiring | [`api/app/observability/tracing.py`](../../api/app/observability/tracing.py) from backlog-407 | Equivalent |
| `pkg/database` (Postgres + pgvector) | Episodic memory store | [`api/app/services/episodic_memory.py`](../../api/app/services/episodic_memory.py) + `migrations/versions/20260521_0034_agent_episodic_memory.py` from backlog-410 | Equivalent |
| `pkg/templates/graphiti` | Knowledge-graph prompts | (not yet) | Pull when backlog-420 lands |
| `pkg/templates/validator` | Output validation templates | [`api/app/services/exploit_validator.py`](../../api/app/services/exploit_validator.py) from backlog-413 | Equivalent (deterministic, no LLM) |
| `pkg/tools` | Pentest tool registry | `workers/runners/*` (30+ runners) + `workers/runners/capabilities.json` | Equivalent — AegisPT registry is broader |
| `pkg/terminal` | Live shell streaming | [`scripts/watch_run.py`](../../scripts/watch_run.py) + [`ui-v2/src/components/screens/MissionControlV3.tsx`](../../ui-v2/src/components/screens/MissionControlV3.tsx) `LiveTaskDrillDown` SSE panel | Equivalent (AegisPT uses SSE; PentAGI uses WebSocket) |
| `pkg/server` (REST + GraphQL) | API surface | `api/app/routers/*.py` REST | REST only — no GraphQL |

## Per-component port-ability

### Specialist prompts (`backend/pkg/templates/prompts/*.tmpl`)

The single most valuable directly portable asset. PentAGI's specialist prompts are MIT-licensed text files that encode hard-won pentest reasoning patterns. AegisPT's backlog-415 lays down the matching specialist roster (Recon / Hypothesis / ExploitDev / Validator / Memorist / Reporter / Reflector); these PentAGI prompts can seed our `prompts/proposals/` versioned-approval flow on day 1 of slice 2.

| PentAGI prompt | AegisPT specialist | Recommendation |
|---|---|---|
| `primary_agent.tmpl` | `MetaCoordinator` (backlog-415) | **Adapt** — extract the orchestration pattern; rewrite for our `_AI_PICKER_SYSTEM_PROMPT` style (Markdown-heavy with explicit HARD RULES sections). |
| `pentester.tmpl` + `question_pentester.tmpl` | Hypothesis specialist | **Adapt** — vulnerability-hypothesis section; keep the question-as-self-check pattern. |
| `coder.tmpl` + `question_coder.tmpl` | ExploitDev specialist | **Adapt** — multi-step code-composition logic; cross-reference with [`exploit_developer._EXPLOIT_DEVELOPER_SYSTEM_PROMPT`](../../api/app/services/exploit_developer.py) which we already harden against fabricated paths per `feedback_no_prescriptive_recipes`. |
| `searcher.tmpl` + `question_searcher.tmpl` | Recon specialist | **Adapt** — external KB integration prompts; cross-reference [`api/app/services/external_knowledge.py`](../../api/app/services/external_knowledge.py) from backlog-416. |
| `memorist.tmpl` + `question_memorist.tmpl` | Memorist specialist | **Port-as-is** (translated) — skeptical-memory pattern; matches our `skeptical_recall_with_verify_hint` envelope already shipped in backlog-410. |
| `reflector.tmpl` + `question_reflector.tmpl` | Reflector specialist | **Port-as-is** (translated) — strong reflection-on-progress prompt; sparse equivalent in AegisPT today. |
| `reporter.tmpl` | Reporter specialist | **Adapt** — PentAGI's reporter is well-developed; AegisPT's `api/app/services/reports.py` is template-driven but lacks the narrative shape. |
| `adviser.tmpl` + `question_adviser.tmpl` | (No 1:1) | **Ignore** for now — PentAGI uses adviser to advise the primary agent; AegisPT's `MetaCoordinator.decide()` (backlog-415) already does this structurally. |
| `enricher.tmpl` + `question_enricher.tmpl` | (No 1:1) | **Adapt later** — context-enrichment hooks may belong in the curator (backlog-411) rather than as a separate specialist. |
| `task_planner` family (`question_task_planner.tmpl`) | Attack tree (backlog-412) | **Adapt** — replace AegisPT's heuristic seed in `attack_state.seed_tree_with_replay_hints` with planner-prompt output. |
| `execution_monitor` family | (no 1:1) | **Adapt later** — AegisPT relies on retry+refinement loops (`#331`/`#403`) rather than a separate monitor; revisit if those degrade. |
| `generator.tmpl`, `installer.tmpl`, `image_chooser.tmpl`, `language_chooser.tmpl`, `refiner.tmpl`, `flow_descriptor.tmpl`, `input_toolcall_fixer.tmpl`, `execution_logs.tmpl`, `full_execution_context.tmpl`, `short_execution_context.tmpl` | Mixed — orchestrational | **Ignore** for direct port — these are tied to PentAGI's specific Go runtime + Docker image selection workflow. Some patterns may inform future AegisPT context-curation tuning (`api/app/services/context_curation.py` from backlog-411). |

**Estimated LoC**: prompts total ~6,000 lines across all `.tmpl` files. Port effort to AegisPT-flavor Markdown prompts: ~2-3 days of focused prompt engineering when slice 2 of backlog-415 lands.

### Container/image selection (`backend/pkg/docker` + `image_chooser.tmpl`)

PentAGI picks Docker images per task from a curated registry. AegisPT's [`sandbox_runner.SandboxConfig`](../../workers/orchestration/sandbox_runner.py) currently hardcodes `curlimages/curl:8.10.1` for exec_plan steps. **Adapt** the heuristic per-tool image selection when expanding sandbox beyond exec_plan (backlog-425+ crypto/reversing/pwn capability runners will benefit). License compatible (MIT) — straight translation to Python.

### LLM provider abstraction (`backend/pkg/providers/*`)

PentAGI rolls its own per-vendor clients. AegisPT chose LiteLLM in backlog-417 (smaller surface, more vendors). **Ignore** — our LiteLLM-wrapped `LLMProvider` already supports the same providers PentAGI lists (Anthropic / OpenAI / Gemini / Bedrock / Ollama / DeepSeek / GLM / Kimi). No port-back.

### Observability (`backend/pkg/observability`)

PentAGI uses OTEL → Jaeger/VictoriaMetrics/Loki via OpenTelemetry SDK. AegisPT [`api/app/observability/tracing.py`](../../api/app/observability/tracing.py) (backlog-407) already runs OTEL → Langfuse + console exporter. **Ignore** — equivalent.

### Episodic memory (Postgres + pgvector)

Identical schema choice. PentAGI emits memorist queries with per-result skeptical handling. AegisPT [`api/app/services/episodic_memory.py`](../../api/app/services/episodic_memory.py) (backlog-410) already returns `[HINT, VERIFY BEFORE USE]`-wrapped envelopes via `skeptical_recall_with_verify_hint`. **Ignore** for module-port; **adapt** the memorist prompt when slice 2 of backlog-415 lands (covered in prompt table above).

### Knowledge graph (Graphiti + Neo4j)

PentAGI integrates Graphiti for semantic relationship tracking. AegisPT does not yet — this is exactly backlog-420's scope. **Port-as-is** (the Graphiti API is language-agnostic): when backlog-420 lands, PentAGI's `pkg/graphiti` + `pkg/templates/graphiti/*.tmpl` are the reference implementation to translate into Python.

### Web scraping (`vxcontrol/scraper` container)

PentAGI uses an isolated browser container as a tool. AegisPT has `workers/runners/playwright_web` already. **Ignore**.

### External search (Tavily / Traversaal / Perplexity / Sploitus)

PentAGI's search-systems set is broader than AegisPT's. We have CISA-KEV + NVD + ExploitDB in [`api/app/services/external_knowledge.py`](../../api/app/services/external_knowledge.py) (backlog-416). **Adapt later** — adding Sploitus as a provider is a single-method addition; the `ExternalKnowledgeHint` shape is generic enough to absorb new sources without API churn. Filed in this report as a future-slice note within backlog-416's scope.

### GraphQL API

PentAGI exposes both REST and GraphQL. AegisPT is REST + SSE only. **Ignore** for now — GraphQL is a UX layer choice; current Mission Control UI doesn't need it.

## Recommendations summary

1. **Port-as-is (translated to Python)**:
   - `memorist.tmpl` + `question_memorist.tmpl` → `prompts/proposals/2026-XX-XX-memorist-rev1.md` (Markdown form).
   - `reflector.tmpl` + `question_reflector.tmpl` → `prompts/proposals/2026-XX-XX-reflector-rev1.md`.
   - Lands as the first batch of operator-approval prompt proposals when backlog-415 slice 2 wires the specialists.

2. **Adapt**:
   - `primary_agent.tmpl` → adapt as the MetaCoordinator's seed prompt (backlog-415).
   - `pentester.tmpl`, `coder.tmpl`, `searcher.tmpl`, `reporter.tmpl` → seed for Hypothesis / ExploitDev / Recon / Reporter specialists.
   - `task_planner` family → seed for `attack_state.seed_tree_with_replay_hints` planner upgrade (backlog-412 follow-up slice).
   - Container/image selection heuristics → expand `sandbox_runner.SandboxConfig` defaults when adding crypto/reversing/pwn runners (backlog-425+).

3. **Ignore (already equivalent)**:
   - LLM provider abstraction (backlog-417).
   - OTEL/Langfuse observability (backlog-407).
   - Episodic memory schema (backlog-410).
   - Web scraping container (playwright_web).

4. **Defer to backlog-420**:
   - Knowledge-graph integration (Graphiti + Neo4j).

## License check

PentAGI is MIT-licensed (verified via [GitHub API license endpoint](https://api.github.com/repos/vxcontrol/pentagi/license) — `spdx_id: MIT`). Prompt files + heuristic snippets can be copied verbatim into AegisPT with the standard MIT attribution requirement in `licenses/PENTAGI-MIT.txt`. Whole-package translation does not invoke copyleft.

## Out-of-scope (per backlog-418 constraint `no_code_in_this_task`)

This task explicitly forbids code edits. The matching commits that act on these recommendations land later:

- Prompt port-as-is + adapt → backlog-415 slice 2 (specialist `run()` entrypoints + `prompts/proposals/`).
- Container image registry → backlog-425..429 (crypto / reversing / pwn / privesc / mobile capability runners).
- Graphiti port → backlog-420.

## Closing note

PentAGI's biggest visible advantage is **completeness of the specialist roster**: 15+ distinct prompts vs AegisPT's currently 2 (picker + exploit_developer). With backlog-415 slice 1 already shipping the MetaCoordinator + per-agent ACL + versioned-prompt-proposal infrastructure, AegisPT now has the *frame* to host an equivalent roster. Slice 2 should adopt the four recommended PentAGI prompts as the initial population.
