# Evidence-Graph First-Class Adoption — Adoption Plan

**Audit task**: backlog-371 (Mythos #321)
**Date**: 2026-05-15
**Status**: audit output — read-only analysis, no code changes performed
**Successor tasks**: backlog-372 (#322 ingestion helpers), backlog-373 (#323 picker reads graph)

## 1. Current evidence data flow

```
Runner execution (workers/runners/<name>/runner.py)
  ├─ stdout / stderr / exit_code  → Task row (api/app/models/control.py)
  ├─ EvidenceArtifact[] (raw)     → evidence_artifacts table
  └─ protected_outputs            → credential_vault path

Post-execution callback (workers/orchestration/tasks.py):
  ├─ findings.py extractor        → Finding rows (per accepted artifact name)
  └─ _store_inventory_snapshot_from_execution
                                  → InventorySnapshot (nmap, httpx, content-discovery,
                                    target-intel, smart-web-probe, easm, several others)

On-demand graph construction (api/app/services/assessment_graph.py):
  build_assessment_graph(run)
    Walks: Run, Scope, InventorySnapshot, Task, ToolExecution, EvidenceArtifact,
           Finding, Approval, TargetContextDocument, AgentProposal,
           RationaleLedgerEntry, FindingChain
    Emits: source graph with nodes (kind=run|scope|task|finding|...) + edges

  build_normalized_evidence_graph(run)
    Normalizes source nodes into typed graph (12 node types — see Section 3)
    Adds: vault credential nodes, inventory_semantic_nodes (identities, APIs, permissions, etc.)
    Caches: NORMALIZED_EVIDENCE_GRAPH_VERSION versioning
```

## 2. Who currently reads the normalized graph

| Consumer | Path | Use |
|---|---|---|
| API endpoint | `api/app/routers/runs.py:1264` | Read-only graph viewer |
| Trust scorer | `api/app/services/saas_identity_trust.py:30` | SaaS-specific trust scoring |
| Confidence scorer | `api/app/services/hypothesis_confidence.py:21` | Finding-hypothesis confidence |
| **AI picker** | `api/app/services/assessment_loop.py` | **NOT a consumer.** Uses findings list + tested_keys + task_outcomes (flat strings). |

**Key gap**: the picker is the most important reasoning surface and does not use the graph.

## 3. Current normalized graph node taxonomy

From `_normalize_source_graph_node()` (assessment_graph.py:612-729) and helpers:

| Node type | Source | Subtype examples |
|---|---|---|
| `run` | Run row | assessment_run |
| `scope` | Scope row | engagement_scope |
| `asset` | InventorySnapshot endpoints/services/hosts | endpoint, service, host |
| `api` | Inventory endpoints matching API patterns | inventory_api, openapi, graphql |
| `identity` | Inventory identities/users/groups/service_accounts | user, group, service_account |
| `saas_connector` | InventorySnapshot saas data | connector, integration |
| `permission` | Inventory permissions/roles | role, permission |
| `credential_ref` | run_credential_vault entries | jwt, cookie, basic_auth |
| `finding` | Finding row | critical, high, medium, low, info |
| `task` | Task row | runner-tool-name |
| `evidence_ref` | ToolExecution + EvidenceArtifact + Context + Rationale | tool_execution, evidence_artifact, context_document, rationale_entry |
| `approval` | Approval row | approved, denied, pending |
| `proposal` | AgentProposal row | proposed-tool-name |
| `runner_capability` | runner_metadata | passive, active, intrusive |
| `attack_path` | FindingChain | pattern_id |

Edges carry `confidence`, `evidence_refs`, `provenance`. Every node + edge is traceable to source rows via `source_ids`.

**Verdict**: the node taxonomy is RICH and covers most of what cross-target reasoning needs. The taxonomy is not the bottleneck.

## 4. Per-runner emission classification

Surveyed runners by how they currently produce evidence the graph normalizer can consume:

| Class | Runners | Count | How they feed the graph |
|---|---|---|---|
| **Inventory-emitting** (write InventorySnapshot directly) | nmap, httpx, content-discovery, target-intel, smart-web-probe, easm, mdns_ssdp, snmp_enum, wifi_survey | 9 | Strong signal — emit structured services/hosts/endpoints. Become `asset` / `api` nodes via inventory_semantic_nodes. |
| **Findings-only** (only emit Finding via findings.py extractor) | All vulnerability probes: xss_extended, xss_proof, sqlmap, idor_bac, csrf-check, headers-security, cookie_tamper_probe, file_upload_probe, info_disclosure_probe, param_pollution_probe, stored_xss_probe, ssti_probe, ssrf_probe, deserialization_probe, http_smuggling, graphql_command_injection, jwt_probe, oauth_probe, leak_check, crypto_audit, session_security, business_logic, etc. | ~50 | Findings show up as `finding` nodes. No structured artifact about WHAT was probed beyond the finding's `target_id` and `category` strings. |
| **Credential-emitting** (write to run_credential_vault) | exec_plan (when capture.from=cookie), auth_flow, responder | 3 | Become `credential_ref` nodes. |
| **Context-emitting** (write TargetContextDocument) | target-intel, smart-web-probe, lan-intel | 3 | Become `evidence_ref` nodes with `context_document` subtype. |
| **Proposal-emitting** (write AgentProposal) | ai_pentest_agent (via on_success.create_proposal), exec_plan | 2 | Become `proposal` nodes. |
| **External-tool wrappers** (stdout only, no inventory/structured output) | zap, burp, metasploit, bloodhound, impacket, netexec, ldap_enum, semgrep, john, hashcat (not currently in repo), playwright_web, ssh_brute, waf_detect, nuclei, nikto, ai_shell, c2_ingest, etc. | ~15 | Only `task` and `evidence_ref` (tool_execution) nodes — no entity content. Findings extracted from stdout JSON if the extractor recognizes the artifact name. |

**Key insight**: 50/75 runners (~67%) produce only findings — no structured entities about what they OBSERVED but didn't flag as a finding. The graph stays at finding-level granularity for two-thirds of runner output.

## 5. What's missing for first-class adoption

### 5.1 Runner-side ingestion path

There is currently **no helper that lets a runner emit `(entity_type, entity_id, attributes, provenance)` records during execution** for entity types other than InventorySnapshot. A runner that observes "this URL is an OpenAPI endpoint" or "this cookie name is JSESSIONID indicating Java backend" has no path to write that as a graph entity. It can only either:

- Write a finding (which represents a discovered vulnerability, not an observation)
- Write an inventory snapshot (only for the 9 inventory-emitting runners)
- Write to stdout (lost to the picker)

**This is the core bottleneck.**

### 5.2 Picker-side consumption

`_claude_select_next_action()` (assessment_loop.py:452) builds Claude's user_content from:

- `findings` (list of `{severity, title, target, tool}` dicts, capped at 5KB)
- `tested_pairs` (sorted strings, capped at 1.5KB)
- `task_outcomes` (last 10 task results, capped at 2.5KB)
- `recent_failures` (last 6 failed tasks, capped at 2KB)
- `discovered_paths` (deeper paths only)
- `phase_picks` (current phase tool list, capped at 2KB)
- `plan_recommendations` (from target-intel test plan)

It does **NOT** read `build_normalized_evidence_graph(run)` output. Pivoting across surfaces (web finding → internal hostname → AD pivot) is therefore invisible to the picker — the linkage exists in the graph but the picker doesn't see it.

### 5.3 Cross-task provenance

When exec_plan captures a value (JWT, cookie, hostname) in step 5, that value is stored in `run_credential_vault` for credentials, or in the step result for other captures. Subsequent tasks have **no first-class way** to query "show me values captured by prior tasks that match this kind." It's a `task_outcomes` string search at best.

### 5.4 No `observed_signal` node type

There's `evidence_ref` (a node pointing at a tool_execution or artifact) but no compact "I observed X" node that a runner can emit. The closest existing concept is `inventory_semantic_nodes` which only the inventory-emitters use.

## 6. Recommended adoption plan for #322 + #323

### #322 — Evidence-Graph Entity Ingestion Helpers

**Add**: `api/app/services/evidence_ingest.py` (~150-200 lines)

**API surface**:

```python
def emit_observation(
    *, session, run, task,
    entity_type: Literal["asset", "api", "identity", "credential_hint", "tech_signal", "observed_url"],
    entity_id: str,
    attributes: dict,
    confidence: float = 0.7,
    evidence_refs: list[str] | None = None,
) -> None:
    """Runner-side entity emission. Writes to new evidence_observations table
    that build_assessment_graph reads alongside InventorySnapshot."""

def emit_capture_provenance(
    *, session, run, task, step_name: str,
    captured_kind: Literal["jwt", "cookie", "hostname", "credential", "token"],
    captured_value_redacted: str,  # last-4 chars or hash, never raw
    origin_finding_id: UUID | None = None,
) -> None:
    """Records that a captured value came from a specific task+step.
    Adds an `observed_signal` node + `captured_from` edge."""
```

**Schema addition**: one new table `evidence_observations` with columns `id, run_id, task_id, entity_type, entity_id, attributes_json, confidence, evidence_refs, created_at`. Alembic migration ~60 lines.

**Graph integration**: extend `build_assessment_graph()` to read `evidence_observations` for the run and emit them as source nodes. `_normalize_source_graph_node()` extends with handlers for new entity types. ~80 lines added to assessment_graph.py.

**Pilot runners (priority order based on observation density)**:

1. **`target_intel`** — already writes context documents; extend to emit `tech_signal` observations (frameworks detected, JS libs, server headers). ~30 lines added.
2. **`smart_web_probe`** — already generates AI-driven attack cases; extend to emit `observed_url` for each discovered endpoint + `tech_signal` for each detected pattern. ~40 lines added.
3. **`http_fetch_backend`** — every picker http_fetch could emit `observed_url` + headers as `tech_signal`. Picker-driven crawl becomes graph-visible. ~20 lines added.
4. **`xss_proof`** — emits captured cookies via emit_capture_provenance. ~25 lines added.
5. **`exec_plan`** — every capture in a step becomes emit_capture_provenance. ~50 lines (touches multiple capture branches).

**Total task #322 estimate**: ~450 lines new code + ~80 lines modifications to existing assessment_graph.py and 5 runners. Schema migration ~60 lines. Unit tests ~150 lines. Realistic AI-tempo: 4-6 hours.

### #323 — Picker Reads Normalized Evidence Graph

**Add**: graph projection helper in assessment_graph.py.

```python
def project_graph_for_picker(graph: dict, *, max_tokens: int = 3500) -> str:
    """Token-bounded text projection of the normalized evidence graph for
    LLM consumption. Emits compact lines:
      ASSETS: <list of distinct hosts/services>
      APIS: <list of API endpoints>
      IDENTITIES: <list of users/roles observed>
      CAPTURES: <recent 5 captured tokens/cookies with origin>
      ATTACK_PATHS: <attack_path nodes with severity + step count>
    Prioritizes high-confidence nodes when truncating."""
```

**Picker integration** (assessment_loop.py:452-680):

- Insert graph projection between `outcomes_block` and `plan_recommendations` blocks.
- Replace flat `findings` list with graph-projected `FINDINGS_WITH_LINEAGE` (each finding shows its source task + any captures that led to it).
- Retain fallback path for runs without graph data (early phase, no inventory yet).

**Estimated picker change**: ~80 lines (add projection, replace fallback paths). One unit test of `project_graph_for_picker` ~100 lines.

**Total task #323 estimate**: ~180 lines new code in assessment_graph.py + assessment_loop.py modifications. Unit tests ~100 lines. Realistic AI-tempo: 2-4 hours.

## 7. Validation gates

Each task has clear success criteria:

**#322 success criteria**:

- `evidence_observations` table created via Alembic migration.
- `emit_observation()` and `emit_capture_provenance()` callable from any runner.
- 5 pilot runners actually emit observations during integration tests against Gruyere.
- `build_normalized_evidence_graph()` includes the new node types without losing existing nodes.
- No regression on `test_assessment_graph.py` suite.

**#323 success criteria**:

- `project_graph_for_picker()` exists, deterministic for the same graph input.
- Token cost per picker hop stays within 10% of pre-change baseline (measure via the cache_read/cache_creation log line).
- Live picker run on Gruyere shows graph projection lines in the prompt (verified via log inspection).
- Live picker run on a non-Gruyere target (juice-shop or testfire) shows graph projection adapts to that target's discovered entities.

## 8. Out-of-scope for #322 and #323

These are valuable but **NOT in scope** for the Phase 1 work:

- Cross-target provenance with detailed lineage (that's #334)
- Cross-runner verifier (that's #335)
- Adopting Graphiti or any external knowledge graph service (separate strategic decision)
- New entity types beyond the 6 enumerated above (tech_signal, observed_url, etc.)
- Replacing InventorySnapshot — keep it, the new observations table augments rather than replaces
- Picker structured outputs (that's #330)

## 9. Risks and mitigations

| Risk | Mitigation |
|---|---|
| New table adds DB write cost per runner execution | Batch emissions in runner; flush at end of task callback. Low frequency (~5-15 emissions per task max). |
| Graph projection bloats picker prompt and breaks cache | Hard 3,500-token cap on projection. Truncate by confidence ranking. Measure cache_read tokens before/after. |
| Pilot runners emit noisy/false observations | Confidence field on every emission. Picker projection filters out confidence < 0.5 by default. |
| Schema migration during a running production deploy | Standard Alembic policy — add table, no breaking change to existing rows. Rollback is safe. |
| New evidence_observations.attributes_json size grows unbounded | Per-attribute cap at 2 KB. Total observation row capped at 8 KB. |

## 10. Recommended next concrete step

Promote **backlog-372 (#322)** to NEXT_TASK.md per the queue progression in TASK_QUEUE.md. This audit task (#321) is complete; the adoption plan in this file is the deliverable.

The pilot-runner selection above (target_intel, smart_web_probe, http_fetch_backend, xss_proof, exec_plan) should be confirmed by the operator before #322 implementation begins, since once those runners are wired the pattern will be replicated to others.

## 11. Files inspected

- `api/app/services/assessment_graph.py` (1522 lines) — full read; node taxonomy from lines 612-729
- `api/app/services/evidence_integrity.py` (361 lines) — hash chain over evidence_refs (not the graph itself; complementary)
- `api/app/services/next_evidence_action.py` (366 lines) — picker hint generator using findings + scope, not graph
- `api/app/services/hypothesis_confidence.py` (360 lines) — consumer of the graph for finding-confidence scoring
- `api/app/services/assessment_loop.py` (lines 452-680 around `_claude_select_next_action`) — confirmed picker reads findings/tested_keys/task_outcomes, NOT graph
- `workers/orchestration/tasks.py` (lines 3972-4030, 4587-4625) — confirmed how InventorySnapshot writes happen
- `workers/orchestration/findings.py` — confirmed findings extractor pipeline
- All 75 directories under `workers/runners/` — classified by emission type (Section 4 table)

## 12. Audit metadata

- last_verified: 2026-05-15
- author: backlog-371 audit (Mythos Phase 1)
- governing doc: docs/MYTHOS_PLAN_FINALITY.md (plan-lock contract)
- supersedes-but-augments: Section 4 of docs/AGENT_SYSTEM_MAP.md (which will be updated when #322 lands)
