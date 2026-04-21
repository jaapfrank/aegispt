# Controlled Multi-Agent Red Team Program

## Purpose

This document defines the product direction for a controlled, multi-agent, AI-assisted red-team capability inside AegisPT.

It is a product architecture direction, not permission for uncontrolled autonomous offensive behavior.

The goal is to let AegisPT behave more like a coordinated offensive team within approved scope, while remaining:

- deterministic where execution must be deterministic
- approval-aware
- evidence-first
- reproducible
- bounded by customer authorization and platform safety controls

## Why this matters

The strongest competitive direction is not a single "smart hacker bot".

It is a coordinated system that can:

- specialize tasks
- parallelize safe work
- cross-check results
- keep provenance intact
- improve operator speed and coverage

In practice, that means AegisPT should evolve from a single-flow testing platform into a controlled digital red-team workspace composed of multiple bounded roles.

## Safety boundary

This program must not change the existing safety model.

It must remain true that:

- no arbitrary public-target expansion is allowed
- no live self-modifying runtime is allowed during active assessments
- no unapproved pack executes in runtime
- no agent may broaden scope beyond what was authorized
- no agent may hide uncertainty or provenance

## Strategic product position

The right goal is not:

- "replace all humans in every red-team scenario"

The right goal is:

- automate the repeatable offensive-security program
- run multiple specialized AI operators in parallel under one controlled platform
- reduce the amount of manual red-team effort required for routine, scalable, evidence-heavy work
- escalate to humans where bespoke creativity, negotiation, or unusual business-logic reasoning is still needed

## Multi-agent role model

The future AegisPT multi-agent team should use explicit bounded roles.

Recommended initial roles:

### 1. Mission Lead Agent

Responsibilities:

- interpret mission intent
- maintain scoped objectives
- keep the plan aligned with rules of engagement
- coordinate handoff between other agents

### 2. Inventory and Surface Agent

Responsibilities:

- normalize discovery outputs
- detect hosts, services, apps, APIs, technologies, and trust boundaries
- maintain confidence scores and inventory assumptions

### 3. Threat and Relevance Agent

Responsibilities:

- correlate inventory with threat intelligence
- map relevant risk patterns
- recommend follow-up coverage
- propose methodology tags and control areas

### 4. Capability Forge Agent

Responsibilities:

- propose or refine pack artifacts
- generate customer-specific templates, flows, rules, and profiles
- hand outputs into the validation/promotion lane

### 5. Execution Planner Agent

Responsibilities:

- decide the next approved run or follow-up action
- select approved execution lanes and pack bindings
- preserve staged progression for internal and deep missions

### 6. Evidence and QA Agent

Responsibilities:

- verify artifact completeness
- detect contradictions between run state, findings, and reports
- block weak evidence from being promoted as a strong conclusion

### 7. Reporting and Assurance Agent

Responsibilities:

- synthesize executive and technical output
- produce remediation and retest guidance
- assemble the evidence-backed assurance package

### 8. Safety and Policy Agent

Responsibilities:

- enforce scope boundaries
- check authorization context
- require approvals where policy demands them
- stop unsupported or risky next actions

## Multi-machine execution model

To behave like a real team, AegisPT should support multiple execution workers or hosts while preserving one control plane and one source of truth.

Recommended high-level model:

- central control plane for mission state, packs, evidence, approvals, and reporting
- multiple bounded worker nodes for tool execution
- per-run or per-task execution identity
- shared evidence and artifact catalog
- explicit worker/agent provenance on every result

This should support:

- parallel safe discovery
- segmented environment testing
- pack validation on isolated build workers
- differentiated internal, external, cloud, and app execution lanes

## Orchestration rules

Multi-agent behavior must be orchestrated through explicit state and approvals, not hidden implicit reasoning.

Required orchestration principles:

- one mission state model
- one evidence catalog
- one pack registry
- one approval system
- one run/provenance model

Agent actions should be:

- observable
- attributable
- replayable where possible
- stoppable
- policy-checked

## Why multi-agent beats a single-agent model

Done correctly, a multi-agent model improves:

- parallelism
- specialization
- cross-review
- fault isolation
- explainability
- scalability across larger customer environments

It also enables a more believable "digital red team" story because the system behaves like a coordinated team rather than a single opaque actor.

## Required guardrails for production use

Before this program can be activated as a real product layer, AegisPT should require:

- explicit per-agent role boundaries
- explicit task and approval records
- host/worker registration and identity
- immutable execution logs
- per-agent evidence provenance
- degraded-state handling when one agent or worker fails
- operator override and kill switch handling

## Competitive implication

Current competitors frequently market:

- AI-powered pentesting
- attack-path analysis
- continuous validation
- remediation closure

Fewer expose a strong, controlled, customer-specific, multi-agent build-and-execution story tied to evidence and pack provenance.

That is where AegisPT can become stronger:

- adaptive pack generation
- multi-agent coordination
- evidence-first execution
- assurance-first reporting

all in one governed system.

## Research context

External signals reviewed:

- VulnBot multi-agent pentesting framework: https://arxiv.org/abs/2501.13411
- xOffense multi-agent framework: https://arxiv.org/abs/2509.13021
- OpenAI Agents SDK orchestration guidance: https://openai.github.io/openai-agents-python/multi_agent/
- OpenAI Agents SDK handoffs: https://openai.github.io/openai-agents-python/handoffs/
- OpenAI Agents SDK guardrails: https://openai.github.io/openai-agents-js/guides/guardrails/
- OpenAI agents product direction: https://openai.com/index/new-tools-for-building-agents/
- Testkube orchestration and agentic test-execution direction: https://docs.testkube.io/
- Testkube execution-engine direction: https://testkube.io/features

Inference:

- multi-agent systems are becoming more practical
- the strongest current engineering pattern is not "free roaming agents", but orchestrated agents with handoffs, guardrails, tracing, and explicit execution control
- coordination, traceability, and failure handling remain the real hard part
- AegisPT should only move forward with multi-agent offensive coordination if orchestration and evidence models stay stronger than the agent hype

## Activation rule

This program is a documented direction until explicitly activated by a future approved task.

Until then:

- no uncontrolled multi-agent offensive runtime is enabled
- no hidden distributed offensive behavior is introduced
- no scope-broadening behavior is allowed

## Bottom line

AegisPT should evolve toward a controlled digital red-team model made of multiple bounded AI operators and multiple execution workers.

But it must do so in a way that is safer, more explainable, and more evidence-backed than the current market.
