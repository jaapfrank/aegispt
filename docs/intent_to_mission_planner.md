# Intent-to-Mission Planner

The intent-to-mission planner converts operator language into an operator-reviewed mission
preview. It is exposed as `intent_mission_plan` on the existing intake interpretation endpoint:

`POST /api/v1/intake/interpretation`

The planner is deterministic and safety-bounded. It does not launch runs, create scope, confirm
authorization, store credentials, dispatch workers, or replace the manual wizard.

## What It Extracts

The planner extracts:

- assessment type, such as External Web App, API Security, Internal Range / LAN, Active Directory, or Cloud Infrastructure
- exact target where the operator supplied a URL, domain, IP, or CIDR
- execution depth: Passive, Active Scan, or Full Pentest
- run mode and full-chain assessment mode when the request clearly asks for a full pentest
- authorization summary, including whether written authorization is still required
- a launch summary describing automatic work, approval-gated work, out-of-scope items, and required actions
- an evidence plan covering operator intent, scope allowlist, authorization confirmation, runner ledger, coverage truth, and ROE policy decision sources

## Full Pentest Behavior

Clear English or Dutch requests such as “do a full pentest on `https://example.test`” or
“doe een volledige pentest op `https://example.test`” produce a complete mission preview without
asking another depth question. If written authorization has not been confirmed, launch remains
blocked with a required action instead of silently proceeding.

## Follow-Up Questions

The planner asks follow-up questions only for missing or unsafe information:

- missing target
- missing assessment type
- missing depth
- broad or unsafe scope language

Authorization confirmation is treated as a launch-blocking required action, not as permission to
infer or bypass ROE.

## UI Use

React v2 Intake consumes `intent_mission_plan` during Guided Intake. It uses the shared payload to
fill target type, scope, depth, and safety posture, then leaves the existing written-authorization
checkbox and launch gate intact. Manual Wizard remains available and unchanged.
