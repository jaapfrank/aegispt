# AegisPT Multi-Turn Agentic Chain Iter-6 Data

Codex added a new data-lane family for the deep-chain gap Claude identified:
the model must keep state across turns, react to tool observations, and advance
until a lab goal is evidenced.

## Artifacts

Generated under `~/.aegispt-tools/training/`:

- `aegispt_multiturn_agentic_chain_iter6_train.jsonl`
- `aegispt_multiturn_agentic_chain_iter6_eval.jsonl`
- `aegispt_multiturn_agentic_chain_iter6_test.jsonl`
- `aegispt_multiturn_agentic_chain_iter6_manifest.json`

Default split sizes:

- train: `3200`
- eval: `400`
- test: `400`

## Coverage

The family covers these chain classes:

- `web_auth_followthrough`
- `api_object_authorization_chain`
- `ssrf_internal_marker_chain`
- `cloud_iam_simulation_chain`
- `ad_graph_readonly_chain`
- `lan_segmentation_chain`
- `iot_mqtt_topic_chain`
- `kube_rbac_chain`

Every row contains at least four assistant turns. Assistant turns must preserve
the latest observation reference, update state, choose the next bounded lab
action, and stop only when the final evidence marks `goal_satisfied=true`.

## Safety

This is training data only:

- no runtime binding
- no live target materialization
- lab/simulator/read-only tools only
- no credential dumping, brute force, persistence, destructive actions, or
  cloud metadata probing
- no copy of the held-out `deep_chain_eval.py` solution path

## Intended Use

Do not inject this into the already-running iter5 SFT candidate unless the
training operator explicitly starts a follow-up curriculum. It is meant as the
next multi-turn follow-through lever for adapter training and rollout-RL/GRPO
after the supervised iter5 gate reveals the deep-chain score.

Fixed validation command:

```bash
bash scripts/run_data_lane_tests.sh
```
