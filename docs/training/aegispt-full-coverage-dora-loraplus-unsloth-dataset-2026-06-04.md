# AegisPT full-coverage DoRA/LoRA+ Unsloth dataset

Date: 2026-06-04

## Purpose

This dataset is a broad, synthetic chat-SFT curriculum for the local AegisPT
pentesting model. It targets DoRA + LoRA+ fine-tuning and is shaped so both the
existing PEFT script and an Unsloth SFT flow can consume it.

It teaches the model to select safe assessment actions, preserve scope, request
approval for invasive work, record evidence, and emit reportable findings across:

- web
- LAN
- WAN
- IoT
- Active Directory
- cloud
- API
- safety/reporting quality gates

## Generated Files

Default generator output:

- `~/.aegispt-tools/training/aegispt_full_coverage_dora_loraplus_unsloth_train.jsonl`
- `~/.aegispt-tools/training/aegispt_full_coverage_dora_loraplus_unsloth_eval.jsonl`
- `~/.aegispt-tools/training/aegispt_full_coverage_dora_loraplus_unsloth_test.jsonl`
- `~/.aegispt-tools/training/aegispt_full_coverage_dora_loraplus_unsloth_manifest.json`

Default split sizes:

- train: 3600 conversations
- eval: 420 conversations
- test: 420 conversations

Regenerate with:

```bash
python3 scripts/training/make_full_pentest_dataset.py
```

Use smaller local smoke files with:

```bash
python3 scripts/training/make_full_pentest_dataset.py \
  --out-dir /tmp/aegispt-training-smoke \
  --count train=80 --count eval=16 --count test=16
```

## Format

Each JSONL row has:

- `messages`: chat messages in `role` / `content` form
- `metadata`: split, domain, facet, case id, and safety tags

Assistant turns contain exactly one JSON object:

```json
{
  "reasoning": "concise action rationale",
  "tool": "safe_http_probe",
  "args": {},
  "evidence": {},
  "finding": null,
  "done": false
}
```

This mirrors the AegisPT agent-control shape while remaining chat-template
friendly for Unsloth. Unsloth's own docs recommend applying the tokenizer chat
template to multi-turn datasets; the `messages` column is intentionally kept as
plain role/content chat data so the training layer can apply the model-specific
template at load time.

## Safety Boundaries

Included:

- reserved example domains and RFC 5737 documentation networks only
- read-only cloud, LDAP, and network posture checks
- bounded synthetic auth checks with explicit ROE limits
- evidence-first findings with standards, impact, and remediation
- approval gates for destructive, out-of-scope, or invasive work

Excluded:

- real targets
- malware, persistence, covert access, or destructive actions
- brute force or credential stuffing
- hash dumping, ticket capture, relay execution, or cloud secret access
- exploit payload recipes intended for live unauthorized use

## Training Use

Existing PEFT lane:

```bash
AEGISPT_TRAIN_DATA=~/.aegispt-tools/training/aegispt_full_coverage_dora_loraplus_unsloth_train.jsonl \
AEGISPT_TRAIN_USE_DORA=1 \
AEGISPT_TRAIN_USE_RSLORA=1 \
AEGISPT_TRAIN_LORAPLUS_RATIO=16 \
AEGISPT_TRAIN_RANK=32 \
python3 scripts/training/qlora_train.py
```

For Unsloth, keep the same data split discipline:

- train only on the train JSONL
- monitor loss/format adherence on eval JSONL
- hold test JSONL for final deep-chain and safety-gate evaluation

Recommended Unsloth data handling:

- load the JSONL with the Hugging Face `datasets` JSON loader
- map each row by applying the tokenizer chat template to `messages`
- keep `metadata` for eval slicing by domain/facet, but remove it from the text
  field used for SFT

## Validation

Generator and schema validation:

```bash
python3 scripts/training/make_full_pentest_dataset.py \
  --out-dir /tmp/aegispt-training-smoke \
  --count train=80 --count eval=16 --count test=16

python3 -m pytest scripts/tests/test_full_pentest_dataset.py -q
```

The generated manifest includes per-split domain, facet, assistant-turn, and
safety-tag counts.

## Source Alignment

The dataset follows the committed local-model training direction in
`docs/strategy/local-model-training-direction-2026-06-04.md`: local controllable
model, parameter-efficient fine-tuning, multi-phase pentest curriculum, and
clean provenance. It does not replace the active score-lane task and does not
modify runtime assessment behavior.

Official Unsloth references used for compatibility checks:

- https://docs.unsloth.ai/basics/chat-templates
- https://docs.unsloth.ai/get-started/fine-tuning-guide/lora-hyperparameters-guide
