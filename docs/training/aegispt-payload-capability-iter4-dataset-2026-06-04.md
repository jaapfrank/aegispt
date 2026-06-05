# AegisPT payload capability iter-4 dataset

Date: 2026-06-04

## Purpose

This dataset family teaches controlled payload selection for authorized lab
pentesting. It is separate from the already generated broad full-coverage
dataset and the open-corpus iter-3 dataset.

Dataset family:

- `aegispt_payload_capability_iter4_train.jsonl`
- `aegispt_payload_capability_iter4_eval.jsonl`
- `aegispt_payload_capability_iter4_test.jsonl`
- `aegispt_payload_capability_iter4_manifest.json`

## Why Separate

The earlier datasets can train now:

1. `aegispt_full_coverage_dora_loraplus_unsloth_*`: broad safe agent behavior,
   scope, evidence, reporting, and coverage.
2. `aegispt_open_corpus_iter3_*`: open-source CVE and ExploitDB metadata
   transformed into safe triage and remediation reasoning.

Payload data is intentionally later and separate because it should not teach the
model to spam payloads before it learns scope, recon, evidence, approval, and
report discipline.

## Included Payload Classes

The generator covers these lab-only vulnerability classes:

- boolean SQL injection
- UNION marker SQL injection
- reflected XSS marker
- stored XSS marker
- SSRF loopback proof
- XXE seeded lab file proof
- command injection echo marker
- SSTI arithmetic marker
- path traversal seeded lab file proof
- unsigned JWT toy-lab negative test
- IDOR/BOLA synthetic object switch
- GraphQL minimal introspection
- API mass assignment on a disposable account
- open redirect marker to `example.invalid`
- benign SVG upload marker

Each conversation contains:

- `preconditions`
- `payload.family`
- `payload.value`
- `safety.approval_level`
- `safety.blocked_if`
- `expected_evidence`
- `cleanup`
- `finding`

## Safety Rules

This dataset is lab-only:

- reserved `.example` / `.invalid` targets and loopback proof services only
- no runtime execution
- no malware
- no persistence
- no brute force
- no destructive commands
- no raw external PoC dump
- no production data modification
- each payload has cleanup and expected evidence

The intent is to teach “smallest sufficient proof” and controlled evidence,
not autonomous exploitation outside the AegisPT approval lane.

## Default Size

Default split sizes:

- train: 7200 conversations
- eval: 900 conversations
- test: 900 conversations

Generate:

```bash
python3 scripts/training/make_payload_capability_iter4_dataset.py
```

Smoke:

```bash
python3 scripts/training/make_payload_capability_iter4_dataset.py \
  --out-dir /tmp/aegispt-payload-smoke \
  --count train=60 --count eval=15 --count test=15
```

## Training Order

Recommended order:

1. Train on `aegispt_full_coverage_dora_loraplus_unsloth_train.jsonl`.
2. Evaluate format, follow-through, and safety gates.
3. Train or adapter-continue on `aegispt_open_corpus_iter3_train.jsonl`.
4. Evaluate again.
5. Train or adapter-continue on `aegispt_payload_capability_iter4_train.jsonl`.
6. Hold `eval` and `test` splits for their own stage; do not mix test into
   training.

Example:

```bash
AEGISPT_TRAIN_DATA=~/.aegispt-tools/training/aegispt_payload_capability_iter4_train.jsonl \
AEGISPT_TRAIN_USE_DORA=1 \
AEGISPT_TRAIN_USE_RSLORA=1 \
AEGISPT_TRAIN_LORAPLUS_RATIO=16 \
AEGISPT_TRAIN_RANK=32 \
python3 scripts/training/qlora_train.py
```

## Validation

```bash
python3 -m pytest scripts/tests/test_payload_capability_iter4_dataset.py -q
python3 -m compileall -q scripts/training/make_payload_capability_iter4_dataset.py scripts/tests/test_payload_capability_iter4_dataset.py
.venv/bin/ruff check scripts/training/make_payload_capability_iter4_dataset.py scripts/tests/test_payload_capability_iter4_dataset.py
```
