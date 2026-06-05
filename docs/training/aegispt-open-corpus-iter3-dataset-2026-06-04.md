# AegisPT open-corpus iter-3 dataset

Date: 2026-06-04

## Why This Is Separate

The earlier full-coverage synthetic dataset is ready to train now:

- `~/.aegispt-tools/training/aegispt_full_coverage_dora_loraplus_unsloth_train.jsonl`
- `~/.aegispt-tools/training/aegispt_full_coverage_dora_loraplus_unsloth_eval.jsonl`
- `~/.aegispt-tools/training/aegispt_full_coverage_dora_loraplus_unsloth_test.jsonl`

This open-corpus iter-3 dataset is a separate dataset family so the first one
can be trained immediately without waiting for external corpus normalization,
license review, deduplication, or safety filtering.

New dataset family:

- `~/.aegispt-tools/training/aegispt_open_corpus_iter3_train.jsonl`
- `~/.aegispt-tools/training/aegispt_open_corpus_iter3_eval.jsonl`
- `~/.aegispt-tools/training/aegispt_open_corpus_iter3_test.jsonl`
- `~/.aegispt-tools/training/aegispt_open_corpus_iter3_manifest.json`

## Current Sources

The first iter-3 builder uses local open corpora already staged under
`~/.aegispt-tools/training/corpus/`:

- `cve_2026.jsonl` from the NVD CVE collector
- `files_exploits.csv` from ExploitDB metadata

ExploitDB is transformed as metadata only. The builder does not read or write
raw PoC files, payload bodies, target recipes, exploit commands, malware,
persistence steps, or destructive actions.

## Default Size

Default generated split sizes:

- train: 12000 conversations
- eval: 1500 conversations
- test: 1500 conversations

Regenerate:

```bash
python3 scripts/training/make_open_corpus_iter3_dataset.py
```

Small smoke generation:

```bash
python3 scripts/training/make_open_corpus_iter3_dataset.py \
  --out-dir /tmp/aegispt-open-corpus-smoke \
  --count train=40 --count eval=8 --count test=8
```

## Approved Next Sources

The curated registry is stored at
`scripts/training/open_source_corpus_registry.json`.

Priority order for the next ingestion pass:

1. `Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset`
2. `Trendyol/All-CVE-Chat-MultiTurn-1999-2025-Dataset`
3. `expertdata-factory/cybersecurity-reasoning-cot-v1`
4. MITRE CTI ATT&CK/CAPEC STIX datasets
5. ProjectDiscovery `nuclei-templates` metadata
6. `CyberNative/CyberSecurityEval` as eval-only, never train

Quarantine:

- `WNT3D/Ultimate-Offensive-Red-Team`: train only after strict sanitizer and
  manual spot checks
- `detoxioai/exploit_db_train_v1`: blocked until license and safety review pass

## Training Use

Train order should remain staged:

1. Train/validate the existing full-coverage synthetic dataset.
2. Evaluate with `deep_chain_eval.py` and safety-format checks.
3. Add this open-corpus iter-3 dataset as a second adapter pass or mixed SFT
   run only after dedup and eval-split isolation.

Example second-pass command:

```bash
AEGISPT_TRAIN_DATA=~/.aegispt-tools/training/aegispt_open_corpus_iter3_train.jsonl \
AEGISPT_TRAIN_USE_DORA=1 \
AEGISPT_TRAIN_USE_RSLORA=1 \
AEGISPT_TRAIN_LORAPLUS_RATIO=16 \
AEGISPT_TRAIN_RANK=32 \
python3 scripts/training/qlora_train.py
```

## Validation

```bash
python3 -m pytest scripts/tests/test_open_corpus_iter3_dataset.py -q
python3 -m compileall -q scripts/training/make_open_corpus_iter3_dataset.py scripts/tests/test_open_corpus_iter3_dataset.py
.venv/bin/ruff check scripts/training/make_open_corpus_iter3_dataset.py scripts/tests/test_open_corpus_iter3_dataset.py
```
