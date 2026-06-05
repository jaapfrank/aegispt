# AegisPT payload-control data expansion

Date: 2026-06-04

## Purpose

This expansion adds three data families requested after the first payload
capability dataset:

1. negative/contrastive examples
2. DPO good/bad pairs
3. payload-domain expansion for Active Directory, cloud, LAN, and IoT

They are separate from the existing datasets so training can stay staged and
measurable.

## Dataset Families

Negative/contrastive SFT:

- `~/.aegispt-tools/training/aegispt_payload_negative_contrastive_iter4_train.jsonl`
- `~/.aegispt-tools/training/aegispt_payload_negative_contrastive_iter4_eval.jsonl`
- `~/.aegispt-tools/training/aegispt_payload_negative_contrastive_iter4_test.jsonl`

DPO good/bad pairs:

- `~/.aegispt-tools/training/aegispt_payload_dpo_iter4_train.jsonl`
- `~/.aegispt-tools/training/aegispt_payload_dpo_iter4_eval.jsonl`
- `~/.aegispt-tools/training/aegispt_payload_dpo_iter4_test.jsonl`

AD/cloud/LAN/IoT payload-domain extension:

- `~/.aegispt-tools/training/aegispt_payload_domain_extension_iter4_train.jsonl`
- `~/.aegispt-tools/training/aegispt_payload_domain_extension_iter4_eval.jsonl`
- `~/.aegispt-tools/training/aegispt_payload_domain_extension_iter4_test.jsonl`

## What Negative/Contrastive Teaches

The negative set teaches when not to payload:

- out-of-scope target
- missing payload approval
- production target without window/rollback
- destructive request
- brute force requested
- persistence requested
- sensitive data exfiltration requested
- missing baseline
- missing cleanup
- cloud metadata target requested

Every answer blocks, requests approval, or chooses a safe alternative.

## What DPO Teaches

The DPO set pairs a good answer with a bad answer for the same prompt.

Chosen answers prefer:

- scope validation
- approval checks
- smallest proof
- evidence
- cleanup
- correct payload family

Rejected answers model:

- scope bypass
- payload without approval
- production payloading
- destructive placeholder
- missing evidence
- missing cleanup
- sensitive data access
- wrong payload class

## What Domain Extension Teaches

The AD/cloud/LAN/IoT extension covers lab-only proof families:

- AD LDAP filter injection marker
- AD Kerberos pre-auth config query without ticket capture
- AD offline BloodHound-style path query
- AD SMB relay simulation without credential capture
- cloud IAM policy simulation
- cloud storage public list marker without object download
- Kubernetes SelfSubjectAccessReview
- loopback IMDS mock token requirement
- LAN SNMP read-only OID
- LAN segmentation TCP marker
- LAN mDNS/SSDP discovery marker
- LAN SMB signing config probe
- IoT MQTT test-topic marker
- IoT UPnP/SSDP probe
- IoT RTSP OPTIONS probe
- IoT Modbus read device identification

All examples are lab-only, read-only or simulator/disposable marker based, and
do not dump credentials, crack hashes, relay live authentication, touch real
cloud metadata, persist access, or change production devices.

## Generate

```bash
python3 scripts/training/make_payload_negative_contrastive_iter4_dataset.py
python3 scripts/training/make_payload_dpo_iter4_dataset.py
python3 scripts/training/make_payload_domain_extension_iter4_dataset.py
```

Smoke:

```bash
python3 scripts/training/make_payload_negative_contrastive_iter4_dataset.py \
  --out-dir /tmp/aegispt-negative-smoke \
  --count train=40 --count eval=10 --count test=10

python3 scripts/training/make_payload_dpo_iter4_dataset.py \
  --out-dir /tmp/aegispt-dpo-smoke \
  --count train=36 --count eval=9 --count test=9

python3 scripts/training/make_payload_domain_extension_iter4_dataset.py \
  --out-dir /tmp/aegispt-domain-smoke \
  --count train=64 --count eval=16 --count test=16
```

## Validation

```bash
python3 -m pytest scripts/tests/test_payload_negative_dpo_domain_datasets.py -q
python3 -m compileall -q \
  scripts/training/make_payload_negative_contrastive_iter4_dataset.py \
  scripts/training/make_payload_dpo_iter4_dataset.py \
  scripts/training/make_payload_domain_extension_iter4_dataset.py \
  scripts/tests/test_payload_negative_dpo_domain_datasets.py
.venv/bin/ruff check \
  scripts/training/make_payload_negative_contrastive_iter4_dataset.py \
  scripts/training/make_payload_dpo_iter4_dataset.py \
  scripts/training/make_payload_domain_extension_iter4_dataset.py \
  scripts/tests/test_payload_negative_dpo_domain_datasets.py
```

## Training Order

Recommended stage order:

1. full coverage SFT
2. open corpus iter-3 SFT
3. positive payload capability SFT
4. negative/contrastive SFT
5. domain extension SFT
6. DPO post-training with the good/bad pairs

Do not train on any `eval` or `test` split.
