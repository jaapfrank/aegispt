# Inventory Model

## Purpose

The inventory model normalizes discovery output before adaptive capability generation starts.

It exists to answer four questions in a consistent way:

1. What assets and services were observed?
2. Which technologies, auth models, APIs, and vendor fingerprints are likely present?
3. How confident are those detections?
4. What stable inventory snapshot should drive relevance analysis and pack generation?

## Normalized schema

Each `inventory_snapshot` stores:

- `engagement_id`
- `requested_by`
- `status`
- `source_tools_json`
- `raw_inputs_json`
- `normalized_inventory_json`
- `summary_json`
- `environment_notes_json`
- `assumptions_json`
- `confidence_score`

`normalized_inventory_json` uses this shape:

```json
{
  "hosts": [],
  "services": [],
  "http_endpoints": [],
  "technologies": [],
  "auth_mechanisms": [],
  "identity_subjects": [],
  "identity_groups": [],
  "privileged_memberships": [],
  "cloud_accounts": [],
  "cloud_regions": [],
  "cloud_resources": [],
  "cloud_security_groups": [],
  "cloud_iam_principals": [],
  "cloud_iam_policies": [],
  "cloud_iam_attachments": [],
  "cloud_collection_errors": [],
  "kubernetes_clusters": [],
  "kubernetes_workloads": [],
  "api_types": [],
  "tls_posture": {
    "protocols": [],
    "issues": [],
    "certificate_subject": null,
    "source": null,
    "confidence": 0.0
  },
  "vendor_product_fingerprints": [],
  "environment_notes": [],
  "assumptions": [],
  "confidence_score": 0.0
}
```

## Sources of truth

The inventory layer is additive and tool-fed. Expected sources include:

- `nmap` for hosts, ports, services, and version hints
- `httpx` for HTTP endpoints, headers, technology hints, and protocol exposure
- `OWASP ZAP` for crawled endpoints and browser-observed paths
- `Playwright` for auth flow and client-visible route discovery
- `Nuclei` for product/version hints where templates expose them
- `ldap-enum` for read-only directory users, groups, privileged memberships, and LDAP password-policy signals
- `aws-inventory` for read-only AWS account, region, VPC, subnet, security group, and EC2 instance metadata
- TLS tooling such as `testssl.sh` for transport posture
- existing stack detection logic and manual operator notes

The raw source payload is preserved in `raw_inputs_json`. The normalized snapshot is the stable input for later stages.

## Implemented read-only AWS inventory slice

The first cloud inventory slice is deliberately narrow and AWS-only. `aws-inventory` runs as a
normal passive runner through the existing approval-aware run/task/artifact path and writes
`aws-inventory-results.json` evidence. The runner uses read-only AWS APIs for:

- caller account identity
- enabled regions
- VPC descriptors
- subnet descriptors
- security group descriptors, rule counts, and rule details already returned by `describe_security_groups`
- EC2 instance descriptors such as instance id, type, state, IP/DNS metadata, VPC/subnet linkage, security group ids, and tags

Credentials are supplied through environment variable names in run configuration, such as
`access_key_id_env`, `secret_access_key_env`, and optional `session_token_env`. Raw AWS key material
must not be stored in the run configuration, inventory snapshot, logs, or report payloads.

The additive normalized cloud fields use this intent:

- `cloud_accounts`: AWS account identity observed through STS
- `cloud_regions`: AWS regions included in the read-only collection
- `cloud_resources`: VPC, subnet, security group, and EC2 instance metadata
- `cloud_security_groups`: security group descriptors, aggregate rule counts, and stored ingress/egress rule details
- `cloud_iam_principals`: optional read-only IAM principal records supplied by supported collectors or operator-approved imports
- `cloud_iam_policies`: optional read-only IAM policy documents supplied by supported collectors or operator-approved imports
- `cloud_iam_attachments`: optional read-only IAM principal/policy relationships
- `cloud_collection_errors`: non-fatal permission or provider errors that explain analysis gaps
- `kubernetes_clusters`: optional safe read-only Kubernetes cluster configuration observations
- `kubernetes_workloads`: optional safe read-only Kubernetes workload configuration observations

The same EC2 instance metadata can also contribute host entries so existing Surface / Attack Map and
report inventory surfaces can show cloud assets before a dedicated cloud UI exists.

## Implemented read-only cloud analysis slice

`GET /api/v1/inventory/{inventory_id}/cloud-analysis` reads the stored normalized snapshot and
returns review-only analysis output. It currently supports AWS public exposure, security-group,
IAM policy, and IAM trust-policy signals. Kubernetes signals are analyzed only when
`kubernetes_clusters` or `kubernetes_workloads` are already present from safe read-only inputs.

The endpoint returns provider-scoped `analysis_findings`, explicit `limitations`, an
`evidence_basis`, and summary counts. It does not mutate cloud or Kubernetes resources, does not
create database `Finding` records, and does not change the finding schema.

## Confidence handling

Confidence is tracked at two levels:

- record-level confidence on hosts, services, endpoints, technologies, auth models, APIs, TLS, and fingerprints
- snapshot-level `confidence_score` as the aggregate inventory confidence

Confidence is intended for prioritization, not hard truth. The relevance engine uses it as one signal among several.

## How inventory feeds adaptive testing

After inventory completes:

1. the snapshot becomes the input to relevance analysis
2. threat intelligence is matched against technologies, products, versions, auth patterns, and attack surface hints
3. proposed customer-specific capabilities are generated from that match set
4. the resulting pack keeps a pointer back to the inventory snapshot used

## Out of scope

The inventory layer does not:

- change runtime behavior during an active run
- directly install or activate new capabilities
- treat weak fingerprints as confirmed findings
- mutate cloud resources, harvest cloud credentials, infer IAM attack paths, run live Kubernetes tests, or chain cloud metadata into active attack paths
