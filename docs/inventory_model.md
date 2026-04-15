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
- TLS tooling such as `testssl.sh` for transport posture
- existing stack detection logic and manual operator notes

The raw source payload is preserved in `raw_inputs_json`. The normalized snapshot is the stable input for later stages.

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

