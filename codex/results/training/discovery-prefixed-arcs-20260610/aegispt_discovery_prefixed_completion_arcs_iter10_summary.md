# Discovery-prefixed completion arcs iter10

- accepted rows: 1272
- source rows: 636
- variant count: 2
- held-out collision count: 0
- forbidden string hits: 0
- policy: data-lane only; no model calls; no runtime execution; no held-out eval rows used for training
- arc shape: terse goal -> infer/hit goal path -> blocked recovery -> retry -> final proof

## Discovery Variants

- `scout_then_semantic`: 636
- `semantic_direct`: 636

## Chain Classes

- `blind_command_injection_filter_bypass`: 144
- `command_injection`: 144
- `eval_rce_provider_refusal`: 72
- `file_upload_webroot`: 72
- `headless_xss_ssrf`: 288
- `java_jsp_other_stack`: 72
- `path_traversal_file_read`: 72
- `php_cms_framework_cve`: 72
- `sqli_filter_bypass`: 72
- `static_file_or_server_misconfig`: 72
- `unknown`: 48
- `unknown_nonweb_or_other_stack`: 72
- `unsafe_deserialization`: 72
