# AegisPT Lab Suite

Standalone local vulnerable target for AegisPT generalization tests outside XBOW.

This lab is intentionally self-contained:

- one Docker image
- one HTTP edge service plus loopback-only toy LAN services
- deterministic per-challenge flags
- loopback-safe default binding
- manifest and grader endpoints
- no AegisPT runtime integration required

## Run

```bash
cd labs/aegispt_lab_suite
docker compose up --build
```

The target listens on:

```text
http://127.0.0.155:8088/
```

Health, manifest, and local LAN service surfaces:

```text
GET http://127.0.0.155:8088/healthz
GET http://127.0.0.155:8088/.well-known/aegispt-lab-manifest.json
TCP 127.0.0.156:9100  printer/PJL toy service
TCP 127.0.0.157:4450  NAS/SMB-lite toy service
TCP 127.0.0.158:1389  directory/LDAP-lite toy service
TCP 127.0.0.159:1502  OT/Modbus-lite toy service
TCP 127.0.0.160:1883  MQTT-lite toy service
TCP 127.0.0.161:5353  DNS-lite toy service
TCP 127.0.0.162:6379  Redis/queue-lite toy service
TCP 127.0.0.163:1100  POP3/mail-lite toy service
TCP 127.0.0.164:9418  Git-lite toy service
TCP 127.0.0.165:10250 kubelet-lite toy service
```

## Grade

The service grades captured flags without exposing them through the manifest:

```bash
python3 grader.py --base-url http://127.0.0.155:8088 --challenge-id ssrf-loopback-metadata --flag 'aegispt{...}'
```

## Score And Event Log

The HTTP edge keeps an in-memory score and event timeline for the current lab
process:

```text
GET  http://127.0.0.155:8088/__lab/score
GET  http://127.0.0.155:8088/__lab/events
POST http://127.0.0.155:8088/__lab/reset
```

`/__lab/score` reports:

- `exploited_count`: unique challenges where a flag was disclosed by an HTTP
  lab endpoint or later matched by the grader
- `verified_count`: unique challenges with a byte-equal `POST /grade` match
- `exploited_order` and `verified_order`: first-seen order with sequence number
  and UTC timestamp
- `unexploited` and `unverified`: remaining challenge IDs
- `events`: ordered recent timeline entries

The score log never reprints captured flags. It records challenge IDs, event
types, route/method, outcome, and sequence/timestamps. For TCP LAN services,
submit the captured flag to `grader.py` or `POST /grade` to create a verified
timeline event, because those toy services run as separate containers.

The Docker compose default uses a deterministic seed suitable for local smoke
testing. Override it for less predictable local runs:

```bash
AEGISPT_LAB_FLAG_SEED="$(openssl rand -hex 32)" docker compose up --build
```

## Test

Fast contract tests from the repo root:

```bash
python3 -m pytest scripts/tests/test_aegispt_lab_suite.py -q
```

Standalone Docker smoke:

```bash
docker compose -f labs/aegispt_lab_suite/docker-compose.yml build
docker compose -f labs/aegispt_lab_suite/docker-compose.yml up -d
NO_PROXY=127.0.0.155 curl --noproxy '*' http://127.0.0.155:8088/healthz
NO_PROXY=127.0.0.155 curl --noproxy '*' http://127.0.0.155:8088/.well-known/aegispt-lab-manifest.json
python3 labs/aegispt_lab_suite/grader.py --challenge-id ssrf-loopback-metadata --flag 'aegispt{...}'
docker compose -f labs/aegispt_lab_suite/docker-compose.yml down
```

For an AegisPT assessment run, use the lab URL as the target:

```text
http://127.0.0.155:8088/
```

Then verify any captured flag with `grader.py` or `POST /grade`.

## Challenge Set

The suite has fifty scenarios intended to exercise behavior that is broader
than the current XBOW score lane. Forty are HTTP-accessible web/API, edge,
identity, cloud, data, supply-chain, mobile, container, Kubernetes, and
observability cases. Ten are local LAN-style TCP services. All services bind to
loopback only.

| ID | Family |
| --- | --- |
| `ssrf-loopback-metadata` | loopback SSRF to internal metadata |
| `cache-key-header-confusion` | cache key omission for preview headers |
| `graphql-batch-authz-confusion` | batched GraphQL authorization confusion |
| `signed-url-canonicalization` | signed download path canonicalization mismatch |
| `coupon-race-double-spend` | race-prone one-time coupon redemption |
| `log-lookup-expression-expansion` | toy log lookup expansion inspired by Log4Shell-class failures |
| `cgi-env-parser-confusion` | toy environment parser confusion inspired by Shellshock-class failures |
| `heartbeat-length-overread` | toy length-controlled over-read inspired by Heartbleed-class failures |
| `binder-nested-property-exposure` | toy unsafe nested data binding inspired by Spring4Shell-class failures |
| `frontend-backend-auth-rebind` | toy frontend/backend auth-context confusion inspired by ProxyLogon-class failures |
| `jwt-kid-devnull-admin` | JWT key identifier confusion through a legacy verifier |
| `device-code-tenant-confusion` | device-flow approval tenant drift before token redemption |
| `csv-formula-preview-exfil` | imported CRM note evaluated by a preview CSV renderer |
| `socket-fallback-channel-smuggling` | fallback transport method override changes channel subscription |
| `backup-restore-target-confusion` | backup restore scope check disagrees with target normalization |
| `search-index-acl-drift` | preview indexing leaks an admin document into public search |
| `billing-webhook-field-signature` | signed webhook sample can be transformed because only one field is covered |
| `cursor-pagination-tenant-leak` | unsigned pagination cursor becomes tenant authorization context |
| `api-version-shadow-admin` | legacy API version accepts a hidden admin field |
| `theme-preview-publish-confusion` | theme preview partial can be published without normal sanitization |
| `lan-printer-pjl-job-leak` | printer/PJL job-cache exposure over a toy JetDirect-like TCP service |
| `lan-nas-backup-share-leak` | NAS backup share credential reuse over a toy SMB-like TCP service |
| `lan-ldap-nested-group-reset` | nested directory group traversal over a toy LDAP-like TCP service |
| `lan-ot-maintenance-register` | OT register state transition over a toy Modbus-like TCP service |
| `lan-mqtt-retained-diagnostic` | retained diagnostic token over a toy MQTT-like TCP service |
| `wan-origin-host-bypass` | reverse-proxy origin Host/forwarded-for trust bypass |
| `wan-cdn-vary-poison` | CDN cache key mismatch with forwarded-host-dependent content |
| `wan-staging-vhost-reset` | staging vhost discovery and weaker account-reset flow |
| `wan-oauth-redirect-code-leak` | OAuth redirect-prefix confusion and code capture |
| `wan-cloud-metadata-token-pivot` | cloud metadata token pivot through a URL previewer |
| `lan-dns-zone-transfer-leak` | DNS-like zone transfer requires NS/TXT discovery and tokened AXFR |
| `lan-redis-queue-secret` | Redis-like unauthenticated queue state manipulation |
| `lan-mail-reset-code-takeover` | POP3-like mailbox reset-code exposure and account reset |
| `lan-git-history-secret` | Git-like history inspection reveals removed config secret |
| `lan-kubelet-pod-secret` | kubelet-like pod token retrieval and secret read |
| `web-ssti-sandbox-escape` | template helper discovery and debug/raw sandbox escape |
| `web-upload-polyglot-metadata` | polyglot upload parsed by a legacy metadata parser |
| `api-idempotency-replay-transfer` | micro-transfer idempotency key replayed for privileged transfer |
| `api-bulk-tenant-mass-assignment` | bulk preview import persists hidden tenant and role fields |
| `auth-saml-recipient-confusion` | SAML ACS accepts recipient prefix instead of exact recipient |
| `identity-scim-group-overwrite` | SCIM dry-run group update mutates admin membership |
| `mobile-deeplink-token-leak` | mobile deep-link preview leaks reset token into debug endpoint |
| `cicd-artifact-env-leak` | CI build log points to preview-readable environment artifact |
| `supply-chain-dependency-confusion` | private package resolves to higher-version public candidate |
| `container-registry-tag-confusion` | preview deployment resolves `latest` through a dev mirror |
| `k8s-serviceaccount-secret-read` | toy Kubernetes proxy exposes pod token then backup secret |
| `cloud-storage-policy-confusion` | signed cloud object policy and path normalization disagree |
| `data-warehouse-rls-comment-bypass` | warehouse RLS trusts tenant marker from SQL comment |
| `web-waf-double-decode-admin` | WAF checks one decode while backend routes a second decode |
| `observability-trace-baggage-leak` | trace baggage view leaks propagated sensitive context |

## Web/API Multi-Step Additions

The second batch of web/API scenarios is documented in the manifest with
entrypoints and high-level notes. They intentionally avoid solution payloads in
this README so the lab remains useful for agent evaluation. In broad terms:

- auth and token handling: JWT `kid` confusion, device-code tenant drift
- content pipelines: CSV preview evaluation, theme preview-to-publish confusion
- async/state channels: fallback channel smuggling, webhook field-signature mismatch
- access-control drift: search index preview ACL drift, cursor tenant leakage
- legacy/version behavior: API version shadow-admin field, backup restore target confusion

## LAN/WAN Additions

The LAN services are intentionally toy line protocols, not real protocol
implementations. They exist to force non-HTTP interaction patterns while staying
safe and deterministic:

- printer/PJL: banner discovery, PJL ID, storage enumeration, PIN-gated file read
- NAS/SMB-lite: share discovery, public metadata leak, service-account reuse, backup read
- directory/LDAP-lite: bind, user lookup, nested group traversal, reset-token use
- OT/Modbus-lite: register discovery, maintenance-state write, protected register read
- MQTT-lite: connect, retained system-topic discovery, diagnostic publish, result subscribe
- DNS-lite: NS lookup, TXT transfer token, tokened zone transfer
- Redis/queue-lite: queue discovery, job inspection, approval-key reuse, artifact retrieval
- POP3/mail-lite: mailbox login, message enumeration, reset-code retrieval, account reset
- Git-lite: repository listing, clone, commit-log inspection, old-config retrieval
- kubelet-lite: pod discovery, service-account token retrieval, namespaced secret read

The WAN scenarios model edge and cloud failure modes that matter in full-scope
pentests without requiring public infrastructure:

- reverse proxy/origin trust mismatch
- CDN cache poisoning through missing `Vary` behavior
- staging vhost discovery and account reset
- OAuth redirect prefix confusion
- IMDSv2-like cloud metadata token pivot through a URL previewer

## Cross-Layer Additions

The final twenty additions broaden the suite toward full pentest coverage:

- LAN/service layer: DNS zone transfer, Redis-like queue state, mailbox reset codes, Git history, kubelet pod tokens
- web/application layer: SSTI sandbox escape, polyglot upload metadata parsing, WAF normalization gap
- API/business-logic layer: idempotency replay, bulk tenant mass assignment
- identity layer: SAML recipient confusion, SCIM dry-run group overwrite
- client/mobile layer: deep-link token handling
- CI/CD and supply-chain layer: artifact environment leak, dependency confusion
- container/Kubernetes layer: registry tag confusion, service-account secret read
- cloud/data/observability layer: signed storage policy mismatch, warehouse RLS bypass, trace baggage leakage

These are lab-only targets. Do not point the service at public networks or use
it as evidence for customer support claims without an AegisPT run artifact and
byte-equal grader proof.

The historical-zero-day-inspired and modern bug-class challenges intentionally
model patterns only. They do not include Java/JNDI, Bash execution, TLS/OpenSSL,
Spring/Tomcat, Microsoft Exchange behavior, external callbacks, file writes, real
RCE, real OAuth infrastructure, real JWT key material exposure, real payment
processing, real SMB/LDAP/MQTT/Modbus implementations, or RF/wireless activity.
