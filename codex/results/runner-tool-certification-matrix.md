# Runner and Tool Certification Matrix

- Generated: `2026-05-06T15:47:31.098789+00:00`
- Source task: `codex/tasks/backlog-240-runner-tool-certification-matrix.json`
- Tool count: `56`
- Overall status: `ready_with_hardware_limitation`
- Certified: `55`
- Supported with gap: `0`
- Blocked: `1`
- Hardware-limited: `1`

This artifact is evidence-only. It does not dispatch tools, install software, grant approval, expand scope, or mutate runtime state.

## Tool Matrix

| Tool | Status | Software state | Auth tier | Evidence | Output/report mapping | Limitation |
| --- | --- | --- | --- | --- | --- | --- |
| `api-assessment` | `certified` | `not-required` | `active` | 9 | finding, inventory | No recorded certification gap. |
| `auth-flow` | `certified` | `not-required` | `active` | 10 | finding | No recorded certification gap. |
| `aws-inventory` | `certified` | `not-required` | `passive` | 6 | inventory | No recorded certification gap. |
| `biz-logic-probe` | `certified` | `not-required` | `active` | 6 | finding | No recorded certification gap. |
| `bloodhound-collect` | `certified` | `ready` | `active` | 7 | finding, inventory | No recorded certification gap. |
| `burp` | `certified` | `not-required` | `passive` | 12 | finding | No recorded certification gap. |
| `camera-test` | `certified` | `not-required` | `active` | 8 | finding, inventory | No recorded certification gap. |
| `cicd-security` | `certified` | `not-required` | `passive` | 7 | finding, inventory | No recorded certification gap. |
| `client-state` | `certified` | `not-required` | `active` | 12 | finding | No recorded certification gap. |
| `cloud-native` | `certified` | `not-required` | `passive` | 6 | finding, inventory | No recorded certification gap. |
| `content-discovery` | `certified` | `ready` | `active` | 10 | finding | No recorded certification gap. |
| `credential-attacks` | `certified` | `ready` | `intrusive` | 10 | finding | No recorded certification gap. |
| `crypto-audit` | `certified` | `ready` | `passive` | 13 | finding | No recorded certification gap. |
| `deserialization-probe` | `certified` | `not-required` | `active` | 10 | finding | No recorded certification gap. |
| `desktop-client` | `certified` | `not-required` | `passive` | 6 | finding, inventory | No recorded certification gap. |
| `easm-discover` | `certified` | `not-required` | `passive` | 15 | inventory | No recorded certification gap. |
| `external-infra` | `certified` | `not-required` | `passive` | 11 | finding, inventory | No recorded certification gap. |
| `external-osint` | `certified` | `not-required` | `passive` | 8 | finding | No recorded certification gap. |
| `graphql-probe` | `certified` | `not-required` | `active` | 12 | finding | No recorded certification gap. |
| `headers-security` | `certified` | `not-required` | `active` | 10 | finding | No recorded certification gap. |
| `http-smuggling` | `certified` | `not-required` | `active` | 10 | finding | No recorded certification gap. |
| `httpx` | `certified` | `ready` | `passive` | 55 | inventory | No recorded certification gap. |
| `idor-bac` | `certified` | `not-required` | `active` | 9 | finding | No recorded certification gap. |
| `impacket-lateral` | `certified` | `ready` | `intrusive` | 7 | finding | No recorded certification gap. |
| `iot-default-creds` | `certified` | `not-required` | `active` | 6 | finding | No recorded certification gap. |
| `ipv6-discovery` | `certified` | `not-required` | `passive` | 11 | finding, inventory | No recorded certification gap. |
| `jwt-probe` | `certified` | `not-required` | `active` | 9 | finding | No recorded certification gap. |
| `ldap-enum` | `certified` | `not-required` | `passive` | 13 | finding, inventory | No recorded certification gap. |
| `llm-probe` | `certified` | `not-required` | `active` | 5 | finding | No recorded certification gap. |
| `logging-probe` | `certified` | `not-required` | `passive` | 11 | finding | No recorded certification gap. |
| `mdns-ssdp` | `certified` | `not-required` | `passive` | 8 | finding, inventory | No recorded certification gap. |
| `metasploit` | `certified` | `ready` | `intrusive` | 10 | finding | No recorded certification gap. |
| `mobile-android` | `certified` | `not-required` | `passive` | 6 | finding, inventory | No recorded certification gap. |
| `netexec` | `certified` | `ready` | `passive` | 11 | finding | No recorded certification gap. |
| `network-capture` | `certified` | `ready` | `passive` | 13 | finding, inventory | No recorded certification gap. |
| `network-segmentation` | `certified` | `not-required` | `passive` | 6 | finding | No recorded certification gap. |
| `nikto` | `certified` | `ready` | `passive` | 9 | finding | No recorded certification gap. |
| `nmap` | `certified` | `ready` | `passive` | 34 | inventory | No recorded certification gap. |
| `nuclei` | `certified` | `ready` | `passive` | 39 | finding | No recorded certification gap. |
| `oauth-probe` | `certified` | `not-required` | `active` | 12 | finding | No recorded certification gap. |
| `playwright-web` | `certified` | `not-required` | `passive` | 6 | finding | No recorded certification gap. |
| `priv-esc-linux` | `certified` | `not-required` | `active` | 15 | finding | No recorded certification gap. |
| `responder` | `certified` | `ready` | `intrusive` | 11 | finding | No recorded certification gap. |
| `semgrep` | `certified` | `ready` | `passive` | 9 | finding | No recorded certification gap. |
| `session-security` | `certified` | `not-required` | `active` | 12 | finding | No recorded certification gap. |
| `smart-home` | `certified` | `not-required` | `passive` | 17 | finding, inventory | No recorded certification gap. |
| `snmp-enum` | `certified` | `ready` | `passive` | 13 | finding, inventory | No recorded certification gap. |
| `sqlmap` | `certified` | `ready` | `active` | 10 | finding | No recorded certification gap. |
| `ssh-brute` | `certified` | `ready` | `active` | 13 | finding | No recorded certification gap. |
| `ssrf-probe` | `certified` | `not-required` | `active` | 10 | finding | No recorded certification gap. |
| `ssti-probe` | `certified` | `not-required` | `active` | 10 | finding | No recorded certification gap. |
| `vuln-components` | `certified` | `not-required` | `active` | 9 | finding | No recorded certification gap. |
| `wifi-survey` | `blocked` | `ready` | `passive` | 13 | finding, inventory | No deterministic hardware lab or monitor-mode adapter proof is recorded in this task. |
| `xss-extended` | `certified` | `not-required` | `active` | 12 | finding | No recorded certification gap. |
| `xxe-probe` | `certified` | `not-required` | `active` | 9 | finding | No recorded certification gap. |
| `zap` | `certified` | `ready` | `intrusive` | 39 | finding | No recorded certification gap. |

## Hardware Blockers

- `wifi-survey`: No deterministic hardware lab or monitor-mode adapter proof is recorded in this task.
