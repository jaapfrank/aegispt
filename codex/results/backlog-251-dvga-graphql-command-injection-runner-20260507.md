# Backlog 251 DVGA GraphQL Command-Injection Runner Evidence

- Captured at: `2026-05-07T01:18:29.660167+00:00`
- Local target root: `http://127.0.0.1:5013/`
- Docker image: `dolevf/dvga:latest`
- Container inspect: `2ef21c2767ab4edb049acbcc55da81e8403486a302434e66db5f75609f55eafb sha256:040aa33c199d99f3380c9ff9a1ee5d725e9abca7b189c63a35a2a73bda79c957 [map[HostIp:127.0.0.1 HostPort:5013]]`
- Runner tool: `graphql-command-injection`
- Runner exit code: `0`
- Artifact: `graphql-command-injection-results.json` (`8ea4c377008b8030b0f0a8eb38cabe3107f852423ac93a91556112d1c71d1022`)

## Approval And Scope

- Profile: `intrusive-web-graphql-command-injection`
- Required approvals: `2`
- Approval step: `intrusive-web-graphql-command-injection`
- Runner authorization flags used for proof: `intrusive_authorized=true`, `allow_command_injection_proof=true`
- Scope allowlist: `http://127.0.0.1:5013/`

## Live Proof

- Endpoint: `http://127.0.0.1:5013/graphql`
- Operation: `AegisPTCommandInjection`
- Field and argument: `systemDiagnostics(cmd: ...)`
- Command allowlist entry: `echo aegispt-command-injection-proof`
- Command SHA-256: `308f3dcf9221cb3fccc3477a7eed7e9bedc24fb0d0694c901fbff52cdd21d40d`
- Status code: `200`
- Confirmed: `True`
- Output excerpt: `aegispt-command-injection-proof`
- Cleanup status: `not_required_no_state_change`

## Safety Notes

- Local DVGA only; no public GraphQL or customer target was contacted.
- The live DVGA schema requires `username` and `password` arguments for `systemDiagnostics`; the runner uses the fixed local-lab default DVGA credential context and stores no password value in evidence.
- No arbitrary shell, reverse shell, file write, network callback, persistence, credential discovery, lateral movement, privilege escalation, or generic `graphql-probe` behavior change was performed.

## Cleanup

- DVGA container `aegispt-dvga-backlog251` was stopped after evidence capture.
