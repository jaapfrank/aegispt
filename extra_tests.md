# Extra Tests

Laatst bijgewerkt: 2026-05-07

## Niet Live Getest / Nog Extra Bewijs Nodig

| ID | Onderdeel | Niet live getest | Reden | Benodigde extra test |
| --- | --- | --- | --- | --- |
| XT-001 | `ai-shell` runner | Echte SSH-uitvoering op een geautoriseerde remote host | De build-lane had geen expliciet aangewezen SSH-labtarget met credential-ref voor deze taak; deterministic tests gebruikten een fake command runner. | Start een lokale of expliciet geautoriseerde SSH fixture buiten de AegisPT host, voeg scope + `credentials_ref` toe, approve precies één benign command zoals `id`, dispatch de queued task, en verifieer audit/output hash/artifact. |
| XT-002 | `ai-shell` kill-switch runtime | Live dispatch terwijl engagement `ai_shell.enabled=false` of kill switch actief is | API review-blocking en runner kill-switch path zijn deterministic getest; geen live worker dispatch met kill switch is uitgevoerd. | Maak een scoped run met `active-ai-shell`, zet `configuration_json.ai_shell.enabled=false`, probeer approval/dispatch, en bevestig dat er geen SSH command start. |
| XT-003 | `ai-shell` out-of-scope download blocking | Real shell command met `curl`/`wget` naar out-of-scope URL | Safety parser is deterministic getest; geen live remote command is uitgevoerd. | In een labhost een benign `curl https://out-of-scope.example/p` proposal aanbieden en bevestigen dat proposal approval of runner preflight blokkeert voor SSH. |
| XT-004 | backlog-247 sqlmap Phase B | Live AutoPenBench WS4 proof | Deterministic runner evidence bestaat, maar geen live WS4 fixture is uitgevoerd in backlog-247. | Run tegen een expliciet geautoriseerde lokale WS4/AutoPenBench fixture met concrete injectable parameter evidence. |
