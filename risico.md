# Risico's

Laatst bijgewerkt: 2026-05-07

## Open Risico's

| ID | Risico | Impact | Status | Mitigatie / volgende stap |
| --- | --- | --- | --- | --- |
| R-001 | backlog-247 heeft deterministic runner evidence, maar nog geen live AutoPenBench WS4 proof tegen een expliciet geautoriseerde fixture. | Medium | Open | Run sqlmap tegen een lokale of expliciet goedgekeurde WS4-benchmarkfixture zodra die beschikbaar is. |
| R-002 | Queue/task packages 252-267 zijn toegevoegd en gevalideerd, maar moeten per actieve taak nog tegen actuele product truth worden gereconciled. | Medium | Open | Bij promotie steeds `NEXT_TASK.md`, task package en huidige runtime truth lezen; geen oude chatcontext als bron gebruiken. |
| R-003 | backlog-248 `AI Free Bash Execution` blijft hoog-risico als toekomstige wijzigingen approval, scope, credentials, banned commands, output cap of kill switch versoepelen. | High | Beheerst / monitoren | Huidige slice is SSH-only, blokkeert AegisPT/loopback targets, eist `credentials_ref`, toont exact command voor approval, cap't output op 8000 chars, blokkeert banned commands en out-of-scope curl/wget, en audit command/output hashes. |
| R-004 | `wifi-survey` blijft hardware-limited zonder geautoriseerde monitor-mode WiFi-adapter en lab proof. | Medium | Open | Pas product-support claimen na proof met goedgekeurde adapter/labopstelling. |
| R-005 | Enterprise release-readiness blijft geblokkeerd voor known-vulnerability detection accuracy en FP/FN posture. | High | Open | Blijf release-readiness als `blocked/no-go` tonen totdat validation matrix en release gate voldoende bewijs leveren. |
| R-006 | AI adaptive loop, attack path UI en narrative reports kunnen vertrouwen schaden als ze vermoedens als feiten tonen. | High | Open | Alleen echte iteration/evidence/finding links tonen; geen fake chains; narrative tekst evidence-backed maken met verwijzingen naar run data. |
| R-007 | `ai-shell` heeft deterministic runner/UI/API proof, maar nog geen echte SSH-dispatch proof op een geautoriseerde remote labhost. | Medium | Open | Zie `extra_tests.md` XT-001: scoped SSH fixture + benign command + approval + dispatch + audit/output hash verificatie. |
| R-008 | backlog-249 RCE Nuclei-dekking is service-aware en governed, maar de meeste lokale officiele RCE templates bevatten raw/body/payload/code/OOB-command constructs en worden daarom geblokkeerd door het detection-only beleid; Bludit en SambaCry waren lokaal niet beschikbaar. | High | Open | Maak of review curated detection-only templates via de bestaande pack lifecycle, of voer expliciet geautoriseerde labvalidatie uit met ROE/tier/OOB-config; zie `extra_tests.md` XT-005 t/m XT-008. |
| R-009 | backlog-250 maakt de nieuwe runnerprofielen bereikbaar via profiles/chains/wizard, maar niet elke runner is end-to-end live tegen een labfixture uitgevoerd in deze wiring-slice. | Medium | Open | Gebruik `extra_tests.md` XT-009 en XT-010 voor expliciete labvalidatie van web/AI/LAN runners en intrusive ARP proof zonder approval/scope gates te versoepelen. |

## Afgesloten / Beheerst

| ID | Risico | Status | Bewijs |
| --- | --- | --- | --- |
| C-001 | sqlmap Phase B zou onbedoeld te agressief kunnen worden. | Beheerst | Runner gebruikt max `--risk 2`, geen `--dump`, geen OS-shell flags, en behoudt expliciete parameter- en scopechecks. |
| C-002 | Lokale host-tool readiness was incompleet. | Beheerst met uitzondering | `tcpdump`, `arping`, `arpspoof`, `gobuster`, `nikto`, `sqlmap` en `hydra` zijn geinstalleerd; WiFi blijft hardware-limited. |
