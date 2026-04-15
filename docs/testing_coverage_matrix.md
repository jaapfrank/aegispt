# Testing Coverage Matrix

This matrix captures the current methodology-oriented view of AegisPT capabilities.

| Capability | Tool(s) | PTES Phase | WSTG Area | NIST Relevance | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Engagement definition and scope registration | API control plane | Pre-Engagement | N/A | Planning | Implemented | Scope and ROE reference anchor later testing and reporting. |
| Passive HTTP reconnaissance | httpx | Intelligence Gathering | Information Gathering | Discovery | Implemented | Used for low-impact baseline discovery. |
| Network and service reconnaissance | nmap | Intelligence Gathering | Information Gathering; Configuration and Deployment Management Testing | Discovery | Planned | Tool is in platform intent, deeper orchestration remains future work. |
| Content and path discovery | ffuf, feroxbuster | Intelligence Gathering | Information Gathering; Configuration and Deployment Management Testing | Discovery | Planned | Good fit for future workflow expansion without architecture change. |
| Template-driven web validation | Nuclei | Analysis / Validation | Configuration and Deployment Management Testing; Input Validation Testing | Discovery | Implemented | Findings may receive WSTG references when the template result clearly maps. |
| Passive web crawling and alert collection | OWASP ZAP | Analysis / Validation | Information Gathering; Configuration and Deployment Management Testing; Client-side Testing | Discovery | Implemented | Approval-gated via existing run profiles when appropriate. |
| Controlled active web validation | OWASP ZAP | Controlled Exploitation / Verification | Authorization; Session Management; Input Validation; Client-side Testing | Attack | Implemented | Active ZAP remains explicitly approval-gated. |
| Static code review validation | Semgrep | Analysis / Validation | Optional WSTG mapping; secure code review support | Discovery | Implemented | WSTG references remain optional because not every code finding is a web test case. |
| Browser-assisted client validation | Playwright | Analysis / Validation | Client-side Testing; Business Logic Testing | Discovery; Attack | Planned | Fits the current execution model but is not yet first-class in the shipped slice. |
| TLS and transport validation | testssl.sh, Nuclei, ZAP | Analysis / Validation | Weak Cryptography Testing | Discovery | Planned / Partial | Methodology alignment now exists; deeper orchestration remains future work. |
| Manual or assisted authorization validation | ZAP, internal validation workflows | Controlled Exploitation / Verification | Authorization Testing; Business Logic Testing | Attack | Partial | Core evidence and approvals are present; richer scenario libraries can expand later. |
| API validation | HTTP tooling, ZAP, future dedicated API checks | Analysis / Validation | API Testing | Discovery; Attack | Partial | Current support is broad but not yet a dedicated API-first workflow. |
| Controlled internal adversary validation | Internal validation sessions, approved runs | Controlled Exploitation / Verification | Depends on launched step | Attack; Post-Testing | Implemented | Stepwise, replayable, and explicitly non-autonomous. |
| Evidence capture and replayability | Artifact store, task execution records | Reporting; Retest | Cross-cutting | Execution, Data Handling, Reporting | Implemented | Core evidence-first architecture stays unchanged. |
| Finding normalization with methodology metadata | Finding pipeline | Analysis / Validation; Controlled Exploitation / Verification | Cross-cutting | Analysis, Reporting | Implemented | This alignment patch adds PTES/NIST/WSTG metadata to findings. |
| Executive-style report export | HTML report renderer | Reporting | Cross-cutting | Reporting | Implemented | Now includes methodology summary, scope, ROE, coverage, findings, and verification status. |
| Technical report export | Markdown report renderer | Reporting | Cross-cutting | Reporting | Implemented | Includes fuller methodology detail and structured evidence/reproduction sections. |
| Retest and verification tracking | Finding status workflow, reruns | Retest | Cross-cutting | Post-Testing | Implemented | Existing status model remains the verification-state carrier. |
