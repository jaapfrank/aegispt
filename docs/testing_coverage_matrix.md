# Testing Coverage Matrix

This matrix captures the current methodology-oriented view of AegisPT capabilities.

| Capability | Tool(s) | PTES Phase | WSTG Area | NIST Relevance | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Engagement definition and scope registration | API control plane | Pre-Engagement | N/A | Planning | Implemented | Scope and ROE reference anchor later testing and reporting. |
| Inventory normalization and snapshotting | Nmap, httpx, ZAP, Playwright, Nuclei, TLS tooling | Intelligence Gathering | Information Gathering; Configuration and Deployment Management Testing | Discovery | Implemented | Creates the stable post-inventory input for adaptive pack planning. |
| Threat intelligence normalization | Approved advisory feeds and curated knowledge | Analysis / Validation | Cross-cutting | Discovery; Reporting | Implemented | Adds normalized advisory context without changing runtime execution. |
| Relevance analysis for customer-specific checks | Inventory plus threat intelligence | Analysis / Validation | Cross-cutting | Discovery; Analysis | Implemented | Reuses Prompt 1 methodology metadata to recommend extra checks and suppress noise. |
| Customer-specific capability pack generation | Capability Factory | Analysis / Validation | Depends on generated artifact | Discovery; Analysis | Implemented | Packs are versioned and reproducible, but not runtime-active until promoted. |
| Pack validation and promotion | Validation pipeline | Analysis / Validation; Controlled Exploitation / Verification | Cross-cutting | Analysis; Reporting | Implemented | Validation, approval, and deployment are explicit release gates. |
| Runtime pack binding | Run binding and task materialization | Controlled Exploitation / Verification | Cross-cutting | Attack; Reporting | Implemented | Runs record exact pack version and deployment binding for reproducibility. |
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
| Adaptive coverage reporting | Markdown and HTML report renderers | Reporting | Cross-cutting | Reporting | Implemented | Reports now show pack provenance, adaptive coverage rationale, and generated-check context. |
| Retest and verification tracking | Finding status workflow, reruns | Retest | Cross-cutting | Post-Testing | Implemented | Existing status model remains the verification-state carrier. |
