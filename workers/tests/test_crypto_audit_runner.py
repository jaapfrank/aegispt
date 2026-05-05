from __future__ import annotations

import json
from types import SimpleNamespace

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS, dispatch_runner
from workers.runners.base.contracts import EvidenceArtifact, RunnerRequest
from workers.runners.crypto_audit.runner import (
    CRYPTO_AUDIT_RESULTS_ARTIFACT_NAME,
    execute_crypto_audit,
)


class ArtifactRecord:
    uri = "artifact://crypto-audit/results"


TLS_FIXTURE = [
    {"id": "export", "finding": "EXPORT cipher offered; FREAK/DROWN downgrade risk"},
    {"id": "poodle", "finding": "POODLE vulnerable SSL 3 support observed"},
    {"id": "tls1", "finding": "TLS 1.0 and TLS 1.1 offered"},
    {"id": "beast", "finding": "BEAST vulnerable CBC cipher on TLS 1.0"},
    {"id": "lucky13", "finding": "LUCKY13 CBC timing-risk signal"},
    {"id": "rc4", "finding": "RC4 cipher offered"},
    {"id": "dh", "finding": "DH group 1024 bits"},
    {"id": "cert", "finding": "RSA certificate key 1024 bits"},
]

SSH_FIXTURE = {
    "raw_payload": {
        "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"],
        "mac": ["hmac-md5", "hmac-sha1-96"],
        "key": ["ssh-dss"],
        "enc": ["aes128-cbc", "arcfour"],
    }
}


def _payload(execution) -> dict:
    artifact = next(
        item for item in execution.artifacts if item.name == CRYPTO_AUDIT_RESULTS_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def test_crypto_audit_normalizes_tls_ssh_and_token_crypto_findings() -> None:
    execution = execute_crypto_audit(
        ["https://portal.example.test"],
        scope_allowlist={
            "urls": ["https://portal.example.test/"],
            "hosts": ["ssh.example.test"],
        },
        tls_targets=["https://portal.example.test"],
        ssh_targets=[{"host": "ssh.example.test", "port": 22}],
        testssl_results={"portal.example.test:443": TLS_FIXTURE},
        ssh_audit_results={"ssh.example.test:22": SSH_FIXTURE},
        http_headers_by_target={"portal.example.test:443": {}},
        token_evidence=[
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            {
                "label": "access-token",
                "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
            },
            {"label": "jwe", "algorithm": "RSA1_5", "target": "https://portal.example.test/app"},
            {"label": "hmac", "algorithm": "HS256", "hmac_key_bits": 128},
        ],
    )

    assert execution.tool == "crypto-audit"
    assert execution.exit_code == 0
    payload = _payload(execution)
    finding_types = {finding["type"] for finding in payload["findings"]}
    assert {
        "tls_export_grade_cipher",
        "tls_sslv3_poodle",
        "tls_legacy_protocol_enabled",
        "tls_beast_cbc_tls10",
        "tls_lucky13_cbc",
        "tls_rc4_enabled",
        "tls_weak_dh_parameters",
        "tls_short_certificate_key",
        "tls_hsts_preload_missing",
        "ssh_weak_kex",
        "ssh_weak_mac",
        "ssh_deprecated_host_key",
        "ssh_weak_cipher",
        "token_md5_length_signal",
        "jws_rsa_pkcs1_v15",
        "jwe_rsa1_5",
        "jwt_hs_short_key",
    }.issubset(finding_types)
    assert payload["safety"]["testssl_used"] is True
    assert payload["safety"]["ssh_audit_used"] is True
    assert payload["safety"]["bruteforce_attempted"] is False
    assert payload["safety"]["decryption_attempted"] is False
    assert payload["safety"]["raw_tokens_stored"] is False
    serialized_payload = json.dumps(payload)
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in serialized_payload
    assert all(finding.get("fix_recommendation") for finding in payload["findings"])
    assert all(finding.get("better_alternative") for finding in payload["findings"])


def test_crypto_audit_dispatch_and_standard_finding_extraction() -> None:
    assert "crypto-audit" in SUPPORTED_TOOLS

    execution = dispatch_runner(
        RunnerRequest(
            tool="crypto-audit",
            targets=["https://portal.example.test"],
            params={
                "tls_targets": ["https://portal.example.test"],
                "ssh_targets": [{"host": "ssh.example.test", "port": 22}],
                "testssl_results": {"portal.example.test:443": TLS_FIXTURE},
                "ssh_audit_results": {"ssh.example.test:22": SSH_FIXTURE},
                "http_headers_by_target": {"portal.example.test:443": {}},
                "timeout_seconds": 5,
            },
            scope_allowlist={
                "urls": ["https://portal.example.test/"],
                "hosts": ["ssh.example.test"],
            },
        )
    )
    artifact = next(
        item for item in execution.artifacts if item.name == CRYPTO_AUDIT_RESULTS_ARTIFACT_NAME
    )

    findings = extract_findings(
        task=SimpleNamespace(
            tool="crypto-audit",
            target_id="https://portal.example.test",
            params_json={},
        ),
        artifact=EvidenceArtifact(
            name=CRYPTO_AUDIT_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=artifact.data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert findings
    assert any(finding.title.startswith("Export-grade TLS cipher") for finding in findings)
    assert all("crypto-audit-validation" in finding.methodology_tags for finding in findings)
