from __future__ import annotations

import json
from typing import Any

from api.app.services.inventory import (
    ldap_enum_observation_from_json,
    normalize_inventory_observations,
)
from workers.orchestration.findings import extract_ldap_enum_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.ldap_enum.runner import (
    ADS_UF_DONT_REQUIRE_PREAUTH,
    LDAP_ENUM_ARTIFACT_NAME,
    LdapAuthenticationError,
    domain_to_base_dn,
    execute_ldap_enum,
    normalize_ldap_collection,
    target_to_server_uri,
)


class StaticDirectoryClient:
    def __init__(
        self, collection: dict[str, Any] | None = None, exc: Exception | None = None
    ) -> None:
        self.collection = collection or {}
        self.exc = exc
        self.calls: list[dict[str, Any]] = []

    def collect(
        self,
        *,
        target: str,
        base_dn: str,
        bind_dn: str | None,
        password: str | None,
        use_ssl: bool,
        timeout_seconds: float,
        page_size: int,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "target": target,
                "base_dn": base_dn,
                "bind_dn": bind_dn,
                "password": password,
                "use_ssl": use_ssl,
                "timeout_seconds": timeout_seconds,
                "page_size": page_size,
            }
        )
        if self.exc is not None:
            raise self.exc
        return self.collection


class ArtifactRecord:
    uri = "artifact://ldap-enum/result"


def _artifact_payload(execution) -> dict[str, Any]:
    assert execution.artifacts[0].name == LDAP_ENUM_ARTIFACT_NAME
    return json.loads(execution.artifacts[0].data.decode("utf-8"))


def test_ldap_target_helpers_are_read_only_uri_builders() -> None:
    assert target_to_server_uri("dc01.corp.example") == "ldap://dc01.corp.example"
    assert target_to_server_uri("dc01.corp.example", use_ssl=True) == "ldaps://dc01.corp.example"
    assert target_to_server_uri("ldap://dc01.corp.example") == "ldap://dc01.corp.example"
    assert domain_to_base_dn("corp.example") == "DC=corp,DC=example"
    assert domain_to_base_dn("DC=corp,DC=example") == "DC=corp,DC=example"


def test_ldap_enum_zero_data_stores_empty_read_only_evidence() -> None:
    client = StaticDirectoryClient(
        {
            "users": [],
            "groups": [],
            "password_policy": {},
            "errors": [],
        }
    )

    execution = execute_ldap_enum(
        ["dc01.corp.example"],
        base_dn="DC=corp,DC=example",
        client=client,
    )
    payload = _artifact_payload(execution)

    assert execution.tool == "ldap-enum"
    assert execution.exit_code == 0
    assert execution.metadata["read_only"] is True
    assert payload["read_only"] is True
    assert payload["status"] == "ok"
    assert payload["summary"]["user_count"] == 0
    assert payload["summary"]["group_count"] == 0
    assert payload["targets"][0]["summary"]["password_policy_present"] is False
    assert client.calls[0]["base_dn"] == "DC=corp,DC=example"


def test_ldap_enum_ip_target_can_discover_base_dn_from_root_dse() -> None:
    client = StaticDirectoryClient(
        {
            "_base_dn": "DC=corp,DC=example",
            "users": [],
            "groups": [],
            "password_policy": {},
            "errors": [],
        }
    )

    execution = execute_ldap_enum(["10.0.20.10"], client=client)
    payload = _artifact_payload(execution)

    assert execution.exit_code == 0
    assert client.calls[0]["base_dn"] == ""
    assert payload["targets"][0]["base_dn"] == "DC=corp,DC=example"


def test_ldap_enum_auth_failure_is_explicit_without_collecting_records() -> None:
    client = StaticDirectoryClient(exc=LdapAuthenticationError("invalid credentials"))

    execution = execute_ldap_enum(
        ["dc01.corp.example"],
        base_dn="DC=corp,DC=example",
        bind_dn="CN=readonly,CN=Users,DC=corp,DC=example",
        password="super-secret",
        client=client,
    )
    payload = _artifact_payload(execution)

    assert execution.exit_code == 2
    assert execution.metadata["status"] == "auth_failed"
    assert payload["status"] == "auth_failed"
    assert payload["targets"][0]["users"] == []
    assert payload["targets"][0]["groups"] == []
    assert "super-secret" not in execution.stdout
    assert "super-secret" not in execution.stderr


def test_ldap_enum_partial_directory_normalizes_identity_signals() -> None:
    alice_dn = "CN=Alice Admin,CN=Users,DC=corp,DC=example"
    service_dn = "CN=svc-sql,CN=Users,DC=corp,DC=example"
    collection = {
        "users": [
            {
                "distinguishedName": alice_dn,
                "sAMAccountName": "alice.admin",
                "userPrincipalName": "alice.admin@corp.example",
                "memberOf": ["CN=Domain Admins,CN=Users,DC=corp,DC=example"],
                "userAccountControl": 512,
            },
            {
                "distinguishedName": service_dn,
                "sAMAccountName": "svc-sql",
                "servicePrincipalName": ["MSSQLSvc/sql01.corp.example:1433"],
                "userAccountControl": 512 + ADS_UF_DONT_REQUIRE_PREAUTH,
            },
        ],
        "groups": [
            {
                "distinguishedName": "CN=Domain Admins,CN=Users,DC=corp,DC=example",
                "cn": "Domain Admins",
                "member": [alice_dn],
            }
        ],
        "password_policy": {
            "minPwdLength": 8,
            "pwdProperties": 0,
            "lockoutThreshold": 0,
            "maxPwdAge": -36288000000000,
        },
        "errors": ["group member range retrieval truncated"],
    }

    execution = execute_ldap_enum(
        ["dc01.corp.example"],
        base_dn="DC=corp,DC=example",
        client=StaticDirectoryClient(collection),
    )
    payload = _artifact_payload(execution)
    target_result = payload["targets"][0]

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "partial"
    assert target_result["status"] == "partial"
    assert target_result["summary"]["user_count"] == 2
    assert target_result["summary"]["group_count"] == 1
    assert target_result["summary"]["privileged_membership_count"] == 1
    assert target_result["summary"]["spn_account_count"] == 1
    assert target_result["summary"]["asrep_roastable_account_count"] == 1
    assert target_result["password_policy"]["min_length"] == 8
    assert target_result["password_policy"]["complexity_enabled"] is False


def test_ldap_collection_normalization_handles_partial_raw_records() -> None:
    normalized = normalize_ldap_collection(
        target="dc01.corp.example",
        base_dn="DC=corp,DC=example",
        collection={
            "users": [{"dn": "CN=NoAttrs,DC=corp,DC=example"}],
            "groups": [
                {
                    "dn": "CN=Domain Admins,DC=corp,DC=example",
                    "member": ["CN=NoAttrs,DC=corp,DC=example"],
                }
            ],
            "password_policy": {},
            "errors": ["users search incomplete"],
        },
    )

    assert normalized["status"] == "partial"
    assert normalized["users"][0]["account_name"] == "NoAttrs"
    assert normalized["groups"][0]["privileged"] is True
    assert normalized["privileged_memberships"][0]["account_name"] == "NoAttrs"


def test_ldap_enum_inventory_and_findings_use_existing_models() -> None:
    payload = {
        "tool": "ldap-enum",
        "status": "ok",
        "read_only": True,
        "targets": [
            {
                "target": "dc01.corp.example",
                "base_dn": "DC=corp,DC=example",
                "status": "ok",
                "users": [
                    {
                        "dn": "CN=svc-sql,CN=Users,DC=corp,DC=example",
                        "account_name": "svc-sql",
                        "user_principal_name": "svc-sql@corp.example",
                        "enabled": True,
                        "member_of": [],
                        "service_principal_names": ["MSSQLSvc/sql01.corp.example:1433"],
                        "preauth_required": False,
                    }
                ],
                "groups": [
                    {
                        "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=example",
                        "name": "Domain Admins",
                        "members": ["CN=svc-sql,CN=Users,DC=corp,DC=example"],
                        "privileged": True,
                    }
                ],
                "privileged_memberships": [
                    {
                        "group": "Domain Admins",
                        "group_dn": "CN=Domain Admins,CN=Users,DC=corp,DC=example",
                        "member_dn": "CN=svc-sql,CN=Users,DC=corp,DC=example",
                        "account_name": "svc-sql",
                        "confidence": 0.86,
                    }
                ],
                "spn_accounts": [
                    {
                        "dn": "CN=svc-sql,CN=Users,DC=corp,DC=example",
                        "account_name": "svc-sql",
                        "service_principal_names": ["MSSQLSvc/sql01.corp.example:1433"],
                    }
                ],
                "asrep_roastable_accounts": [
                    {
                        "dn": "CN=svc-sql,CN=Users,DC=corp,DC=example",
                        "account_name": "svc-sql",
                    }
                ],
                "password_policy": {
                    "min_length": 8,
                    "complexity_enabled": False,
                    "lockout_threshold": 0,
                    "raw_policy_present": True,
                },
                "errors": [],
                "summary": {},
            }
        ],
        "summary": {},
    }
    artifact = EvidenceArtifact(
        name=LDAP_ENUM_ARTIFACT_NAME,
        content_type="application/json",
        data=json.dumps(payload).encode("utf-8"),
        kind="identity-enum-results",
    )

    observation = ldap_enum_observation_from_json(
        json_bytes=artifact.data, target_id="dc01.corp.example"
    )
    normalized_inventory = normalize_inventory_observations(
        observations=[observation],
        environment_notes=[],
        assumptions=[],
    )
    findings = extract_ldap_enum_findings(
        target_id="dc01.corp.example",
        artifact=artifact,
        artifact_record=ArtifactRecord(),
    )

    assert normalized_inventory["identity_subjects"][0]["account_name"] == "svc-sql"
    assert normalized_inventory["identity_groups"][0]["name"] == "Domain Admins"
    assert normalized_inventory["privileged_memberships"][0]["member"] == "svc-sql"
    assert {finding.title for finding in findings} == {
        "AS-REP roastable account indicators observed",
        "Kerberoastable account indicators observed",
        "Privileged directory memberships observed",
        "Weak password policy signals observed",
    }
