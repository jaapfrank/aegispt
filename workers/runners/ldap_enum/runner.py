from __future__ import annotations

import json
import os
from ipaddress import ip_address
from typing import Any, Protocol
from urllib.parse import urlparse

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

ADS_UF_ACCOUNTDISABLE = 0x0002
ADS_UF_DONT_REQUIRE_PREAUTH = 0x400000
DOMAIN_PASSWORD_COMPLEX = 0x0001

LDAP_ENUM_ARTIFACT_NAME = "ldap-enum-results.json"
PRIVILEGED_GROUP_NAMES = frozenset(
    {
        "account operators",
        "administrators",
        "backup operators",
        "domain admins",
        "enterprise admins",
        "schema admins",
        "server operators",
    }
)


class LdapEnumerationError(RuntimeError):
    """Base error for read-only LDAP enumeration failures."""


class LdapAuthenticationError(LdapEnumerationError):
    """Raised when the directory rejects the configured bind context."""


class LdapDirectoryClient(Protocol):
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
        """Collect raw LDAP records using read-only search operations."""


def target_to_server_uri(target: str, *, use_ssl: bool = False) -> str:
    normalized = target.strip()
    if not normalized:
        raise ValueError("target must not be blank")
    if normalized.startswith(("ldap://", "ldaps://")):
        return normalized
    scheme = "ldaps" if use_ssl else "ldap"
    return f"{scheme}://{normalized}"


def domain_to_base_dn(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("base domain must not be blank")
    if normalized.upper().startswith("DC="):
        return normalized

    parsed = urlparse(normalized if "://" in normalized else f"//{normalized}")
    host = parsed.hostname or normalized.split(":", maxsplit=1)[0]
    labels = [label for label in host.strip(".").split(".") if label]
    if len(labels) < 2:
        raise ValueError("base_dn is required when target is not a domain name")
    return ",".join(f"DC={label}" for label in labels)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _string_list(value: Any) -> list[str]:
    items: list[str] = []
    for item in _as_list(value):
        normalized = str(item or "").strip()
        if normalized:
            items.append(normalized)
    return items


def _first_string(*values: Any) -> str:
    for value in values:
        for item in _string_list(value):
            return item
    return ""


def _int_or_none(value: Any) -> int | None:
    for item in _as_list(value):
        if isinstance(item, bool):
            return int(item)
        if isinstance(item, int):
            return item
        normalized = str(item or "").strip()
        if not normalized:
            continue
        try:
            return int(normalized)
        except ValueError:
            continue
    return None


def _ad_interval_to_days(value: Any) -> int | None:
    interval = _int_or_none(value)
    if interval is None or interval == 0:
        return None
    return round(abs(interval) / 10_000_000 / 60 / 60 / 24)


def _entry_payload(entry: dict[str, Any]) -> dict[str, Any]:
    attrs = entry.get("attributes")
    if isinstance(attrs, dict):
        payload = dict(attrs)
        if entry.get("dn") and "distinguishedName" not in payload:
            payload["distinguishedName"] = entry.get("dn")
        return payload
    return dict(entry)


def _name_from_dn(dn: str) -> str:
    first_rdn = dn.split(",", maxsplit=1)[0].strip()
    if "=" in first_rdn:
        return first_rdn.split("=", maxsplit=1)[1].strip()
    return dn.strip()


def _normalize_user(entry: dict[str, Any]) -> dict[str, Any]:
    payload = _entry_payload(entry)
    dn = _first_string(payload.get("distinguishedName"), payload.get("dn"))
    account_name = _first_string(
        payload.get("sAMAccountName"), payload.get("cn"), _name_from_dn(dn)
    )
    principal = _first_string(payload.get("userPrincipalName"))
    user_account_control = _int_or_none(payload.get("userAccountControl")) or 0
    service_principal_names = _string_list(payload.get("servicePrincipalName"))
    member_of = _string_list(payload.get("memberOf"))
    preauth_required = not bool(user_account_control & ADS_UF_DONT_REQUIRE_PREAUTH)
    enabled = not bool(user_account_control & ADS_UF_ACCOUNTDISABLE)
    return {
        "dn": dn,
        "account_name": account_name,
        "user_principal_name": principal or None,
        "enabled": enabled,
        "member_of": member_of,
        "service_principal_names": service_principal_names,
        "preauth_required": preauth_required,
        "user_account_control": user_account_control,
    }


def _normalize_group(entry: dict[str, Any]) -> dict[str, Any]:
    payload = _entry_payload(entry)
    dn = _first_string(payload.get("distinguishedName"), payload.get("dn"))
    name = _first_string(payload.get("cn"), payload.get("sAMAccountName"), _name_from_dn(dn))
    members = _string_list(payload.get("member"))
    member_of = _string_list(payload.get("memberOf"))
    return {
        "dn": dn,
        "name": name,
        "members": members,
        "member_of": member_of,
        "privileged": name.strip().lower() in PRIVILEGED_GROUP_NAMES,
    }


def _normalize_password_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    min_length = _int_or_none(value.get("minPwdLength"))
    pwd_properties = _int_or_none(value.get("pwdProperties"))
    lockout_threshold = _int_or_none(value.get("lockoutThreshold"))
    max_password_age_days = _ad_interval_to_days(value.get("maxPwdAge"))
    if (
        min_length is None
        and pwd_properties is None
        and lockout_threshold is None
        and max_password_age_days is None
    ):
        return {}
    return {
        "min_length": min_length,
        "complexity_enabled": (
            bool(pwd_properties & DOMAIN_PASSWORD_COMPLEX) if pwd_properties is not None else None
        ),
        "lockout_threshold": lockout_threshold,
        "max_password_age_days": max_password_age_days,
        "raw_policy_present": True,
    }


def normalize_ldap_collection(
    *,
    target: str,
    base_dn: str,
    collection: dict[str, Any] | None,
) -> dict[str, Any]:
    payload = collection if isinstance(collection, dict) else {}
    users = [
        _normalize_user(entry) for entry in payload.get("users", []) if isinstance(entry, dict)
    ]
    groups = [
        _normalize_group(entry) for entry in payload.get("groups", []) if isinstance(entry, dict)
    ]
    user_by_dn = {user["dn"].lower(): user for user in users if user.get("dn")}

    privileged_memberships: list[dict[str, Any]] = []
    for group in groups:
        if not group.get("privileged"):
            continue
        for member_dn in group.get("members", []):
            user = user_by_dn.get(str(member_dn).lower())
            privileged_memberships.append(
                {
                    "group": group["name"],
                    "group_dn": group["dn"],
                    "member_dn": member_dn,
                    "account_name": user["account_name"] if user else _name_from_dn(member_dn),
                    "direct": True,
                    "confidence": 0.86 if user else 0.7,
                }
            )

    spn_accounts = [
        {
            "dn": user["dn"],
            "account_name": user["account_name"],
            "user_principal_name": user["user_principal_name"],
            "service_principal_names": user["service_principal_names"],
        }
        for user in users
        if user.get("enabled") and user.get("service_principal_names")
    ]
    asrep_roastable_accounts = [
        {
            "dn": user["dn"],
            "account_name": user["account_name"],
            "user_principal_name": user["user_principal_name"],
        }
        for user in users
        if user.get("enabled") and user.get("preauth_required") is False
    ]
    errors = _string_list(payload.get("errors"))
    status = "partial" if errors else "ok"
    password_policy = _normalize_password_policy(payload.get("password_policy"))
    return {
        "target": target,
        "base_dn": base_dn,
        "status": status,
        "users": users,
        "groups": groups,
        "privileged_memberships": privileged_memberships,
        "spn_accounts": spn_accounts,
        "asrep_roastable_accounts": asrep_roastable_accounts,
        "password_policy": password_policy,
        "errors": errors,
        "summary": {
            "user_count": len(users),
            "group_count": len(groups),
            "privileged_membership_count": len(privileged_memberships),
            "spn_account_count": len(spn_accounts),
            "asrep_roastable_account_count": len(asrep_roastable_accounts),
            "password_policy_present": bool(password_policy),
        },
    }


def _load_ldap3():
    try:
        import ldap3  # type: ignore[import-not-found]
    except (
        ImportError
    ) as exc:  # pragma: no cover - exercised only when real LDAP is configured without ldap3.
        raise LdapEnumerationError("ldap3 is required for live LDAP enumeration") from exc
    return ldap3


def _ldap3_attributes(entry: dict[str, Any]) -> dict[str, Any]:
    attrs = entry.get("attributes")
    if isinstance(attrs, dict):
        payload = dict(attrs)
        dn = str(entry.get("dn") or "").strip()
        if dn and "distinguishedName" not in payload:
            payload["distinguishedName"] = dn
        return payload
    return {}


class Ldap3DirectoryClient:
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
        ldap3 = _load_ldap3()
        server_uri = target_to_server_uri(target, use_ssl=use_ssl)
        server = ldap3.Server(server_uri, get_info=ldap3.NONE, connect_timeout=timeout_seconds)

        try:
            connection = ldap3.Connection(
                server,
                user=bind_dn,
                password=password,
                auto_bind=True,
                receive_timeout=timeout_seconds,
                read_only=True,
            )
        except ldap3.core.exceptions.LDAPBindError as exc:
            raise LdapAuthenticationError(str(exc)) from exc
        except Exception as exc:
            raise LdapEnumerationError(str(exc)) from exc

        try:
            effective_base_dn = base_dn.strip() or self._default_naming_context(
                ldap3=ldap3,
                connection=connection,
            )
            if not effective_base_dn:
                raise LdapEnumerationError("LDAP RootDSE did not expose a default naming context")
            return {
                "_base_dn": effective_base_dn,
                "users": self._search(
                    ldap3=ldap3,
                    connection=connection,
                    base_dn=effective_base_dn,
                    search_filter="(&(objectCategory=person)(objectClass=user))",
                    attributes=[
                        "distinguishedName",
                        "sAMAccountName",
                        "userPrincipalName",
                        "memberOf",
                        "servicePrincipalName",
                        "userAccountControl",
                    ],
                    page_size=page_size,
                ),
                "groups": self._search(
                    ldap3=ldap3,
                    connection=connection,
                    base_dn=effective_base_dn,
                    search_filter="(objectClass=group)",
                    attributes=["distinguishedName", "cn", "member", "memberOf"],
                    page_size=page_size,
                ),
                "password_policy": self._password_policy(
                    ldap3=ldap3, connection=connection, base_dn=effective_base_dn
                ),
                "errors": [],
            }
        finally:
            connection.unbind()

    def _search(
        self,
        *,
        ldap3,
        connection,
        base_dn: str,
        search_filter: str,
        attributes: list[str],
        page_size: int,
    ) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for entry in connection.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes,
            paged_size=page_size,
            generator=True,
        ):
            if not isinstance(entry, dict) or entry.get("type") != "searchResEntry":
                continue
            entries.append(_ldap3_attributes(entry))
        return entries

    def _password_policy(self, *, ldap3, connection, base_dn: str) -> dict[str, Any]:
        if not connection.search(
            search_base=base_dn,
            search_filter="(objectClass=domainDNS)",
            search_scope=ldap3.BASE,
            attributes=["minPwdLength", "pwdProperties", "lockoutThreshold", "maxPwdAge"],
        ):
            return {}
        for entry in connection.response:
            if isinstance(entry, dict) and entry.get("type") == "searchResEntry":
                return _ldap3_attributes(entry)
        return {}

    def _default_naming_context(self, *, ldap3, connection) -> str:
        if not connection.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=["defaultNamingContext", "rootDomainNamingContext", "namingContexts"],
        ):
            return ""
        for entry in connection.response:
            if not isinstance(entry, dict) or entry.get("type") != "searchResEntry":
                continue
            attrs = _ldap3_attributes(entry)
            for key in ("defaultNamingContext", "rootDomainNamingContext", "namingContexts"):
                for value in _string_list(attrs.get(key)):
                    if value.upper().startswith("DC="):
                        return value
        return ""


def _result_summary(target_results: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "target_count": len(target_results),
        "user_count": sum(
            int(result.get("summary", {}).get("user_count", 0)) for result in target_results
        ),
        "group_count": sum(
            int(result.get("summary", {}).get("group_count", 0)) for result in target_results
        ),
        "privileged_membership_count": sum(
            int(result.get("summary", {}).get("privileged_membership_count", 0))
            for result in target_results
        ),
        "spn_account_count": sum(
            int(result.get("summary", {}).get("spn_account_count", 0)) for result in target_results
        ),
        "asrep_roastable_account_count": sum(
            int(result.get("summary", {}).get("asrep_roastable_account_count", 0))
            for result in target_results
        ),
    }


def execute_ldap_enum(
    targets: list[str],
    *,
    base_dn: str | None = None,
    bind_dn: str | None = None,
    password: str | None = None,
    password_env: str | None = None,
    use_ssl: bool = False,
    timeout_seconds: float = 10.0,
    page_size: int = 500,
    client: LdapDirectoryClient | None = None,
) -> RunnerExecution:
    normalized_targets = [target.strip() for target in targets if target.strip()]
    if not normalized_targets:
        raise ValueError("at least one target is required")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    if page_size <= 0:
        raise ValueError("page_size must be greater than zero")

    resolved_password = password
    if resolved_password is None and password_env:
        resolved_password = os.getenv(password_env)

    directory_client = client or Ldap3DirectoryClient()
    target_results: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    for target in normalized_targets:
        try:
            if isinstance(base_dn, str) and base_dn.strip():
                resolved_base_dn = base_dn.strip()
            else:
                host = urlparse(target if "://" in target else f"//{target}").hostname or target
                try:
                    ip_address(host.split(":", maxsplit=1)[0])
                    resolved_base_dn = ""
                except ValueError:
                    resolved_base_dn = domain_to_base_dn(target)
            collection = directory_client.collect(
                target=target,
                base_dn=resolved_base_dn,
                bind_dn=bind_dn,
                password=resolved_password,
                use_ssl=use_ssl,
                timeout_seconds=timeout_seconds,
                page_size=page_size,
            )
            target_results.append(
                normalize_ldap_collection(
                    target=target,
                    base_dn=str(collection.get("_base_dn") or resolved_base_dn),
                    collection=collection,
                )
            )
        except LdapAuthenticationError as exc:
            exit_code = max(exit_code, 2)
            message = f"{target}: LDAP bind failed"
            stderr_lines.append(message)
            target_results.append(
                {
                    "target": target,
                    "base_dn": base_dn or None,
                    "status": "auth_failed",
                    "users": [],
                    "groups": [],
                    "privileged_memberships": [],
                    "spn_accounts": [],
                    "asrep_roastable_accounts": [],
                    "password_policy": {},
                    "errors": [str(exc)],
                    "summary": {
                        "user_count": 0,
                        "group_count": 0,
                        "privileged_membership_count": 0,
                        "spn_account_count": 0,
                        "asrep_roastable_account_count": 0,
                        "password_policy_present": False,
                    },
                }
            )
        except Exception as exc:
            exit_code = max(exit_code, 1)
            message = f"{target}: {exc}"
            stderr_lines.append(message)
            target_results.append(
                {
                    "target": target,
                    "base_dn": base_dn or None,
                    "status": "failed",
                    "users": [],
                    "groups": [],
                    "privileged_memberships": [],
                    "spn_accounts": [],
                    "asrep_roastable_accounts": [],
                    "password_policy": {},
                    "errors": [str(exc)],
                    "summary": {
                        "user_count": 0,
                        "group_count": 0,
                        "privileged_membership_count": 0,
                        "spn_account_count": 0,
                        "asrep_roastable_account_count": 0,
                        "password_policy_present": False,
                    },
                }
            )

    if exit_code == 0 and any(result.get("status") == "partial" for result in target_results):
        status = "partial"
    elif exit_code == 2:
        status = "auth_failed"
    elif exit_code != 0:
        status = "failed"
    else:
        status = "ok"

    payload = {
        "tool": "ldap-enum",
        "status": status,
        "read_only": True,
        "targets": target_results,
        "summary": _result_summary(target_results),
    }
    artifact = EvidenceArtifact(
        name=LDAP_ENUM_ARTIFACT_NAME,
        content_type="application/json",
        data=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
        kind="identity-enum-results",
    )
    return RunnerExecution(
        tool="ldap-enum",
        exit_code=exit_code,
        stdout=json.dumps({"status": status, "summary": payload["summary"]}, sort_keys=True),
        stderr="\n".join(stderr_lines),
        metadata={
            "status": status,
            "normalized_targets": normalized_targets,
            "read_only": True,
            "use_ssl": use_ssl,
            "page_size": page_size,
            "tool_version": "ldap3",
            "runner_digest": "workers.ldap_enum.runner:v1",
            "result_count": len(target_results),
        },
        artifacts=[artifact],
    )
