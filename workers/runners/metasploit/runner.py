from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from api.app.config import get_settings
from api.app.policy.engine import execution_kill_switch_enabled
from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import (
    EvidenceArtifact,
    ProtectedSecretMaterial,
    RunnerExecution,
)
from workers.runners.metasploit.module_allowlist import (
    AllowlistedMetasploitModule,
    resolve_allowlisted_module,
)

try:
    import msgpack  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - fallback path for local dev envs without explicit msgpack
    from pip._vendor import msgpack  # type: ignore[no-redef]


METASPLOIT_RESULTS_ARTIFACT_NAME = "metasploit-results.json"
METASPLOIT_LOG_ARTIFACT_NAME = "metasploit-session.log"
DEFAULT_RPC_URL = "http://127.0.0.1:55553/api/1.0"
DEFAULT_LHOST = "127.0.0.1"
DEFAULT_LPORT = 4444
DEFAULT_RPC_TIMEOUT_SECONDS = 10.0
DEFAULT_SESSION_WAIT_SECONDS = 45.0
DEFAULT_JOB_WAIT_SECONDS = 20.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.2
_SAFE_SLUG_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")
_GETUID_PATTERN = re.compile(r"Server username:\s*(?P<value>.+)", re.IGNORECASE)
_HOSTNAME_PATTERN = re.compile(r"Computer\s*:\s*(?P<value>.+)", re.IGNORECASE)


def _safe_slug(value: str) -> str:
    return _SAFE_SLUG_PATTERN.sub("-", str(value or "").strip()).strip("-") or "target"


def _normalize_loopback_host(value: str | None) -> str:
    normalized = str(value or DEFAULT_LHOST).strip().lower()
    if normalized in {"localhost", "127.0.0.1"}:
        return "127.0.0.1"
    if normalized == "::1":
        return "::1"
    raise ValueError("Metasploit LHOST must stay on loopback for controlled exploitation")


def _normalize_port(value: object, *, default: int) -> int:
    if value is None:
        return default
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Metasploit port values must be numeric") from exc
    if normalized <= 0 or normalized > 65535:
        raise ValueError("Metasploit port values must be between 1 and 65535")
    return normalized


def _normalize_rpc_url(value: str | None) -> str:
    normalized = str(value or DEFAULT_RPC_URL).strip()
    if not normalized:
        raise ValueError("Metasploit RPC URL must not be blank")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Metasploit RPC URL must use http or https")
    hostname = str(parsed.hostname or "").strip().lower()
    if hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Metasploit RPC service must stay on loopback")
    return normalized


def _normalize_auth_contexts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, Any]] = []
    for raw_context in value:
        if not isinstance(raw_context, dict):
            continue
        username = str(raw_context.get("username") or "").strip()
        password = str(raw_context.get("password") or "").strip()
        ntlm_hash = str(raw_context.get("ntlm_hash") or "").strip()
        if not username or (not password and not ntlm_hash):
            continue
        normalized.append(
            {
                "label": str(raw_context.get("label") or username).strip() or username,
                "username": username,
                "password": password or None,
                "ntlm_hash": ntlm_hash or None,
                "domain": str(raw_context.get("domain") or "").strip() or None,
                "local_auth": bool(raw_context.get("local_auth", False)),
            }
        )
    return normalized


def _normalize_finding_context(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(
            "Metasploit requires source finding context from an approved prior finding"
        )
    title = str(value.get("title") or "").strip()
    target_id = str(value.get("target_id") or "").strip()
    if not title or not target_id:
        raise ValueError("Metasploit source finding context must include title and target_id")
    return {
        "id": str(value.get("id") or "").strip() or None,
        "title": title,
        "summary": str(value.get("summary") or "").strip() or None,
        "severity": str(value.get("severity") or "").strip() or None,
        "target_id": target_id,
        "methodology_tags": [
            str(tag).strip()
            for tag in list(value.get("methodology_tags") or [])
            if str(tag).strip()
        ],
    }


def _sanitize_text(value: str, secrets: list[str]) -> str:
    sanitized = str(value or "")
    for secret in secrets:
        candidate = str(secret or "").strip()
        if candidate:
            sanitized = sanitized.replace(candidate, "[REDACTED]")
    return sanitized


def _smb_auth_datastore(auth_context: dict[str, Any], *, target_port: int) -> dict[str, Any]:
    datastore: dict[str, Any] = {
        "RPORT": target_port,
    }
    username = str(auth_context.get("username") or "").strip()
    if not username:
        raise ValueError("Metasploit SMB exploitation requires a username")
    datastore["SMBUser"] = username
    if auth_context.get("ntlm_hash"):
        datastore["SMBHash"] = str(auth_context.get("ntlm_hash") or "").strip()
    elif auth_context.get("password"):
        datastore["SMBPass"] = str(auth_context.get("password") or "").strip()
    else:
        raise ValueError("Metasploit SMB exploitation requires a password or NTLM hash")
    domain = str(auth_context.get("domain") or "").strip()
    if domain:
        datastore["SMBDomain"] = domain
    return datastore


def _build_exploit_datastore(
    *,
    target: str,
    allowlisted_module: AllowlistedMetasploitModule,
    lhost: str,
    lport: int,
    target_port: int,
    auth_context: dict[str, Any] | None,
) -> dict[str, Any]:
    datastore: dict[str, Any] = {
        "RHOSTS": target,
        "RPORT": target_port,
        "LHOST": lhost,
        "LPORT": lport,
        "PAYLOAD": allowlisted_module.payload,
    }
    if allowlisted_module.requires_auth:
        if auth_context is None:
            raise ValueError("This allowlisted Metasploit module requires authenticated access")
        if allowlisted_module.auth_scheme != "smb":
            raise ValueError("Unsupported Metasploit authentication scheme")
        datastore.update(_smb_auth_datastore(auth_context, target_port=target_port))
    return datastore


def build_msfrpcd_command(
    binary: str,
    *,
    rpc_url: str,
    username: str,
    password: str,
) -> list[str]:
    normalized_binary = str(binary or "").strip()
    if not normalized_binary:
        raise ValueError("Metasploit msfrpcd binary must not be blank")
    parsed = urlparse(_normalize_rpc_url(rpc_url))
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 55553
    ssl_enabled = parsed.scheme == "https"
    return [
        normalized_binary,
        "-U",
        str(username or "").strip(),
        "-P",
        str(password or "").strip(),
        "-a",
        host,
        "-p",
        str(port),
        "-S",
        "true" if ssl_enabled else "false",
        "-f",
    ]


@dataclass(slots=True)
class MetasploitRpcClient:
    base_url: str
    username: str
    password: str
    verify_ssl: bool = False
    timeout_seconds: float = DEFAULT_RPC_TIMEOUT_SECONDS
    client_factory: Any = httpx.Client

    def __post_init__(self) -> None:
        self.base_url = _normalize_rpc_url(self.base_url)
        self.username = str(self.username or "").strip()
        self.password = str(self.password or "").strip()
        if not self.username or not self.password:
            raise ValueError("Metasploit RPC username and password are required")
        self._token: str | None = None
        self._client = self.client_factory(
            timeout=max(float(self.timeout_seconds), 1.0),
            verify=bool(self.verify_ssl),
            follow_redirects=True,
        )

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, *params: object, authenticated: bool = True) -> dict[str, Any]:
        payload = [method]
        if authenticated:
            if not self._token:
                self.login()
            payload.append(self._token)
        payload.extend(params)
        response = self._client.post(
            self.base_url,
            content=msgpack.packb(payload, use_bin_type=True),
            headers={
                "Content-Type": "binary/message-pack",
                "Accept": "binary/message-pack",
            },
        )
        response.raise_for_status()
        decoded = msgpack.unpackb(response.content, raw=False, strict_map_key=False)
        if not isinstance(decoded, dict):
            raise RuntimeError(f"Unexpected Metasploit RPC response for {method}")
        if decoded.get("error"):
            raise RuntimeError(
                f"Metasploit RPC {method} failed: {decoded.get('error_message') or decoded.get('error_class') or 'unknown error'}"
            )
        return decoded

    def login(self) -> str:
        payload = self._request("auth.login", self.username, self.password, authenticated=False)
        token = str(payload.get("token") or "").strip()
        if not token:
            raise RuntimeError("Metasploit RPC did not return an auth token")
        self._token = token
        return token

    def call(self, method: str, *params: object) -> dict[str, Any]:
        return self._request(method, *params, authenticated=True)


def _start_msfrpcd_process(
    *,
    binary: str,
    rpc_url: str,
    username: str,
    password: str,
) -> subprocess.Popen[str]:
    command = build_msfrpcd_command(
        binary,
        rpc_url=rpc_url,
        username=username,
        password=password,
    )
    return subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=os.environ.copy(),
    )


def _terminate_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3.0)


def _wait_for_rpc_ready(
    client: MetasploitRpcClient,
    *,
    timeout_seconds: float,
    poll_interval_seconds: float,
    kill_switch_check: Callable[[], bool] | None,
) -> bool:
    deadline = time.monotonic() + max(float(timeout_seconds), 1.0)
    while time.monotonic() < deadline:
        if kill_switch_check is not None and bool(kill_switch_check()):
            return False
        try:
            client.login()
            return True
        except Exception:
            time.sleep(max(float(poll_interval_seconds), 0.05))
    return False


def _job_id_from_payload(payload: dict[str, Any]) -> str | None:
    for field_name in ("job_id", "jobid"):
        raw_value = payload.get(field_name)
        if raw_value in (None, ""):
            continue
        return str(raw_value).strip()
    return None


def _wait_for_job_completion(
    client: MetasploitRpcClient,
    *,
    job_id: str | None,
    timeout_seconds: float,
    poll_interval_seconds: float,
    kill_switch_check: Callable[[], bool] | None,
) -> bool:
    if not job_id:
        return True
    deadline = time.monotonic() + max(float(timeout_seconds), 1.0)
    while time.monotonic() < deadline:
        if kill_switch_check is not None and bool(kill_switch_check()):
            return False
        jobs_payload = client.call("job.list")
        jobs = jobs_payload.get("jobs", jobs_payload)
        if isinstance(jobs, dict) and str(job_id) not in {str(key) for key in jobs}:
            return True
        time.sleep(max(float(poll_interval_seconds), 0.05))
    return False


def _new_session_id(
    *,
    before_sessions: dict[str, Any],
    after_sessions: dict[str, Any],
    target: str,
) -> str | None:
    before_ids = {str(key) for key in before_sessions}
    for raw_session_id, raw_session in after_sessions.items():
        session_id = str(raw_session_id)
        if session_id in before_ids or not isinstance(raw_session, dict):
            continue
        target_host = str(raw_session.get("target_host") or "").strip()
        tunnel_peer = str(raw_session.get("tunnel_peer") or "").strip()
        if target_host == target or target in tunnel_peer or not before_ids:
            return session_id
    for raw_session_id, raw_session in after_sessions.items():
        session_id = str(raw_session_id)
        if session_id not in before_ids and isinstance(raw_session, dict):
            return session_id
    return None


def _wait_for_new_session(
    client: MetasploitRpcClient,
    *,
    before_sessions: dict[str, Any],
    target: str,
    timeout_seconds: float,
    poll_interval_seconds: float,
    kill_switch_check: Callable[[], bool] | None,
) -> tuple[str | None, dict[str, Any], bool]:
    deadline = time.monotonic() + max(float(timeout_seconds), 1.0)
    last_sessions: dict[str, Any] = before_sessions
    while time.monotonic() < deadline:
        if kill_switch_check is not None and bool(kill_switch_check()):
            return None, last_sessions, True
        payload = client.call("session.list")
        sessions = payload if isinstance(payload, dict) else {}
        session_id = _new_session_id(
            before_sessions=before_sessions, after_sessions=sessions, target=target
        )
        if session_id is not None:
            session_payload = sessions.get(session_id)
            return session_id, session_payload if isinstance(session_payload, dict) else {}, False
        last_sessions = sessions
        time.sleep(max(float(poll_interval_seconds), 0.05))
    return None, last_sessions, False


def _read_meterpreter_output(
    client: MetasploitRpcClient,
    *,
    session_id: str,
    timeout_seconds: float,
    poll_interval_seconds: float,
    kill_switch_check: Callable[[], bool] | None,
) -> str:
    deadline = time.monotonic() + max(float(timeout_seconds), 1.0)
    chunks: list[str] = []
    while time.monotonic() < deadline:
        if kill_switch_check is not None and bool(kill_switch_check()):
            break
        payload = client.call("session.meterpreter_read", session_id)
        data = str(payload.get("data") or payload.get("result") or "").strip()
        if data:
            chunks.append(data)
        if data and not bool(payload.get("busy", False)):
            break
        time.sleep(max(float(poll_interval_seconds), 0.05))
    return "\n".join(chunk for chunk in chunks if chunk).strip()


def _run_meterpreter_command(
    client: MetasploitRpcClient,
    *,
    session_id: str,
    command: str,
    timeout_seconds: float,
    poll_interval_seconds: float,
    kill_switch_check: Callable[[], bool] | None,
) -> str:
    client.call("session.meterpreter_run_single", session_id, command)
    return _read_meterpreter_output(
        client,
        session_id=session_id,
        timeout_seconds=timeout_seconds,
        poll_interval_seconds=poll_interval_seconds,
        kill_switch_check=kill_switch_check,
    )


def _cleanup_remote_state(
    client: MetasploitRpcClient,
    *,
    session_ids: list[str],
    job_ids: list[str],
    stop_core: bool,
) -> None:
    for session_id in session_ids:
        try:
            client.call("session.stop", session_id)
        except Exception:
            continue
    for job_id in job_ids:
        try:
            client.call("job.stop", job_id)
        except Exception:
            continue
    if stop_core:
        try:
            client.call("core.stop")
        except Exception:
            return


def _session_username(session_payload: dict[str, Any], getuid_output: str) -> str:
    match = _GETUID_PATTERN.search(getuid_output)
    if match is not None:
        value = str(match.group("value") or "").strip()
        if value:
            return value
    return str(session_payload.get("username") or "unknown").strip() or "unknown"


def _session_hostname(session_payload: dict[str, Any], sysinfo_output: str) -> str | None:
    match = _HOSTNAME_PATTERN.search(sysinfo_output)
    if match is not None:
        value = str(match.group("value") or "").strip()
        if value:
            return value
    hostname = str(
        session_payload.get("session_host") or session_payload.get("target_host") or ""
    ).strip()
    return hostname or None


def _privilege_level(*, username: str, group_output: str) -> str:
    normalized_haystack = f"{username}\n{group_output}".lower()
    if any(
        marker in normalized_haystack for marker in ("system", "administrators", "domain admins")
    ):
        return "administrator"
    return "user"


def _protected_session_bundle(
    *,
    target: str,
    reference_label: str,
    module_name: str,
    session_id: str,
    username: str,
    hostname: str | None,
    privilege_level: str,
    getuid_output: str,
    sysinfo_output: str,
    whoami_groups_output: str,
) -> str:
    payload = {
        "target": target,
        "reference_label": reference_label,
        "module_name": module_name,
        "session_id": session_id,
        "username": username,
        "hostname": hostname,
        "privilege_level": privilege_level,
        "evidence_commands": {
            "getuid": getuid_output,
            "sysinfo": sysinfo_output,
            "whoami_groups": whoami_groups_output,
        },
        "raw_secret_material_exposed": False,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def execute_metasploit_exploit(
    targets: list[str],
    *,
    source_finding: dict[str, Any],
    module_name: str | None = None,
    auth_contexts: list[dict[str, Any]] | object = None,
    lhost: str = DEFAULT_LHOST,
    lport: int = DEFAULT_LPORT,
    rport: int | None = None,
    rpc_url: str = DEFAULT_RPC_URL,
    rpc_username: str,
    rpc_password: str,
    rpc_verify_ssl: bool = False,
    msfrpcd_binary: str = "msfrpcd",
    scope_allowlist: dict[str, object] | None = None,
    kill_switch_check: Callable[[], bool] | None = None,
    start_rpc_daemon: bool = True,
    rpc_start_timeout_seconds: float = 15.0,
    rpc_timeout_seconds: float = DEFAULT_RPC_TIMEOUT_SECONDS,
    session_wait_seconds: float = DEFAULT_SESSION_WAIT_SECONDS,
    job_wait_seconds: float = DEFAULT_JOB_WAIT_SECONDS,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
    rpc_client_factory: Any = MetasploitRpcClient,
) -> RunnerExecution:
    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    if not normalized_targets:
        raise ValueError("Metasploit exploitation requires at least one approved host target")

    scope_allowlist = scope_allowlist or {}
    for target in normalized_targets:
        if not target_value_is_allowed(scope_allowlist, target):
            raise ValueError(f"target outside scope: {target}")

    normalized_finding = _normalize_finding_context(source_finding)
    allowlisted_module = resolve_allowlisted_module(
        normalized_finding, requested_module=module_name
    )
    if allowlisted_module.persistence_allowed:
        raise ValueError("Persistence is not permitted in the Metasploit allowlist")

    normalized_auth_contexts = _normalize_auth_contexts(auth_contexts)
    if allowlisted_module.requires_auth and not normalized_auth_contexts:
        raise ValueError("This allowlisted Metasploit module requires authenticated access context")

    normalized_lhost = _normalize_loopback_host(lhost)
    normalized_lport = _normalize_port(lport, default=DEFAULT_LPORT)
    normalized_rport = _normalize_port(rport, default=allowlisted_module.default_rport)
    normalized_rpc_url = _normalize_rpc_url(rpc_url)
    kill_switch = (
        kill_switch_check
        if kill_switch_check is not None
        else lambda: execution_kill_switch_enabled(get_settings())
    )

    secrets_to_redact = [
        str(rpc_username or ""),
        str(rpc_password or ""),
        *[
            str(value)
            for auth_context in normalized_auth_contexts
            for value in (
                auth_context.get("username"),
                auth_context.get("password"),
                auth_context.get("ntlm_hash"),
            )
            if value
        ],
    ]
    log_sections: list[str] = []
    target_results: list[dict[str, Any]] = []
    protected_outputs: list[ProtectedSecretMaterial] = []
    terminated_by_kill_switch = False

    with tempfile.TemporaryDirectory(prefix="aegispt-metasploit-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        daemon_process: subprocess.Popen[str] | None = None
        client = rpc_client_factory(
            base_url=normalized_rpc_url,
            username=rpc_username,
            password=rpc_password,
            verify_ssl=rpc_verify_ssl,
            timeout_seconds=rpc_timeout_seconds,
        )
        try:
            if start_rpc_daemon:
                daemon_process = _start_msfrpcd_process(
                    binary=msfrpcd_binary,
                    rpc_url=normalized_rpc_url,
                    username=rpc_username,
                    password=rpc_password,
                )
            if not _wait_for_rpc_ready(
                client,
                timeout_seconds=rpc_start_timeout_seconds,
                poll_interval_seconds=poll_interval_seconds,
                kill_switch_check=kill_switch,
            ):
                terminated_by_kill_switch = bool(kill_switch())
                raise RuntimeError("Metasploit RPC service was not ready in time")

            recorded_session_ids: list[str] = []
            recorded_job_ids: list[str] = []
            for target in normalized_targets:
                if kill_switch():
                    terminated_by_kill_switch = True
                    break

                target_result: dict[str, Any] = {
                    "target": target,
                    "status": "failed",
                    "module_name": allowlisted_module.module_name,
                    "reference_label": allowlisted_module.reference_label,
                    "source_finding_title": normalized_finding["title"],
                    "precheck_executed": bool(
                        allowlisted_module.precheck_module_name
                        and allowlisted_module.precheck_module_type
                    ),
                    "session_metadata_stored_as": "protected_secret_ref",
                    "persistence_actions_performed": False,
                    "data_exfiltration_performed": False,
                    "analysis_findings": [],
                }
                before_sessions = client.call("session.list")
                if (
                    allowlisted_module.precheck_module_name
                    and allowlisted_module.precheck_module_type
                ):
                    precheck_payload = client.call(
                        "module.execute",
                        allowlisted_module.precheck_module_type,
                        allowlisted_module.precheck_module_name,
                        {
                            "RHOSTS": target,
                            "RPORT": normalized_rport,
                        },
                    )
                    precheck_job_id = _job_id_from_payload(precheck_payload)
                    if precheck_job_id:
                        recorded_job_ids.append(precheck_job_id)
                    _wait_for_job_completion(
                        client,
                        job_id=precheck_job_id,
                        timeout_seconds=job_wait_seconds,
                        poll_interval_seconds=poll_interval_seconds,
                        kill_switch_check=kill_switch,
                    )

                auth_context = normalized_auth_contexts[0] if normalized_auth_contexts else None
                exploit_datastore = _build_exploit_datastore(
                    target=target,
                    allowlisted_module=allowlisted_module,
                    lhost=normalized_lhost,
                    lport=normalized_lport,
                    target_port=normalized_rport,
                    auth_context=auth_context,
                )
                exploit_payload = client.call(
                    "module.execute",
                    allowlisted_module.module_type,
                    allowlisted_module.module_name,
                    exploit_datastore,
                )
                exploit_job_id = _job_id_from_payload(exploit_payload)
                if exploit_job_id:
                    recorded_job_ids.append(exploit_job_id)
                session_id, session_payload, killed_while_waiting = _wait_for_new_session(
                    client,
                    before_sessions=before_sessions,
                    target=target,
                    timeout_seconds=session_wait_seconds,
                    poll_interval_seconds=poll_interval_seconds,
                    kill_switch_check=kill_switch,
                )
                if killed_while_waiting:
                    terminated_by_kill_switch = True
                    break
                if not session_id:
                    target_result["summary"] = (
                        f"Metasploit did not open a session for {allowlisted_module.reference_label} on {target}."
                    )
                    target_results.append(target_result)
                    continue

                recorded_session_ids.append(session_id)
                getuid_output = _run_meterpreter_command(
                    client,
                    session_id=session_id,
                    command="getuid",
                    timeout_seconds=5.0,
                    poll_interval_seconds=poll_interval_seconds,
                    kill_switch_check=kill_switch,
                )
                sysinfo_output = _run_meterpreter_command(
                    client,
                    session_id=session_id,
                    command="sysinfo",
                    timeout_seconds=5.0,
                    poll_interval_seconds=poll_interval_seconds,
                    kill_switch_check=kill_switch,
                )
                whoami_groups_output = _run_meterpreter_command(
                    client,
                    session_id=session_id,
                    command="shell whoami /groups",
                    timeout_seconds=5.0,
                    poll_interval_seconds=poll_interval_seconds,
                    kill_switch_check=kill_switch,
                )
                if kill_switch():
                    terminated_by_kill_switch = True
                    break
                username = _session_username(session_payload, getuid_output)
                hostname = _session_hostname(session_payload, sysinfo_output)
                privilege_level = _privilege_level(
                    username=username,
                    group_output=whoami_groups_output,
                )

                target_result.update(
                    {
                        "status": "ok",
                        "confirmed_user": username,
                        "confirmed_hostname": hostname,
                        "privilege_level": privilege_level,
                        "summary": (
                            f"Metasploit confirmed {allowlisted_module.reference_label} on {target} as {username}; "
                            "session metadata remains protected outside the visible artifact trail."
                        ),
                        "analysis_findings": [
                            {
                                "title": f"Confirmed RCE — {allowlisted_module.reference_label} on {target} as {username}",
                                "severity": "critical",
                                "target_id": target,
                                "summary": (
                                    f"Metasploit opened a controlled loopback Meterpreter session against {target} via {allowlisted_module.module_name}, "
                                    f"confirmed execution context as {username}, captured bounded privilege evidence, and immediately closed the session."
                                ),
                                "methodology_tags": [
                                    "metasploit",
                                    "confirmed_rce",
                                    "controlled_exploitation",
                                    "no_persistence",
                                    "owasp-wstg",
                                ],
                                "ptes_phase": "exploitation",
                                "nist_phase": "exploitation",
                                "wstg_id": "WSTG-CONF",
                                "control_family": "execution",
                            }
                        ],
                    }
                )
                per_target_artifact_name = f"metasploit-{_safe_slug(target)}.json"
                protected_outputs.append(
                    ProtectedSecretMaterial(
                        artifact_name=per_target_artifact_name,
                        value=_protected_session_bundle(
                            target=target,
                            reference_label=allowlisted_module.reference_label,
                            module_name=allowlisted_module.module_name,
                            session_id=session_id,
                            username=username,
                            hostname=hostname,
                            privilege_level=privilege_level,
                            getuid_output=getuid_output,
                            sysinfo_output=sysinfo_output,
                            whoami_groups_output=whoami_groups_output,
                        ),
                        secret_kind="metasploit_session_bundle",
                        purpose=f"task.metasploit.session.{_safe_slug(target)}",
                        display_label=f"Metasploit session evidence for {target}",
                        content_type="application/json",
                        metadata={"raw_secret_material_exposed": False},
                    )
                )
                target_results.append(target_result)
                log_sections.append(
                    _sanitize_text(
                        "\n".join(
                            part
                            for part in (
                                f"## {target}",
                                f"module={allowlisted_module.module_name}",
                                f"session={session_id}",
                                getuid_output,
                                sysinfo_output,
                                whoami_groups_output,
                            )
                            if part
                        ),
                        secrets_to_redact,
                    )
                )

            if terminated_by_kill_switch:
                _cleanup_remote_state(
                    client,
                    session_ids=recorded_session_ids,
                    job_ids=recorded_job_ids,
                    stop_core=True,
                )
            else:
                _cleanup_remote_state(
                    client,
                    session_ids=recorded_session_ids,
                    job_ids=recorded_job_ids,
                    stop_core=True,
                )

            aggregate_payload = {
                "summary": {
                    "status": (
                        "cancelled"
                        if terminated_by_kill_switch
                        else (
                            "ok"
                            if any(result["status"] == "ok" for result in target_results)
                            else "failed"
                        )
                    ),
                    "finding_count": sum(
                        len(result.get("analysis_findings", []))
                        for result in target_results
                        if isinstance(result, dict)
                    ),
                    "target_count": len(target_results),
                    "terminated_by_kill_switch": terminated_by_kill_switch,
                    "lhost": normalized_lhost,
                    "lport": normalized_lport,
                    "loopback_lhost_enforced": True,
                    "persistence_actions_performed": False,
                    "data_exfiltration_performed": False,
                },
                "targets": target_results,
            }
            per_target_artifacts = [
                EvidenceArtifact(
                    name=f"metasploit-{_safe_slug(result['target'])}.json",
                    content_type="application/json",
                    data=(json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                    kind="exploitation-result",
                )
                for result in target_results
            ]
            artifacts = [
                EvidenceArtifact(
                    name=METASPLOIT_RESULTS_ARTIFACT_NAME,
                    content_type="application/json",
                    data=(json.dumps(aggregate_payload, indent=2, sort_keys=True) + "\n").encode(
                        "utf-8"
                    ),
                    kind="exploitation-results",
                ),
                *per_target_artifacts,
                EvidenceArtifact(
                    name=METASPLOIT_LOG_ARTIFACT_NAME,
                    content_type="text/plain",
                    data=(
                        "\n\n".join(section for section in log_sections if section).strip()
                        + ("\n" if log_sections else "")
                    ).encode("utf-8"),
                    kind="execution-log",
                ),
            ]
            exit_code = 0 if any(result["status"] == "ok" for result in target_results) else 1
            if terminated_by_kill_switch:
                exit_code = 0
            return RunnerExecution(
                tool="metasploit",
                exit_code=exit_code,
                stdout=(
                    "Metasploit controlled exploitation completed.\n"
                    if not terminated_by_kill_switch and exit_code == 0
                    else ""
                ),
                stderr=(
                    ""
                    if terminated_by_kill_switch or exit_code == 0
                    else "Metasploit controlled exploitation failed.\n"
                ),
                metadata={
                    "status": (
                        "cancelled"
                        if terminated_by_kill_switch
                        else ("ok" if exit_code == 0 else "failed")
                    ),
                    "tool_version": "msfrpcd",
                    "runner_digest": "workers.metasploit.runner:v1",
                    "terminated_by_kill_switch": terminated_by_kill_switch,
                    "finding_count": aggregate_payload["summary"]["finding_count"],
                    "loopback_lhost_enforced": True,
                    "persistence_actions_performed": False,
                    "data_exfiltration_performed": False,
                },
                artifacts=artifacts,
                protected_outputs=protected_outputs,
            )
        finally:
            try:
                client.close()
            finally:
                _terminate_process(daemon_process)
