from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import httpx

SAFE_TARGET_CLASSIFICATIONS = {"local_dev", "authorized_customer", "training_lab"}
TARGET_RUNNABILITY_STATES = {
    "runnable",
    "fixture_backed",
    "documentation_only",
    "disabled_template",
}
DEFAULT_MODULE_STATE = {
    "discovery": False,
    "web_crawling": False,
    "auth_flows": False,
    "content_discovery": False,
    "nuclei_checks": False,
    "zap_active_checks": False,
    "ssl_tls_analysis": False,
    "business_logic_testing": False,
    "adaptive_ai_generated_tests": False,
    "internal_validation_modules": False,
    "api_security_testing": False,
    "mobile_static_review": False,
    "cloud_native_static_review": False,
    "cicd_security_review": False,
    "secrets_hygiene_review": False,
    "llm_application_probing": False,
    "ad_lab_validation": False,
    "benchmark_fixture_review": False,
}
DEFAULT_SAFETY = {
    "rate_limit_rps": 2,
    "concurrency": 2,
    "time_budget_minutes": 90,
    "active_checks": "guarded",
    "adaptive_generation": False,
    "max_validation_depth": "standard",
}
RUN_PROFILE_TOOL_HINTS = {
    "passive-network-discovery": ["nmap"],
    "passive-web-baseline": ["httpx"],
    "passive-crypto-audit": ["crypto-audit"],
    "passive-web-logging-probe": ["logging-probe"],
    "passive-web-nuclei-audit": ["nuclei"],
    "passive-code-semgrep-audit": ["semgrep"],
    "passive-cicd-security-assessment": ["cicd-security"],
    "passive-cloud-native-assessment": ["cloud-native"],
    "passive-mobile-android-static": ["mobile-android"],
    "active-web-safe": ["zap"],
    "active-web-zap-active": ["zap"],
    "active-web-oauth-probe": ["oauth-probe"],
    "active-api-assessment": ["api-assessment"],
    "active-llm-application-probe": ["llm-probe"],
    "intrusive-credential-priv-esc-linux": ["priv-esc-linux"],
    "intrusive-validation": ["zap", "nuclei"],
    "active-lan-ssh-brute": ["ssh-brute"],
    "passive-lan-network-capture": ["network-capture"],
}
PROFILE_TOOL_MAP = RUN_PROFILE_TOOL_HINTS
TERMINAL_RUN_STATUSES = {
    "completed",
    "completed_with_errors",
    "failed",
    "cancelled",
    "rejected",
}

HTTP_READY_STATUSES = {
    200,
    201,
    202,
    204,
    301,
    302,
    303,
    307,
    308,
    401,
    403,
}


class _LocalProbeHandler(BaseHTTPRequestHandler):
    response_body = b'{"status":"ok","fixture":"local-http-probe"}'
    response_path = "/health/live"

    def do_GET(self) -> None:  # noqa: N802
        if self.path != self.response_path:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.response_body)))
        self.end_headers()
        self.wfile.write(self.response_body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def results_dir() -> Path:
    path = repo_root() / "codex" / "results"
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_product_matrix_path() -> Path:
    return repo_root() / "codex" / "tasks" / "product_acceptance_matrix.json"


def default_ui_matrix_path() -> Path:
    return repo_root() / "codex" / "tasks" / "ui_acceptance_matrix.json"


def default_target_catalog_path() -> Path:
    return repo_root() / "codex" / "tasks" / "target_lab_matrix.json"


def load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_product_matrix(path: str | Path | None = None) -> dict[str, Any]:
    return load_json(path or default_product_matrix_path())


def load_ui_matrix(path: str | Path | None = None) -> dict[str, Any]:
    return load_json(path or default_ui_matrix_path())


def load_target_catalog(path: str | Path | None = None) -> dict[str, Any]:
    return load_json(path or default_target_catalog_path())


def _target_runnability(target: dict[str, Any]) -> str:
    raw_value = (
        target.get("runnability")
        or target.get("runnable_state")
        or target.get("execution_state")
        or "runnable"
    )
    return str(raw_value).strip().lower()


def validate_target_catalog(catalog: dict[str, Any]) -> dict[str, Any]:
    targets = catalog.get("targets")
    scenarios = catalog.get("real_run_scenarios")
    if not isinstance(targets, list):
        raise ValueError("target catalog must contain a targets list")
    if scenarios is not None and not isinstance(scenarios, list):
        raise ValueError("target catalog real_run_scenarios must be a list when present")

    seen_targets: set[str] = set()
    runnable_counts = {state: 0 for state in TARGET_RUNNABILITY_STATES}
    surface_kinds: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("target catalog entries must be objects")
        target_id = str(target.get("id") or "").strip()
        if not target_id:
            raise ValueError("target catalog entry missing id")
        if target_id in seen_targets:
            raise ValueError(f"duplicate target id: {target_id}")
        seen_targets.add(target_id)

        classification = target.get("classification")
        if classification not in SAFE_TARGET_CLASSIFICATIONS:
            raise ValueError(f"Target {target_id} is not in an approved safe classification.")
        if target.get("unauthorized_public") is True:
            raise ValueError(f"Target {target_id} is marked as unauthorized public scope.")

        runnability = _target_runnability(target)
        if runnability not in TARGET_RUNNABILITY_STATES:
            raise ValueError(f"Target {target_id} has unsupported runnability: {runnability}")
        runnable_counts[runnability] += 1
        if target.get("enabled", True) is True and runnability == "documentation_only":
            raise ValueError(
                f"Documentation-only target {target_id} must not be enabled for execution."
            )
        if target.get("surface_kind"):
            surface_kinds.add(str(target["surface_kind"]))

        benchmark_metadata = target.get("benchmark_metadata")
        if benchmark_metadata is not None:
            if not isinstance(benchmark_metadata, dict):
                raise ValueError(f"Target {target_id} benchmark_metadata must be an object")
            vulnerable_families = benchmark_metadata.get("vulnerable_families")
            prerequisites = benchmark_metadata.get("prerequisites")
            if not isinstance(vulnerable_families, list):
                raise ValueError(
                    f"Target {target_id} benchmark_metadata.vulnerable_families must be a list"
                )
            if prerequisites is not None and not isinstance(prerequisites, list):
                raise ValueError(
                    f"Target {target_id} benchmark_metadata.prerequisites must be a list"
                )

    seen_scenarios: set[str] = set()
    scenario_count = 0
    for scenario in scenarios or []:
        if not isinstance(scenario, dict):
            raise ValueError("real-run scenarios must be objects")
        scenario_id = str(scenario.get("id") or "").strip()
        if not scenario_id:
            raise ValueError("real-run scenario missing id")
        if scenario_id in seen_scenarios:
            raise ValueError(f"duplicate real-run scenario id: {scenario_id}")
        seen_scenarios.add(scenario_id)
        scenario_count += 1
        target_id = str(scenario.get("target_id") or "").strip()
        if target_id not in seen_targets:
            raise ValueError(
                f"real-run scenario {scenario_id} references unknown target {target_id}"
            )

    return {
        "target_count": len(targets),
        "scenario_count": scenario_count,
        "runnability_counts": runnable_counts,
        "surface_kinds": sorted(surface_kinds),
    }


def list_enabled_scenarios(
    matrix: dict[str, Any], *, lane: str | None = None
) -> list[dict[str, Any]]:
    scenarios = [
        deepcopy(item)
        for item in matrix.get("scenarios", [])
        if item.get("enabled", True) is True and (lane is None or item.get("lane") == lane)
    ]
    return sorted(scenarios, key=lambda item: item.get("priority", 999))


def select_matrix_scenario(matrix: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    for scenario in matrix.get("scenarios", []):
        if scenario.get("id") == scenario_id:
            return deepcopy(scenario)
    raise ValueError(f"Unknown acceptance scenario: {scenario_id}")


def resolve_safe_target(
    catalog: dict[str, Any],
    target_id: str,
    *,
    allow_disabled: bool = False,
) -> dict[str, Any]:
    for target in catalog.get("targets", []):
        if target.get("id") != target_id:
            continue
        resolved = deepcopy(target)
        classification = resolved.get("classification")
        if classification not in SAFE_TARGET_CLASSIFICATIONS:
            raise ValueError(f"Target {target_id} is not in an approved safe classification.")
        if resolved.get("unauthorized_public") is True:
            raise ValueError(f"Target {target_id} is marked as unauthorized public scope.")
        if not allow_disabled and resolved.get("enabled", True) is not True:
            raise ValueError(f"Target {target_id} is disabled until it is explicitly configured.")
        if resolved.get("authorized", True) is not True:
            raise ValueError(f"Target {target_id} does not currently record authorization.")
        return resolved
    raise ValueError(f"Unknown safe target: {target_id}")


def _reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _append_target_note(target: dict[str, Any], note: str) -> None:
    existing = str(target.get("notes") or "").strip()
    target["notes"] = f"{existing} {note}".strip() if existing else note


def _primary_scope_url(target: dict[str, Any]) -> str:
    scope = target.get("scope") or {}
    urls = scope.get("urls") or []
    api_base_urls = scope.get("api_base_urls") or []
    for candidate in [*urls, *api_base_urls]:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return "http://127.0.0.1/"


def _rewrite_scope_url(template_url: str, *, host: str, port: int) -> str:
    parsed = urlsplit(template_url)
    scheme = parsed.scheme or "http"
    path = parsed.path or "/"
    return urlunsplit((scheme, f"{host}:{port}", path, parsed.query, ""))


def _wait_for_http_ready(
    url: str,
    *,
    timeout_seconds: float = 60.0,
    acceptable_statuses: set[int] | None = None,
) -> int:
    accepted = acceptable_statuses or HTTP_READY_STATUSES
    deadline = time.monotonic() + max(timeout_seconds, 1.0)
    last_error = "no response"

    with httpx.Client(timeout=5.0, follow_redirects=True) as client:
        while time.monotonic() < deadline:
            try:
                response = client.get(url)
                if response.status_code in accepted:
                    return response.status_code
                last_error = f"unexpected HTTP {response.status_code}"
            except httpx.HTTPError as exc:
                last_error = str(exc)
            time.sleep(1.0)

    raise RuntimeError(
        f"runtime target {url} did not become ready within {timeout_seconds:.0f}s ({last_error})"
    )


def _verify_zap_daemon() -> dict[str, str]:
    base_url = os.getenv("ZAP_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
    api_key = os.getenv("ZAP_API_KEY", "change-me-zap-key")

    try:
        with httpx.Client(timeout=5.0, follow_redirects=True) as client:
            response = client.get(
                f"{base_url}/JSON/core/view/version/",
                params={"apikey": api_key},
            )
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"ZAP daemon is required for active-safe acceptance scenarios but is not reachable at {base_url}: {exc}"
        ) from exc

    version = str(payload.get("version") or "").strip()
    if not version:
        raise RuntimeError(f"ZAP daemon at {base_url} did not return a usable version response")
    return {"zap_base_url": base_url, "zap_version": version}


def assert_runtime_prerequisites(
    *, scenario: dict[str, Any], target: dict[str, Any]
) -> dict[str, Any]:
    run_profile = (
        scenario.get("run_profile")
        or target.get("recommended_run_profile")
        or "passive-web-baseline"
    )
    tool_hints = RUN_PROFILE_TOOL_HINTS.get(run_profile, [])
    context: dict[str, Any] = {"run_profile": run_profile, "tool_hints": list(tool_hints)}

    if "zap" in tool_hints:
        context.update(_verify_zap_daemon())

    scope_inputs = build_target_inputs(target)
    preflight_urls = [
        url
        for url in [*scope_inputs["urls"], *scope_inputs["api_base_urls"]]
        if isinstance(url, str) and url.strip()
    ]
    ready_urls: list[dict[str, Any]] = []
    for url in preflight_urls:
        ready_urls.append(
            {
                "url": url,
                "status_code": _wait_for_http_ready(url, timeout_seconds=30.0),
            }
        )
    context["ready_urls"] = ready_urls
    return context


@contextmanager
def activate_runtime_target(target: dict[str, Any]):
    prepared = deepcopy(target)
    fixture = prepared.get("runtime_fixture")
    if fixture == "docker_gruyere":
        template_url = _primary_scope_url(prepared)
        image = str(prepared.get("runtime_fixture_image") or "karthequian/gruyere:latest")
        app_container_port = int(prepared.get("runtime_fixture_container_port") or 8008)
        startup_timeout = float(prepared.get("runtime_fixture_startup_timeout_seconds") or 90.0)
        container_name = f"aegispt-gruyere-{uuid4().hex[:12]}"
        host = "127.0.0.1"
        app_port = _reserve_loopback_port()

        subprocess.run(
            ["docker", "rm", "-f", container_name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    container_name,
                    "-p",
                    f"{host}:{app_port}:{app_container_port}",
                    image,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if isinstance(exc.stderr, str) else str(exc)
            raise RuntimeError(f"failed to launch Gruyere runtime fixture: {stderr}") from exc

        resolved_url = _rewrite_scope_url(template_url, host=host, port=app_port)
        _wait_for_http_ready(resolved_url, timeout_seconds=startup_timeout)
        scope = deepcopy(prepared.get("scope") or {})
        scope["urls"] = [resolved_url]
        prepared["scope"] = scope
        prepared.setdefault("runtime_fixture_context", {})
        prepared["runtime_fixture_context"].update(
            {
                "fixture": fixture,
                "container_name": container_name,
                "resolved_url": resolved_url,
                "runtime_image": image,
            }
        )
        _append_target_note(
            prepared,
            f"Auto-spawned Gruyere fixture resolved to {resolved_url} with an isolated loopback port.",
        )

        try:
            yield prepared
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        return

    if fixture == "docker_webgoat":
        template_url = _primary_scope_url(prepared)
        image = str(prepared.get("runtime_fixture_image") or "webgoat/webgoat")
        app_container_port = int(prepared.get("runtime_fixture_container_port") or 8080)
        aux_container_port = int(prepared.get("runtime_fixture_aux_port") or 9090)
        startup_timeout = float(prepared.get("runtime_fixture_startup_timeout_seconds") or 180.0)
        container_name = f"aegispt-webgoat-{uuid4().hex[:12]}"
        host = "127.0.0.1"
        app_port = _reserve_loopback_port()
        aux_port = _reserve_loopback_port()

        subprocess.run(
            ["docker", "rm", "-f", container_name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    container_name,
                    "-p",
                    f"{host}:{app_port}:{app_container_port}",
                    "-p",
                    f"{host}:{aux_port}:{aux_container_port}",
                    image,
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if isinstance(exc.stderr, str) else str(exc)
            raise RuntimeError(f"failed to launch WebGoat runtime fixture: {stderr}") from exc

        resolved_url = _rewrite_scope_url(template_url, host=host, port=app_port)
        _wait_for_http_ready(resolved_url, timeout_seconds=startup_timeout)
        scope = deepcopy(prepared.get("scope") or {})
        scope["urls"] = [resolved_url]
        prepared["scope"] = scope
        prepared.setdefault("runtime_fixture_context", {})
        prepared["runtime_fixture_context"].update(
            {
                "fixture": fixture,
                "container_name": container_name,
                "resolved_url": resolved_url,
                "webwolf_url": f"http://{host}:{aux_port}/WebWolf",
                "runtime_image": image,
            }
        )
        _append_target_note(
            prepared,
            f"Auto-spawned WebGoat fixture resolved to {resolved_url} with isolated loopback ports.",
        )

        try:
            yield prepared
        finally:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        return

    if fixture != "local_http_probe":
        yield prepared
        return

    response_path = str(prepared.get("runtime_fixture_path") or "/health/live")
    handler = type(
        "RuntimeLocalProbeHandler",
        (_LocalProbeHandler,),
        {"response_path": response_path},
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    resolved_url = f"http://{host}:{port}{response_path}"
    scope = deepcopy(prepared.get("scope") or {})
    scope["urls"] = [resolved_url]
    api_base_path = prepared.get("runtime_fixture_api_base_path")
    if isinstance(api_base_path, str) and api_base_path.strip():
        scope["api_base_urls"] = [f"http://{host}:{port}{api_base_path}"]
    prepared["scope"] = scope
    prepared.setdefault("runtime_fixture_context", {})
    prepared["runtime_fixture_context"].update(
        {
            "fixture": fixture,
            "resolved_url": resolved_url,
        }
    )
    _append_target_note(prepared, f"Auto-spawned local probe fixture resolved to {resolved_url}.")

    try:
        yield prepared
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def list_real_run_scenarios(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    scenarios = [
        deepcopy(item)
        for item in catalog.get("real_run_scenarios", [])
        if item.get("enabled", True) is True
    ]
    return sorted(scenarios, key=lambda item: item.get("priority", 999))


def select_real_run_scenario(catalog: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    for scenario in catalog.get("real_run_scenarios", []):
        if scenario.get("id") == scenario_id:
            return deepcopy(scenario)
    raise ValueError(f"Unknown real-run scenario: {scenario_id}")


def load_result_history(path: str | Path | None = None) -> list[dict[str, Any]]:
    history_path = Path(path) if path else results_dir()
    if history_path.is_file():
        return [load_json(history_path)]
    results: list[dict[str, Any]] = []
    for item in sorted(history_path.glob("acceptance-*.json")):
        try:
            results.append(load_json(item))
        except json.JSONDecodeError:
            continue
    return results


def select_next_real_run_scenario(
    catalog: dict[str, Any],
    history: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    scenarios = list_real_run_scenarios(catalog)
    if not scenarios:
        raise ValueError("No enabled real-run scenarios are available.")
    passed = {item.get("scenario_id") for item in history or [] if item.get("status") == "passed"}
    for scenario in scenarios:
        if scenario.get("id") not in passed:
            return scenario
    return scenarios[0]


def build_module_state(enabled_keys: list[str] | None) -> dict[str, bool]:
    modules = deepcopy(DEFAULT_MODULE_STATE)
    for key in enabled_keys or []:
        if key in modules:
            modules[key] = True
    return modules


def merge_safety(overrides: dict[str, Any] | None) -> dict[str, Any]:
    safety = deepcopy(DEFAULT_SAFETY)
    for key, value in (overrides or {}).items():
        if value is not None:
            safety[key] = value
    return safety


def build_target_inputs(target: dict[str, Any]) -> dict[str, list[str]]:
    scope = target.get("scope", {})
    return {
        "domains": list(scope.get("domains", [])),
        "subdomains": list(scope.get("subdomains", [])),
        "directory_domains": list(scope.get("directory_domains", [])),
        "urls": list(scope.get("urls", [])),
        "ip_addresses": list(scope.get("hosts", [])),
        "cidr_ranges": list(scope.get("cidrs", [])),
        "api_base_urls": list(scope.get("api_base_urls", [])),
        "pipeline_config_paths": list(scope.get("pipeline_config_paths", [])),
        "repositories": list(scope.get("repositories", [])),
        "llm_endpoints": list(scope.get("llm_endpoints", [])),
        "apk_paths": list(scope.get("apk_paths", [])),
        "container_images": list(scope.get("container_images", [])),
        "kubernetes_manifest_paths": list(scope.get("kubernetes_manifest_paths", [])),
    }


def build_allowlist_from_target(target: dict[str, Any]) -> dict[str, list[str]]:
    inputs = build_target_inputs(target)
    return {
        "domains": [*inputs["domains"], *inputs["subdomains"], *inputs["directory_domains"]],
        "urls": [*inputs["urls"], *inputs["api_base_urls"]],
        "hosts": list(inputs["ip_addresses"]),
        "cidrs": list(inputs["cidr_ranges"]),
        "pipeline_config_paths": list(inputs["pipeline_config_paths"]),
        "repositories": list(inputs["repositories"]),
        "llm_endpoints": list(inputs["llm_endpoints"]),
        "apk_paths": list(inputs["apk_paths"]),
        "container_images": list(inputs["container_images"]),
        "kubernetes_manifest_paths": list(inputs["kubernetes_manifest_paths"]),
    }


def build_inventory_seed_payload(
    engagement_id: str,
    *,
    scenario: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    inputs = build_target_inputs(target)
    hosts = [*inputs["domains"], *inputs["subdomains"], *inputs["ip_addresses"]]
    urls = [*inputs["urls"], *inputs["api_base_urls"]]
    return {
        "engagement_id": engagement_id,
        "source_tools": ["wizard-input"],
        "observations": [
            {
                "tool": "wizard-input",
                "kind": "inventory-seed",
                "data": {
                    "hosts": hosts,
                    "urls": urls,
                    "endpoints": [
                        {
                            "url": url,
                            "methods": [],
                            "status_code": None,
                            "title": "Acceptance-seeded target",
                        }
                        for url in urls
                    ],
                    "confidence": target.get("inventory_confidence", 0.72),
                },
            }
        ],
        "environment_notes": [
            f"Acceptance scenario: {scenario.get('id')}",
            f"Safe target: {target.get('label')}",
        ],
        "assumptions": [
            "Seed inventory was created from the safe-target catalog before controlled validation.",
            target.get("notes") or "No additional target note supplied.",
        ],
    }


def build_run_configuration(
    *,
    scenario: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    run_profile = (
        scenario.get("run_profile")
        or target.get("recommended_run_profile")
        or "passive-web-baseline"
    )
    safety = merge_safety(scenario.get("safety") or target.get("recommended_safety"))
    target_inputs = build_target_inputs(target)
    modules = build_module_state(
        scenario.get("modules") or target.get("recommended_modules") or ["discovery"]
    )
    eta = deepcopy(scenario.get("eta") or {})
    eta.setdefault("estimated_total_minutes", scenario.get("estimated_total_minutes", 45))
    eta.setdefault("estimated_impact", scenario.get("estimated_impact", "low"))
    eta.setdefault("confidence", scenario.get("eta_confidence", "medium"))
    acceptance_metadata = {
        "scenario_id": scenario.get("id"),
        "scenario_name": scenario.get("name"),
        "scenario_lane": "real_run",
        "target_id": target.get("id"),
        "target_label": target.get("label"),
        "target_classification": target.get("classification"),
        "lab_profile": run_profile,
        "expected_outputs": list(scenario.get("expected_outputs", [])),
    }
    return {
        "assessment_type": scenario.get("assessment_type")
        or target.get("assessment_type")
        or "Website / Web App",
        "test_profile": scenario.get("profile") or target.get("recommended_profile") or "Standard",
        "execution_profile": run_profile,
        "execution_plan": {
            "profile_name": run_profile,
            "planned_tools": RUN_PROFILE_TOOL_HINTS.get(run_profile, []),
            "description": scenario.get("description")
            or target.get("notes")
            or "Acceptance harness run.",
        },
        "targets": target_inputs,
        "modules": modules,
        "safety": safety,
        "eta": eta,
        "acceptance_metadata": acceptance_metadata,
    }


def build_engagement_payload(*, scenario: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    suffix = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    return {
        "name": f"Acceptance · {scenario.get('name', scenario.get('id', 'scenario'))} · {suffix}",
        "client": target.get("owner") or "Safe Target Catalog",
        "roe_ref": scenario.get("roe_ref")
        or target.get("authorization_ref")
        or "SAFE-LAB-ACCEPTANCE",
    }


def summarize_result(
    *,
    scenario: dict[str, Any],
    target: dict[str, Any],
    engagement_id: str,
    run: dict[str, Any],
    findings: list[dict[str, Any]],
    reports: list[dict[str, Any]],
    inventory: list[dict[str, Any]],
    packs: list[dict[str, Any]],
    task_details: list[dict[str, Any]],
    base_url: str,
) -> dict[str, Any]:
    expected_outputs = set(scenario.get("expected_outputs", []))
    report_variants = {item.get("variant") for item in reports}
    any_execution = any(item.get("executions") for item in task_details)
    any_artifact = any(
        execution.get("artifacts")
        for item in task_details
        for execution in item.get("executions", [])
    )
    checks = {
        "run_created": bool(run.get("id")),
        "run_terminal": (
            run.get("status") in TERMINAL_RUN_STATUSES if scenario.get("dispatch", True) else True
        ),
        "findings_surface_available": isinstance(findings, list),
        "report_catalog_available": isinstance(reports, list)
        and len(report_variants) >= scenario.get("minimum_reports", 1),
        "inventory_available": not expected_outputs.intersection(
            {"inventory", "inventory_snapshot"}
        )
        or bool(inventory),
        "task_execution_available": "task_evidence" not in expected_outputs or any_execution,
        "artifact_available": "task_evidence" not in expected_outputs or any_artifact,
        "pack_visibility_available": "pack_state" not in expected_outputs
        or isinstance(packs, list),
        "minimum_findings_met": len(findings) >= scenario.get("minimum_findings", 0),
    }
    passed = all(checks.values())
    run_id = run.get("id")
    return {
        "status": "passed" if passed else "failed",
        "scenario_id": scenario.get("id"),
        "target_id": target.get("id"),
        "target_label": target.get("label"),
        "classification": target.get("classification"),
        "engagement_id": engagement_id,
        "run_id": run_id,
        "run_status": run.get("status"),
        "checks": checks,
        "counts": {
            "findings": len(findings),
            "reports": len(reports),
            "inventory_snapshots": len(inventory),
            "packs": len(packs),
            "task_records": len(task_details),
        },
        "links": {
            "operator_console": f"{base_url.rstrip('/')}/app/",
            "run_report_html": (
                f"{base_url.rstrip('/')}/api/v1/runs/{run_id}/report?format=html&variant=technical"
                if run_id
                else None
            ),
            "run_report_pdf": (
                f"{base_url.rstrip('/')}/api/v1/runs/{run_id}/report?format=pdf&variant=technical"
                if run_id
                else None
            ),
        },
        "created_at": datetime.now(tz=UTC).isoformat(),
    }


def write_result(payload: dict[str, Any], *, output_path: str | Path | None = None) -> Path:
    timestamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    path = (
        Path(output_path)
        if output_path
        else results_dir() / f"acceptance-{payload['scenario_id']}-{timestamp}.json"
    )
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
