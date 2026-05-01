from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings, get_settings
from api.app.models import Finding, FindingRemediation, InventorySnapshot, Run, Task, ToolExecution
from api.app.services.chatgpt_oauth import (
    CHATGPT_OAUTH_PROVIDER,
    DISABLED_PROVIDER_NAMES,
    effective_ai_provider_name,
    send_chatgpt_backend_streaming_json_request,
)
from api.app.services.settings import effective_runtime_settings_for_finding


class AutoFixError(RuntimeError):
    pass


FORBIDDEN_VERIFICATION_COMMAND_PATTERNS = (
    "rm -rf",
    "mkfs",
    "drop database",
    "truncate table",
    "curl http",
    "curl https",
    "wget http",
    "wget https",
    "| sh",
    "| bash",
)
AI_AUTOFIX_DISCLAIMER = (
    "This is an AI-generated suggestion. Review before applying. "
    "Do not apply to production without testing."
)


@dataclass(frozen=True, slots=True)
class AutoFixResult:
    patch_language: str
    patch_before: str
    patch_after: str
    patch_explanation: str
    verification_command: str
    confidence: str
    metadata: dict[str, Any]


class AutoFixProvider(Protocol):
    name: str

    def generate(self, context: dict[str, Any]) -> AutoFixResult:
        raise NotImplementedError


class DeterministicAutoFixProvider:
    name = "deterministic"

    def generate(self, context: dict[str, Any]) -> AutoFixResult:
        finding = context.get("finding") if isinstance(context.get("finding"), dict) else {}
        stack = context.get("stack") if isinstance(context.get("stack"), dict) else {}
        vulnerability_class = str(context.get("vulnerability_class") or "generic_input_validation")
        language = str(stack.get("language") or "text")
        framework = str(stack.get("framework") or "").strip()
        target = str(finding.get("target_id") or "the affected target").strip() or "the affected target"

        if vulnerability_class == "sql_injection":
            return self._sql_injection_fix(language=language, framework=framework, target=target)
        if vulnerability_class == "security_headers":
            return self._security_header_fix(language=language, framework=framework, target=target)
        if vulnerability_class == "xss":
            return self._xss_fix(language=language, framework=framework, target=target)
        return self._generic_fix(language=language, framework=framework, target=target)

    def _sql_injection_fix(self, *, language: str, framework: str, target: str) -> AutoFixResult:
        if language == "javascript":
            before = (
                "const sql = `SELECT * FROM users WHERE email = '${email}'`;\n"
                "const [rows] = await db.query(sql);"
            )
            after = (
                "const sql = \"SELECT * FROM users WHERE email = ?\";\n"
                "const [rows] = await db.execute(sql, [email]);"
            )
            verification = "npm test -- --runInBand --grep \"security parameterization\""
        else:
            before = (
                "query = f\"SELECT * FROM users WHERE email = '{email}'\"\n"
                "row = db.execute(query).fetchone()"
            )
            after = (
                "query = \"SELECT * FROM users WHERE email = :email\"\n"
                "row = db.execute(text(query), {\"email\": email}).fetchone()"
            )
            verification = "pytest -q tests/security -k parameterized_query"
        framework_copy = f" in {framework}" if framework else ""
        return AutoFixResult(
            patch_language=language,
            patch_before=before,
            patch_after=after,
            patch_explanation=(
                f"Replace string-interpolated SQL with a parameterized query{framework_copy}. "
                f"This keeps untrusted input from {target} out of the SQL parser."
            ),
            verification_command=verification,
            confidence="high",
            metadata={"provider_mode": "deterministic-test", "fix_class": "sql_injection"},
        )

    def _security_header_fix(self, *, language: str, framework: str, target: str) -> AutoFixResult:
        if language == "javascript":
            before = "app.use(router);"
            after = (
                "import helmet from \"helmet\";\n\n"
                "app.use(helmet({\n"
                "  frameguard: { action: \"deny\" },\n"
                "  contentSecurityPolicy: false,\n"
                "}));\n"
                "app.use(router);"
            )
            verification = "npm test -- --runInBand --grep \"security headers\""
        elif language == "python":
            before = "app = FastAPI()\napp.include_router(router)"
            after = (
                "app = FastAPI()\n\n"
                "@app.middleware(\"http\")\n"
                "async def security_headers(request, call_next):\n"
                "    response = await call_next(request)\n"
                "    response.headers.setdefault(\"X-Frame-Options\", \"DENY\")\n"
                "    response.headers.setdefault(\"X-Content-Type-Options\", \"nosniff\")\n"
                "    return response\n\n"
                "app.include_router(router)"
            )
            verification = "pytest -q tests/security -k headers"
        else:
            before = "# Security headers are not explicitly set for the affected response path."
            after = (
                "# Add response hardening for the affected route or middleware layer.\n"
                "response.headers.setdefault(\"X-Frame-Options\", \"DENY\")\n"
                "response.headers.setdefault(\"X-Content-Type-Options\", \"nosniff\")"
            )
            verification = "review affected response headers and run the project's header regression checks"
        return AutoFixResult(
            patch_language=language,
            patch_before=before,
            patch_after=after,
            patch_explanation=(
                f"Add server-side response header hardening for {target}. "
                f"The stored evidence points to missing or weak framing/type-sniffing protection{f' in {framework}' if framework else ''}."
            ),
            verification_command=verification,
            confidence="medium",
            metadata={"provider_mode": "deterministic-test", "fix_class": "security_headers"},
        )

    def _xss_fix(self, *, language: str, framework: str, target: str) -> AutoFixResult:
        if language == "javascript":
            before = "return res.send(`<div>${userInput}</div>`);"
            after = (
                "import escapeHtml from \"escape-html\";\n\n"
                "return res.send(`<div>${escapeHtml(userInput)}</div>`);"
            )
            verification = "npm test -- --runInBand --grep \"output encoding\""
        else:
            before = "return HTMLResponse(f\"<div>{user_input}</div>\")"
            after = "return HTMLResponse(f\"<div>{html.escape(user_input)}</div>\")"
            verification = "pytest -q tests/security -k output_encoding"
        return AutoFixResult(
            patch_language=language,
            patch_before=before,
            patch_after=after,
            patch_explanation=(
                f"Encode untrusted output before it is reflected back to clients on {target}. "
                f"This keeps browser interpretation aligned with literal text instead of executable markup."
            ),
            verification_command=verification,
            confidence="medium",
            metadata={"provider_mode": "deterministic-test", "fix_class": "xss"},
        )

    def _generic_fix(self, *, language: str, framework: str, target: str) -> AutoFixResult:
        stack_copy = f"{framework} / {language}".strip(" /") or "the detected stack"
        return AutoFixResult(
            patch_language=language or "text",
            patch_before="# Vulnerable code path was not captured verbatim in stored evidence.",
            patch_after=(
                "# Review the handler that processes untrusted input for this finding.\n"
                "# Validate input early, prefer allowlists, and add a regression test for the affected route."
            ),
            patch_explanation=(
                f"Stored evidence for {target} was too sparse for a stack-specific patch, so this fallback keeps the fix advisory. "
                f"Use the evidence excerpt, methodology tags, and {stack_copy} context to place the remediation in the right handler."
            ),
            verification_command="review the affected route and run the project's targeted security regression tests",
            confidence="low",
            metadata={"provider_mode": "deterministic-test", "fix_class": "generic_input_validation"},
        )


class ChatGPTOAuthAutoFixProvider:
    name = CHATGPT_OAUTH_PROVIDER

    def __init__(self, *, session: Session, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def generate(self, context: dict[str, Any]) -> AutoFixResult:
        finding = context.get("finding") if isinstance(context.get("finding"), dict) else {}
        run_context = context.get("run") if isinstance(context.get("run"), dict) else {}
        if not run_context.get("engagement_id"):
            raise AutoFixError("ChatGPT OAuth AutoFix requires engagement context")
        response = send_chatgpt_backend_streaming_json_request(
            session=self.session,
            engagement_id=run_context["engagement_uuid"],
            settings=self.settings,
            model=str(self.settings.chatgpt_oauth_model or self.settings.ai_autofix_model or "gpt-5.4"),
            instructions=_chatgpt_autofix_instructions(context),
            input_items=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "input_text",
                            "text": _chatgpt_autofix_payload_text(context),
                        }
                    ],
                }
            ],
        )
        result_payload = response.get("autofix") if isinstance(response.get("autofix"), dict) else response
        return AutoFixResult(
            patch_language=_required_text(result_payload, "patch_language"),
            patch_before=_required_text(result_payload, "patch_before"),
            patch_after=_required_text(result_payload, "patch_after"),
            patch_explanation=_required_text(result_payload, "patch_explanation"),
            verification_command=_required_text(result_payload, "verification_command"),
            confidence=_required_text(result_payload, "confidence"),
            metadata={
                "provider_mode": CHATGPT_OAUTH_PROVIDER,
                "backend_status": response.get("status"),
                "model": response.get("model")
                or str(self.settings.chatgpt_oauth_model or self.settings.ai_autofix_model or "gpt-5.4"),
                "target_id": finding.get("target_id"),
                "ai_generated": True,
                "token_exposed": False,
            },
        )


def build_autofix_provider(
    settings: Settings,
    *,
    session: Session | None = None,
) -> AutoFixProvider | None:
    if not settings.ai_autofix_enabled:
        return None

    provider_name = effective_ai_provider_name(settings, settings.ai_autofix_provider)
    if provider_name in DISABLED_PROVIDER_NAMES:
        return None
    if provider_name in {"deterministic", "mock", "test"}:
        return DeterministicAutoFixProvider()
    if provider_name == CHATGPT_OAUTH_PROVIDER:
        if session is None:
            raise AutoFixError("chatgpt_oauth autofix requires a database session")
        return ChatGPTOAuthAutoFixProvider(session=session, settings=settings)
    raise AutoFixError(f"unsupported autofix provider: {provider_name}")


def ensure_autofix_for_finding(
    *,
    session: Session,
    finding: Finding,
    settings: Settings | None = None,
    provider: AutoFixProvider | None = None,
) -> dict[str, Any] | None:
    settings = effective_runtime_settings_for_finding(
        session,
        finding=finding,
        settings=settings or get_settings(),
    )
    stored = _normalize_autofix_json(finding.autofix_json)
    if stored is not None:
        return stored
    if not settings.ai_autofix_enabled or finding.id is None:
        return None
    if str(finding.status or "").lower() == "false_positive":
        return None

    active_finding = _load_finding_for_autofix(session=session, finding=finding)
    active_provider = provider or build_autofix_provider(settings, session=session)
    if active_provider is None:
        return None

    try:
        context = _build_autofix_context(session=session, finding=active_finding)
        result = active_provider.generate(context)
        normalized = _validated_autofix_payload(
            result,
            provider=active_provider.name,
            model=str(
                result.metadata.get("model")
                or settings.chatgpt_oauth_model
                or settings.ai_autofix_model
                or "gpt-5.4"
            ),
        )
    except Exception as exc:
        if provider is not None or active_provider.name != CHATGPT_OAUTH_PROVIDER:
            return None
        fallback = DeterministicAutoFixProvider()
        result = fallback.generate(_build_autofix_context(session=session, finding=active_finding))
        result.metadata["fallback_from_provider"] = active_provider.name
        result.metadata["fallback_reason"] = str(exc)
        normalized = _validated_autofix_payload(
            result,
            provider=fallback.name,
            model=str(settings.ai_autofix_model or "deterministic"),
        )

    active_finding.autofix_json = normalized
    if normalized.get("provider") == CHATGPT_OAUTH_PROVIDER:
        _store_ai_fix_suggestion(session=session, finding=active_finding, suggestion=normalized["patch_after"])
    session.flush()
    return normalized


def autofix_view(
    *,
    autofix_json: dict[str, Any] | None,
    enabled: bool,
    ai_fix_suggestion: str | None = None,
) -> dict[str, Any]:
    stored = _normalize_autofix_json(autofix_json)
    if stored is None:
        return {
            "available": False,
            "enabled": bool(enabled),
            "advisory_only": True,
            "detail": (
                "AutoFix is disabled for this deployment."
                if not enabled
                else "No advisory patch has been generated for this finding yet."
            ),
        }
    if ai_fix_suggestion and not stored.get("ai_fix_suggestion"):
        stored["ai_fix_suggestion"] = ai_fix_suggestion
    if stored.get("provider") == CHATGPT_OAUTH_PROVIDER or stored.get("ai_fix_suggestion"):
        stored["ai_generated"] = True
        stored["disclaimer"] = AI_AUTOFIX_DISCLAIMER
    return {"available": True, "enabled": bool(enabled), **stored}


def _load_finding_for_autofix(*, session: Session, finding: Finding) -> Finding:
    if finding.id is None:
        raise AutoFixError("finding must be persisted before AutoFix generation")
    loaded = session.scalar(
        select(Finding)
        .options(
            selectinload(Finding.run).selectinload(Run.profile),
            selectinload(Finding.run)
            .selectinload(Run.tasks)
            .selectinload(Task.executions)
            .selectinload(ToolExecution.artifacts),
            selectinload(Finding.source_inventory_snapshot),
        )
        .where(Finding.id == finding.id)
    )
    if loaded is None:
        raise AutoFixError("finding not found for AutoFix generation")
    return loaded


def _build_autofix_context(*, session: Session, finding: Finding) -> dict[str, Any]:
    run = finding.run
    if run is None and finding.run_id is not None:
        run = session.get(Run, finding.run_id)
    inventory_snapshot = finding.source_inventory_snapshot
    if inventory_snapshot is None and finding.source_inventory_snapshot_id is not None:
        inventory_snapshot = session.get(InventorySnapshot, finding.source_inventory_snapshot_id)

    stack = _detect_stack_context(finding=finding, inventory_snapshot=inventory_snapshot)
    stdout_excerpt = _matched_stdout_excerpt(finding)
    vulnerability_class = _classify_finding(finding, stdout_excerpt=stdout_excerpt)
    return {
        "finding": {
            "id": str(finding.id) if finding.id else None,
            "title": finding.title,
            "severity": finding.severity,
            "target_id": finding.target_id,
            "evidence_ref": finding.evidence_ref,
            "status": finding.status,
            "summary": finding.summary,
            "cvss_score": finding.cvss_score,
            "cvss_vector": finding.cvss_vector,
            "cwe": _extract_cwe(finding),
            "control_family": finding.control_family,
            "methodology_tags": list(finding.methodology_tags or []),
            "wstg_id": finding.wstg_id,
            "ptes_phase": finding.ptes_phase,
            "nist_phase": finding.nist_phase,
        },
        "run": {
            "engagement_id": str(run.engagement_id) if run is not None and run.engagement_id else None,
            "engagement_uuid": run.engagement_id if run is not None else None,
            "run_id": str(run.id) if run is not None and run.id else None,
            "profile_name": run.profile.name if run is not None and run.profile is not None else None,
        },
        "inventory_context": _inventory_context(inventory_snapshot=inventory_snapshot, target=finding.target_id),
        "stack": stack,
        "stdout_excerpt": stdout_excerpt,
        "vulnerability_class": vulnerability_class,
        "methodology": {
            "methodology_tags": list(finding.methodology_tags or []),
            "wstg_id": finding.wstg_id,
            "control_family": finding.control_family,
        },
        "guardrails": {
            "advisory_only": True,
            "auto_apply_allowed": False,
            "file_writes_allowed": False,
            "commit_creation_allowed": False,
            "verification_must_remain_reviewable": True,
        },
    }


def _matched_stdout_excerpt(finding: Finding) -> str | None:
    run = finding.run
    if run is None:
        return None
    for task in list(run.tasks or []):
        for execution in list(task.executions or []):
            if _execution_matches_finding(finding=finding, execution=execution):
                return (execution.stdout_text or execution.stderr_text or "")[:500] or None
    return None


def _execution_matches_finding(*, finding: Finding, execution: ToolExecution) -> bool:
    for artifact in list(execution.artifacts or []):
        if artifact.uri == finding.evidence_ref or artifact.id == finding.source_pack_artifact_id:
            return True
    return False


def _detect_stack_context(*, finding: Finding, inventory_snapshot: InventorySnapshot | None) -> dict[str, Any]:
    normalized = (
        inventory_snapshot.normalized_inventory_json
        if inventory_snapshot is not None and isinstance(inventory_snapshot.normalized_inventory_json, dict)
        else {}
    )
    technologies = [
        item
        for item in [
            *list(normalized.get("technologies") or []),
            *list(normalized.get("vendor_product_fingerprints") or []),
        ]
        if isinstance(item, dict)
    ]
    tokens = " ".join(
        str(item.get(key) or "")
        for item in technologies
        for key in ("name", "vendor", "product", "version", "source")
    ).lower()
    target_host = _target_host(finding.target_id)
    framework = "Generic"
    language = "text"
    if "fastapi" in tokens:
        framework = "FastAPI"
        language = "python"
    elif "django" in tokens:
        framework = "Django"
        language = "python"
    elif "flask" in tokens:
        framework = "Flask"
        language = "python"
    elif "express" in tokens or "node" in tokens or "node.js" in tokens:
        framework = "Express"
        language = "javascript"
    elif "spring" in tokens:
        framework = "Spring"
        language = "java"
    elif "asp.net" in tokens or ".net" in tokens or "dotnet" in tokens:
        framework = "ASP.NET"
        language = "csharp"
    elif "rails" in tokens:
        framework = "Rails"
        language = "ruby"
    elif "laravel" in tokens or "php" in tokens:
        framework = "Laravel"
        language = "php"
    return {
        "framework": framework,
        "language": language,
        "target_host": target_host,
        "technology_count": len(technologies),
    }


def _inventory_context(*, inventory_snapshot: InventorySnapshot | None, target: str) -> dict[str, Any]:
    normalized = (
        inventory_snapshot.normalized_inventory_json
        if inventory_snapshot is not None and isinstance(inventory_snapshot.normalized_inventory_json, dict)
        else {}
    )
    target_host = _target_host(target)
    technologies = [
        item
        for item in [
            *list(normalized.get("technologies") or []),
            *list(normalized.get("vendor_product_fingerprints") or []),
        ]
        if isinstance(item, dict)
        and any(target_host in str(item.get(key) or "").lower() for key in ("host", "url", "name", "vendor", "product"))
    ]
    services = [
        item
        for item in list(normalized.get("services") or [])
        if isinstance(item, dict) and target_host in str(item.get("host") or "").lower()
    ]
    endpoints = [
        item
        for item in [*list(normalized.get("http_endpoints") or []), *list(normalized.get("endpoints") or [])]
        if isinstance(item, dict) and target_host in str(item.get("url") or "").lower()
    ]
    return {
        "available": inventory_snapshot is not None,
        "snapshot_id": str(inventory_snapshot.id) if inventory_snapshot is not None else None,
        "services": services[:5],
        "endpoints": endpoints[:5],
        "technologies": technologies[:5],
    }


def _classify_finding(finding: Finding, *, stdout_excerpt: str | None) -> str:
    haystack = " ".join(
        str(item or "").lower()
        for item in (
            finding.title,
            finding.summary,
            finding.control_family,
            finding.wstg_id,
            stdout_excerpt,
            " ".join(finding.methodology_tags or []),
        )
    )
    if any(token in haystack for token in ("sql injection", "sqli", "cwe-89", "parameterized query")):
        return "sql_injection"
    if any(token in haystack for token in ("x-frame-options", "content-security-policy", "security header", "header missing", "header")):
        return "security_headers"
    if any(token in haystack for token in ("cross-site scripting", "xss", "cwe-79", "unsafe html")):
        return "xss"
    return "generic_input_validation"


def _validated_autofix_payload(result: AutoFixResult, *, provider: str, model: str) -> dict[str, Any]:
    patch_language = _required_text({"patch_language": result.patch_language}, "patch_language")
    patch_before = _required_text({"patch_before": result.patch_before}, "patch_before")
    patch_after = _required_text({"patch_after": result.patch_after}, "patch_after")
    patch_explanation = _required_text({"patch_explanation": result.patch_explanation}, "patch_explanation")
    verification_command = _required_text({"verification_command": result.verification_command}, "verification_command")
    confidence = str(result.confidence or "review").strip().lower() or "review"
    if any(token in verification_command.lower() for token in FORBIDDEN_VERIFICATION_COMMAND_PATTERNS):
        raise AutoFixError("autofix verification command failed safety validation")
    ai_generated = provider == CHATGPT_OAUTH_PROVIDER or bool((result.metadata or {}).get("ai_generated"))
    return {
        "patch_language": patch_language,
        "patch_before": patch_before,
        "patch_after": patch_after,
        "patch_explanation": patch_explanation,
        "verification_command": verification_command,
        "confidence": confidence,
        "provider": provider,
        "model": model,
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "advisory_only": True,
        "auto_apply_allowed": False,
        "ai_generated": ai_generated,
        "ai_fix_suggestion": patch_after if ai_generated else None,
        "disclaimer": AI_AUTOFIX_DISCLAIMER if ai_generated else None,
        "metadata": dict(result.metadata or {}),
    }


def _normalize_autofix_json(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    required = ("patch_language", "patch_before", "patch_after", "patch_explanation", "verification_command", "confidence")
    if any(not str(value.get(key) or "").strip() for key in required):
        return None
    return {
        "patch_language": str(value.get("patch_language") or "").strip(),
        "patch_before": str(value.get("patch_before") or ""),
        "patch_after": str(value.get("patch_after") or ""),
        "patch_explanation": str(value.get("patch_explanation") or ""),
        "verification_command": str(value.get("verification_command") or ""),
        "confidence": str(value.get("confidence") or "review"),
        "provider": str(value.get("provider") or "") or None,
        "model": str(value.get("model") or "") or None,
        "generated_at": str(value.get("generated_at") or "") or None,
        "advisory_only": bool(value.get("advisory_only", True)),
        "auto_apply_allowed": bool(value.get("auto_apply_allowed", False)),
        "ai_generated": bool(value.get("ai_generated", False)),
        "ai_fix_suggestion": str(value.get("ai_fix_suggestion") or "") or None,
        "disclaimer": str(value.get("disclaimer") or "") or None,
        "metadata": value.get("metadata") if isinstance(value.get("metadata"), dict) else {},
        "detail": None,
    }


def _store_ai_fix_suggestion(*, session: Session, finding: Finding, suggestion: str) -> None:
    if finding.id is None:
        return
    remediation = session.scalar(select(FindingRemediation).where(FindingRemediation.finding_id == finding.id))
    if remediation is None:
        remediation = FindingRemediation(
            finding_id=finding.id,
            state="not_started",
            created_by="system:autofix",
            updated_by="system:autofix",
        )
        session.add(remediation)
    remediation.ai_fix_suggestion = suggestion
    remediation.updated_by = "system:autofix"


def _extract_cwe(finding: Finding) -> str | None:
    haystack = " ".join(
        str(item or "")
        for item in (
            finding.title,
            finding.summary,
            finding.control_family,
            finding.wstg_id,
            " ".join(finding.methodology_tags or []),
        )
    )
    for token in haystack.replace("(", " ").replace(")", " ").replace(",", " ").split():
        normalized = token.strip().upper()
        if normalized.startswith("CWE-"):
            suffix = normalized[4:].strip()
            if suffix.isdigit():
                return f"CWE-{suffix}"
    return None


def _chatgpt_autofix_instructions(context: dict[str, Any]) -> str:
    stack = context.get("stack") if isinstance(context.get("stack"), dict) else {}
    finding = context.get("finding") if isinstance(context.get("finding"), dict) else {}
    technology_stack = f"{stack.get('framework') or 'Generic'} / {stack.get('language') or 'text'}"
    finding_type = context.get("vulnerability_class") or finding.get("title") or "security finding"
    return (
        "You are AegisPT AutoFix, an advisory-only secure coding assistant. "
        "Generate a technology-specific remediation code suggestion for the provided finding. "
        "Never claim to have applied code, never execute tools, never create pull requests, and never expand scope. "
        f"Generate a specific remediation code snippet for {technology_stack} fixing {finding_type}. "
        "Keep patch_after under 20 lines and include any import, middleware, parameterization, or configuration change needed. "
        "Return only a JSON object with these string fields: patch_language, patch_before, patch_after, "
        "patch_explanation, verification_command, confidence."
    )


def _chatgpt_autofix_payload_text(context: dict[str, Any]) -> str:
    payload = {
        "finding": context.get("finding") if isinstance(context.get("finding"), dict) else {},
        "stack": context.get("stack") if isinstance(context.get("stack"), dict) else {},
        "inventory_context": context.get("inventory_context") if isinstance(context.get("inventory_context"), dict) else {},
        "vulnerability_class": context.get("vulnerability_class"),
        "evidence_excerpt": context.get("stdout_excerpt"),
        "guardrails": context.get("guardrails") if isinstance(context.get("guardrails"), dict) else {},
    }
    return json.dumps(payload, default=str, ensure_ascii=True)


def _required_text(payload: dict[str, Any], field_name: str) -> str:
    value = str(payload.get(field_name) or "").strip()
    if not value:
        raise AutoFixError(f"missing autofix field: {field_name}")
    return value


def _target_host(target: str) -> str:
    parsed = urlparse(str(target or ""))
    host = parsed.hostname or str(target or "").split("/")[0].split(":")[0]
    return host.strip().lower()
