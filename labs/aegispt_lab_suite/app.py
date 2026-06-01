#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import posixpath
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

SUITE_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = SUITE_DIR / "suite_manifest.json"
DEFAULT_SEED = "aegispt-local-lab-suite-default-seed"
SAFE_FETCH_HOSTS = {"127.0.0.1", "127.0.0.155", "localhost"}


def load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


MANIFEST = load_manifest()
CHALLENGE_IDS = tuple(challenge["id"] for challenge in MANIFEST["challenges"])


def flag_seed() -> str:
    return os.environ.get("AEGISPT_LAB_FLAG_SEED", DEFAULT_SEED)


def expected_flag(challenge_id: str, *, seed: str | None = None) -> str:
    if challenge_id not in CHALLENGE_IDS:
        raise KeyError(f"unknown challenge id: {challenge_id}")
    digest = hmac.new(
        (seed or flag_seed()).encode("utf-8"),
        challenge_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]
    return f"aegispt{{{challenge_id}:{digest}}}"


class LabState:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.event_seq = 0
        self.exploited_challenges: dict[str, dict[str, Any]] = {}
        self.verified_challenges: dict[str, dict[str, Any]] = {}
        self.cache: dict[str, dict[str, Any]] = {}
        self.coupon_redeemed = False
        self.coupon_redemptions = 0
        self.coupon_flag_unlocked = False
        self.device_flows: dict[str, dict[str, Any]] = {}
        self.crm_contacts: list[dict[str, str]] = []
        self.channels: dict[str, dict[str, Any]] = {}
        self.backups: dict[str, dict[str, Any]] = {}
        self.search_index_public = False
        self.billing_credit_unlocked = False
        self.profile_admin_unlocked = False
        self.theme_previews: dict[str, str] = {}
        self.theme_published: dict[str, str] = {}
        self.wan_cache: dict[str, dict[str, Any]] = {}
        self.wan_staging_tokens: dict[str, str] = {}
        self.wan_staging_admin_unlocked = False
        self.oauth_codes: dict[str, dict[str, Any]] = {}
        self.oauth_collector: dict[str, str] = {}
        self.metadata_tokens: set[str] = set()
        self.media_uploads: dict[str, dict[str, str]] = {}
        self.payment_keys: dict[str, dict[str, Any]] = {}
        self.payment_receipts: set[str] = set()
        self.bulk_root_auditor = False
        self.scim_users: dict[str, dict[str, str]] = {}
        self.scim_admin_members: set[str] = set()
        self.mobile_tokens: set[str] = set()
        self.deploy_previews: dict[str, str] = {}
        self.k8s_tokens: set[str] = set()

    def reset(self) -> None:
        self.events.clear()
        self.event_seq = 0
        self.exploited_challenges.clear()
        self.verified_challenges.clear()
        self.cache.clear()
        self.coupon_redeemed = False
        self.coupon_redemptions = 0
        self.coupon_flag_unlocked = False
        self.device_flows.clear()
        self.crm_contacts.clear()
        self.channels.clear()
        self.backups.clear()
        self.search_index_public = False
        self.billing_credit_unlocked = False
        self.profile_admin_unlocked = False
        self.theme_previews.clear()
        self.theme_published.clear()
        self.wan_cache.clear()
        self.wan_staging_tokens.clear()
        self.wan_staging_admin_unlocked = False
        self.oauth_codes.clear()
        self.oauth_collector.clear()
        self.metadata_tokens.clear()
        self.media_uploads.clear()
        self.payment_keys.clear()
        self.payment_receipts.clear()
        self.bulk_root_auditor = False
        self.scim_users.clear()
        self.scim_admin_members.clear()
        self.mobile_tokens.clear()
        self.deploy_previews.clear()
        self.k8s_tokens.clear()

    def record_event(
        self,
        event_type: str,
        *,
        challenge_id: str | None = None,
        details: dict[str, Any] | None = None,
        method: str | None = None,
        outcome: str | None = None,
        route: str | None = None,
        source: str | None = None,
    ) -> dict[str, Any]:
        self.event_seq += 1
        event: dict[str, Any] = {
            "seq": self.event_seq,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": event_type,
        }
        if challenge_id:
            event["challenge_id"] = challenge_id
        if details:
            event["details"] = details
        if method:
            event["method"] = method
        if outcome:
            event["outcome"] = outcome
        if route:
            event["route"] = route
        if source:
            event["source"] = source
        self.events.append(event)
        if challenge_id and event_type in {"flag_disclosed", "grade_match"}:
            self.exploited_challenges.setdefault(
                challenge_id,
                {
                    "challenge_id": challenge_id,
                    "first_seq": event["seq"],
                    "first_seen_utc": event["timestamp_utc"],
                    "first_source": source or event_type,
                },
            )
        if challenge_id and event_type == "grade_match":
            self.verified_challenges.setdefault(
                challenge_id,
                {
                    "challenge_id": challenge_id,
                    "first_seq": event["seq"],
                    "first_seen_utc": event["timestamp_utc"],
                    "first_source": source or event_type,
                },
            )
        return event


STATE = LabState()


def make_response(payload: Any, *, status: int = 200, content_type: str = "application/json") -> tuple[int, bytes, str]:
    if isinstance(payload, (dict, list)):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        return status, body, content_type
    return status, str(payload).encode("utf-8"), content_type


def parse_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length") or "0")
    raw = handler.rfile.read(length) if length else b""
    content_type = handler.headers.get("Content-Type", "")
    if "application/json" in content_type and raw:
        payload = json.loads(raw.decode("utf-8"))
        return payload if isinstance(payload, dict) else {"_json": payload}
    parsed = urllib.parse.parse_qs(raw.decode("utf-8"), keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items()}


def query_params(path: str) -> dict[str, str]:
    parsed = urllib.parse.urlparse(path)
    values = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return {key: items[-1] for key, items in values.items()}


def canonical_for_signature(file_name: str) -> str:
    return file_name.split("/../", 1)[0]


def sign_file(file_name: str) -> str:
    canonical = canonical_for_signature(file_name)
    return hmac.new(flag_seed().encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def b64url_encode(raw: bytes) -> str:
    return urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def jwt_secret_for_kid(kid: str) -> bytes | None:
    if kid == "lab-user-v1":
        return hmac.new(flag_seed().encode("utf-8"), b"jwt-user-key", hashlib.sha256).digest()
    if kid == "lab-dev-null":
        return b""
    return None


def encode_lab_jwt(payload: dict[str, Any], *, kid: str = "lab-user-v1") -> str:
    header = {"alg": "HS256", "kid": kid, "typ": "JWT"}
    header_part = b64url_encode(json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    payload_part = b64url_encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    secret = jwt_secret_for_kid(kid)
    if secret is None:
        raise KeyError(f"unknown kid: {kid}")
    signature = hmac.new(secret, f"{header_part}.{payload_part}".encode("ascii"), hashlib.sha256).digest()
    return f"{header_part}.{payload_part}.{b64url_encode(signature)}"


def decode_lab_jwt(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_part, payload_part, signature_part = parts
    try:
        header = json.loads(b64url_decode(header_part).decode("utf-8"))
        payload = json.loads(b64url_decode(payload_part).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None
    kid = str(header.get("kid") or "")
    secret = jwt_secret_for_kid(kid)
    if secret is None:
        return None
    expected = hmac.new(secret, f"{header_part}.{payload_part}".encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(signature_part, b64url_encode(expected)):
        return None
    return payload if isinstance(payload, dict) else None


def transient_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def sign_billing_event_id(event_id: str) -> str:
    return hmac.new(flag_seed().encode("utf-8"), event_id.encode("utf-8"), hashlib.sha256).hexdigest()


def canonical_storage_object(object_name: str) -> str:
    return object_name.split("/../", 1)[0]


def sign_storage_policy(object_name: str) -> str:
    canonical = canonical_storage_object(object_name)
    material = f"storage:{canonical}"
    return hmac.new(flag_seed().encode("utf-8"), material.encode("utf-8"), hashlib.sha256).hexdigest()


def encode_cursor(payload: dict[str, Any]) -> str:
    return b64url_encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def decode_cursor(cursor: str) -> dict[str, Any] | None:
    try:
        decoded = json.loads(b64url_decode(cursor).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return None
    return decoded if isinstance(decoded, dict) else None


def resolve_virtual_file(file_name: str) -> str:
    normalized = posixpath.normpath("/" + file_name).lstrip("/")
    files = {
        "public.txt": "Quarterly release notes: stable.\n",
        "flag.txt": expected_flag("signed-url-canonicalization") + "\n",
    }
    return files.get(normalized, "not found\n")


def ordered_challenges(records: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(records.values(), key=lambda item: int(item["first_seq"]))


def score_snapshot(*, limit: int = 200) -> dict[str, Any]:
    total = len(CHALLENGE_IDS)
    exploited = ordered_challenges(STATE.exploited_challenges)
    verified = ordered_challenges(STATE.verified_challenges)
    exploited_ids = {item["challenge_id"] for item in exploited}
    verified_ids = {item["challenge_id"] for item in verified}
    return {
        "suite_id": MANIFEST["suite_id"],
        "total_challenges": total,
        "exploited_count": len(exploited),
        "verified_count": len(verified),
        "exploited_percent": round((len(exploited) / total) * 100, 2) if total else 0,
        "verified_percent": round((len(verified) / total) * 100, 2) if total else 0,
        "exploited_order": exploited,
        "verified_order": verified,
        "unexploited": [challenge_id for challenge_id in CHALLENGE_IDS if challenge_id not in exploited_ids],
        "unverified": [challenge_id for challenge_id in CHALLENGE_IDS if challenge_id not in verified_ids],
        "total_events": len(STATE.events),
        "events": STATE.events[-limit:],
    }


class LabRequestHandler(BaseHTTPRequestHandler):
    server_version = "AegisPTLabSuite/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("AEGISPT_LAB_ACCESS_LOG") == "1":
            super().log_message(fmt, *args)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self._send(*make_response(index_html(), content_type="text/html"))
        elif parsed.path == "/healthz":
            self._send(*make_response({"status": "ok", "suite_id": MANIFEST["suite_id"], "challenges": len(CHALLENGE_IDS)}))
        elif parsed.path == "/.well-known/aegispt-lab-manifest.json":
            self._send(*make_response(MANIFEST))
        elif parsed.path == "/__lab/score":
            self._handle_lab_score()
        elif parsed.path == "/__lab/events":
            self._handle_lab_events()
        elif parsed.path == "/internal/metadata":
            self._handle_internal_metadata()
        elif parsed.path == "/edge/cache":
            self._handle_edge_cache()
        elif parsed.path == "/files/sign":
            self._handle_file_sign()
        elif parsed.path == "/files/download":
            self._handle_file_download()
        elif parsed.path == "/coupons/status":
            self._handle_coupon_status()
        elif parsed.path == "/auth/jwks":
            self._handle_auth_jwks()
        elif parsed.path == "/auth/admin":
            self._handle_auth_admin()
        elif parsed.path == "/socket/fallback/recv":
            self._handle_socket_recv()
        elif parsed.path == "/crm/export":
            self._handle_crm_export()
        elif parsed.path == "/docs/search":
            self._handle_docs_search()
        elif parsed.path == "/billing/webhook/sample":
            self._handle_billing_sample()
        elif parsed.path == "/billing/status":
            self._handle_billing_status()
        elif parsed.path == "/inventory/list":
            self._handle_inventory_list()
        elif parsed.path == "/api/v2/admin/export":
            self._handle_api_admin_export()
        elif parsed.path == "/themes/render":
            self._handle_theme_render()
        elif parsed.path == "/wan/edge-config":
            self._handle_wan_edge_config()
        elif parsed.path == "/wan/origin/admin":
            self._handle_wan_origin_admin()
        elif parsed.path == "/wan/cdn/page":
            self._handle_wan_cdn_page()
        elif parsed.path == "/wan/robots.txt":
            self._handle_wan_robots()
        elif parsed.path == "/wan/staging/admin":
            self._handle_wan_staging_admin()
        elif parsed.path == "/wan/oauth/apps":
            self._handle_wan_oauth_apps()
        elif parsed.path == "/wan/oauth/authorize":
            self._handle_wan_oauth_authorize()
        elif parsed.path == "/wan/oauth/collector":
            self._handle_wan_oauth_collector()
        elif parsed.path == "/render/helpers":
            self._handle_render_helpers()
        elif parsed.path == "/media/metadata":
            self._handle_media_metadata()
        elif parsed.path == "/payments/receipt":
            self._handle_payments_receipt()
        elif parsed.path == "/api/bulk/audit":
            self._handle_bulk_audit()
        elif parsed.path == "/sso/metadata":
            self._handle_sso_metadata()
        elif parsed.path == "/scim/v2/Audit":
            self._handle_scim_audit()
        elif parsed.path == "/mobile/assetlinks":
            self._handle_mobile_assetlinks()
        elif parsed.path == "/mobile/debug":
            self._handle_mobile_debug()
        elif parsed.path == "/ci/jobs":
            self._handle_ci_jobs()
        elif parsed.path == "/ci/artifacts":
            self._handle_ci_artifacts()
        elif parsed.path == "/packages/manifest":
            self._handle_packages_manifest()
        elif parsed.path == "/registry/tags":
            self._handle_registry_tags()
        elif parsed.path == "/deploy/status":
            self._handle_deploy_status()
        elif parsed.path == "/k8s/openapi":
            self._handle_k8s_openapi()
        elif parsed.path == "/cloud/storage/policy":
            self._handle_cloud_storage_policy()
        elif parsed.path == "/cloud/storage/download":
            self._handle_cloud_storage_download()
        elif parsed.path == "/warehouse/schema":
            self._handle_warehouse_schema()
        elif parsed.path == "/waf/rules":
            self._handle_waf_rules()
        elif parsed.path == "/waf/proxy":
            self._handle_waf_proxy()
        elif parsed.path == "/trace/search":
            self._handle_trace_search()
        elif parsed.path == "/trace/detail":
            self._handle_trace_detail()
        elif parsed.path == "/cgi/diagnostic":
            self._handle_cgi_diagnostic()
        elif parsed.path == "/exchange/autodiscover":
            self._handle_exchange_autodiscover()
        elif parsed.path == "/exchange/proxy":
            self._handle_exchange_proxy()
        else:
            self._send(*make_response({"error": "not_found"}, status=HTTPStatus.NOT_FOUND))

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/grade":
            self._handle_grade()
        elif parsed.path == "/tools/webhook-tester":
            self._handle_webhook_tester()
        elif parsed.path == "/graphql":
            self._handle_graphql()
        elif parsed.path == "/coupons/redeem":
            self._handle_coupon_redeem()
        elif parsed.path == "/auth/login":
            self._handle_auth_login()
        elif parsed.path == "/device/start":
            self._handle_device_start()
        elif parsed.path == "/device/approve":
            self._handle_device_approve()
        elif parsed.path == "/device/token":
            self._handle_device_token()
        elif parsed.path == "/crm/import":
            self._handle_crm_import()
        elif parsed.path == "/socket/negotiate":
            self._handle_socket_negotiate()
        elif parsed.path == "/socket/fallback/send":
            self._handle_socket_send()
        elif parsed.path == "/backup/create":
            self._handle_backup_create()
        elif parsed.path == "/backup/restore":
            self._handle_backup_restore()
        elif parsed.path == "/docs/reindex":
            self._handle_docs_reindex()
        elif parsed.path == "/billing/webhook":
            self._handle_billing_webhook()
        elif parsed.path == "/api/v2/profile":
            self._handle_api_profile()
        elif parsed.path == "/themes/preview":
            self._handle_theme_preview()
        elif parsed.path == "/themes/publish":
            self._handle_theme_publish()
        elif parsed.path == "/wan/account/reset/request":
            self._handle_wan_reset_request()
        elif parsed.path == "/wan/account/reset/confirm":
            self._handle_wan_reset_confirm()
        elif parsed.path == "/wan/oauth/token":
            self._handle_wan_oauth_token()
        elif parsed.path == "/wan/cloud/preview":
            self._handle_wan_cloud_preview()
        elif parsed.path == "/render/sandbox":
            self._handle_render_sandbox()
        elif parsed.path == "/media/upload":
            self._handle_media_upload()
        elif parsed.path == "/payments/prepare":
            self._handle_payments_prepare()
        elif parsed.path == "/payments/transfer":
            self._handle_payments_transfer()
        elif parsed.path == "/api/bulk/users":
            self._handle_bulk_users()
        elif parsed.path == "/sso/acs":
            self._handle_sso_acs()
        elif parsed.path == "/scim/v2/Users":
            self._handle_scim_users()
        elif parsed.path == "/scim/v2/Groups/admin":
            self._handle_scim_admin_group()
        elif parsed.path == "/mobile/link/preview":
            self._handle_mobile_link_preview()
        elif parsed.path == "/packages/resolve":
            self._handle_packages_resolve()
        elif parsed.path == "/deploy/preview":
            self._handle_deploy_preview()
        elif parsed.path == "/k8s/proxy":
            self._handle_k8s_proxy()
        elif parsed.path == "/warehouse/query":
            self._handle_warehouse_query()
        elif parsed.path == "/logs/ingest":
            self._handle_log_ingest()
        elif parsed.path == "/tls/heartbeat":
            self._handle_heartbeat()
        elif parsed.path == "/bind/profile":
            self._handle_bind_profile()
        elif parsed.path == "/__lab/reset":
            STATE.reset()
            STATE.record_event("lab_reset", method="POST", route="/__lab/reset", source="lab_control")
            self._send(*make_response({"status": "reset"}))
        else:
            self._send(*make_response({"error": "not_found"}, status=HTTPStatus.NOT_FOUND))

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self._record_disclosed_flags(body, content_type=content_type)
        self.send_response(int(status))
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _record_disclosed_flags(self, body: bytes, *, content_type: str) -> None:
        if b"aegispt{" not in body:
            return
        if "application/json" not in content_type and not content_type.startswith("text/"):
            return
        text = body.decode("utf-8", errors="ignore")
        route = urllib.parse.urlparse(self.path).path
        for challenge_id in CHALLENGE_IDS:
            if expected_flag(challenge_id) in text:
                STATE.record_event(
                    "flag_disclosed",
                    challenge_id=challenge_id,
                    method=self.command,
                    outcome="flag_returned",
                    route=route,
                    source="http_response",
                )

    def _handle_lab_score(self) -> None:
        params = query_params(self.path)
        try:
            limit = max(0, min(1000, int(params.get("limit") or 200)))
        except ValueError:
            limit = 200
        self._send(*make_response(score_snapshot(limit=limit)))

    def _handle_lab_events(self) -> None:
        params = query_params(self.path)
        try:
            limit = max(0, min(1000, int(params.get("limit") or 200)))
        except ValueError:
            limit = 200
        self._send(*make_response({"events": STATE.events[-limit:], "total_events": len(STATE.events)}))

    def _handle_grade(self) -> None:
        payload = parse_body(self)
        challenge_id = str(payload.get("challenge_id") or "")
        supplied = str(payload.get("flag") or "")
        if challenge_id not in CHALLENGE_IDS:
            STATE.record_event(
                "grade_unknown",
                details={"supplied_sha256_12": hashlib.sha256(supplied.encode("utf-8")).hexdigest()[:12]},
                method="POST",
                outcome="unknown_challenge",
                route="/grade",
                source="grader",
            )
            self._send(*make_response({"match": False, "error": "unknown_challenge"}, status=HTTPStatus.BAD_REQUEST))
            return
        match = hmac.compare_digest(supplied, expected_flag(challenge_id))
        STATE.record_event(
            "grade_match" if match else "grade_mismatch",
            challenge_id=challenge_id,
            details={"supplied_sha256_12": hashlib.sha256(supplied.encode("utf-8")).hexdigest()[:12]},
            method="POST",
            outcome="match" if match else "mismatch",
            route="/grade",
            source="grader",
        )
        self._send(*make_response({"challenge_id": challenge_id, "match": match}))

    def _handle_internal_metadata(self) -> None:
        if self.headers.get("X-AegisPT-Internal-Hop") != "webhook-tester":
            self._send(*make_response({"error": "internal_metadata_requires_service_hop"}, status=HTTPStatus.FORBIDDEN))
            return
        self._send(*make_response({"service": "metadata", "secret": expected_flag("ssrf-loopback-metadata")}))

    def _handle_webhook_tester(self) -> None:
        payload = parse_body(self)
        url = str(payload.get("url") or "")
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            self._send(*make_response({"error": "url_required"}, status=HTTPStatus.BAD_REQUEST))
            return
        if parsed.hostname not in SAFE_FETCH_HOSTS:
            self._send(*make_response({"status": "external_fetch_suppressed", "host": parsed.hostname}))
            return
        request = urllib.request.Request(url, headers={"X-AegisPT-Internal-Hop": "webhook-tester"})
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                body = response.read(4096).decode("utf-8", errors="replace")
                status = response.status
        except urllib.error.HTTPError as exc:
            body = exc.read(4096).decode("utf-8", errors="replace")
            status = exc.code
        except Exception as exc:  # pragma: no cover - defensive runtime path
            self._send(*make_response({"error": "fetch_failed", "detail": str(exc)}, status=HTTPStatus.BAD_GATEWAY))
            return
        self._send(*make_response({"fetched_status": status, "fetched_body": body}))

    def _handle_edge_cache(self) -> None:
        params = query_params(self.path)
        doc = params.get("doc") or "public"
        cache_key = f"/edge/cache?doc={doc}"
        if cache_key in STATE.cache:
            self._send(*make_response({**STATE.cache[cache_key], "cache": "hit"}))
            return
        preview = self.headers.get("X-Lab-Preview") == "1"
        document = {
            "doc": doc,
            "body": "public edge document",
            "preview": preview,
        }
        if preview:
            document["preview_secret"] = expected_flag("cache-key-header-confusion")
        STATE.cache[cache_key] = document
        self._send(*make_response({**document, "cache": "miss"}))

    def _handle_graphql(self) -> None:
        parsed_body = parse_body(self)
        raw = parsed_body.get("_json") if "_json" in parsed_body else parsed_body
        operations = raw if isinstance(raw, list) else [raw]
        if not operations or not all(isinstance(item, dict) for item in operations):
            self._send(*make_response({"errors": [{"message": "invalid request"}]}, status=HTTPStatus.BAD_REQUEST))
            return
        batch_public = len(operations) > 1 and "publicInfo" in str(operations[0].get("query", ""))
        results: list[dict[str, Any]] = []
        for operation in operations:
            query = str(operation.get("query") or "")
            if "publicInfo" in query:
                results.append({"data": {"publicInfo": {"status": "ok"}}})
            elif "adminAuditLog" in query:
                if self.headers.get("Authorization") == "Bearer lab-admin" or batch_public:
                    results.append({"data": {"adminAuditLog": [{"event": "flag", "value": expected_flag("graphql-batch-authz-confusion")}]}})
                else:
                    results.append({"errors": [{"message": "unauthorized"}]})
            else:
                results.append({"errors": [{"message": "unknown query"}]})
        response: Any = results if isinstance(raw, list) else results[0]
        self._send(*make_response(response))

    def _handle_file_sign(self) -> None:
        params = query_params(self.path)
        file_name = params.get("file") or "public.txt"
        self._send(*make_response({"file": canonical_for_signature(file_name), "signature": sign_file(file_name)}))

    def _handle_file_download(self) -> None:
        params = query_params(self.path)
        file_name = params.get("file") or ""
        supplied_sig = params.get("sig") or ""
        if not hmac.compare_digest(supplied_sig, sign_file(file_name)):
            self._send(*make_response({"error": "bad_signature"}, status=HTTPStatus.FORBIDDEN))
            return
        body = resolve_virtual_file(file_name).encode("utf-8")
        status = HTTPStatus.OK if body != b"not found\n" else HTTPStatus.NOT_FOUND
        self._send(status, body, "text/plain")

    def _handle_coupon_redeem(self) -> None:
        payload = parse_body(self)
        if payload.get("coupon") != "ONCE-PER-CUSTOMER":
            self._send(*make_response({"error": "unknown_coupon"}, status=HTTPStatus.BAD_REQUEST))
            return
        if STATE.coupon_redeemed:
            self._send(*make_response({"status": "already_redeemed"}))
            return
        time.sleep(0.2)
        STATE.coupon_redemptions += 1
        if STATE.coupon_redemptions >= 2:
            STATE.coupon_flag_unlocked = True
        STATE.coupon_redeemed = True
        self._send(*make_response({"status": "redeemed", "redemptions": STATE.coupon_redemptions}))

    def _handle_coupon_status(self) -> None:
        payload: dict[str, Any] = {
            "redeemed": STATE.coupon_redeemed,
            "redemptions": STATE.coupon_redemptions,
            "flag_unlocked": STATE.coupon_flag_unlocked,
        }
        if STATE.coupon_flag_unlocked:
            payload["flag"] = expected_flag("coupon-race-double-spend")
        self._send(*make_response(payload))

    def _handle_auth_jwks(self) -> None:
        self._send(
            *make_response(
                {
                    "issuer": "aegispt-lab-auth",
                    "keys": [{"alg": "HS256", "kid": "lab-user-v1", "kty": "oct", "use": "sig"}],
                    "legacy_compatibility": {"accepted_kid_hint": "lab-dev-null"},
                }
            )
        )

    def _handle_auth_login(self) -> None:
        payload = parse_body(self)
        if payload.get("username") != "researcher" or payload.get("password") != "researcher":
            self._send(*make_response({"error": "invalid_credentials"}, status=HTTPStatus.FORBIDDEN))
            return
        token = encode_lab_jwt({"role": "user", "sub": "researcher"}, kid="lab-user-v1")
        self._send(*make_response({"access_token": token, "token_type": "Bearer"}))

    def _handle_auth_admin(self) -> None:
        authz = self.headers.get("Authorization", "")
        if not authz.startswith("Bearer "):
            self._send(*make_response({"error": "bearer_required"}, status=HTTPStatus.UNAUTHORIZED))
            return
        claims = decode_lab_jwt(authz.removeprefix("Bearer ").strip())
        if not claims:
            self._send(*make_response({"error": "invalid_token"}, status=HTTPStatus.FORBIDDEN))
            return
        if claims.get("role") != "admin":
            self._send(*make_response({"error": "admin_role_required", "role": claims.get("role")}, status=HTTPStatus.FORBIDDEN))
            return
        self._send(*make_response({"admin": True, "flag": expected_flag("jwt-kid-devnull-admin")}))

    def _handle_device_start(self) -> None:
        payload = parse_body(self)
        username = str(payload.get("username") or "guest")
        device_code = transient_id("dev")
        user_code = f"LAB-{len(STATE.device_flows) + 1:04d}"
        STATE.device_flows[device_code] = {
            "approved": False,
            "client_id": str(payload.get("client_id") or "public-cli"),
            "device_code": device_code,
            "tenant": "public",
            "user": username,
            "user_code": user_code,
        }
        self._send(
            *make_response(
                {
                    "device_code": device_code,
                    "interval": 1,
                    "verification_uri": "/device/approve",
                    "user_code": user_code,
                }
            )
        )

    def _handle_device_approve(self) -> None:
        payload = parse_body(self)
        user_code = str(payload.get("user_code") or "")
        flow = next((item for item in STATE.device_flows.values() if item["user_code"] == user_code), None)
        if flow is None:
            self._send(*make_response({"error": "unknown_user_code"}, status=HTTPStatus.NOT_FOUND))
            return
        flow["approved"] = True
        flow["approver"] = str(payload.get("approver") or flow["user"])
        if self.headers.get("X-Tenant-Switch") == "allow":
            flow["tenant"] = str(payload.get("tenant") or flow["tenant"])
        self._send(*make_response({"approved": True, "tenant": flow["tenant"]}))

    def _handle_device_token(self) -> None:
        payload = parse_body(self)
        device_code = str(payload.get("device_code") or "")
        client_id = str(payload.get("client_id") or "")
        flow = STATE.device_flows.get(device_code)
        if flow is None:
            self._send(*make_response({"error": "unknown_device_code"}, status=HTTPStatus.NOT_FOUND))
            return
        if not flow["approved"]:
            self._send(*make_response({"error": "authorization_pending"}, status=HTTPStatus.FORBIDDEN))
            return
        response: dict[str, Any] = {
            "access_token": transient_id("tok"),
            "client_id": client_id,
            "tenant": flow["tenant"],
        }
        if client_id == "ops-console" and flow["tenant"] == "admin":
            response["flag"] = expected_flag("device-code-tenant-confusion")
        self._send(*make_response(response))

    def _handle_crm_import(self) -> None:
        payload = parse_body(self)
        contact = {
            "contact_id": str(payload.get("contact_id") or transient_id("contact")),
            "note": str(payload.get("note") or ""),
            "owner": str(payload.get("owner") or "sales"),
        }
        STATE.crm_contacts.append(contact)
        self._send(*make_response({"imported": True, "row_count": len(STATE.crm_contacts)}))

    def _handle_crm_export(self) -> None:
        params = query_params(self.path)
        owner = params.get("owner") or "sales"
        renderer = params.get("renderer") or "download"
        rows: list[dict[str, str]] = []
        for contact in STATE.crm_contacts:
            if contact["owner"] != owner:
                continue
            note = contact["note"]
            if renderer == "preview" and note.strip().upper().startswith("=LAB.FLAG()"):
                note = expected_flag("csv-formula-preview-exfil")
            rows.append({"contact_id": contact["contact_id"], "note": note, "owner": owner})
        self._send(*make_response({"renderer": renderer, "rows": rows}))

    def _handle_socket_negotiate(self) -> None:
        payload = parse_body(self)
        channel_id = transient_id("chan")
        STATE.channels[channel_id] = {
            "admin_subscribed": False,
            "messages": [{"topic": "system", "body": "welcome"}],
            "user": str(payload.get("user") or "guest"),
        }
        self._send(*make_response({"channel_id": channel_id, "fallback_url": "/socket/fallback/send"}))

    def _handle_socket_send(self) -> None:
        payload = parse_body(self)
        channel_id = str(payload.get("channel_id") or "")
        channel = STATE.channels.get(channel_id)
        if channel is None:
            self._send(*make_response({"error": "unknown_channel"}, status=HTTPStatus.NOT_FOUND))
            return
        message = str(payload.get("message") or "")
        if self.headers.get("X-HTTP-Method-Override") == "SUBSCRIBE" and message == "admin.audit":
            channel["admin_subscribed"] = True
            channel["messages"].append({"topic": "admin.audit", "body": "subscription accepted"})
        else:
            channel["messages"].append({"topic": "user", "body": message})
        self._send(*make_response({"queued": True, "message_count": len(channel["messages"])}))

    def _handle_socket_recv(self) -> None:
        params = query_params(self.path)
        channel = STATE.channels.get(params.get("channel_id") or "")
        if channel is None:
            self._send(*make_response({"error": "unknown_channel"}, status=HTTPStatus.NOT_FOUND))
            return
        messages = list(channel["messages"])
        if channel["admin_subscribed"]:
            messages.append({"topic": "admin.audit", "body": expected_flag("socket-fallback-channel-smuggling")})
        self._send(*make_response({"messages": messages}))

    def _handle_backup_create(self) -> None:
        payload = parse_body(self)
        backup_id = transient_id("bak")
        STATE.backups[backup_id] = {
            "files": {"public/readme.txt": "public backup created\n"},
            "scope": str(payload.get("scope") or "public"),
        }
        self._send(*make_response({"backup_id": backup_id, "scope": STATE.backups[backup_id]["scope"]}))

    def _handle_backup_restore(self) -> None:
        payload = parse_body(self)
        backup = STATE.backups.get(str(payload.get("backup_id") or ""))
        if backup is None:
            self._send(*make_response({"error": "unknown_backup"}, status=HTTPStatus.NOT_FOUND))
            return
        target = str(payload.get("target") or "public/readme.txt")
        normalized = posixpath.normpath("/restore/" + target).lstrip("/")
        if normalized == "admin/flag.txt":
            restored = expected_flag("backup-restore-target-confusion")
        else:
            restored = backup["files"].get(normalized.removeprefix("restore/"), "restore target not found")
        self._send(*make_response({"normalized_target": normalized, "restored": restored}))

    def _handle_docs_reindex(self) -> None:
        payload = parse_body(self)
        preview_admin = payload.get("mode") == "preview" and self.headers.get("X-Preview-Principal") == "admin"
        if preview_admin:
            STATE.search_index_public = True
        self._send(*make_response({"indexed": True, "preview_admin": preview_admin}))

    def _handle_docs_search(self) -> None:
        params = query_params(self.path)
        query = (params.get("q") or "").lower()
        results = [{"id": "pub-1", "snippet": "Public release calendar"}]
        if STATE.search_index_public and "roadmap" in query:
            results.append({"id": "admin-roadmap", "snippet": expected_flag("search-index-acl-drift")})
        self._send(*make_response({"query": query, "results": results}))

    def _handle_billing_sample(self) -> None:
        event = {
            "account_id": "acct-public",
            "action": "invoice.created",
            "amount": 25,
            "event_id": "evt_lab_100",
        }
        self._send(*make_response({"event": event, "signature": sign_billing_event_id(event["event_id"])}))

    def _handle_billing_webhook(self) -> None:
        payload = parse_body(self)
        signature = str(self.headers.get("X-Lab-Signature") or payload.get("signature") or "")
        event_id = str(payload.get("event_id") or "")
        if not hmac.compare_digest(signature, sign_billing_event_id(event_id)):
            self._send(*make_response({"error": "bad_signature"}, status=HTTPStatus.FORBIDDEN))
            return
        if payload.get("account_id") == "admin-research" and payload.get("action") == "credit.grant":
            try:
                amount = int(payload.get("amount") or 0)
            except ValueError:
                amount = 0
            if amount >= 9000:
                STATE.billing_credit_unlocked = True
        self._send(*make_response({"accepted": True, "event_id": event_id}))

    def _handle_billing_status(self) -> None:
        params = query_params(self.path)
        payload: dict[str, Any] = {
            "account_id": params.get("account_id") or "acct-public",
            "credit_unlocked": STATE.billing_credit_unlocked,
        }
        if params.get("account_id") == "admin-research" and STATE.billing_credit_unlocked:
            payload["flag"] = expected_flag("billing-webhook-field-signature")
        self._send(*make_response(payload))

    def _handle_inventory_list(self) -> None:
        params = query_params(self.path)
        cursor = params.get("cursor")
        if cursor:
            decoded = decode_cursor(cursor)
            if decoded is None:
                self._send(*make_response({"error": "invalid_cursor"}, status=HTTPStatus.BAD_REQUEST))
                return
            tenant = str(decoded.get("tenant") or "public")
            page = int(decoded.get("page") or 1)
        else:
            tenant = params.get("tenant") or "public"
            page = int(params.get("page") or 1)
        items: list[dict[str, str]] = [{"name": "public-api", "tenant": "public"}]
        if tenant == "root" and page == 2:
            items.append({"name": "root-admin-inventory", "tenant": "root", "secret": expected_flag("cursor-pagination-tenant-leak")})
        next_cursor = encode_cursor({"page": page + 1, "tenant": tenant})
        self._send(*make_response({"items": items, "next_cursor": next_cursor, "page": page, "tenant": tenant}))

    def _handle_api_profile(self) -> None:
        payload = parse_body(self)
        legacy_shadow = self.headers.get("X-API-Version") == "2019-legacy" and payload.get("_method") == "PATCH"
        if legacy_shadow and str(payload.get("is_admin")).lower() == "true":
            STATE.profile_admin_unlocked = True
        self._send(
            *make_response(
                {
                    "profile": {"display_name": str(payload.get("display_name") or "anonymous")},
                    "shadow_admin": STATE.profile_admin_unlocked,
                }
            )
        )

    def _handle_api_admin_export(self) -> None:
        if not STATE.profile_admin_unlocked:
            self._send(*make_response({"error": "admin_session_required"}, status=HTTPStatus.FORBIDDEN))
            return
        self._send(*make_response({"export": expected_flag("api-version-shadow-admin")}))

    def _handle_theme_preview(self) -> None:
        payload = parse_body(self)
        if self.headers.get("X-Theme-Preview") != "1":
            self._send(*make_response({"error": "preview_header_required"}, status=HTTPStatus.FORBIDDEN))
            return
        tenant = str(payload.get("tenant") or "demo")
        partial = str(payload.get("partial") or "")
        STATE.theme_previews[tenant] = partial
        self._send(*make_response({"preview_saved": True, "tenant": tenant}))

    def _handle_theme_publish(self) -> None:
        payload = parse_body(self)
        tenant = str(payload.get("tenant") or "demo")
        if payload.get("source") != "preview" or tenant not in STATE.theme_previews:
            self._send(*make_response({"error": "missing_preview"}, status=HTTPStatus.BAD_REQUEST))
            return
        STATE.theme_published[tenant] = STATE.theme_previews[tenant]
        self._send(*make_response({"published": True, "tenant": tenant}))

    def _handle_theme_render(self) -> None:
        params = query_params(self.path)
        tenant = params.get("tenant") or "demo"
        partial = STATE.theme_published.get(tenant, "Welcome")
        rendered = partial.replace("{{flag}}", expected_flag("theme-preview-publish-confusion"))
        self._send(*make_response({"rendered": rendered, "tenant": tenant}))

    def _handle_wan_edge_config(self) -> None:
        self._send(
            *make_response(
                {
                    "edge": "public-waf",
                    "origin_host_header": "origin.lab.internal",
                    "origin_path": "/wan/origin/admin",
                    "trusted_forwarded_for": "127.0.0.1",
                }
            )
        )

    def _handle_wan_origin_admin(self) -> None:
        host = (self.headers.get("Host") or "").split(":", 1)[0]
        forwarded_for = self.headers.get("X-Forwarded-For") or ""
        if host != "origin.lab.internal" or forwarded_for != "127.0.0.1":
            self._send(*make_response({"error": "origin_trust_required"}, status=HTTPStatus.FORBIDDEN))
            return
        self._send(*make_response({"origin_admin": expected_flag("wan-origin-host-bypass")}))

    def _handle_wan_cdn_page(self) -> None:
        params = query_params(self.path)
        path = params.get("path") or "/"
        cache_key = f"cdn:{path}"
        if cache_key in STATE.wan_cache:
            self._send(*make_response({**STATE.wan_cache[cache_key], "cache": "hit"}))
            return
        forwarded_host = self.headers.get("X-Forwarded-Host") or "portal.lab.example"
        body = f"Public page for {path} via {forwarded_host}"
        response = {"body": body, "cache": "miss", "path": path}
        if self.headers.get("X-CDN-Debug") == "1" and forwarded_host == "attacker.lab.example":
            response["body"] = f"Password reset link: https://{forwarded_host}/r?token={expected_flag('wan-cdn-vary-poison')}"
        STATE.wan_cache[cache_key] = {key: value for key, value in response.items() if key != "cache"}
        self._send(*make_response(response))

    def _handle_wan_robots(self) -> None:
        body = "User-agent: *\nDisallow: /wan/staging/\nHost: staging.lab.example\n"
        self._send(HTTPStatus.OK, body.encode("utf-8"), "text/plain")

    def _handle_wan_reset_request(self) -> None:
        payload = parse_body(self)
        host = (self.headers.get("Host") or "").split(":", 1)[0]
        if host != "staging.lab.example":
            self._send(*make_response({"error": "staging_host_required"}, status=HTTPStatus.FORBIDDEN))
            return
        if payload.get("email") != "admin@lab.example":
            self._send(*make_response({"sent": False}))
            return
        token = transient_id("rst")
        STATE.wan_staging_tokens[token] = "admin@lab.example"
        self._send(*make_response({"reset_token": token, "sent": True}))

    def _handle_wan_reset_confirm(self) -> None:
        payload = parse_body(self)
        host = (self.headers.get("Host") or "").split(":", 1)[0]
        token = str(payload.get("token") or "")
        if host != "staging.lab.example" or STATE.wan_staging_tokens.get(token) != "admin@lab.example":
            self._send(*make_response({"error": "bad_reset_context"}, status=HTTPStatus.FORBIDDEN))
            return
        if str(payload.get("new_password") or ""):
            STATE.wan_staging_admin_unlocked = True
        self._send(*make_response({"reset": STATE.wan_staging_admin_unlocked}))

    def _handle_wan_staging_admin(self) -> None:
        host = (self.headers.get("Host") or "").split(":", 1)[0]
        if host != "staging.lab.example" or not STATE.wan_staging_admin_unlocked:
            self._send(*make_response({"error": "staging_admin_required"}, status=HTTPStatus.FORBIDDEN))
            return
        self._send(*make_response({"staging_admin": expected_flag("wan-staging-vhost-reset")}))

    def _handle_wan_oauth_apps(self) -> None:
        self._send(
            *make_response(
                {
                    "client_id": "portal",
                    "redirect_policy": "prefix:/wan/redirect",
                    "collector_hint": "/wan/oauth/collector",
                }
            )
        )

    def _handle_wan_oauth_authorize(self) -> None:
        params = query_params(self.path)
        client_id = params.get("client_id") or ""
        redirect_uri = params.get("redirect_uri") or ""
        state = params.get("state") or transient_id("state")
        if client_id != "portal" or not redirect_uri.startswith("/wan/redirect"):
            self._send(*make_response({"error": "invalid_oauth_request"}, status=HTTPStatus.BAD_REQUEST))
            return
        code = transient_id("code")
        STATE.oauth_codes[code] = {"client_id": client_id, "leaked": False}
        parsed_redirect = urllib.parse.urlparse(redirect_uri)
        redirect_params = urllib.parse.parse_qs(parsed_redirect.query, keep_blank_values=True)
        next_path = redirect_params.get("next", [""])[-1]
        if next_path == "/wan/oauth/collector":
            STATE.oauth_codes[code]["leaked"] = True
            STATE.oauth_collector[state] = code
        self._send(*make_response({"code_issued": True, "redirect_uri": redirect_uri, "state": state}))

    def _handle_wan_oauth_collector(self) -> None:
        params = query_params(self.path)
        state = params.get("state") or ""
        code = STATE.oauth_collector.get(state)
        if not code:
            self._send(*make_response({"error": "no_code"}, status=HTTPStatus.NOT_FOUND))
            return
        self._send(*make_response({"code": code, "state": state}))

    def _handle_wan_oauth_token(self) -> None:
        payload = parse_body(self)
        code = str(payload.get("code") or "")
        record = STATE.oauth_codes.get(code)
        if not record or record.get("client_id") != payload.get("client_id"):
            self._send(*make_response({"error": "bad_code"}, status=HTTPStatus.FORBIDDEN))
            return
        response: dict[str, Any] = {"access_token": transient_id("oauth")}
        if record.get("leaked"):
            response["flag"] = expected_flag("wan-oauth-redirect-code-leak")
        self._send(*make_response(response))

    def _handle_wan_cloud_preview(self) -> None:
        payload = parse_body(self)
        url = str(payload.get("url") or "")
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname != "metadata.lab.internal":
            self._send(*make_response({"status": "external_fetch_suppressed", "host": parsed.hostname}))
            return
        method = str(payload.get("method") or "GET").upper()
        headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
        if method == "PUT" and parsed.path == "/latest/api/token":
            if str(headers.get("X-Metadata-Token-TTL-Seconds") or ""):
                token = transient_id("imds")
                STATE.metadata_tokens.add(token)
                self._send(*make_response({"fetched_status": 200, "fetched_body": token}))
                return
        if method == "GET" and parsed.path == "/latest/meta-data/iam/security-credentials/admin":
            token = str(headers.get("X-Metadata-Token") or "")
            if token in STATE.metadata_tokens:
                self._send(
                    *make_response(
                        {
                            "fetched_status": 200,
                            "fetched_body": expected_flag("wan-cloud-metadata-token-pivot"),
                        }
                    )
                )
                return
        self._send(*make_response({"fetched_status": 403, "fetched_body": "metadata token required"}))

    def _handle_render_helpers(self) -> None:
        self._send(
            *make_response(
                {
                    "debug_header": "X-Template-Mode: debug",
                    "escape_wrapper": "{% raw %}...{% endraw %}",
                    "safe_context": ["user.display_name", "config.public_name"],
                }
            )
        )

    def _handle_render_sandbox(self) -> None:
        payload = parse_body(self)
        template = str(payload.get("template") or "")
        debug_mode = self.headers.get("X-Template-Mode") == "debug"
        raw_wrapped = "{% raw %}" in template and "{% endraw %}" in template
        if "{{config.lab_flag}}" in template and debug_mode and raw_wrapped:
            self._send(*make_response({"rendered": expected_flag("web-ssti-sandbox-escape")}))
            return
        if "{{config.lab_flag}}" in template:
            self._send(*make_response({"error": "unsafe_expression_blocked"}, status=HTTPStatus.FORBIDDEN))
            return
        self._send(*make_response({"rendered": template.replace("{{config.public_name}}", "AegisPT Lab")}))

    def _handle_media_upload(self) -> None:
        payload = parse_body(self)
        upload_id = transient_id("media")
        STATE.media_uploads[upload_id] = {
            "body": str(payload.get("body") or ""),
            "content_type": str(payload.get("content_type") or "application/octet-stream"),
            "filename": str(payload.get("filename") or "upload.bin"),
        }
        self._send(*make_response({"stored": True, "upload_id": upload_id}))

    def _handle_media_metadata(self) -> None:
        params = query_params(self.path)
        upload = STATE.media_uploads.get(params.get("id") or "")
        if upload is None:
            self._send(*make_response({"error": "unknown_upload"}, status=HTTPStatus.NOT_FOUND))
            return
        response: dict[str, Any] = {
            "content_type": upload["content_type"],
            "filename": upload["filename"],
            "parser": params.get("parser") or "safe",
        }
        if (
            params.get("parser") == "exiftool-lab"
            and upload["content_type"] == "image/png"
            and upload["filename"].endswith(".png.php")
            and "LABMETA:flag" in upload["body"]
        ):
            response["metadata"] = expected_flag("web-upload-polyglot-metadata")
        self._send(*make_response(response))

    def _handle_payments_prepare(self) -> None:
        payload = parse_body(self)
        try:
            amount = int(payload.get("amount") or 0)
        except ValueError:
            amount = 0
        if amount > 10:
            self._send(*make_response({"error": "micro_transfer_only"}, status=HTTPStatus.BAD_REQUEST))
            return
        key = transient_id("idem")
        STATE.payment_keys[key] = {"amount": amount, "used": False}
        self._send(*make_response({"idempotency_key": key, "prepared_amount": amount}))

    def _handle_payments_transfer(self) -> None:
        payload = parse_body(self)
        key = str(payload.get("idempotency_key") or "")
        record = STATE.payment_keys.get(key)
        if record is None:
            self._send(*make_response({"error": "unknown_idempotency_key"}, status=HTTPStatus.FORBIDDEN))
            return
        try:
            amount = int(payload.get("amount") or 0)
        except ValueError:
            amount = 0
        receipt_id = transient_id("rcpt")
        if payload.get("to") == "admin-vault" and amount >= 1000 and record["amount"] <= 10:
            STATE.payment_receipts.add(receipt_id)
        record["used"] = True
        self._send(*make_response({"receipt_id": receipt_id, "transferred": True}))

    def _handle_payments_receipt(self) -> None:
        params = query_params(self.path)
        receipt_id = params.get("id") or ""
        payload: dict[str, Any] = {"receipt_id": receipt_id, "settled": receipt_id in STATE.payment_receipts}
        if receipt_id in STATE.payment_receipts:
            payload["flag"] = expected_flag("api-idempotency-replay-transfer")
        self._send(*make_response(payload))

    def _handle_bulk_users(self) -> None:
        payload = parse_body(self)
        users = payload.get("_json") if "_json" in payload else payload.get("users")
        if not isinstance(users, list):
            self._send(*make_response({"error": "users_array_required"}, status=HTTPStatus.BAD_REQUEST))
            return
        for user in users:
            if isinstance(user, dict) and user.get("tenant_id") == "root" and user.get("role") == "auditor":
                STATE.bulk_root_auditor = True
        self._send(*make_response({"imported": len(users), "preview": self.headers.get("X-Bulk-Preview") == "1"}))

    def _handle_bulk_audit(self) -> None:
        params = query_params(self.path)
        payload: dict[str, Any] = {"tenant_id": params.get("tenant_id") or "public"}
        if params.get("tenant_id") == "root" and STATE.bulk_root_auditor:
            payload["flag"] = expected_flag("api-bulk-tenant-mass-assignment")
        self._send(*make_response(payload))

    def _handle_sso_metadata(self) -> None:
        self._send(*make_response({"acs": "/sso/acs", "audience": "lab-sp", "recipient_policy": "prefix"}))

    def _handle_sso_acs(self) -> None:
        payload = parse_body(self)
        audience_ok = payload.get("audience") == "lab-sp"
        recipient = str(payload.get("recipient") or "")
        if audience_ok and recipient.startswith("/sso/acs") and payload.get("role") == "admin":
            self._send(*make_response({"subject": payload.get("subject") or "unknown", "flag": expected_flag("auth-saml-recipient-confusion")}))
            return
        self._send(*make_response({"error": "invalid_assertion"}, status=HTTPStatus.FORBIDDEN))

    def _handle_scim_users(self) -> None:
        payload = parse_body(self)
        user_id = transient_id("scim")
        STATE.scim_users[user_id] = {
            "externalId": str(payload.get("externalId") or user_id),
            "userName": str(payload.get("userName") or "unknown"),
        }
        self._send(*make_response({"id": user_id, "userName": STATE.scim_users[user_id]["userName"]}))

    def _handle_scim_admin_group(self) -> None:
        payload = parse_body(self)
        members = payload.get("members")
        if not isinstance(members, list):
            members = []
        if self.headers.get("X-SCIM-Dry-Run") == "1":
            for member in members:
                if isinstance(member, dict) and str(member.get("value") or "") in STATE.scim_users:
                    STATE.scim_admin_members.add(str(member["value"]))
        self._send(*make_response({"dry_run": self.headers.get("X-SCIM-Dry-Run") == "1", "member_count": len(members)}))

    def _handle_scim_audit(self) -> None:
        params = query_params(self.path)
        user_id = params.get("user_id") or ""
        payload: dict[str, Any] = {"admin_member": user_id in STATE.scim_admin_members, "user_id": user_id}
        if user_id in STATE.scim_admin_members:
            payload["flag"] = expected_flag("identity-scim-group-overwrite")
        self._send(*make_response(payload))

    def _handle_mobile_assetlinks(self) -> None:
        self._send(*make_response({"allowed_scheme": "aegispt", "debug_path": "/mobile/debug", "host": "mobile.lab.example"}))

    def _handle_mobile_link_preview(self) -> None:
        payload = parse_body(self)
        parsed = urllib.parse.urlparse(str(payload.get("url") or ""))
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        token = params.get("token", [""])[-1]
        if parsed.scheme == "aegispt" and parsed.netloc == "reset" and token:
            STATE.mobile_tokens.add(token)
        self._send(*make_response({"previewed": True, "scheme": parsed.scheme}))

    def _handle_mobile_debug(self) -> None:
        params = query_params(self.path)
        token = params.get("token") or ""
        if token not in STATE.mobile_tokens:
            self._send(*make_response({"error": "unknown_mobile_token"}, status=HTTPStatus.NOT_FOUND))
            return
        self._send(*make_response({"flag": expected_flag("mobile-deeplink-token-leak")}))

    def _handle_ci_jobs(self) -> None:
        self._send(*make_response({"jobs": [{"artifact_id": "art-build-778", "name": "release-build"}]}))

    def _handle_ci_artifacts(self) -> None:
        params = query_params(self.path)
        if params.get("id") != "art-build-778":
            self._send(*make_response({"error": "unknown_artifact"}, status=HTTPStatus.NOT_FOUND))
            return
        if params.get("file") == "logs":
            self._send(*make_response({"content": "build ok; env artifact captured; preview requires X-Artifact-Preview"}))
            return
        if params.get("file") == "env" and self.headers.get("X-Artifact-Preview") == "1":
            self._send(*make_response({"content": f"DEPLOY_TOKEN={expected_flag('cicd-artifact-env-leak')}"}))
            return
        self._send(*make_response({"error": "artifact_file_denied"}, status=HTTPStatus.FORBIDDEN))

    def _handle_packages_manifest(self) -> None:
        self._send(
            *make_response(
                {
                    "dependencies": [{"name": "@aegispt/internal", "registry": "private", "version": "1.2.3"}],
                    "resolution_order": ["public", "private"],
                }
            )
        )

    def _handle_packages_resolve(self) -> None:
        payload = parse_body(self)
        if payload.get("name") == "@aegispt/internal" and payload.get("registry") == "public" and payload.get("version") == "99.0.0":
            self._send(*make_response({"resolved": True, "flag": expected_flag("supply-chain-dependency-confusion")}))
            return
        self._send(*make_response({"resolved": True, "source": "private"}))

    def _handle_registry_tags(self) -> None:
        params = query_params(self.path)
        image = params.get("image") or "backend"
        self._send(*make_response({"image": image, "tags": {"dev-latest": "sha256:dev", "latest": "sha256:prod"}}))

    def _handle_deploy_preview(self) -> None:
        payload = parse_body(self)
        image = str(payload.get("image") or "")
        mirror = self.headers.get("X-Registry-Mirror") or "prod"
        if image == "backend:latest" and mirror == "dev":
            STATE.deploy_previews["backend"] = "sha256:dev"
        self._send(*make_response({"deployed": image, "mirror": mirror}))

    def _handle_deploy_status(self) -> None:
        params = query_params(self.path)
        service = params.get("service") or "backend"
        digest = STATE.deploy_previews.get(service, "sha256:prod")
        payload: dict[str, Any] = {"digest": digest, "service": service}
        if digest == "sha256:dev":
            payload["flag"] = expected_flag("container-registry-tag-confusion")
        self._send(*make_response(payload))

    def _handle_k8s_openapi(self) -> None:
        self._send(
            *make_response(
                {
                    "anonymous_paths": ["/api/v1/namespaces/default/pods"],
                    "service_account_hint": "default/api",
                }
            )
        )

    def _handle_k8s_proxy(self) -> None:
        payload = parse_body(self)
        path = str(payload.get("path") or "")
        if path == "/api/v1/namespaces/default/pods" and self.headers.get("X-Pod-ServiceAccount") == "default/api":
            token = transient_id("k8s")
            STATE.k8s_tokens.add(token)
            self._send(*make_response({"pods": [{"name": "api", "token": token}]}))
            return
        if path == "/api/v1/namespaces/kube-system/secrets/cluster-backup":
            token = str(self.headers.get("X-ServiceAccount-Token") or "")
            if token in STATE.k8s_tokens:
                self._send(*make_response({"secret": expected_flag("k8s-serviceaccount-secret-read")}))
                return
        self._send(*make_response({"error": "k8s_forbidden"}, status=HTTPStatus.FORBIDDEN))

    def _handle_cloud_storage_policy(self) -> None:
        params = query_params(self.path)
        object_name = params.get("object") or "public/report.txt"
        self._send(*make_response({"object": canonical_storage_object(object_name), "policy": sign_storage_policy(object_name)}))

    def _handle_cloud_storage_download(self) -> None:
        params = query_params(self.path)
        object_name = params.get("object") or ""
        policy = params.get("policy") or ""
        if not hmac.compare_digest(policy, sign_storage_policy(object_name)):
            self._send(*make_response({"error": "bad_policy"}, status=HTTPStatus.FORBIDDEN))
            return
        normalized = posixpath.normpath("/" + object_name).lstrip("/")
        if normalized == "admin/flag.txt":
            self._send(HTTPStatus.OK, (expected_flag("cloud-storage-policy-confusion") + "\n").encode("utf-8"), "text/plain")
            return
        self._send(HTTPStatus.OK, b"public object\n", "text/plain")

    def _handle_warehouse_schema(self) -> None:
        self._send(*make_response({"tables": ["public_reports", "admin_finance"], "tenant_filter": "comment-bound"}))

    def _handle_warehouse_query(self) -> None:
        payload = parse_body(self)
        query = str(payload.get("query") or "")
        if "/*tenant=public*/" in query and "admin_finance" in query:
            self._send(*make_response({"rows": [{"flag": expected_flag("data-warehouse-rls-comment-bypass")}]}))
            return
        self._send(*make_response({"rows": [{"report": "public quarterly metrics"}]}))

    def _handle_waf_rules(self) -> None:
        self._send(*make_response({"blocked_prefix": "/admin", "normalization": "single_decode"}))

    def _handle_waf_proxy(self) -> None:
        params = query_params(self.path)
        once_decoded = params.get("path") or "/"
        if once_decoded.startswith("/admin"):
            self._send(*make_response({"error": "waf_blocked"}, status=HTTPStatus.FORBIDDEN))
            return
        backend_path = urllib.parse.unquote(once_decoded)
        if backend_path == "/admin/flag":
            self._send(*make_response({"flag": expected_flag("web-waf-double-decode-admin")}))
            return
        self._send(*make_response({"backend_path": backend_path}))

    def _handle_trace_search(self) -> None:
        params = query_params(self.path)
        service = params.get("service") or "checkout"
        self._send(*make_response({"service": service, "traces": [{"trace_id": "trace-checkout-7001"}]}))

    def _handle_trace_detail(self) -> None:
        params = query_params(self.path)
        payload: dict[str, Any] = {"span_count": 4, "trace_id": params.get("id") or ""}
        if params.get("id") == "trace-checkout-7001" and params.get("include") == "baggage":
            payload["baggage"] = {"debug_token": expected_flag("observability-trace-baggage-leak")}
        self._send(*make_response(payload))

    def _handle_log_ingest(self) -> None:
        payload = parse_body(self)
        message = str(payload.get("message") or "")
        expanded = message.replace(
            "${lab:lookup:flag}",
            expected_flag("log-lookup-expression-expansion"),
        )
        self._send(
            *make_response(
                {
                    "stored": True,
                    "lookup_expanded": expanded != message,
                    "rendered_message": expanded,
                }
            )
        )

    def _handle_cgi_diagnostic(self) -> None:
        function_env = self.headers.get("X-Lab-Function", "")
        parser_confused = function_env.startswith("fn:") and "|print_flag" in function_env
        payload = {"diagnostic": "ok", "parser_confused": parser_confused}
        if parser_confused:
            payload["flag"] = expected_flag("cgi-env-parser-confusion")
        self._send(*make_response(payload))

    def _handle_heartbeat(self) -> None:
        payload = parse_body(self)
        heartbeat = str(payload.get("payload") or "")
        try:
            requested_length = int(payload.get("length") or len(heartbeat))
        except ValueError:
            self._send(*make_response({"error": "invalid_length"}, status=HTTPStatus.BAD_REQUEST))
            return
        memory = (
            "session=redacted;"
            f"flag={expected_flag('heartbeat-length-overread')};"
            "tail=end"
        )
        leaked = ""
        if requested_length > len(heartbeat):
            leaked = memory[: requested_length - len(heartbeat)]
        self._send(
            *make_response(
                {
                    "echo": heartbeat,
                    "requested_length": requested_length,
                    "returned_length": len(heartbeat) + len(leaked),
                    "data": heartbeat + leaked,
                }
            )
        )

    def _handle_bind_profile(self) -> None:
        payload = parse_body(self)
        profile = {
            "display_name": str(payload.get("profile.display_name") or "anonymous"),
            "role": "user",
        }
        secret_requested = (
            payload.get("profile.class.module.loader.resource") == "flag"
            or payload.get("profile.__class__.loader.resource") == "flag"
        )
        response: dict[str, Any] = {"saved": True, "profile": profile}
        if secret_requested:
            response["bound_resource"] = expected_flag("binder-nested-property-exposure")
        self._send(*make_response(response))

    def _handle_exchange_autodiscover(self) -> None:
        host = self.headers.get("Host") or "127.0.0.155:8088"
        self._send(
            *make_response(
                {
                    "tenant": "lab.local",
                    "frontend_hint": "trusted-autodiscover",
                    "backend_url": f"http://{host}/exchange/proxy?backend=/admin/mailbox",
                }
            )
        )

    def _handle_exchange_proxy(self) -> None:
        params = query_params(self.path)
        backend = params.get("backend") or ""
        if backend != "/admin/mailbox":
            self._send(*make_response({"error": "unknown_backend"}, status=HTTPStatus.NOT_FOUND))
            return
        if self.headers.get("X-Frontend-Trust") != "trusted-autodiscover":
            self._send(*make_response({"error": "frontend_trust_required"}, status=HTTPStatus.FORBIDDEN))
            return
        self._send(
            *make_response(
                {
                    "mailbox": "admin",
                    "admin_export": expected_flag("frontend-backend-auth-rebind"),
                }
            )
        )


def index_html() -> str:
    rows = "\n".join(
        f"<li><code>{challenge['id']}</code> - {challenge['family']}</li>"
        for challenge in MANIFEST["challenges"]
    )
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>AegisPT Lab Suite</title></head>
<body>
<h1>AegisPT Lab Suite</h1>
<p>Local authorized vulnerable target. Use the manifest for machine-readable scope.</p>
<ul>{rows}</ul>
</body>
</html>
"""


def main() -> None:
    host = os.environ.get("AEGISPT_LAB_HOST", "127.0.0.1")
    port = int(os.environ.get("AEGISPT_LAB_PORT", "8080"))
    server = ThreadingHTTPServer((host, port), LabRequestHandler)
    print(f"AegisPT Lab Suite listening on http://{host}:{port}/", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
