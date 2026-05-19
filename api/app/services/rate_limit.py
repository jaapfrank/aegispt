from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from threading import Lock

from fastapi import Request


@dataclass(frozen=True)
class RateLimitRule:
    name: str
    pattern: re.Pattern[str]
    methods: frozenset[str]
    max_requests: int
    window_seconds: int


RATE_LIMIT_RULES: tuple[RateLimitRule, ...] = (
    RateLimitRule(
        name="auth_api_key_create",
        pattern=re.compile(r"^/api/v1/auth/keys/?$"),
        methods=frozenset({"POST"}),
        max_requests=5,
        window_seconds=60,
    ),
    RateLimitRule(
        name="run_create",
        pattern=re.compile(r"^/api/v1/engagements/[^/]+/runs/?$"),
        methods=frozenset({"POST"}),
        max_requests=10,
        window_seconds=60,
    ),
    RateLimitRule(
        name="chatgpt_oauth_post",
        pattern=re.compile(r"^/api/v1/auth/chatgpt(?:/.*)?$"),
        methods=frozenset({"POST"}),
        max_requests=3,
        window_seconds=60,
    ),
)


class InMemoryRateLimiter:
    def __init__(self, rules: Iterable[RateLimitRule] = RATE_LIMIT_RULES) -> None:
        self._rules = tuple(rules)
        self._requests: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def rule_for_request(self, request: Request) -> RateLimitRule | None:
        method = request.method.upper()
        path = request.url.path
        for rule in self._rules:
            if method in rule.methods and rule.pattern.match(path):
                return rule
        return None

    def check(self, *, rule: RateLimitRule, client_id: str, now: float | None = None) -> tuple[bool, int, int]:
        timestamp = time.monotonic() if now is None else now
        bucket_key = (rule.name, client_id)
        with self._lock:
            bucket = self._requests[bucket_key]
            cutoff = timestamp - rule.window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= rule.max_requests:
                retry_after = max(1, int(rule.window_seconds - (timestamp - bucket[0])))
                return False, retry_after, 0
            bucket.append(timestamp)
            remaining = max(rule.max_requests - len(bucket), 0)
            return True, 0, remaining


def client_identifier(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    first_forwarded = forwarded_for.split(",", 1)[0].strip()
    if first_forwarded:
        return first_forwarded
    if request.client and request.client.host:
        return request.client.host
    return "unknown"
