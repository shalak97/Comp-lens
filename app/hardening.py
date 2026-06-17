"""Production-hardening layer: rate limiting, security headers, request IDs,
structured error envelopes, and request logging.

This is the difference between a demo and a service other people can depend on.
Everything here is dependency-free (in-process) so it works on any host,
including free tiers with no Redis.
"""
from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("complens.access")


# ════════════════════════════════════════════════════════════════════
# Rate limiting — in-process sliding-window per client key
# ════════════════════════════════════════════════════════════════════
class SlidingWindowLimiter:
    """Per-key sliding window. No Redis — works anywhere, resets on restart.

    For a single-instance deployment this is correct. For multi-instance you'd
    swap the backing store for Redis, but the interface stays identical.
    """

    def __init__(self, max_requests: int, window_seconds: int):
        self.max = max_requests
        self.window = window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def check(self, key: str) -> Tuple[bool, int, float]:
        """Return (allowed, remaining, retry_after_seconds)."""
        now = time.monotonic()
        q = self._hits[key]
        cutoff = now - self.window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.max:
            retry = self.window - (now - q[0])
            return False, 0, max(retry, 0.0)
        q.append(now)
        return True, self.max - len(q), 0.0

    def sweep(self, max_keys: int = 10000) -> None:
        """Bound memory: drop empty/old buckets if the table grows large."""
        if len(self._hits) <= max_keys:
            return
        now = time.monotonic()
        cutoff = now - self.window
        for k in list(self._hits.keys()):
            q = self._hits[k]
            while q and q[0] < cutoff:
                q.popleft()
            if not q:
                del self._hits[k]


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Applies the limiter, keyed by API key (or client IP for anonymous)."""

    def __init__(self, app, max_requests: int = 120, window_seconds: int = 60,
                 exempt_paths: Tuple[str, ...] = ("/health", "/docs", "/openapi.json",
                                                  "/redoc", "/dashboard")):
        super().__init__(app)
        self.limiter = SlidingWindowLimiter(max_requests, window_seconds)
        self.exempt = exempt_paths
        self._n = 0

    def _key(self, request: Request) -> str:
        api_key = request.headers.get("x-api-key")
        if api_key:
            return "k:" + api_key[:12]
        client = request.client.host if request.client else "unknown"
        return "ip:" + client

    async def dispatch(self, request: Request, call_next: Callable):
        path = request.url.path
        if any(path.startswith(p) for p in self.exempt):
            return await call_next(request)
        allowed, remaining, retry = self.limiter.check(self._key(request))
        self._n += 1
        if self._n % 1000 == 0:
            self.limiter.sweep()
        if not allowed:
            rid = getattr(request.state, "request_id", "")
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(int(retry) + 1),
                         "X-RateLimit-Remaining": "0"},
                content={"error": {"type": "rate_limited",
                                   "message": "Too many requests. Slow down and retry.",
                                   "retry_after_seconds": int(retry) + 1,
                                   "request_id": rid}})
        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


# ════════════════════════════════════════════════════════════════════
# Request context — request id + structured access logging + timing
# ════════════════════════════════════════════════════════════════════
class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable):
        rid = request.headers.get("x-request-id") or "req_" + uuid.uuid4().hex[:16]
        request.state.request_id = rid
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001 — logged + re-raised to the error handler
            dur = (time.monotonic() - start) * 1000
            logger.exception("request_failed rid=%s %s %s dur_ms=%.1f",
                             rid, request.method, request.url.path, dur)
            raise
        dur = (time.monotonic() - start) * 1000
        response.headers["X-Request-ID"] = rid
        response.headers["X-Response-Time-ms"] = f"{dur:.1f}"
        logger.info("%s %s -> %s rid=%s dur_ms=%.1f",
                    request.method, request.url.path, response.status_code, rid, dur)
        return response


# ════════════════════════════════════════════════════════════════════
# Security headers — standard hardening headers on every response
# ════════════════════════════════════════════════════════════════════
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, hsts: bool = True):
        super().__init__(app)
        self.hsts = hsts

    async def dispatch(self, request: Request, call_next: Callable):
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        h.setdefault("X-XSS-Protection", "0")  # modern browsers: rely on CSP, disable legacy auditor
        h.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        if self.hsts and request.url.scheme == "https":
            h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


# ════════════════════════════════════════════════════════════════════
# Structured error envelope — consistent JSON errors with request id
# ════════════════════════════════════════════════════════════════════
def install_exception_handlers(app) -> None:
    from fastapi import HTTPException
    from fastapi.exceptions import RequestValidationError

    @app.exception_handler(HTTPException)
    async def _http_exc(request: Request, exc: HTTPException):
        rid = getattr(request.state, "request_id", "")
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"type": _type_for(exc.status_code),
                               "message": exc.detail, "request_id": rid}})

    @app.exception_handler(RequestValidationError)
    async def _validation_exc(request: Request, exc: RequestValidationError):
        rid = getattr(request.state, "request_id", "")
        return JSONResponse(
            status_code=422,
            content={"error": {"type": "validation_error",
                               "message": "Request validation failed",
                               "details": exc.errors()[:10], "request_id": rid}})

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        rid = getattr(request.state, "request_id", "")
        logger.exception("unhandled rid=%s: %s", rid, exc)
        return JSONResponse(
            status_code=500,
            content={"error": {"type": "internal_error",
                               "message": "An internal error occurred.",
                               "request_id": rid}})


def _type_for(status: int) -> str:
    return {400: "bad_request", 401: "unauthorized", 403: "forbidden",
            404: "not_found", 409: "conflict", 422: "validation_error",
            429: "rate_limited"}.get(status, "error")
