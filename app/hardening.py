"""Production-hardening layer: rate limiting, security headers, request IDs,
structured error envelopes, and request logging.

This is the difference between a demo and a service other people can depend on.
Everything here is dependency-free (in-process) so it works on any host,
including free tiers with no Redis.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import logging
import re
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable

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
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> tuple[bool, int, float]:
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
                 exempt_paths: tuple[str, ...] = ("/health", "/docs", "/openapi.json",
                                                  "/redoc", "/dashboard"),
                 trusted_proxy_hops: int = 0):
        super().__init__(app)
        self.limiter = SlidingWindowLimiter(max_requests, window_seconds)
        self.exempt = exempt_paths
        # Number of trusted reverse proxies in front of the app. 0 (default) uses
        # the socket peer, which behind a proxy is the PROXY ip — so every
        # anonymous caller shares one bucket. Set to the real hop count (e.g. 1
        # on Render) to key anonymous requests on the true client ip from
        # X-Forwarded-For instead. Only enable when actually behind that many
        # trusted proxies, or the header becomes spoofable.
        self.trusted_proxy_hops = max(0, int(trusted_proxy_hops))
        self._n = 0

    def _client_ip(self, request: Request) -> str:
        if self.trusted_proxy_hops > 0:
            xff = request.headers.get("x-forwarded-for", "")
            chain = [h.strip() for h in xff.split(",") if h.strip()]
            # the (hops)-th entry from the right is the ip the outermost trusted
            # proxy saw; anything further left is client-supplied and untrusted
            if len(chain) >= self.trusted_proxy_hops:
                return chain[-self.trusted_proxy_hops]
        return request.client.host if request.client else "unknown"

    def _key(self, request: Request) -> str:
        api_key = request.headers.get("x-api-key")
        if api_key:
            # Hash the WHOLE key, not a prefix. This middleware runs before
            # authentication, so the bucket is chosen from an unverified header:
            # keying on `api_key[:12]` meant any request sharing a victim's
            # first 12 characters consumed the victim's budget, even though the
            # request itself would go on to fail auth. A digest also keeps the
            # secret out of the in-memory bucket map.
            return "k:" + hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:32]
        return "ip:" + self._client_ip(request)

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
# Content-Security-Policy for the served HTML consoles
# ════════════════════════════════════════════════════════════════════
_INLINE_SCRIPT = re.compile(rb"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S)


def _script_hashes(html: bytes) -> list[str]:
    """A `'sha256-...'` source for every inline <script> in the document.

    Computed from the file that is actually served, so the policy cannot drift
    from the page: edit the HTML and the hash follows on the next read. Written
    by hand rather than pulled from a library because getting this wrong fails
    open — a stale hash means the browser refuses the script and the console is
    blank, which is at least loud.
    """
    out = []
    for body in _INLINE_SCRIPT.findall(html):
        digest = hashlib.sha256(body).digest()
        out.append("'sha256-" + base64.b64encode(digest).decode("ascii") + "'")
    return out


def csp_for(html: bytes, *, connect_extra: str = "") -> str:
    """The policy for one HTML console.

    `script-src` names each inline block by hash and nothing else — no
    'unsafe-inline', no 'unsafe-eval'. That is what makes an injected
    <script> or an injected event attribute inert rather than merely
    discouraged, and it is why every on* attribute had to go first: a hash
    covers a <script> element, never an attribute.

    `style-src` keeps 'unsafe-inline', and that is a real limitation rather
    than an oversight. The dashboard carries 283 style="" attributes; removing
    them is a CSS refactor with no security benefit against the threat that
    matters here, which is script execution. Style injection can deface, not
    execute.

    `connect-src` includes the configured API origins because the dashboard's
    base URL is user-configurable — pinning it to 'self' would break exactly
    the deployments that point a hosted console at their own API.
    """
    parts = [
        "default-src 'none'",
        "script-src " + " ".join(_script_hashes(html)),
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src https://fonts.gstatic.com data:",
        "img-src 'self' data:",
        "connect-src 'self'" + (" " + connect_extra if connect_extra else ""),
        "base-uri 'none'",          # an injected <base> would re-point every URL
        "form-action 'none'",       # nothing here posts a form
        "frame-ancestors 'none'",   # clickjacking; also covered by X-Frame-Options
        "object-src 'none'",
    ]
    return "; ".join(parts)


# ════════════════════════════════════════════════════════════════════
# Response compression
# ════════════════════════════════════════════════════════════════════
#: Media types that are already compressed. Gzipping these spends CPU to make
#: the body very slightly larger. `application/gzip` is the one that matters
#: here — /enforcement/bundle serves a .tar.gz.
_INCOMPRESSIBLE = (
    "application/gzip", "application/zip", "application/x-tar",
    "application/pdf", "image/", "video/", "audio/", "font/",
)


class CompressibleGZipMiddleware:
    """gzip responses that benefit from it, and only those.

    Written as plain ASGI rather than using Starlette's GZipMiddleware because
    the decision that matters — whether a body is already compressed — depends
    on library behaviour this codebase cannot check from its build environment.
    Being explicit makes it testable here instead of at a customer.

    Two deliberate limits:

    * A streaming response (one that arrives in more than one chunk) is passed
      through untouched. Buffering it to compress it would defeat the reason it
      was streamed. Nothing in this app streams today; this keeps that true if
      something starts.
    * Bodies below ``minimum_size`` are left alone. Below roughly one packet
      there is nothing to win, and gzip's own header can make the response
      bigger than it started.
    """

    def __init__(self, app, minimum_size: int = 800, compress_level: int = 6):
        self.app = app
        self.minimum_size = minimum_size
        self.compress_level = compress_level

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        if "gzip" not in headers.get("accept-encoding", ""):
            return await self.app(scope, receive, send)

        start: dict | None = None
        sent_through = False

        async def _send(message):
            nonlocal start, sent_through
            if sent_through:
                return await send(message)

            if message["type"] == "http.response.start":
                start = message
                return  # hold it: the body decides whether we compress

            if message["type"] != "http.response.body":
                return await send(message)

            body = message.get("body", b"")
            raw = [(k.decode("latin-1").lower(), v.decode("latin-1"))
                   for k, v in start["headers"]]
            ctype = next((v for k, v in raw if k == "content-type"), "")
            already = any(k == "content-encoding" for k, _ in raw)

            too_small = len(body) < self.minimum_size
            streaming = message.get("more_body", False)
            skip = (already or streaming or too_small
                    or ctype.startswith(_INCOMPRESSIBLE))

            if skip:
                sent_through = True
                await send(start)
                return await send(message)

            packed = gzip.compress(body, self.compress_level)
            out = [(k, v) for k, v in start["headers"]
                   if k.decode("latin-1").lower() != b"content-length".decode()]
            out.append((b"content-encoding", b"gzip"))
            out.append((b"content-length", str(len(packed)).encode("latin-1")))
            # Caches must not serve a gzipped body to a client that did not ask
            # for one.
            if not any(k == "vary" for k, _ in raw):
                out.append((b"vary", b"Accept-Encoding"))
            sent_through = True
            await send({**start, "headers": out})
            await send({"type": "http.response.body", "body": packed,
                        "more_body": False})

        await self.app(scope, receive, _send)
        # A response that produced a start but no body (rare, but legal) must
        # still be delivered rather than swallowed by the buffer above.
        if start is not None and not sent_through:
            await send(start)


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
