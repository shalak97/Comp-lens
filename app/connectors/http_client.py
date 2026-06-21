"""Enterprise-grade HTTP client for connectors.

Every connector that talks to an external API routes through ResilientClient
instead of calling requests.get directly. This gives all of them, uniformly:

  - timeouts                 never hang on a slow upstream
  - retries w/ backoff       transient 5xx / network errors retried with jitter
  - rate-limit handling      429 honored via Retry-After, then backoff
  - circuit breaker          stop hammering a failing service; fail fast, recover
  - SSRF protection          block requests to internal/loopback/metadata IPs
  - read-only enforcement    only safe HTTP methods permitted
  - structured errors        ConnectorError with status + service context
  - redaction                credentials never appear in logs or error text

This is the difference between "makes an API call" and "production connector".
"""
from __future__ import annotations

import ipaddress
import logging
import random
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

from app.connectors.base import ConnectorError

logger = logging.getLogger(__name__)

_READ_ONLY_METHODS = {"GET", "HEAD", "OPTIONS"}
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("::1/128"), ipaddress.ip_network("fc00::/7"),
]


def _is_blocked_host(host: str) -> bool:
    """Resolve host and reject if it maps to a private/loopback/metadata range."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False  # can't resolve — let the request fail normally, not as SSRF
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(addr in net for net in _BLOCKED_NETS):
            return True
    return False


@dataclass
class CircuitBreaker:
    """Per-service breaker: opens after N consecutive failures, half-opens after cooldown."""
    fail_threshold: int = 5
    cooldown_seconds: float = 30.0
    _failures: int = 0
    _opened_at: float = 0.0

    def allow(self) -> bool:
        if self._failures < self.fail_threshold:
            return True
        # open — allow a probe after cooldown (half-open)
        if time.time() - self._opened_at >= self.cooldown_seconds:
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = 0.0

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.fail_threshold and not self._opened_at:
            self._opened_at = time.time()

    @property
    def is_open(self) -> bool:
        return self._failures >= self.fail_threshold and \
            (time.time() - self._opened_at) < self.cooldown_seconds


_breakers: Dict[str, CircuitBreaker] = {}


def _breaker_for(service: str) -> CircuitBreaker:
    return _breakers.setdefault(service, CircuitBreaker())


@dataclass
class ResilientClient:
    """Hardened HTTP client scoped to one external service."""
    service: str
    timeout: float = 15.0
    max_retries: int = 3
    backoff_base: float = 0.5
    allow_ssrf_check: bool = True
    session: requests.Session = field(default_factory=requests.Session)

    def get(self, url: str, headers: Optional[Dict[str, str]] = None,
            params: Optional[Dict[str, Any]] = None) -> Any:
        return self._request("GET", url, headers=headers, params=params)

    def request(self, method: str, url: str, **kwargs) -> Any:
        return self._request(method, url, **kwargs)

    def _request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None,
                 params: Optional[Dict[str, Any]] = None,
                 json: Optional[Any] = None) -> Any:
        method = method.upper()
        if method not in _READ_ONLY_METHODS:
            raise ConnectorError(
                f"{self.service}: method {method} blocked — connectors are read-only")
        if self.allow_ssrf_check:
            host = urlparse(url).hostname or ""
            if _is_blocked_host(host):
                raise ConnectorError(
                    f"{self.service}: refusing request to internal/metadata host")

        breaker = _breaker_for(self.service)
        if breaker.is_open:
            raise ConnectorError(
                f"{self.service}: circuit open — service failing, backing off")

        last_err = "unknown"
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.session.request(
                    method, url, headers=headers, params=params, json=json,
                    timeout=self.timeout)
            except requests.RequestException as exc:
                last_err = f"network: {type(exc).__name__}"
                breaker.record_failure()
                if attempt < self.max_retries:
                    self._sleep(attempt)
                    continue
                raise ConnectorError(f"{self.service}: {last_err}") from exc

            if resp.status_code in _RETRYABLE_STATUS and attempt < self.max_retries:
                breaker.record_failure()
                # honor Retry-After on 429 if present
                wait = None
                if resp.status_code == 429:
                    ra = resp.headers.get("Retry-After")
                    if ra and ra.isdigit():
                        wait = float(ra)
                self._sleep(attempt, override=wait)
                continue

            if resp.status_code >= 400:
                breaker.record_failure()
                raise ConnectorError(
                    f"{self.service}: HTTP {resp.status_code} {_redact(resp.text)[:160]}")

            breaker.record_success()
            try:
                return resp.json()
            except ValueError:
                return resp.text

        breaker.record_failure()
        raise ConnectorError(f"{self.service}: exhausted retries ({last_err})")

    def _sleep(self, attempt: int, override: Optional[float] = None) -> None:
        if override is not None:
            time.sleep(min(override, 30))
            return
        # exponential backoff with full jitter
        delay = min(self.backoff_base * (2 ** attempt), 20.0)
        time.sleep(delay * (0.5 + random.random() * 0.5))


def _redact(text: str) -> str:
    """Strip anything that looks like a token/secret from error text."""
    import re
    text = re.sub(r"(SSWS|Bearer|Basic)\s+[A-Za-z0-9._\-=/+]+", r"\1 [REDACTED]", text)
    text = re.sub(r'("?(?:token|secret|password|api[_-]?key)"?\s*[:=]\s*)"?[^"\s,}]+',
                  r"\1[REDACTED]", text, flags=re.IGNORECASE)
    return text


def paginate(client: ResilientClient, url: str, headers: Dict[str, str],
             next_key: str = "next", item_key: Optional[str] = None,
             max_pages: int = 20) -> list:
    """Generic cursor pagination — follows `next`-style links, capped for safety."""
    out: list = []
    page = 0
    while url and page < max_pages:
        data = client.get(url, headers=headers)
        items = data.get(item_key, []) if (item_key and isinstance(data, dict)) else data
        if isinstance(items, list):
            out.extend(items)
        nxt = None
        if isinstance(data, dict):
            nxt = data.get(next_key)
            if isinstance(nxt, dict):
                nxt = nxt.get("href") or nxt.get("url")
        url = nxt
        page += 1
    return out
