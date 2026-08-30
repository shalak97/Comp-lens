"""Structured logging and metrics.

Request correlation ids and per-request timing already exist in
hardening.RequestContextMiddleware. What was missing is machine-readable output
and any numeric signal at all: logs were human-format strings that a log
aggregator has to regex, and there were no metrics, so nothing could answer
"how many assessments failed in the last hour" without reading the database.

Two pieces, both optional at runtime:

  * JSON logs — stdlib only. Enabled with LOG_FORMAT=json; the default stays
    the human-readable format so local development is unchanged.
  * Prometheus metrics — exposed at /metrics. prometheus_client is imported
    defensively so a deployment without it degrades to no-op recorders rather
    than failing to boot; the API surface here is identical either way, so call
    sites never branch on availability.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

# ──────────────────────────────────────────────────────────────────────────
# Structured logging
# ──────────────────────────────────────────────────────────────────────────
#: Attributes LogRecord always carries; anything else a caller attached via
#: `extra=` is application context worth emitting.
_STANDARD = frozenset(vars(logging.LogRecord("", 0, "", 0, "", (), None)).keys()) | {
    "asctime", "message", "taskName",
}


class JsonFormatter(logging.Formatter):
    """One JSON object per line, with any `extra=` fields merged in."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", fmt: str | None = None) -> None:
    """Install the root handler. `fmt` of "json" switches to structured output."""
    fmt = (fmt or os.getenv("LOG_FORMAT", "text")).lower()
    handler = logging.StreamHandler()
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


# ──────────────────────────────────────────────────────────────────────────
# Metrics
# ──────────────────────────────────────────────────────────────────────────
try:  # pragma: no cover - exercised by whichever branch the deployment has
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Histogram,
        generate_latest,
    )
    _PROM = True
except Exception:  # noqa: BLE001
    _PROM = False
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"


class _NoopMetric:
    """Stands in for a metric when prometheus_client is not installed.

    Call sites use the same API either way, so instrumentation never needs an
    `if metrics_enabled` guard and can't drift between the two branches.
    """

    def labels(self, *a: Any, **k: Any) -> _NoopMetric:
        return self

    def inc(self, *a: Any, **k: Any) -> None:
        return None

    def observe(self, *a: Any, **k: Any) -> None:
        return None


if _PROM:
    REGISTRY = CollectorRegistry()
    REQUESTS = Counter(
        "complens_http_requests_total", "HTTP requests",
        ["method", "path", "status"], registry=REGISTRY)
    REQUEST_SECONDS = Histogram(
        "complens_http_request_duration_seconds", "HTTP request duration",
        ["method", "path"], registry=REGISTRY)
    ASSESSMENTS = Counter(
        "complens_assessments_total", "Control assessments committed",
        ["source_system", "status"], registry=REGISTRY)
    EVIDENCE_WRITES = Counter(
        "complens_evidence_writes_total", "Evidence artifacts persisted",
        ["outcome"], registry=REGISTRY)
    SCHEDULE_RUNS = Counter(
        "complens_schedule_runs_total", "Scheduled runs by outcome",
        ["outcome"], registry=REGISTRY)
    CONNECTOR_ERRORS = Counter(
        "complens_connector_errors_total", "Connector collection failures",
        ["source_system"], registry=REGISTRY)
else:  # pragma: no cover
    REGISTRY = None
    REQUESTS = REQUEST_SECONDS = ASSESSMENTS = _NoopMetric()
    EVIDENCE_WRITES = SCHEDULE_RUNS = CONNECTOR_ERRORS = _NoopMetric()


def metrics_available() -> bool:
    return _PROM


def render_metrics() -> bytes:
    """The Prometheus exposition payload, or an explanatory comment."""
    if not _PROM:
        return b"# prometheus_client is not installed; no metrics exported\n"
    return generate_latest(REGISTRY)


def normalize_path(path: str) -> str:
    """Collapse identifiers out of a path so label cardinality stays bounded.

    `/findings/9f3c…/` and `/findings/2a71…/` must share one series, or every
    id ever seen becomes its own time series and the metric store degrades.
    """
    parts = []
    for seg in path.split("/"):
        if not seg:
            continue
        # uuid-ish, long hex, or plainly numeric segments are identifiers
        if seg.isdigit() or (len(seg) >= 16 and all(
                c.isalnum() or c == "-" for c in seg) and any(c.isdigit() for c in seg)):
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/" + "/".join(parts) if parts else "/"


__all__ = [
    "JsonFormatter", "configure_logging", "metrics_available", "render_metrics",
    "normalize_path", "CONTENT_TYPE_LATEST", "REQUESTS", "REQUEST_SECONDS",
    "ASSESSMENTS", "EVIDENCE_WRITES", "SCHEDULE_RUNS", "CONNECTOR_ERRORS",
]
