"""Guardrailed external-page crawler.

Reuses the SSRF-safe fetch primitive already used for document-URL ingestion
(app.services.doc_fetch.fetch_url_text — validates scheme, resolves and blocks
private/loopback/link-local/reserved/cloud-metadata addresses on every redirect
hop, caps size/time/redirects) and layers crawler-specific guardrails on top:

  - Domain pinning:   a target may only ever be fetched at the exact host it
                       was registered with (an admin-set allowlist of one).
  - robots.txt:        checked and honoured before every fetch.
  - Rate limiting:      a target cannot be re-fetched inside its configured
                       min_interval_hours; even a forced/manual run is bounded
                       by a hard minimum cooldown.
  - Public-only:        no credentials, cookies, or auth headers are ever
                       attached — this crawler reads public pages only.
  - Read-only:          GET only; fetched content is parsed to text and never
                       executed, evaluated, or rendered.
  - Content-addressed:  each result is sha256-hashed so "changed" is a real,
                       reproducible signal, not a guess.
  - Fully audited:      every fetch attempt (success, no-change, error,
                       blocked, robots-disallowed, rate-limited) is written to
                       the platform audit log.
  - Fault-isolated:      one target failing never aborts a batch run.
"""
from __future__ import annotations

import hashlib
import time
import urllib.robotparser
from datetime import UTC
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.crawler_models import CrawlResult, CrawlTarget, utc_now
from app.services.doc_fetch import FetchError, _assert_safe, fetch_url_text

KINDS = ("vendor_trust", "regulatory", "advisory")
HARD_MIN_COOLDOWN_MIN = 5          # even a forced run can't beat this
EXCERPT_CHARS = 500
_ROBOTS_CACHE: dict[str, tuple] = {}   # domain -> (RobotFileParser, cached_at)
_ROBOTS_TTL_SEC = 3600
_UA = "CompLens-Crawler/1.0 (guardrailed, public-page-only)"


def _aware(dt):
    """SQLite returns naive datetimes; coerce to aware UTC for safe comparison."""
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


class CrawlError(Exception):
    pass


# ─────────────────────────── validation ───────────────────────────
def _domain_of(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if not host:
        raise CrawlError("URL has no host.")
    return host


def validate_target_url(url: str) -> str:
    """Raise if the URL is unsafe to register as a crawl target; return its domain."""
    if urlparse(url).scheme not in ("http", "https"):
        raise CrawlError("Only http/https URLs may be crawled.")
    try:
        _assert_safe(url)   # resolves + blocks private/loopback/link-local/reserved/metadata
    except FetchError as e:
        raise CrawlError(str(e)) from e
    return _domain_of(url)


# ─────────────────────────── robots.txt ───────────────────────────
def _robots_allowed(url: str) -> bool:
    domain = _domain_of(url)
    now = time.time()
    cached = _ROBOTS_CACHE.get(domain)
    if cached and now - cached[1] < _ROBOTS_TTL_SEC:
        rp = cached[0]
    else:
        scheme = urlparse(url).scheme
        robots_url = f"{scheme}://{domain}/robots.txt"
        rp = urllib.robotparser.RobotFileParser()
        try:
            _assert_safe(robots_url)
            text, _ = fetch_url_text(robots_url)
            rp.parse(text.splitlines())
        except Exception:  # noqa: BLE001
            # No robots.txt, or it's unreadable — default to allowed (standard
            # crawler behaviour), but never let a robots.txt fetch failure
            # crash the caller.
            rp.parse([])
        _ROBOTS_CACHE[domain] = (rp, now)
    try:
        return rp.can_fetch(_UA, url)
    except Exception:  # noqa: BLE001
        return True


# ─────────────────────────── serialisers ───────────────────────────
def _target_dict(t: CrawlTarget) -> dict[str, Any]:
    return {"id": t.id, "kind": t.kind, "name": t.name, "url": t.url, "domain": t.domain,
            "linked_vendor_id": t.linked_vendor_id, "linked_framework": t.linked_framework,
            "min_interval_hours": t.min_interval_hours, "enabled": t.enabled,
            "last_hash": t.last_hash,
            "last_checked_at": t.last_checked_at.isoformat() if t.last_checked_at else None,
            "created_at": t.created_at.isoformat() if t.created_at else None}


def _result_dict(r: CrawlResult) -> dict[str, Any]:
    return {"id": r.id, "target_id": r.target_id, "status": r.status,
            "content_hash": r.content_hash, "excerpt": r.excerpt,
            "http_status": r.http_status, "error": r.error, "duration_ms": r.duration_ms,
            "meta": r.meta or {}, "fetched_at": r.fetched_at.isoformat() if r.fetched_at else None}


# ─────────────────────────── CRUD ───────────────────────────
def create_target(db: Session, tenant_id: str, kind: str, name: str, url: str, *,
                  linked_vendor_id: str | None = None,
                  linked_framework: str | None = None,
                  min_interval_hours: int = 24) -> dict[str, Any]:
    if kind not in KINDS:
        raise CrawlError(f"Unknown kind '{kind}'; must be one of {KINDS}.")
    domain = validate_target_url(url)
    t = CrawlTarget(tenant_id=tenant_id, kind=kind, name=name or domain, url=url,
                    domain=domain, linked_vendor_id=linked_vendor_id,
                    linked_framework=linked_framework,
                    min_interval_hours=max(1, min_interval_hours), enabled=True)
    db.add(t)
    db.commit()
    return _target_dict(t)


def list_targets(db: Session, tenant_id: str, kind: str | None = None) -> list[dict[str, Any]]:
    q = select(CrawlTarget).where(CrawlTarget.tenant_id == tenant_id)
    if kind:
        q = q.where(CrawlTarget.kind == kind)
    q = q.order_by(CrawlTarget.created_at.desc())
    return [_target_dict(t) for t in db.execute(q).scalars().all()]


def update_target(db: Session, tenant_id: str, target_id: str, *,
                  enabled: bool | None = None,
                  min_interval_hours: int | None = None) -> dict[str, Any] | None:
    t = db.get(CrawlTarget, target_id)
    if not t or t.tenant_id != tenant_id:
        return None
    if enabled is not None:
        t.enabled = enabled
    if min_interval_hours is not None:
        t.min_interval_hours = max(1, min_interval_hours)
    db.commit()
    return _target_dict(t)


def delete_target(db: Session, tenant_id: str, target_id: str) -> bool:
    t = db.get(CrawlTarget, target_id)
    if not t or t.tenant_id != tenant_id:
        return False
    db.delete(t)
    db.commit()
    return True


def list_results(db: Session, tenant_id: str, target_id: str | None = None,
                 limit: int = 200) -> list[dict[str, Any]]:
    q = select(CrawlResult).where(CrawlResult.tenant_id == tenant_id)
    if target_id:
        q = q.where(CrawlResult.target_id == target_id)
    q = q.order_by(desc(CrawlResult.fetched_at)).limit(limit)
    return [_result_dict(r) for r in db.execute(q).scalars().all()]


# ─────────────────────────── crawl execution ───────────────────────────
def _record(db: Session, tenant_id: str, target: CrawlTarget, status: str, *,
           content_hash: str | None = None, excerpt: str | None = None,
           http_status: int | None = None, error: str | None = None,
           duration_ms: int | None = None, meta: dict | None = None) -> dict[str, Any]:
    r = CrawlResult(tenant_id=tenant_id, target_id=target.id, status=status,
                    content_hash=content_hash, excerpt=excerpt, http_status=http_status,
                    error=error, duration_ms=duration_ms, meta=meta or {})
    db.add(r)
    try:
        from app.services import privacy as _pv
        _pv.record_event(db, tenant_id, "crawler." + status, entity_type="crawl_target",
                         entity_id=target.id,
                         summary=f"{target.kind}:{target.name} — {status}",
                         meta={"url": target.url, "domain": target.domain})
    except Exception:  # noqa: BLE001 — audit logging must never break a crawl
        pass
    db.commit()
    return _result_dict(r)


def run_target(db: Session, tenant_id: str, target_id: str, *, force: bool = False) -> dict[str, Any]:
    t = db.get(CrawlTarget, target_id)
    if not t or t.tenant_id != tenant_id:
        raise CrawlError("Unknown crawl target.")
    if not t.enabled and not force:
        raise CrawlError("Target is disabled.")

    now = utc_now()
    last_checked = _aware(t.last_checked_at)
    if last_checked:
        elapsed_min = (now - last_checked).total_seconds() / 60
        hard_floor = HARD_MIN_COOLDOWN_MIN
        soft_floor = t.min_interval_hours * 60
        floor = hard_floor if force else max(hard_floor, soft_floor)
        if elapsed_min < floor:
            return _record(db, tenant_id, t, "rate_limited",
                           meta={"retry_after_min": round(floor - elapsed_min, 1)})

    # domain pin: the registered URL's host must still match what we validated at creation
    try:
        current_domain = _domain_of(t.url)
    except CrawlError as e:
        return _record(db, tenant_id, t, "blocked", error=str(e))
    if current_domain != t.domain:
        return _record(db, tenant_id, t, "blocked",
                       error=f"URL host '{current_domain}' no longer matches registered domain '{t.domain}'.")

    # robots.txt
    try:
        if not _robots_allowed(t.url):
            return _record(db, tenant_id, t, "robots_disallowed")
    except Exception:  # noqa: BLE001
        pass  # never let a robots-check failure block a crawl; default allow

    # the guarded fetch itself
    start = time.monotonic()
    try:
        text, source_type = fetch_url_text(t.url)
    except FetchError as e:
        dur = int((time.monotonic() - start) * 1000)
        return _record(db, tenant_id, t, "error", error=str(e), duration_ms=dur)
    except Exception as e:  # noqa: BLE001 — a crawl failure must never propagate
        dur = int((time.monotonic() - start) * 1000)
        return _record(db, tenant_id, t, "error", error=f"{type(e).__name__}: {e}", duration_ms=dur)
    dur = int((time.monotonic() - start) * 1000)

    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    excerpt = text[:EXCERPT_CHARS]
    changed = t.last_hash is not None and digest != t.last_hash
    status = "changed" if changed else "ok"
    first_check = t.last_hash is None

    t.last_hash = digest
    t.last_checked_at = now
    db.commit()

    return _record(db, tenant_id, t, status, content_hash=digest, excerpt=excerpt,
                   duration_ms=dur, meta={"source_type": source_type, "first_check": first_check})


def run_due_targets(db: Session, tenant_id: str) -> dict[str, Any]:
    """Run every enabled target whose min_interval has elapsed. Fault-isolated
    per target — one failing target is reported, not fatal to the batch."""
    targets = list(db.execute(select(CrawlTarget).where(
        CrawlTarget.tenant_id == tenant_id, CrawlTarget.enabled == True)).scalars().all())  # noqa: E712
    ran, errors = [], {}
    for t in targets:
        try:
            ran.append({"target_id": t.id, "name": t.name, **run_target(db, tenant_id, t.id)})
        except Exception as e:  # noqa: BLE001
            db.rollback()
            errors[t.id] = f"{type(e).__name__}: {e}"
    changed = [r for r in ran if r.get("status") == "changed"]
    return {"checked": len(ran), "changed": len(changed), "errors": errors,
            "results": ran}
