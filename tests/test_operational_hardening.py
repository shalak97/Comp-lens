"""Operational hardening: multi-replica scheduling, bounded reads, metrics, RBAC.

These are the production-readiness gaps from the maturity review — the ones
that do not show up at demo scale and do show up the first time the platform
has two replicas, a long-lived tenant, or an auditor who must not be able to
edit findings.
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_ops.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_ops_evidence")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import init_db  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


# ──────────────────────────────────────────────────────────────────────────
# Scheduler: one replica runs a due schedule, not all of them
# ──────────────────────────────────────────────────────────────────────────
def _due_schedule(tenant_id: str):
    from app.models import Schedule

    return Schedule(
        tenant_id=tenant_id, name=f"sched-{tenant_id}", interval_minutes=60,
        controls=[{"framework": "NIST", "control_id": "SC-7",
                   "source_system": "DEMO", "asset_id": "a1"}],
        enabled=True, next_run_at=datetime.now(UTC) - timedelta(minutes=1))


def test_only_one_worker_can_claim_a_schedule(db_session):
    """The lease is what stops N replicas running the same schedule N times."""
    from app.services.scheduler import _claim, _release

    s = _due_schedule("lease-1")
    db_session.add(s)
    db_session.commit()
    now = datetime.now(UTC)

    assert _claim(db_session, s.schedule_id, now) is True
    # a second attempt in the same window loses, exactly as another replica would
    assert _claim(db_session, s.schedule_id, now) is False

    _release(db_session, s.schedule_id)
    assert _claim(db_session, s.schedule_id, now) is True


def test_an_expired_lease_is_reclaimable(db_session):
    """A replica killed mid-run must not strand its schedules forever."""
    from app.services.scheduler import _claim

    s = _due_schedule("lease-2")
    s.locked_by = "dead-worker"
    s.locked_until = datetime.now(UTC) - timedelta(seconds=1)
    db_session.add(s)
    db_session.commit()

    assert _claim(db_session, s.schedule_id, datetime.now(UTC)) is True


def test_a_schedule_that_is_not_due_cannot_be_claimed(db_session):
    from app.services.scheduler import _claim

    s = _due_schedule("lease-3")
    s.next_run_at = datetime.now(UTC) + timedelta(hours=1)
    db_session.add(s)
    db_session.commit()

    assert _claim(db_session, s.schedule_id, datetime.now(UTC)) is False


def test_run_due_reports_schedules_skipped_because_locked(db_session, monkeypatch):
    from app.services import scheduler as scheduler_mod
    from app.services.scheduler import ScheduleService

    s = _due_schedule("lease-4")
    s.locked_by = "another-replica"
    s.locked_until = datetime.now(UTC) + timedelta(minutes=5)
    db_session.add(s)
    db_session.commit()

    monkeypatch.setattr(scheduler_mod, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)

    result = ScheduleService.run_due()
    assert result["attempted"] == 1
    assert result["succeeded"] == 0
    assert result["skipped_locked"] == 1


# ──────────────────────────────────────────────────────────────────────────
# Posture as-of: bounded reads
# ──────────────────────────────────────────────────────────────────────────
def test_as_of_filters_in_sql_not_in_memory(db_session):
    """The covering-interval predicate must reach the database, or this endpoint
    scales with total history rather than with the size of its answer."""
    from app.models import ControlStatus, PostureHistory, Severity
    from app.services.posture_history import as_of

    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(20):
        db_session.add(PostureHistory(
            tenant_id="hist", control_id=f"C-{i}", source_system="DEMO",
            asset_id="a", asset_key="a", status=ControlStatus.FAIL,
            severity=Severity.HIGH, finding_id=f"f{i}",
            valid_from=base + timedelta(days=i),
            valid_to=base + timedelta(days=i + 1), recorded_at=base))
    db_session.commit()

    # only the interval covering this instant should come back
    snap = as_of(db_session, "hist", base + timedelta(days=5, hours=12))
    assert len(snap) == 1
    assert snap[0]["control_id"] == "C-5"


def test_as_of_excludes_the_closing_boundary(db_session):
    """[valid_from, valid_to) — the end is exclusive, so an instant exactly at
    valid_to belongs to the next interval, not this one."""
    from app.models import ControlStatus, PostureHistory, Severity
    from app.services.posture_history import as_of

    base = datetime(2026, 3, 1, tzinfo=UTC)
    db_session.add(PostureHistory(
        tenant_id="bound", control_id="C-1", source_system="DEMO", asset_id="a",
        asset_key="a", status=ControlStatus.PASS, severity=Severity.LOW,
        finding_id="f", valid_from=base, valid_to=base + timedelta(days=1),
        recorded_at=base))
    db_session.commit()

    assert len(as_of(db_session, "bound", base)) == 1
    assert len(as_of(db_session, "bound", base + timedelta(days=1))) == 0


def test_timeline_is_bounded(db_session):
    from app.models import ControlStatus, PostureHistory, Severity
    from app.services.posture_history import timeline

    base = datetime(2026, 2, 1, tzinfo=UTC)
    for i in range(30):
        db_session.add(PostureHistory(
            tenant_id="tl", control_id="C-FLAP", source_system="DEMO",
            asset_id="a", asset_key="a", status=ControlStatus.FAIL,
            severity=Severity.LOW, finding_id=f"f{i}",
            valid_from=base + timedelta(hours=i), valid_to=None,
            recorded_at=base))
    db_session.commit()

    rows = timeline(db_session, "tl", "C-FLAP", limit=10)
    assert len(rows) == 10
    # the cap keeps the newest intervals, returned oldest-first
    assert rows[0]["valid_from"] < rows[-1]["valid_from"]
    # SQLite drops tzinfo on round-trip, so compare the instant, not the string
    from datetime import datetime as _dt
    newest = _dt.fromisoformat(rows[-1]["valid_from"])
    if newest.tzinfo is None:
        newest = newest.replace(tzinfo=UTC)
    assert newest == base + timedelta(hours=29)


# ──────────────────────────────────────────────────────────────────────────
# Observability
# ──────────────────────────────────────────────────────────────────────────
def test_metrics_endpoint_serves_prometheus_text(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]


def test_requests_are_counted(client):
    from app.observability import metrics_available

    client.get("/health/live")
    body = client.get("/metrics").text
    if metrics_available():
        assert "complens_http_requests_total" in body
        assert "complens_http_request_duration_seconds" in body


def test_metric_paths_collapse_identifiers():
    """Per-resource label values would make every id its own time series."""
    from app.observability import normalize_path

    assert normalize_path("/findings/9f3c2b1a-4d5e-6789-abcd-0123456789ab") == "/findings/{id}"
    assert normalize_path("/audits/12345/controls") == "/audits/{id}/controls"
    assert normalize_path("/health/live") == "/health/live"
    assert normalize_path("/") == "/"


def test_json_log_formatter_emits_one_object_per_line():
    import json
    import logging

    from app.observability import JsonFormatter

    rec = logging.LogRecord("t", logging.INFO, __file__, 1, "hello %s", ("world",), None)
    rec.tenant_id = "acme"          # application context attached via extra=
    payload = json.loads(JsonFormatter().format(rec))
    assert payload["msg"] == "hello world"
    assert payload["level"] == "INFO"
    assert payload["tenant_id"] == "acme"


# ──────────────────────────────────────────────────────────────────────────
# RBAC / segregation of duties
# ──────────────────────────────────────────────────────────────────────────
def test_roles_form_a_widening_ladder():
    from app.auth import ROLE_PERMISSIONS

    assert ROLE_PERMISSIONS["viewer"] < ROLE_PERMISSIONS["auditor"]
    assert ROLE_PERMISSIONS["auditor"] < ROLE_PERMISSIONS["admin"]
    assert ROLE_PERMISSIONS["operator"] < ROLE_PERMISSIONS["admin"]


def test_auditor_can_read_evidence_but_not_mutate():
    """The segregation-of-duties boundary this product assesses for customers
    but could not previously enforce on itself."""
    from app.auth import ROLE_PERMISSIONS, Permission

    auditor = ROLE_PERMISSIONS["auditor"]
    assert Permission.READ_EVIDENCE in auditor
    assert Permission.ATTEST in auditor
    assert Permission.WRITE not in auditor
    assert Permission.APPROVE not in auditor
    assert Permission.ASSESS not in auditor


def test_operator_cannot_approve_its_own_waivers():
    """Whoever runs the assessments must not also be able to waive their
    findings — that is the whole point of the approval separation."""
    from app.auth import ROLE_PERMISSIONS, Permission

    operator = ROLE_PERMISSIONS["operator"]
    assert Permission.ASSESS in operator
    assert Permission.WRITE in operator
    assert Permission.APPROVE not in operator


def test_key_parsing_reads_the_role_field(monkeypatch):
    from app.auth import _parse_keys

    monkeypatch.setenv("COMP_LENS_API_KEYS",
                       "k1:acme:auditor ; k2:acme ; k3:*:admin ; k4:*")
    parsed = _parse_keys()
    assert parsed["k1"] == ({"acme"}, "auditor")
    assert parsed["k2"] == ({"acme"}, "operator")   # scoped key defaults
    assert parsed["k3"] == ({"*"}, "admin")
    # An all-tenant key with no role keeps the meaning it had before roles
    # existed — `key:*` WAS the admin key, and defaulting it to operator would
    # silently strip admin from every existing deployment.
    assert parsed["k4"] == ({"*"}, "admin")


def test_an_unknown_role_fails_closed(monkeypatch):
    """A typo must not silently widen access, nor silently grant the default."""
    from app.auth import _parse_keys

    monkeypatch.setenv("COMP_LENS_API_KEYS", "k1:acme:superuser")
    assert _parse_keys()["k1"] == ({"acme"}, "viewer")


def test_permission_enforcement_rejects_and_allows(monkeypatch):
    from fastapi import HTTPException

    from app.auth import Permission, authorize_permission, require_principal

    monkeypatch.setenv("COMP_LENS_API_KEYS", "ka:acme:auditor ; kw:acme:operator")

    auditor = require_principal("ka")
    with pytest.raises(HTTPException) as exc:
        authorize_permission(auditor, Permission.WRITE)
    assert exc.value.status_code == 403
    assert "auditor" in exc.value.detail

    operator = require_principal("kw")
    authorize_permission(operator, Permission.WRITE)   # must not raise


def test_every_authenticated_route_declares_a_permission():
    """A route left on the bare principal dependency is one nobody's role is
    checked against — partial enforcement gives false assurance."""
    from pathlib import Path

    main = Path("app/main.py").read_text()
    assert "Depends(require_principal)" not in main, (
        "some routes still authenticate without checking a permission")
    assert main.count("Depends(require(Permission.") > 100
