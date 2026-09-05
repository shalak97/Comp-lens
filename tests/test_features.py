"""Tests for the 7 added capabilities."""
from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_feat.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", "./test_feat_evidence")

import pytest
from fastapi.testclient import TestClient

from app.database import init_db


@pytest.fixture(scope="module")
def client():
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


# 1. Multi-framework mapping
def test_frameworks_and_crosswalk(client):
    fw = client.get("/frameworks").json()["frameworks"]
    assert {"NIST", "ISO27001", "SOC2", "CIS"} <= set(fw)
    cw = client.get("/crosswalk?control_id=SC-7").json()["mappings"]
    assert "ISO27001" in cw and "SOC2" in cw
    # controls endpoint now carries framework mappings
    ctrls = client.get("/controls").json()
    assert any(c["frameworks"] for c in ctrls)


def test_summary_filtered_by_framework(client):
    client.post("/assessments", json={"tenant_id": "fw", "control_id": "SC-7", "source_system": "DEMO", "asset_id": "a"})
    s = client.get("/summary?tenant_id=fw&framework=ISO27001").json()
    assert s["framework"] == "ISO27001"
    assert s["total"] >= 1


# 2. Exception/waiver workflow + lifecycle
def test_waiver_suppresses_failure_from_score(client):
    # create a failing finding
    client.post("/assessments", json={"tenant_id": "wv", "control_id": "SC-28", "source_system": "DEMO",
                "asset_id": "bad", "params": {"fail": True}})
    before = client.get("/summary?tenant_id=wv").json()
    assert before["by_status"]["fail"] == 1
    # waive it
    w = client.post("/waivers", json={"tenant_id": "wv", "control_id": "SC-28", "asset_id": "bad",
                    "reason": "compensating control in place", "approver": "ciso@acme"}).json()
    assert w["status"] == "active"
    after = client.get("/summary?tenant_id=wv").json()
    assert after["by_status"]["fail"] == 0 and after["waived"] == 1
    # revoke -> fail counts again
    client.delete(f"/waivers/{w['waiver_id']}?tenant_id=wv")
    restored = client.get("/summary?tenant_id=wv").json()
    assert restored["by_status"]["fail"] == 1


def test_finding_lifecycle_update(client):
    f = client.post("/assessments", json={"tenant_id": "lc", "control_id": "SC-7", "source_system": "DEMO", "asset_id": "a"}).json()
    assert f["lifecycle"] == "open"
    upd = client.patch(f"/findings/{f['finding_id']}?tenant_id=lc",
                       json={"lifecycle": "in_progress", "assigned_to": "alice"}).json()
    assert upd["lifecycle"] == "in_progress" and upd["assigned_to"] == "alice"


# 3. Scheduled assessments
def test_schedule_create_and_run(client):
    s = client.post("/schedules", json={"tenant_id": "sc", "name": "daily", "interval_minutes": 1440,
        "controls": [{"control_id": "SC-7", "source_system": "DEMO", "asset_id": "a"},
                     {"control_id": "AU-2", "source_system": "DEMO", "asset_id": "b"}]}).json()
    assert s["name"] == "daily"
    run = client.post(f"/schedules/{s['schedule_id']}/run?tenant_id=sc").json()
    assert run["ran"] == 2
    # running creates findings + a trend snapshot
    assert len(client.get("/findings?tenant_id=sc").json()) == 2
    assert len(client.get("/trends?tenant_id=sc").json()) >= 1
    assert any(x["schedule_id"] == s["schedule_id"] for x in client.get("/schedules?tenant_id=sc").json())
    client.delete(f"/schedules/{s['schedule_id']}?tenant_id=sc")
    assert all(x["schedule_id"] != s["schedule_id"] for x in client.get("/schedules?tenant_id=sc").json())


# 4. Reports
def test_csv_report(client):
    client.post("/assessments", json={"tenant_id": "rp", "control_id": "SC-7", "source_system": "DEMO", "asset_id": "a"})
    r = client.get("/reports/csv?tenant_id=rp")
    assert r.status_code == 200 and "text/csv" in r.headers["content-type"]
    assert b"control_id" in r.content and b"SC-7" in r.content


def test_pdf_report(client):
    client.post("/assessments", json={"tenant_id": "rp", "control_id": "AU-2", "source_system": "DEMO", "asset_id": "b"})
    r = client.get("/reports/pdf?tenant_id=rp")
    assert r.status_code == 200 and r.content[:4] == b"%PDF"


# 6. Asset discovery + bulk assess (uses a connector that discovers assets)
def test_discover_and_bulk_assess(client, monkeypatch):
    # DEMO has no discover; stub the AWS connector's discover via the registry
    from app.connectors.base import Asset
    from app.connectors.registry import registry
    demo = registry.get("DEMO")
    monkeypatch.setattr(demo, "discover_assets",
        lambda params: [Asset(asset_id=f"u{i}", asset_type="user", source_system="DEMO") for i in range(3)],
        raising=False)
    n = client.post("/inventory/discover?source_system=DEMO&tenant_id=inv").json()["discovered_new"]
    assert n == 3
    assert len(client.get("/inventory?tenant_id=inv").json()) == 3
    bulk = client.post("/assessments/bulk", json={"tenant_id": "inv", "control_id": "AC-2-7", "source_system": "DEMO"}).json()
    assert bulk["assessed"] == 3


# 7. Trend history + drift detection
def test_drift_detection(client):
    # pass then fail on the same control/asset -> regression
    client.post("/assessments", json={"tenant_id": "dr", "control_id": "SC-7", "source_system": "DEMO",
                "asset_id": "x", "idempotency_key": "d1"})
    client.post("/assessments", json={"tenant_id": "dr", "control_id": "SC-7", "source_system": "DEMO",
                "asset_id": "x", "params": {"fail": True}, "idempotency_key": "d2"})
    d = client.get("/drift?tenant_id=dr").json()
    assert d["regression_count"] >= 1
    assert any(r["control_id"] == "SC-7" for r in d["regressions"])


# 5. Notifications (dispatch logic without network)
def test_notification_dispatch(monkeypatch):
    monkeypatch.setenv("NOTIFY_SLACK_WEBHOOK", "https://hooks.slack.test/x")
    monkeypatch.setenv("NOTIFY_ON_STATUS", "fail")
    import importlib

    import app.config as cfg
    importlib.reload(cfg)
    import app.notifications as nt
    importlib.reload(nt)
    sent = {}

    class _Resp:
        """A response double that behaves like a real one.

        `requests.post` does not raise on 4xx/5xx, so notifications now call
        raise_for_status() — a webhook answering `404 invalid_token` was
        previously recorded as delivered. A stub with only `status_code` no
        longer stands in for a response.
        """
        status_code = 200
        text = "ok"

        def raise_for_status(self):
            return None

    monkeypatch.setattr(nt.requests, "post",
                        lambda url, **kw: sent.update({"url": url, "json": kw.get("json")})
                        or _Resp())
    class F:
        status = type("S", (), {"value": "fail"})()
        control_id = "SC-7"
        source_system = "DEMO"
        asset_id = "a"
        severity = type("S", (), {"value": "critical"})()
        tenant_id = "t"
        finding_id = "f1"
        description = "bad"
    res = nt.notify_finding(F())
    assert res.get("slack") is True and "slack" in sent["url"]
    # a passing finding should NOT notify
    class P(F):
        status = type("S", (), {"value": "pass"})()
    assert nt.notify_finding(P()) == {}
