"""Connector safety guardrails — prove no live call escapes when locked."""
import os
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_safety.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")


@pytest.fixture()
def client():
    import app.main as M
    with TestClient(M.app) as c:
        yield c


def _clear_env():
    os.environ.pop("LIVE_CONNECTORS_ENABLED", None)
    os.environ.pop("LIVE_CONNECTORS_ALLOWLIST", None)


def test_default_is_locked(client):
    _clear_env()
    s = client.get("/connectors/safety").json()
    assert s["live_enabled"] is False
    assert s["mode"] == "SAFE"
    assert "no live api calls" in s["summary"].lower()


def test_kill_switch_alone_still_locked(client):
    _clear_env()
    os.environ["LIVE_CONNECTORS_ENABLED"] = "true"  # but no allowlist
    s = client.get("/connectors/safety").json()
    assert s["mode"] == "SAFE"  # fail-closed
    assert s["allowlist"] == []
    _clear_env()


def test_full_live_requires_both(client):
    _clear_env()
    os.environ["LIVE_CONNECTORS_ENABLED"] = "true"
    os.environ["LIVE_CONNECTORS_ALLOWLIST"] = "OKTA"
    s = client.get("/connectors/safety").json()
    assert s["mode"] == "LIVE"
    assert s["allowlist"] == ["OKTA"]
    _clear_env()


def test_live_allowed_logic():
    from app.connectors import safety as S
    _clear_env()
    assert S.live_allowed("OKTA")["allowed"] is False
    os.environ["LIVE_CONNECTORS_ENABLED"] = "true"
    os.environ["LIVE_CONNECTORS_ALLOWLIST"] = "OKTA,GITHUB"
    assert S.live_allowed("OKTA")["allowed"] is True
    assert S.live_allowed("github")["allowed"] is True  # case-insensitive
    assert S.live_allowed("AWS_SECURITY_HUB")["allowed"] is False
    _clear_env()


def test_read_only_blocks_mutations():
    from app.connectors import safety as S
    S.assert_read_only("collect_telemetry")  # ok
    S.assert_read_only("get_findings")        # ok
    S.assert_read_only("list_users")          # ok
    for bad in ["delete_user", "create_policy", "update_config",
                "post_message", "revoke_token", "disable_mfa"]:
        with pytest.raises(PermissionError):
            S.assert_read_only(bad)


def test_sync_stays_demo_when_locked(client):
    """Even calling sync never flips to live while locked."""
    _clear_env()
    r = client.post("/connectors/OKTA/sync", json={"tenant_id": "safe_t"})
    assert r.status_code == 200
    assert r.json()["mode"] == "demo"  # locked -> demo regardless


def test_test_connection_reports_guardrail(client):
    _clear_env()
    # no creds set on the test runner anyway, so it's demo; the key check is
    # that with the kill-switch off, test never claims a live connection
    r = client.post("/connectors/OKTA/test", json={})
    assert r.json()["mode"] == "demo"
