"""Production hardening: rate limiting, security headers, request ids, errors."""
import os
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_hard.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")


@pytest.fixture()
def client():
    import app.main as M
    with TestClient(M.app) as c:
        yield c


def test_security_headers_present(client):
    r = client.get("/health/live")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert "referrer-policy" in r.headers
    assert "permissions-policy" in r.headers


def test_request_id_generated(client):
    r = client.get("/health/live")
    assert r.headers.get("x-request-id", "").startswith("req_")
    assert "x-response-time-ms" in r.headers


def test_request_id_echoed(client):
    r = client.get("/health/live", headers={"X-Request-ID": "req_custom123"})
    assert r.headers.get("x-request-id") == "req_custom123"


def test_readiness_checks_database(client):
    r = client.get("/health/ready").json()
    assert r["ready"] is True
    assert r["checks"]["database"] == "ok"


def test_structured_404(client):
    r = client.patch("/grc/risks/does-not-exist", json={"title": "x"})
    assert r.status_code == 404
    body = r.json()
    assert body["error"]["type"] == "not_found"
    assert "request_id" in body["error"]


def test_structured_validation_error(client):
    r = client.post("/grc/risks", json={"likelihood": 99})
    assert r.status_code == 422
    assert r.json()["error"]["type"] == "validation_error"


def test_rate_limiting():
    # Build an isolated app with a tiny limit — never mutate the shared module,
    # so this test can't contaminate the rest of the suite.
    from fastapi import FastAPI
    from app.hardening import RateLimitMiddleware
    mini = FastAPI()
    mini.add_middleware(RateLimitMiddleware, max_requests=4, window_seconds=60,
                        exempt_paths=("/health",))

    @mini.get("/ping")
    def ping():
        return {"ok": True}

    mc = TestClient(mini)
    codes = [mc.get("/ping").status_code for _ in range(8)]
    assert 429 in codes
    assert codes.count(200) == 4
    blocked = mc.get("/ping")
    assert blocked.status_code == 429
    assert blocked.json()["error"]["type"] == "rate_limited"
    assert "retry-after" in blocked.headers


def test_health_exempt_from_rate_limit(client):
    codes = [client.get("/health/live").status_code for _ in range(20)]
    assert all(x == 200 for x in codes)
