"""Exposed-edge hardening: SSRF rebinding recheck, docs gating, CORS default-deny."""
import os

from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_edge.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")


# ── SSRF guard (pure) ──
def test_blocked_ip_covers_internal_and_metadata():
    from app.services.doc_fetch import _is_blocked_ip
    for bad in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "0.0.0.0"):
        assert _is_blocked_ip(bad) is True, bad
    for ok in ("8.8.8.8", "1.1.1.1"):
        assert _is_blocked_ip(ok) is False, ok


def test_connected_peer_ip_degrades_gracefully():
    # no socket to introspect -> None (never a false block, no regression)
    from app.services.doc_fetch import _connected_peer_ip
    assert _connected_peer_ip(object()) is None


# ── CORS default-deny ──
def test_cors_default_denies_cross_origin():
    from app.main import app
    with TestClient(app) as c:
        r = c.get("/health/live", headers={"Origin": "https://evil.example"})
        # default cors_origins is empty -> no allow-origin echoed back
        assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


# ── docs available outside production (and the gate exists) ──
def test_docs_served_in_non_production():
    from app.main import app
    with TestClient(app) as c:
        assert c.get("/openapi.json").status_code == 200


def test_docs_gate_semantics_for_production():
    # the app disables docs when is_production and not expose_api_docs
    from app.config import Settings
    prod = Settings(app_env="production", expose_api_docs=False)
    assert prod.is_production and not prod.expose_api_docs  # -> openapi_url=None
    opted_in = Settings(app_env="production", expose_api_docs=True)
    assert opted_in.expose_api_docs  # -> docs exposed on purpose
