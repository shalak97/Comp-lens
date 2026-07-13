"""Enterprise connector resilience: retries, circuit breaker, SSRF, redaction."""
from unittest.mock import MagicMock, patch

import pytest

from app.connectors.base import ConnectorError
from app.connectors.http_client import (
    ResilientClient,
    _breaker_for,
    _breakers,
    _is_blocked_host,
    _redact,
)


def setup_function():
    _breakers.clear()


def test_ssrf_blocks_metadata():
    assert _is_blocked_host("169.254.169.254") is True

def test_ssrf_allows_public():
    assert _is_blocked_host("example.okta.com") is False

def test_read_only_blocks_post():
    with pytest.raises(ConnectorError) as e:
        ResilientClient(service="T").request("POST", "https://api.example.com/x")
    assert "read-only" in str(e.value)

def test_retries_then_succeeds():
    calls = {"n": 0}
    def fake(method, url, **kw):
        calls["n"] += 1
        m = MagicMock()
        m.headers = {}
        if calls["n"] < 3:
            m.status_code = 503
            m.text = "busy"
        else:
            m.status_code = 200
            m.json = lambda: {"ok": True}
        return m
    c = ResilientClient(service="R", backoff_base=0.001, max_retries=3)
    with patch.object(c.session, "request", side_effect=fake):
        assert c.get("https://api.example.com/d") == {"ok": True}
    assert calls["n"] == 3

def test_429_honored():
    calls = {"n": 0}
    def fake(method, url, **kw):
        calls["n"] += 1
        m = MagicMock()
        if calls["n"] == 1:
            m.status_code = 429
            m.headers = {"Retry-After": "0"}
            m.text = "rl"
        else:
            m.status_code = 200
            m.headers = {}
            m.json = lambda: {"ok": 1}
        return m
    c = ResilientClient(service="RL", backoff_base=0.001)
    with patch.object(c.session, "request", side_effect=fake):
        assert c.get("https://api.example.com/x") == {"ok": 1}

def test_circuit_breaker_opens():
    def down(method, url, **kw):
        m = MagicMock()
        m.status_code = 500
        m.text = "down"
        m.headers = {}
        return m
    c = ResilientClient(service="CB", backoff_base=0.001, max_retries=0)
    with patch.object(c.session, "request", side_effect=down):
        for _ in range(6):
            try:
                c.get("https://api.example.com/x")
            except ConnectorError:
                pass
    assert _breaker_for("CB").is_open
    with pytest.raises(ConnectorError) as e:
        c.get("https://api.example.com/x")
    assert "circuit open" in str(e.value)

def test_credential_redaction():
    assert "secret999" not in _redact('bad token: SSWS secret999')
    assert "[REDACTED]" in _redact('{"api_key": "supersecret"}')

def test_error_redacts_leaked_creds():
    def leak(method, url, **kw):
        m = MagicMock()
        m.status_code = 401
        m.text = '{"error":"bad: SSWS leaked123"}'
        m.headers = {}
        return m
    c = ResilientClient(service="S", max_retries=0)
    with patch.object(c.session, "request", side_effect=leak):
        with pytest.raises(ConnectorError) as e:
            c.get("https://api.example.com/x")
    assert "leaked123" not in str(e.value)
