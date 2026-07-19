"""Regressions for the fault-finding pass.

- YAML anchor/alias 'billion laughs' and oversize DoS via POST /policies/import.
- Rate-limit client-ip resolution behind a trusted proxy (and its safe default).
- (The policy-drawer stored-XSS fix is frontend-only; verified via headless run.)
"""
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_secfaults.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")


# ── YAML DoS guard (pure) ──
def test_parse_policy_yaml_rejects_alias_bomb():
    from app.policy_as_code.engine import PolicyValidationError, parse_policy_yaml
    bomb = ("a: &a [x,x,x,x,x,x,x,x,x,x]\n"
            "b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
            "c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
            "d: [*c,*c,*c,*c,*c,*c,*c,*c,*c,*c]")
    with pytest.raises(PolicyValidationError):
        parse_policy_yaml(bomb)


def test_parse_policy_yaml_rejects_oversize():
    from app.policy_as_code.engine import PolicyValidationError, parse_policy_yaml
    with pytest.raises(PolicyValidationError):
        parse_policy_yaml("x: " + "A" * (300 * 1024))


def test_parse_policy_yaml_accepts_normal_and_rejects_non_mapping():
    from app.policy_as_code.engine import PolicyValidationError, parse_policy_yaml
    assert parse_policy_yaml("control: AC-2\npass_when: 'mfa == true'")["control"] == "AC-2"
    with pytest.raises(PolicyValidationError):
        parse_policy_yaml("- a\n- b\n- c")


# ── import endpoint rejects the bomb end-to-end ──
def test_policies_import_rejects_yaml_bomb():
    from app.main import app
    bomb = ("a: &a [x,x,x,x,x,x,x,x,x,x]\n"
            "b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
            "c: [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\ncontrol: X")
    with TestClient(app) as c:
        r = c.post("/policies/import", json={"yaml": bomb})
        assert r.status_code == 400
        # error envelope differs (FastAPI 'detail' vs the app's {"error": {...}}),
        # so just assert the alias rejection surfaced somewhere in the body
        assert "alias" in r.text.lower()


# ── rate-limit client-ip resolution ──
def test_ratelimit_client_ip_trusted_proxy():
    from app.hardening import RateLimitMiddleware

    class _Req:
        def __init__(self, xff, peer):
            self.headers = {"x-forwarded-for": xff} if xff is not None else {}
            self.client = type("C", (), {"host": peer})() if peer else None

    # hops=0 (default): always the socket peer, XFF ignored (unspoofable)
    mw0 = RateLimitMiddleware(lambda *a, **k: None, trusted_proxy_hops=0)
    assert mw0._client_ip(_Req("1.2.3.4, 5.6.7.8", "10.0.0.1")) == "10.0.0.1"

    # hops=1 (behind one proxy): the true client is the rightmost XFF entry, and
    # a spoofed value prepended by the client is not trusted
    mw1 = RateLimitMiddleware(lambda *a, **k: None, trusted_proxy_hops=1)
    assert mw1._client_ip(_Req("evil-spoof, 203.0.113.7", "10.0.0.1")) == "203.0.113.7"
    # short/absent chain falls back to the peer without crashing
    assert mw1._client_ip(_Req("", "10.0.0.1")) == "10.0.0.1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
