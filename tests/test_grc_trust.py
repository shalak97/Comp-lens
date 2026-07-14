"""GRC Trust Telemetry — configurable scoring (freshness, corroboration, conflict)."""
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.grc_platforms.base import GRCPlatformConnector
from app.grc_platforms.models import GRCAttestation
from app.grc_platforms.profiles import VANTA
from app.grc_platforms.trust_telemetry import (
    TrustPolicy,
    _control_trust,
    resolve_policy,
)

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_grctrust.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")


def _att(platform, status, days, conf=0.9):
    a = GRCAttestation()
    a.platform = platform
    a.status = status
    a.freshness_days = days
    a.confidence = conf
    a.comp_lens_control_id = "AC-2"
    return a


@pytest.fixture()
def client():
    import app.main as M
    with TestClient(M.app) as c:
        yield c


# ── scoring fundamentals ──
def test_fresh_pass_high_trust():
    assert _control_trust([_att("VANTA", "pass", 1)], TrustPolicy())["trust"] >= 75

def test_conflict_collapses_trust():
    t = _control_trust([_att("VANTA", "pass", 1), _att("DRATA", "fail", 1)], TrustPolicy())
    assert t["agreement"] == "conflict" and t["trust"] < 30

def test_corroboration_boosts():
    one = _control_trust([_att("VANTA", "pass", 1)], TrustPolicy())["trust"]
    two = _control_trust([_att("VANTA", "pass", 1), _att("DRATA", "pass", 1)], TrustPolicy())["trust"]
    assert two >= one


# ── configurability ──
def test_freshness_policy_changes_score():
    atts = [_att("VANTA", "pass", 40)]
    default = _control_trust(atts, TrustPolicy())["trust"]
    strict = _control_trust(atts, TrustPolicy.from_overrides({"fresh_days": 1, "stale_days": 20}))["trust"]
    assert strict < default

def test_conflict_factor_configurable():
    atts = [_att("VANTA", "pass", 1), _att("DRATA", "fail", 1)]
    harsh = _control_trust(atts, TrustPolicy.from_overrides({"conflict_factor": 0.1}))["trust"]
    soft = _control_trust(atts, TrustPolicy.from_overrides({"conflict_factor": 0.8}))["trust"]
    assert harsh <= soft

def test_policy_validation_clamps():
    bad = TrustPolicy.from_overrides({"conflict_factor": 5.0, "freshness_floor": -1,
                                      "fresh_days": 100, "stale_days": 10})
    assert bad.conflict_factor <= 1.0
    assert bad.freshness_floor >= 0.0
    assert bad.stale_days > bad.fresh_days

def test_env_var_policy(monkeypatch):
    monkeypatch.setenv("GRC_TRUST_POLICY", '{"fresh_days": 1}')
    assert resolve_policy().fresh_days == 1

def test_inline_override_precedence(monkeypatch):
    monkeypatch.setenv("GRC_TRUST_POLICY", '{"fresh_days": 1}')
    # inline beats env
    assert resolve_policy(inline={"fresh_days": 14}).fresh_days == 14


# ── API ──
def test_policy_endpoint(client):
    pol = client.get("/v1/grc-trust/policy").json()
    assert "fresh_days" in pol["fields"]
    assert pol["active_policy"]["fresh_days"] == 7

def test_score_preview_changes_result(client):
    V = {"results": [{"testId": "v1", "outcome": "OK", "controlId": "CC6.1",
         "name": "x", "latestFlipTime": "2026-05-01T00:00:00Z", "frameworks": {}}],
         "pageInfo": {"endCursor": None}}

    class FV(GRCPlatformConnector):
        def _authed_get(self, p, cursor=None): return V

    with patch("app.grc_platforms.service.get_grc_connector", side_effect=lambda p: FV(VANTA)):
        client.post("/v1/grc-sync/VANTA")
    default = client.get("/v1/grc-trust/score").json()
    strict = client.post("/v1/grc-trust/score-preview",
                         json={"policy": {"fresh_days": 1, "stale_days": 20}}).json()
    assert strict["policy"]["fresh_days"] == 1
    assert strict["grc_trust_score"] <= default["grc_trust_score"]
