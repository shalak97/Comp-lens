"""GRC-platform connectors — separate set, bulk ingest, multi-source attestation."""
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.connectors.base import ConnectorError
from app.grc_platforms.base import GRCPlatformConnector
from app.grc_platforms.profiles import DRATA, VANTA
from app.grc_platforms.registry import GRC_PLATFORM_REGISTRY, get_grc_connector

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_grc.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")

VANTA_R = {"results": [
    {"testId": "v1", "outcome": "OK", "controlId": "CC6.1", "name": "MFA",
     "latestFlipTime": "2026-06-15T00:00:00Z", "frameworks": {"SOC2": ["CC6.1"]}},
    {"testId": "v2", "outcome": "FAILING", "controlId": "ZZ9", "name": "Custom",
     "latestFlipTime": "2026-06-10T00:00:00Z", "frameworks": {}}],
    "pageInfo": {"endCursor": None}}


class FakeVanta(GRCPlatformConnector):
    def _authed_get(self, path, cursor=None):
        return VANTA_R


@pytest.fixture()
def client():
    import app.main as M
    with TestClient(M.app) as c:
        yield c


def test_bulk_ingest_normalizes():
    atts = FakeVanta(VANTA).bulk_ingest()
    assert len(atts) == 2
    mfa = [a for a in atts if a.external_test_id == "v1"][0]
    assert mfa.status == "pass" and mfa.comp_lens_control_id == "AC-2"


def test_unmapped_kept_not_dropped():
    atts = FakeVanta(VANTA).bulk_ingest()
    unmapped = [a for a in atts if a.comp_lens_control_id is None]
    assert len(unmapped) == 1
    assert unmapped[0].confidence < 0.5


def test_telemetry_tagged_separate_lane():
    att = FakeVanta(VANTA).bulk_ingest()[0]
    tel = att.to_telemetry()
    assert tel["source_kind"] == "grc_platform"
    assert tel["source_system"] == "VANTA"


def test_mutually_exclusive_registries():
    from app.connectors.registry import _load_registry
    native = set(_load_registry().keys())
    grc = set(GRC_PLATFORM_REGISTRY.keys())
    assert native.isdisjoint(grc)
    assert "VANTA" not in native


def test_fail_closed_no_creds():
    for v in VANTA.env_vars:
        os.environ.pop(v, None)
    with pytest.raises(ConnectorError):
        get_grc_connector("VANTA")


def test_unknown_platform():
    with pytest.raises(ConnectorError):
        get_grc_connector("NOTAPLATFORM")


def test_sync_and_status(client):
    with patch("app.grc_platforms.service.get_grc_connector",
               side_effect=lambda p: FakeVanta(VANTA)):
        r = client.post("/v1/grc-sync/VANTA").json()
    assert r["ingested"] == 2 and r["mapped"] == 1
    st = client.get("/v1/grc-sync/status").json()
    assert "VANTA" in st["connected"]


def test_multi_source_conflict(client):
    v_pass = {"results": [{"testId": "v1", "outcome": "OK", "controlId": "CC6.1",
              "name": "MFA", "latestFlipTime": "2026-06-15T00:00:00Z", "frameworks": {}}],
              "pageInfo": {"endCursor": None}}
    d_fail = {"data": [{"id": "d1", "checkStatus": "UNHEALTHY", "code": "CC6.1",
              "name": "Access", "updatedAt": "2026-06-15T00:00:00Z", "frameworkTags": {}}],
              "meta": {"nextCursor": None}}

    class FV(GRCPlatformConnector):
        def _authed_get(self, path, cursor=None): return v_pass

    class FD(GRCPlatformConnector):
        def _authed_get(self, path, cursor=None): return d_fail

    with patch("app.grc_platforms.service.get_grc_connector",
               side_effect=lambda p: FV(VANTA) if p.upper() == "VANTA" else FD(DRATA)):
        client.post("/v1/grc-sync/VANTA")
        client.post("/v1/grc-sync/DRATA")
    ms = client.get("/v1/grc-sync/multi-source").json()
    ac2 = [a for a in ms["attestations"] if a["control_id"] == "AC-2"]
    assert ac2 and ac2[0]["agreement"] == "conflict"


def test_platforms_endpoint(client):
    pl = client.get("/v1/grc-sync/platforms").json()
    assert set(pl["platforms"].keys()) == {"VANTA", "DRATA", "ONETRUST"}
