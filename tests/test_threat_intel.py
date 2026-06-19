"""External threat intelligence: KEV/EPSS/NVD feeds + honest control enrichment.

Feeds are network-blocked in CI, so these exercise the seed-fallback path and the
enrichment logic (which is what we actually need to verify — the bridge honesty)."""
import os
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_threat.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")


@pytest.fixture()
def client():
    import app.main as M
    with TestClient(M.app) as c:
        yield c


def test_threat_summary(client):
    s = client.get("/v1/threat/summary").json()
    assert s["total_known_exploited"] > 0
    assert s["ransomware_linked"] >= 0
    assert len(s["recent"]) > 0


def test_kev_catalog(client):
    k = client.get("/v1/threat/kev?limit=5").json()
    assert k["count"] > 0
    assert all(v.get("cve") for v in k["vulnerabilities"])


def test_kev_ransomware_filter(client):
    k = client.get("/v1/threat/kev?ransomware_only=true").json()
    assert all(v["ransomware"] for v in k["vulnerabilities"])


def test_kev_search(client):
    k = client.get("/v1/threat/kev?q=log4j").json()
    assert len(k["vulnerabilities"]) > 0


def test_enrich_vuln_controls_only(client):
    """The honest bridge: vuln-mgmt controls get enriched, unrelated ones do NOT."""
    e = client.post("/v1/threat/enrich",
                    json={"controls": ["RA-5", "SI-2", "AC-2", "SC-28"]}).json()
    assert "RA-5" in e["enrichment"]      # vulnerability scanning — genuine
    assert "SI-2" in e["enrichment"]      # flaw remediation — genuine
    assert "AC-2" not in e["enrichment"]  # account mgmt — no honest CVE bridge
    assert "SC-28" not in e["enrichment"] # encryption — no honest CVE bridge


def test_enrich_specific_cves(client):
    e = client.post("/v1/threat/enrich",
                    json={"controls": ["RA-5"],
                          "cve_map": {"RA-5": ["CVE-2021-44228", "CVE-2099-0000"]}}).json()
    ctx = e["enrichment"]["RA-5"]
    assert "CVE-2021-44228" in ctx.get("kev_exploited_cves", [])


def test_enrich_requires_controls(client):
    assert client.post("/v1/threat/enrich", json={}).status_code == 400


def test_simulate_carries_threat_intel(client):
    sim = client.post("/simulate",
                      json={"framework": "NIST",
                            "changes": [{"control_id": "RA-5", "state": "failed"}]}).json()
    assert "cascade" in sim
    assert "threat_intel" in sim  # RA-5 itself is a vuln control, so always enriched
