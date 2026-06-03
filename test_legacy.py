"""Tests for the legacy integration layer (SQL, file, mapping, security)."""
from __future__ import annotations
import csv, json, os, sqlite3, tempfile

# Build fixtures and point config at them BEFORE importing the app
_TMP = tempfile.mkdtemp(prefix="legacy_test_")
_HR = os.path.join(_TMP, "hr.db")
_CSV = os.path.join(_TMP, "hosts.csv")
_JSON = os.path.join(_TMP, "vulns.json")

con = sqlite3.connect(_HR)
con.execute("CREATE TABLE users(user_id TEXT, mfa TEXT, last_login TEXT)")
con.executemany("INSERT INTO users VALUES(?,?,?)",
                [("alice", "1", "2026-05-25T00:00:00Z"), ("bob", "0", "2024-01-01T00:00:00Z")])
con.commit(); con.close()

with open(_CSV, "w", newline="") as f:
    w = csv.writer(f); w.writerow(["host", "luks"]); w.writerow(["s1", "true"]); w.writerow(["s2", "false"])

with open(_JSON, "w") as f:
    json.dump([{"ip": "10.0.0.1", "crit": 0}, {"ip": "10.0.0.2", "crit": 4}], f)

_SOURCES = json.dumps([
    {"name": "hr", "type": "sql", "url": f"sqlite:///{_HR}",
     "query": "SELECT mfa, last_login FROM users WHERE user_id = :asset_id",
     "discovery_query": "SELECT user_id FROM users", "key_column": "user_id",
     "field_map": {"mfa_enforced": {"from": "mfa", "coerce": "bool", "truthy": ["1"]},
                   "days_since_last_login": {"from": "last_login", "coerce": "days_since"}}},
    {"name": "hosts", "type": "file", "url": f"file://{_CSV}", "format": "csv", "key_column": "host",
     "field_map": {"disk_encrypted": {"from": "luks", "coerce": "bool"}}},
    {"name": "vulns", "type": "file", "url": f"file://{_JSON}", "format": "json", "key_column": "ip",
     "field_map": {"critical_vulnerabilities": {"from": "crit", "coerce": "int"}}},
])
os.environ["LEGACY_SOURCES_JSON"] = _SOURCES
os.environ.setdefault("APP_ENV", "local")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP}/app.db")
os.environ.setdefault("EVIDENCE_LOCAL_PATH", f"{_TMP}/ev")

import pytest
from fastapi.testclient import TestClient
from app.database import init_db
from app.legacy.sources import reload_sources


@pytest.fixture(scope="module")
def client():
    reload_sources()
    init_db()
    from app.main import app
    with TestClient(app) as c:
        yield c


def test_legacy_listed_as_connector(client):
    assert "LEGACY" in client.get("/").json()["connectors"]
    srcs = client.get("/legacy/sources").json()
    assert {s["name"] for s in srcs} == {"hr", "hosts", "vulns"}
    # never expose connection strings
    assert all("url" not in s for s in srcs)


def test_legacy_sql_pass_and_fail(client):
    a = client.post("/assessments", json={"tenant_id": "lg", "control_id": "AC-2-7",
        "source_system": "LEGACY", "asset_id": "alice", "params": {"source": "hr"}}).json()
    assert a["status"] == "pass"
    b = client.post("/assessments", json={"tenant_id": "lg", "control_id": "AC-2-7",
        "source_system": "LEGACY", "asset_id": "bob", "params": {"source": "hr"}}).json()
    assert b["status"] == "fail"


def test_legacy_days_since_coercion(client):
    r = client.post("/assessments", json={"tenant_id": "lg", "control_id": "AC-2-3",
        "source_system": "LEGACY", "asset_id": "bob", "params": {"source": "hr"}}).json()
    assert r["status"] == "fail"  # 2024 login -> stale


def test_legacy_file_csv(client):
    p = client.post("/assessments", json={"tenant_id": "lg", "control_id": "SC-28-HOST",
        "source_system": "LEGACY", "asset_id": "s1", "params": {"source": "hosts"}}).json()
    assert p["status"] == "pass"
    f = client.post("/assessments", json={"tenant_id": "lg", "control_id": "SC-28-HOST",
        "source_system": "LEGACY", "asset_id": "s2", "params": {"source": "hosts"}}).json()
    assert f["status"] == "fail"


def test_legacy_file_json_int(client):
    ok = client.post("/assessments", json={"tenant_id": "lg", "control_id": "RA-5",
        "source_system": "LEGACY", "asset_id": "10.0.0.1", "params": {"source": "vulns"}}).json()
    assert ok["status"] == "pass"  # 0 crit
    bad = client.post("/assessments", json={"tenant_id": "lg", "control_id": "RA-5",
        "source_system": "LEGACY", "asset_id": "10.0.0.2", "params": {"source": "vulns"}}).json()
    assert bad["status"] == "fail"  # 4 crit


def test_legacy_unknown_source_rejected(client):
    r = client.post("/assessments", json={"tenant_id": "lg", "control_id": "AC-2-7",
        "source_system": "LEGACY", "asset_id": "x", "params": {"source": "nope"}})
    assert r.status_code == 400


def test_legacy_missing_source_param_rejected(client):
    r = client.post("/assessments", json={"tenant_id": "lg", "control_id": "AC-2-7",
        "source_system": "LEGACY", "asset_id": "x", "params": {}})
    assert r.status_code == 400


def test_legacy_client_cannot_inject_raw_query(client):
    # passing url/query in params must be ignored; only the named source counts
    r = client.post("/assessments", json={"tenant_id": "lg", "control_id": "AC-2-7",
        "source_system": "LEGACY", "asset_id": "alice",
        "params": {"source": "hr", "url": "sqlite:///evil", "query": "SELECT 1"}}).json()
    assert r["status"] == "pass"  # used the real source, ignored injected url/query


def test_legacy_missing_record_errors_cleanly(client):
    r = client.post("/assessments", json={"tenant_id": "lg", "control_id": "AC-2-7",
        "source_system": "LEGACY", "asset_id": "ghost", "params": {"source": "hr"}})
    assert r.status_code == 400  # no record -> ConnectorError -> 400, not 500


def test_legacy_mapping_unit():
    from app.legacy.mapping import normalize
    out = normalize({"flag": "Y", "n": "5"},
                    {"mfa_enforced": {"from": "flag", "coerce": "bool", "truthy": ["Y"]},
                     "count": {"from": "n", "coerce": "int"}})
    assert out["mfa_enforced"] is True and out["count"] == 5
