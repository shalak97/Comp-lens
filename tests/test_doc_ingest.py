"""Document → markdown → controls → telemetry events pipeline."""
import base64
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_doc.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")

DOC = """INFORMATION SECURITY POLICY
4.1 Access Control
All user accounts must be protected with multi-factor authentication (MFA).
4.2 Encryption
All data at rest is encrypted using AES-256. Data in transit uses TLS 1.2 or higher.
4.3 Vulnerability Management
The organization performs vulnerability scanning monthly."""


@pytest.fixture()
def client():
    import app.main as M
    with TestClient(M.app) as c:
        yield c


def test_to_markdown_normalizes():
    from app.services.doc_ingest import to_markdown
    md = to_markdown("INFORMATION SECURITY POLICY\n4.1 Access Control\n- item one")
    assert "##" in md or "###" in md
    assert md.strip()


def test_extract_finds_controls(client):
    r = client.post("/v1/documents/extract", json={"text": DOC}).json()
    assert r["controls_found"] > 0
    cids = [c["control_id"] for c in r["controls"]]
    assert any("IA-2" in c for c in cids)         # MFA
    assert any(c.startswith("SC-") for c in cids)  # encryption


def test_extract_keeps_quotes(client):
    r = client.post("/v1/documents/extract", json={"text": DOC}).json()
    assert all(c.get("quote") for c in r["controls"])


def test_events_are_canonical(client):
    r = client.post("/v1/documents/extract", json={"text": DOC}).json()
    ev = r["events"][0]
    assert ev["control_id"]
    assert ev["status"] == "pass"
    assert ev["evidence"]["from_document"] is True


def test_ingest_persists_or_notes(client):
    r = client.post("/v1/documents/ingest", json={"text": DOC}).json()
    assert r["persisted"] is not None


def test_base64_upload(client):
    b64 = base64.b64encode(DOC.encode()).decode()
    r = client.post("/v1/documents/upload",
                    json={"filename": "p.txt", "content_base64": b64}).json()
    assert r["controls_found"] > 0


def test_empty_text_rejected(client):
    assert client.post("/v1/documents/extract", json={}).status_code == 400


def test_bad_base64_rejected(client):
    r = client.post("/v1/documents/upload", json={"content_base64": "!!!notbase64!!!"})
    assert r.status_code in (400, 422)
