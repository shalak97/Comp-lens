"""
Comp-Lens Enforcement Control Plane (reference)
================================================
The SaaS half of the hybrid architecture. It does NOT sit in the request path.
It (1) serves the signed policy *bundle* to OPA, (2) receives OPA *decision logs*
and turns them into evidence, and (3) exposes read APIs the dashboard renders.

Endpoints
  GET  /enforcement/bundles/complens.tar.gz   bundle pulled by every PDP (OPA)
  POST /enforcement/logs                       OPA decision-log sink (gzip JSON)
  GET  /enforcement/status                     fleet + counters for the dashboard
  GET  /enforcement/systems                    per-system config + live counters
  GET  /enforcement/decisions?limit=           recent decision stream
  POST /enforcement/systems/{host}/mode        flip shadow<->enforce (pushes bundle)
  GET  /healthz

This is intentionally standalone so it runs in isolation; the same routes can be
mounted into the existing Comp-Lens FastAPI app under the same /enforcement prefix.
Storage is in-memory (a ring buffer) for the reference — swap for the Comp-Lens
evidence ledger in production. No auth here: in production require mTLS or a
bearer token from each PDP (see README).
"""
from __future__ import annotations

import contextlib
import gzip
import hashlib
import io
import json
import tarfile
import time
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

# The ingestion core (in-memory store + decision-log parser) lives in
# app.services.enforcement so the platform's trust telemetry reads the same
# live counters this control plane populates — one source of truth.
from app.services.enforcement import (
    BOOT,
    DECISIONS,
    PEPS,
    POLICY_DIR,
    SYS_COUNTERS,
    _ingest_entry,
    _systems_config,
)

app = FastAPI(title="Comp-Lens Enforcement Control Plane")


# ----------------------------------------------------------------------------
# Bundle: the single source of truth shipped to every PDP.
# revision = short sha256 of the policy + data, so each decision log entry is
# cryptographically linked to the exact policy that produced it.
# ----------------------------------------------------------------------------
def _policy_bytes() -> tuple[bytes, bytes]:
    rego = (POLICY_DIR / "main.rego").read_bytes()
    data = (POLICY_DIR / "data.json").read_bytes()
    return rego, data


def bundle_revision() -> str:
    rego, data = _policy_bytes()
    return hashlib.sha256(rego + b"\x00" + data).hexdigest()[:12]


def build_bundle() -> tuple[bytes, str]:
    rego, data = _policy_bytes()
    rev = bundle_revision()
    manifest = json.dumps({"revision": rev, "roots": [""]}).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, payload in [(".manifest", manifest), ("main.rego", rego), ("data.json", data)]:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(payload))
    return buf.getvalue(), rev


@app.get("/enforcement/bundles/complens.tar.gz")
def get_bundle():
    body, rev = build_bundle()
    return Response(content=body, media_type="application/gzip",
                    headers={"ETag": rev, "X-Bundle-Revision": rev})


# ----------------------------------------------------------------------------
# Decision-log sink: OPA POSTs gzipped JSON arrays here. Each entry becomes a
# decision record (evidence) via app.services.enforcement._ingest_entry.
# ----------------------------------------------------------------------------
@app.post("/enforcement/logs")
async def decision_logs(request: Request):
    raw = await request.body()
    if request.headers.get("content-encoding", "").lower() == "gzip" or raw[:2] == b"\x1f\x8b":
        with contextlib.suppress(OSError):
            raw = gzip.decompress(raw)
    try:
        payload = json.loads(raw or b"[]")
    except json.JSONDecodeError as e:
        raise HTTPException(400, "invalid decision log payload") from e
    entries = payload if isinstance(payload, list) else [payload]
    ingested = sum(1 for e in entries if _ingest_entry(e) is not None)
    return {"received": len(entries), "ingested": ingested}


# ----------------------------------------------------------------------------
# Dashboard read APIs
# ----------------------------------------------------------------------------
@app.get("/enforcement/status")
def status():
    cfg = _systems_config()
    fail_open = [h for h, c in cfg.items() if c.get("fail") == "open"]
    enforcing = [h for h, c in cfg.items() if c.get("mode") == "enforce"]
    totals = {"allow": 0, "denied": 0, "would_block": 0, "requests": 0}
    for c in SYS_COUNTERS.values():
        for k in totals:
            totals[k] += c.get(k, 0)
    live_cut = time.time() - 120
    peps = []
    for _n, p in PEPS.items():
        last = p.get("last_seen")
        online = bool(last and datetime.fromisoformat(last).timestamp() > live_cut)
        peps.append({**p, "online": online})
    return {
        "control_plane": "ok",
        "uptime_s": int(time.time() - BOOT),
        "bundle_revision": bundle_revision(),
        "pdp_nodes": len(PEPS),
        "peps_online": sum(1 for p in peps if p["online"]),
        "systems_protected": len(cfg),
        "systems_enforcing": len(enforcing),
        "systems_shadow": len(cfg) - len(enforcing),
        "systems_fail_open": fail_open,
        "totals": totals,
        "peps": peps,
    }


@app.get("/enforcement/systems")
def systems():
    cfg = _systems_config()
    out = []
    for host, c in cfg.items():
        ctr = SYS_COUNTERS.get(host, {})
        out.append({
            "system": host,
            "mode": c.get("mode", "shadow"),
            "fail": c.get("fail", "open"),
            "policy_id": c.get("policy_id", "unconfigured"),
            "allowed_roles": c.get("allowed_roles", []),
            "revision": bundle_revision(),
            "requests": ctr.get("requests", 0),
            "allow": ctr.get("allow", 0),
            "denied": ctr.get("denied", 0),
            "would_block": ctr.get("would_block", 0),
            "last_seen": ctr.get("last_seen"),
        })
    out.sort(key=lambda s: (s["mode"] != "enforce", -s["would_block"]))
    return out


@app.get("/enforcement/decisions")
def decisions(limit: int = 100):
    items = list(DECISIONS)[-limit:][::-1]
    return items


@app.post("/enforcement/systems/{host}/mode")
def set_mode(host: str, body: dict):
    mode = (body or {}).get("mode")
    if mode not in ("shadow", "enforce"):
        raise HTTPException(400, "mode must be 'shadow' or 'enforce'")
    path = POLICY_DIR / "data.json"
    doc = json.loads(path.read_text())
    if host not in doc.get("systems", {}):
        raise HTTPException(404, f"unknown system '{host}'")
    doc["systems"][host]["mode"] = mode
    path.write_text(json.dumps(doc, indent=2) + "\n")
    # bundle revision changes -> every PDP picks it up on its next poll
    return {"system": host, "mode": mode, "bundle_revision": bundle_revision()}


@app.get("/healthz")
def healthz():
    return {"ok": True, "revision": bundle_revision()}


@app.get("/")
def root():
    return JSONResponse({
        "service": "comp-lens enforcement control plane",
        "bundle": "/enforcement/bundles/complens.tar.gz",
        "decision_log_sink": "/enforcement/logs",
        "revision": bundle_revision(),
    })
