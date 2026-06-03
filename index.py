from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(
    title="Comp-Lens GRC Platform",
    version="2.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_HTML = (Path(__file__).parent / "public" / "index.html").read_text()

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Dashboard ──────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    return _HTML


# ── Health ─────────────────────────────────────────────────────────────────
@app.get("/api/health/live")
async def liveness():
    return {"status": "alive", "platform": "Vercel", "time": _now()}


# ── Root ───────────────────────────────────────────────────────────────────
@app.get("/api")
async def root():
    return {
        "service": "Comp-Lens GRC Platform",
        "version": "2.0.0",
        "endpoints": [
            "/api/health/live", "/api/controls", "/api/connectors",
            "/api/assessments", "/api/findings", "/api/summary", "/api/docs",
        ],
    }


# ── Controls ───────────────────────────────────────────────────────────────
@app.get("/api/controls")
async def controls(framework: Optional[str] = None):
    data = [
        {"control_id": "SC-7",   "title": "No public exposure",     "frameworks": ["NIST", "ISO27001", "SOC2"]},
        {"control_id": "SC-28",  "title": "Encryption at rest",     "frameworks": ["NIST", "ISO27001"]},
        {"control_id": "AC-2-7", "title": "Privileged account MFA", "frameworks": ["NIST", "SOC2"]},
    ]
    if framework:
        fw = framework.upper()
        data = [c for c in data if fw in [f.upper() for f in c["frameworks"]]]
    return data


# ── Connectors ─────────────────────────────────────────────────────────────
@app.get("/api/connectors")
async def connectors():
    return [
        {"id": "DEMO", "category": "testing",  "status": "healthy",              "maturity": "stable"},
        {"id": "AWS",  "category": "cloud",    "status": "requires_credentials", "maturity": "production-ready"},
        {"id": "OKTA", "category": "identity", "status": "requires_credentials", "maturity": "production-ready"},
    ]


# ── Assessments ────────────────────────────────────────────────────────────
class AssessmentRequest(BaseModel):
    tenant_id: str = "default"
    control_id: str = "SC-7"
    source_system: str = "DEMO"
    asset_id: Optional[str] = None
    fail: bool = False


@app.post("/api/assessments")
async def run_assessment(req: AssessmentRequest):
    passed = not (req.source_system == "DEMO" and req.fail)
    return {
        "assessment_id": f"a-{uuid.uuid4().hex[:8]}",
        "tenant_id": req.tenant_id,
        "control_id": req.control_id,
        "source_system": req.source_system,
        "asset_id": req.asset_id,
        "status": "completed",
        "result": "PASSED" if passed else "FAILED",
        "timestamp": _now(),
    }


# ── Findings ───────────────────────────────────────────────────────────────
@app.get("/api/findings")
async def findings(tenant_id: str = "default"):
    items = [
        {"id": "f-001", "control_id": "SC-7",  "status": "OPEN", "severity": "HIGH"},
        {"id": "f-002", "control_id": "AC-2-7","status": "OPEN", "severity": "CRITICAL"},
    ]
    return {
        "tenant_id": tenant_id,
        "findings": items,
        "summary": {"total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0},
    }


# ── Summary ────────────────────────────────────────────────────────────────
@app.get("/api/summary")
async def summary(tenant_id: str = "default", framework: Optional[str] = None):
    return {
        "tenant_id": tenant_id,
        "framework": framework or "ALL",
        "compliance_score": 87.5,
        "controls_passed": 47,
        "controls_failed": 6,
        "total_controls": 53,
        "last_assessment": _now(),
    }
