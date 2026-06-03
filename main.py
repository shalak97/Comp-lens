"""FastAPI application entry point.

Run locally:
    uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import Principal, auth_enabled, authorize_tenant, require_principal
from app.config import settings
from app.connectors.base import ConnectorError
from app.connectors.registry import registry
from app.database import get_db, init_db
from app.frameworks import crosswalk_for, frameworks
from app.models import (AISystemRequest, AssessmentRequest, AssetRecord, BatchAssessmentRequest,
                        BulkAssessRequest, FindingOut, FindingUpdate, PolicyDraftRequest,
                        ScheduleOut, ScheduleRequest, WaiverOut, WaiverRequest)
from app.policy.engine import CONTROL_CATALOG
from app.services.assessment import AssessmentService
from app.services.inventory import InventoryService
from app.services.reporting import ReportService
from app.services.scheduler import ScheduleService, start_background_runner, stop_background_runner
from app.services.trends import TrendService
from app.services.waivers import WaiverService

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO),
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("comp-lens")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.autocreate_enabled():
        init_db()
        logger.info("tables auto-created (dev). Use Alembic in production.")
    start_background_runner()
    logger.info("Comp-Lens started env=%s scheduler=%s", settings.app_env, settings.enable_scheduler)
    yield
    stop_background_runner()


app = FastAPI(title=settings.app_name, version="1.2.0", lifespan=lifespan)

_wildcard = "*" in settings.cors_origins
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins,
                   allow_credentials=not _wildcard, allow_methods=["GET", "POST", "PATCH", "DELETE"],
                   allow_headers=["Content-Type", "X-API-Key"])


def _client_error(exc: ConnectorError) -> HTTPException:
    logger.warning("connector error: %s", exc)
    return HTTPException(status_code=400, detail="Connector could not collect telemetry "
                        "(check credentials, asset id, and that the control is supported).")


def _server_error() -> HTTPException:
    return HTTPException(status_code=500, detail="Internal error. See server logs.")


# ── meta (public) ──
@app.get("/")
def root() -> dict:
    return {"service": settings.app_name, "status": "ok", "version": "1.2.0", "docs": "/docs",
            "connectors": registry.supported(), "controls": list(CONTROL_CATALOG.keys()),
            "frameworks": frameworks(), "auth_required": auth_enabled()}


@app.get("/health/live")
def live() -> dict: return {"status": "alive"}


@app.get("/health/ready")
def ready() -> dict: return {"ready": True, "env": settings.app_env}


@app.get("/controls")
def list_controls() -> list[dict]:
    return [{"control_id": cid, "title": m["title"], "domain": m["domain"],
             "severity": m["severity"].value, "frameworks": crosswalk_for(cid)}
            for cid, m in CONTROL_CATALOG.items()]


@app.get("/frameworks")
def list_frameworks() -> dict:
    return {"frameworks": frameworks()}


@app.get("/crosswalk")
def crosswalk(control_id: str) -> dict:
    return {"control_id": control_id, "mappings": crosswalk_for(control_id)}


@app.get("/connectors")
def list_connectors(_: Principal = Depends(require_principal)) -> list[dict]:
    return [{"source_system": n, "healthy": registry.healthcheck(n)} for n in registry.supported()]


@app.get("/legacy/sources")
def legacy_sources(_: Principal = Depends(require_principal)) -> list[dict]:
    # names + types only; connection strings/credentials are never exposed
    from app.legacy.sources import list_sources
    return list_sources()


# ── assessments ──
@app.post("/assessments", response_model=FindingOut)
def create_assessment(req: AssessmentRequest, db: Session = Depends(get_db),
                      p: Principal = Depends(require_principal)) -> FindingOut:
    authorize_tenant(p, req.tenant_id)
    try:
        return FindingOut.model_validate(AssessmentService(db).run_single(req))
    except ConnectorError as exc:
        raise _client_error(exc) from exc
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001
        logger.exception("assessment failed"); raise _server_error()


@app.post("/assessment-jobs")
def create_batch(req: BatchAssessmentRequest, db: Session = Depends(get_db),
                 p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    try:
        return AssessmentService(db).run_batch(req.tenant_id, req.controls)
    except Exception:  # noqa: BLE001
        logger.exception("batch failed"); raise _server_error()


@app.post("/assessments/bulk")
def bulk_assess(req: BulkAssessRequest, db: Session = Depends(get_db),
                p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    try:
        return InventoryService(db).bulk_assess(req.tenant_id, req.framework, req.control_id,
                                                req.source_system, req.params)
    except ConnectorError as exc:
        raise _client_error(exc) from exc
    except Exception:  # noqa: BLE001
        logger.exception("bulk failed"); raise _server_error()


# ── findings + lifecycle ──
@app.get("/findings", response_model=list[FindingOut])
def list_findings(tenant_id: str = "default", control_id: str | None = None,
                  limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                  db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> list[FindingOut]:
    authorize_tenant(p, tenant_id)
    return [FindingOut.model_validate(f) for f in AssessmentService(db).list_findings(tenant_id, control_id, limit, offset)]


@app.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: str, upd: FindingUpdate, tenant_id: str = "default",
                   db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> FindingOut:
    authorize_tenant(p, tenant_id)
    f = AssessmentService(db).update_finding(tenant_id, finding_id, upd)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return FindingOut.model_validate(f)


@app.get("/summary")
def summary(tenant_id: str = "default", framework: str | None = None,
            db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return AssessmentService(db).compliance_summary(tenant_id, framework)


# ── waivers / exceptions ──
@app.post("/waivers", response_model=WaiverOut)
def create_waiver(req: WaiverRequest, db: Session = Depends(get_db),
                  p: Principal = Depends(require_principal)) -> WaiverOut:
    authorize_tenant(p, req.tenant_id)
    return WaiverOut.model_validate(WaiverService(db).create(req))


@app.get("/waivers", response_model=list[WaiverOut])
def list_waivers(tenant_id: str = "default", db: Session = Depends(get_db),
                 p: Principal = Depends(require_principal)) -> list[WaiverOut]:
    authorize_tenant(p, tenant_id)
    return [WaiverOut.model_validate(w) for w in WaiverService(db).list(tenant_id)]


@app.delete("/waivers/{waiver_id}")
def revoke_waiver(waiver_id: str, tenant_id: str = "default", db: Session = Depends(get_db),
                  p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    ok = WaiverService(db).revoke(tenant_id, waiver_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Waiver not found.")
    return {"revoked": waiver_id}


# ── inventory / discovery ──
@app.post("/inventory/discover")
def discover(source_system: str, tenant_id: str = "default", db: Session = Depends(get_db),
             p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    try:
        n = InventoryService(db).discover(tenant_id, source_system, {})
        return {"discovered_new": n}
    except ConnectorError as exc:
        raise _client_error(exc) from exc


@app.get("/inventory")
def inventory(tenant_id: str = "default", source_system: str | None = None,
              db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    return [{"asset_id": a.asset_id, "asset_type": a.asset_type, "source_system": a.source_system,
             "owner": a.owner, "criticality": a.criticality} for a in InventoryService(db).list(tenant_id, source_system)]


# ── schedules ──
@app.post("/schedules", response_model=ScheduleOut)
def create_schedule(req: ScheduleRequest, db: Session = Depends(get_db),
                    p: Principal = Depends(require_principal)) -> ScheduleOut:
    authorize_tenant(p, req.tenant_id)
    return ScheduleOut.model_validate(ScheduleService(db).create(req))


@app.get("/schedules", response_model=list[ScheduleOut])
def list_schedules(tenant_id: str = "default", db: Session = Depends(get_db),
                   p: Principal = Depends(require_principal)) -> list[ScheduleOut]:
    authorize_tenant(p, tenant_id)
    return [ScheduleOut.model_validate(s) for s in ScheduleService(db).list(tenant_id)]


@app.post("/schedules/{schedule_id}/run")
def run_schedule(schedule_id: str, tenant_id: str = "default", db: Session = Depends(get_db),
                 p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    try:
        return ScheduleService(db).run(schedule_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Schedule not found.")


@app.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: str, tenant_id: str = "default", db: Session = Depends(get_db),
                    p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    if not ScheduleService(db).delete(tenant_id, schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found.")
    return {"deleted": schedule_id}


# ── trends / drift ──
@app.get("/trends")
def trends(tenant_id: str = "default", db: Session = Depends(get_db),
           p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    return TrendService(db).trends(tenant_id)


@app.post("/trends/snapshot")
def snapshot(tenant_id: str = "default", framework: str | None = None,
             db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    summary = AssessmentService(db).compliance_summary(tenant_id, framework)
    snap = TrendService(db).snapshot(tenant_id, summary, framework or "ALL")
    return {"captured_at": snap.captured_at.isoformat(), "score": snap.score}


@app.get("/drift")
def drift(tenant_id: str = "default", db: Session = Depends(get_db),
          p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return TrendService(db).drift(tenant_id)


@app.get("/remediation")
def remediation(tenant_id: str = "default", top: int = Query(10, ge=1, le=100),
                db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services.remediation import RemediationService
    return RemediationService(db).priorities(tenant_id, top)


@app.get("/evidence/verify")
def evidence_verify(tenant_id: str = "default", db: Session = Depends(get_db),
                    p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services.integrity import IntegrityService
    return IntegrityService(db).verify(tenant_id)


# ── AI governance: register & assess the org's own AI systems ──
@app.post("/ai-systems")
def register_ai_system(req: AISystemRequest, db: Session = Depends(get_db),
                       p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    from app.models import AISystem
    s = AISystem(tenant_id=req.tenant_id, name=req.name, owner=req.owner, risk_tier=req.risk_tier,
                 impact_assessment=req.impact_assessment, data_governance=req.data_governance,
                 human_oversight=req.human_oversight, transparency_notice=req.transparency_notice,
                 eval_report=req.eval_report, logging_enabled=req.logging_enabled,
                 accuracy_tested=req.accuracy_tested)
    db.add(s); db.flush()
    return {"id": s.id, "name": s.name, "risk_tier": s.risk_tier}


@app.get("/ai-systems")
def list_ai_systems(tenant_id: str = "default", db: Session = Depends(get_db),
                    p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    from app.models import AISystem
    rows = db.execute(select(AISystem).where(AISystem.tenant_id == tenant_id)).scalars().all()
    return [{"id": s.id, "name": s.name, "owner": s.owner, "risk_tier": s.risk_tier} for s in rows]


# ── Merkle transparency log ──
@app.post("/evidence/anchor")
def evidence_anchor(tenant_id: str = "default", db: Session = Depends(get_db),
                    p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services.merkle import MerkleService
    return MerkleService(db).anchor(tenant_id)


@app.get("/evidence/anchors")
def evidence_anchors(tenant_id: str = "default", db: Session = Depends(get_db),
                     p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    from app.services.merkle import MerkleService
    return MerkleService(db).anchors(tenant_id)


@app.get("/evidence/proof")
def evidence_proof(evidence_id: str, tenant_id: str = "default", db: Session = Depends(get_db),
                   p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services.merkle import MerkleService
    return MerkleService(db).proof(tenant_id, evidence_id)


# ── NL -> policy authoring (human-in-the-loop) ──
@app.post("/policy/draft")
def policy_draft(req: PolicyDraftRequest, db: Session = Depends(get_db),
                 p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    from app.services.policy_authoring import PolicyAuthoringService
    d = PolicyAuthoringService(db).draft(req)
    return {"id": d.id, "control_id": d.control_id, "telemetry_field": d.telemetry_field,
            "confidence": d.confidence, "status": d.status, "rego": d.rego}


@app.get("/policy/drafts")
def policy_drafts(tenant_id: str = "default", db: Session = Depends(get_db),
                  p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    from app.services.policy_authoring import PolicyAuthoringService
    return [{"id": d.id, "control_id": d.control_id, "confidence": d.confidence,
             "status": d.status, "description": d.description}
            for d in PolicyAuthoringService(db).list(tenant_id)]


@app.post("/policy/{draft_id}/approve")
def policy_approve(draft_id: str, approve: bool = True, tenant_id: str = "default",
                   db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services.policy_authoring import PolicyAuthoringService
    d = PolicyAuthoringService(db).decide(tenant_id, draft_id, approve)
    if not d:
        raise HTTPException(status_code=404, detail="Draft not found.")
    return {"id": d.id, "status": d.status}


# ── predictive drift forecast ──
@app.get("/forecast")
def forecast(tenant_id: str = "default", horizon_days: int = Query(30, ge=1, le=365),
             threshold: float = Query(80.0, ge=0, le=100),
             db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services.forecast import ForecastService
    return ForecastService(db).forecast(tenant_id, horizon_days, threshold)


# ── reports ──
@app.get("/reports/csv")
def report_csv(tenant_id: str = "default", db: Session = Depends(get_db),
               p: Principal = Depends(require_principal)) -> Response:
    authorize_tenant(p, tenant_id)
    data = ReportService(db).csv_bytes(tenant_id)
    return Response(content=data, media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="compliance_{tenant_id}.csv"'})


@app.get("/reports/pdf")
def report_pdf(tenant_id: str = "default", db: Session = Depends(get_db),
               p: Principal = Depends(require_principal)) -> Response:
    authorize_tenant(p, tenant_id)
    data = ReportService(db).pdf_bytes(tenant_id)
    return Response(content=data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="compliance_{tenant_id}.pdf"'})


@app.get("/reports/oscal")
def report_oscal(tenant_id: str = "default", db: Session = Depends(get_db),
                 p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return ReportService(db).oscal_results(tenant_id)


# ── ingestion from external scanners ──
@app.post("/ingest/securityhub")
def ingest_securityhub(tenant_id: str = "default", max_findings: int = Query(100, ge=1, le=500),
                       db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services.ingestion import IngestionService
    try:
        return IngestionService(db).from_security_hub(tenant_id, max_findings)
    except Exception:  # noqa: BLE001
        logger.exception("security hub ingest failed")
        raise _server_error()


@app.post("/ingest/report")
def ingest_report(payload: dict, tenant_id: str = "default", source: str = "PROWLER",
                  db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    """Ingest a Prowler / Steampipe / Powerpipe JSON report.

    Body: {"findings": [ {control_id|check_id, status|result, asset_id|resource, severity, ...}, ... ]}
    """
    authorize_tenant(p, tenant_id)
    from app.services.ingestion import IngestionService
    findings = payload.get("findings", payload if isinstance(payload, list) else [])
    return IngestionService(db).from_report(tenant_id, source, findings)
