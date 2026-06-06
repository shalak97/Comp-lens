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


# ── static dashboard console ──
import os as _os
from fastapi.responses import FileResponse as _FileResponse
from fastapi.staticfiles import StaticFiles as _StaticFiles

_STATIC_DIR = _os.path.join(_os.path.dirname(__file__), "static")
if _os.path.isdir(_STATIC_DIR):
    app.mount("/static", _StaticFiles(directory=_STATIC_DIR), name="static")

    @app.get("/dashboard", include_in_schema=False)
    def _serve_dashboard():
        return _FileResponse(_os.path.join(_STATIC_DIR, "dashboard.html"))


# ── framework catalog + attestation (full coverage) ──
from pydantic import BaseModel as _BaseModel
from app.services import framework_catalog as _catalog
from app.services.attestation import AttestationService as _AttestationService


class _AttestationRequest(_BaseModel):
    tenant_id: str = "default"
    framework: str
    control_id: str
    status: str
    owner: str | None = None
    approver: str | None = None
    note: str | None = None
    evidence_ref: str | None = None


@app.get("/catalog/frameworks", tags=["catalog"])
def catalog_frameworks(_: Principal = Depends(require_principal)) -> list[dict]:
    return _catalog.frameworks()


@app.get("/catalog/families", tags=["catalog"])
def catalog_families(framework: str, _: Principal = Depends(require_principal)) -> list[dict]:
    return _catalog.families(framework)


@app.get("/catalog", tags=["catalog"])
def catalog_controls(framework: str, family: str | None = None,
                     _: Principal = Depends(require_principal)) -> list[dict]:
    return _catalog.controls(framework, family)


@app.post("/attestations", tags=["catalog"])
def upsert_attestation(req: _AttestationRequest, db: Session = Depends(get_db),
                       p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    try:
        row = _AttestationService(db).upsert(req.tenant_id, req.framework, req.control_id,
                                             req.status, req.owner, req.approver, req.note, req.evidence_ref)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"id": row.id, "tenant_id": row.tenant_id, "framework": row.framework,
            "control_id": row.control_id, "status": row.status.value, "owner": row.owner,
            "approver": row.approver, "note": row.note, "evidence_ref": row.evidence_ref,
            "updated_at": row.updated_at.isoformat()}


@app.get("/attestations", tags=["catalog"])
def list_attestations(tenant_id: str = "default", framework: str | None = None,
                      db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    return [{"control_id": a.control_id, "framework": a.framework, "status": a.status.value,
             "owner": a.owner, "approver": a.approver, "note": a.note,
             "evidence_ref": a.evidence_ref, "updated_at": a.updated_at.isoformat()}
            for a in _AttestationService(db).list(tenant_id, framework)]


@app.get("/coverage", tags=["catalog"])
def framework_coverage(framework: str, tenant_id: str = "default",
                       db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return _AttestationService(db).coverage(tenant_id, framework)


# ── evidence graph (LLM-grounded document → concept → control mindmap) ──
from app.services.evidence_graph import EvidenceService as _EvidenceService
from app.services import evidence_graph as _evg
from app.services import llm_client as _llm


class _DocumentRequest(_BaseModel):
    tenant_id: str = "default"
    name: str | None = None
    content: str | None = None
    url: str | None = None
    source_type: str = "text"


class _ConfirmRequest(_BaseModel):
    confirmed: bool = True
    auto_attest: bool = False
    approver: str | None = None


@app.get("/evidence/lexicon", tags=["evidence-graph"])
def evidence_lexicon(_: Principal = Depends(require_principal)) -> dict:
    lex = _evg.lexicon()
    return {"concepts": len(lex), "llm_available": _llm.available(),
            "items": [{"id": c["id"], "label": c["label"], "controls": len(c["controls"])} for c in lex]}


@app.get("/evidence/compliance", tags=["evidence-graph"])
def evidence_compliance(control_id: str, framework: str = "NIST_800_53",
                        tenant_id: str = "default", db: Session = Depends(get_db),
                        p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services import evidence_policy
    return evidence_policy.evaluate(db, tenant_id, framework, control_id)


@app.get("/evidence/documents/{doc_id}/verify", tags=["evidence-graph"])
def verify_evidence_document(doc_id: str, tenant_id: str = "default",
                            db: Session = Depends(get_db),
                            p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.models import EvidenceDocument
    from app.services.evidence_sign import verify
    doc = db.get(EvidenceDocument, doc_id)
    if not doc or doc.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="document not found")
    ok = verify(doc.content_hash, doc.tenant_id, doc.doc_id, doc.signed_at, doc.signature or "")
    return {"doc_id": doc_id, "signed": bool(doc.signature),
            "verified": ok, "signed_at": doc.signed_at,
            "detail": "Signature valid — content unchanged since ingestion." if ok
                      else ("No signature on record." if not doc.signature
                            else "SIGNATURE MISMATCH — document may have been altered.")}


@app.get("/evidence/crosswalk", tags=["evidence-graph"])
def control_crosswalk(control_id: str, framework: str = "NIST_800_53",
                      p: Principal = Depends(require_principal)) -> dict:
    from app.services.crosswalk import mapped_controls
    return {"control_id": control_id, "framework": framework,
            "mapped": mapped_controls(control_id, framework)}


@app.get("/evidence/export/oscal", tags=["evidence-graph"])
def export_oscal(framework: str = "NIST_800_53", tenant_id: str = "default",
                 db: Session = Depends(get_db),
                 p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services.oscal_export import export_assessment_results
    return export_assessment_results(db, tenant_id, framework)


@app.post("/evidence/documents", tags=["evidence-graph"])
def add_evidence_document(req: _DocumentRequest, db: Session = Depends(get_db),
                          p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    content, name, stype = req.content, req.name, req.source_type
    if req.url:
        from app.services.doc_fetch import fetch_url_text, FetchError
        try:
            content, stype = fetch_url_text(req.url.strip())
        except FetchError as e:
            raise HTTPException(status_code=400, detail=f"URL fetch failed: {e}")
        name = name or req.url.strip()[:120]
    if not content or not content.strip():
        raise HTTPException(status_code=400, detail="No content (provide 'content' or a fetchable 'url').")
    return _EvidenceService(db).add_document(req.tenant_id, name or "document", content, stype)


@app.get("/evidence/documents", tags=["evidence-graph"])
def list_evidence_documents(tenant_id: str = "default", db: Session = Depends(get_db),
                            p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    return _EvidenceService(db).list_documents(tenant_id)


@app.get("/evidence/graph", tags=["evidence-graph"])
def evidence_graph(tenant_id: str = "default", framework: str | None = None,
                   db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return _EvidenceService(db).graph(tenant_id, framework)


@app.post("/evidence/hits/{hit_id}/confirm", tags=["evidence-graph"])
def confirm_evidence_hit(hit_id: str, req: _ConfirmRequest, db: Session = Depends(get_db),
                         p: Principal = Depends(require_principal)) -> dict:
    try:
        return _EvidenceService(db).confirm_hit(hit_id, req.confirmed, req.auto_attest, req.approver)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/evidence/documents/{doc_id}", tags=["evidence-graph"])
def delete_evidence_document(doc_id: str, db: Session = Depends(get_db),
                             p: Principal = Depends(require_principal)) -> dict:
    _EvidenceService(db).delete_document(doc_id)
    return {"deleted": doc_id}


# ── ontology-driven resolver (telemetry / document / attestation routing) ──
from app.services import resolver as _resolver


class _ResolveRequest(_BaseModel):
    tenant_id: str = "default"
    framework: str = "NIST_800_53"
    control_id: str
    asset: dict | None = None
    available_connectors: list[str] = []
    dry_run: bool = False


@app.get("/ontology/planes", tags=["ontology"])
def ontology_planes(_: Principal = Depends(require_principal)) -> dict:
    return _resolver.ontology()


@app.get("/ontology/bindings", tags=["ontology"])
def ontology_bindings(control_id: str, framework: str = "NIST_800_53",
                      _: Principal = Depends(require_principal)) -> dict:
    b = _resolver.control_binding(framework, control_id)
    if not b:
        raise HTTPException(status_code=404, detail=f"No binding for {control_id} in {framework}")
    return {"framework": framework, "control_id": control_id, **b}


@app.post("/resolve", tags=["ontology"])
def resolve_control(req: _ResolveRequest, db: Session = Depends(get_db),
                    p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    try:
        return _resolver.resolve(db, req.tenant_id, req.framework, req.control_id,
                                 req.asset, req.available_connectors, req.dry_run)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/resolve/decisions", tags=["ontology"])
def list_routing_decisions(tenant_id: str = "default", control_id: str | None = None,
                           db: Session = Depends(get_db),
                           p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    return [{"decision_id": d.id, "control_id": d.control_id, "framework": d.framework,
             "asset_type": d.asset_type, "plane": d.plane, "strategy_type": d.strategy_type,
             "module": d.module, "status": d.status, "reason": d.reason,
             "executed": d.executed, "skipped": d.skipped, "finding_id": d.finding_id,
             "created_at": d.created_at.isoformat()}
            for d in _resolver.list_decisions(db, tenant_id, control_id)]


# ── evidence mindmap ──
import os as _os_evm
from fastapi.responses import FileResponse as _FileResponse_evm

_EVMAP_FILE = _os_evm.path.join(_os_evm.path.dirname(__file__), "static", "evidence-map.html")


@app.get("/evidence-map", include_in_schema=False)
def _serve_evidence_map():
    return _FileResponse_evm(_EVMAP_FILE, headers={"Cache-Control":"no-cache,no-store,must-revalidate","Pragma":"no-cache","Expires":"0"})
