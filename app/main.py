"""FastAPI application entry point.

Run locally:
    uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import json as _json
import logging
import os as _os
import os as _os_evm
from contextlib import asynccontextmanager
from dataclasses import asdict as _asdict

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse as _FileResponse
from fastapi.responses import FileResponse as _FileResponse_evm
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles as _StaticFiles
from pydantic import BaseModel as _BaseModel
from pydantic import BaseModel as _PydBase
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai_governance_models import AISystemPET as _PET
from app.audit_models import AuditIn as _AuditIn
from app.audit_models import AuditPatch as _AuditPatch
from app.audit_models import ControlReviewPatch as _CtrlPatch
from app.audit_models import EvidenceRequestIn as _ReqIn
from app.audit_models import EvidenceRequestPatch as _ReqPatch
from app.auth import Principal, auth_enabled, authorize_tenant, require_principal
from app.config import settings
from app.connectors.base import ConnectorError
from app.connectors.registry import registry
from app.database import get_db, init_db
from app.frameworks import crosswalk_for, frameworks
from app.grc_platforms import service as _grc_svc
from app.grc_platforms.registry import GRC_PLATFORM_REGISTRY as _GRC_REG
from app.grc_platforms.trust_telemetry import GRCTrustTelemetry as _GRCTrust
from app.grc_platforms.trust_telemetry import resolve_policy as _resolve_trust_policy
from app.grc_tprm_models import RiskIn as _RiskIn
from app.grc_tprm_models import RiskPatch as _RiskPatch
from app.grc_tprm_models import VendorIn as _VendorIn
from app.grc_tprm_models import VendorPatch as _VendorPatch
from app.hardening import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    install_exception_handlers,
)
from app.models import (
    AISystemRequest,
    AssessmentRequest,
    BatchAssessmentRequest,
    BulkAssessRequest,
    FindingOut,
    FindingUpdate,
    PolicyDraftRequest,
    ScheduleOut,
    ScheduleRequest,
    WaiverOut,
    WaiverRequest,
)
from app.policy.engine import CONTROL_CATALOG
from app.policy_as_code import get_engine as _policy_engine
from app.policy_as_code import reload_engine as _reload_policies
from app.services import ai_governance as _aigov
from app.services import doc_ingest as _doc_ingest
from app.services import evidence_graph as _evg
from app.services import framework_catalog as _catalog
from app.services import integration as _integ
from app.services import llm_client as _llm
from app.services import resolver as _resolver
from app.services import threat_intel as _threat
from app.services.assessment import AssessmentService
from app.services.attestation import AttestationService as _AttestationService
from app.services.audit_service import AuditService as _AuditSvc
from app.services.evidence_graph import EvidenceService as _EvidenceService
from app.services.grc_tprm import RiskService as _RiskService
from app.services.grc_tprm import VendorService as _VendorService
from app.services.inventory import InventoryService
from app.services.reporting import ReportService
from app.services.scheduler import ScheduleService, start_background_runner, stop_background_runner
from app.services.trends import TrendService
from app.services.trust_graph import TrustGraphService as _TrustGraph
from app.services.waivers import WaiverService

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO),
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("comp-lens")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail closed in production: refuse to start if authentication is not
    # configured (empty COMP_LENS_API_KEYS would otherwise make every request an
    # all-tenant admin). Mirrors the demo/auto-create production guards.
    if settings.is_production and not auth_enabled():
        raise RuntimeError(
            "Refusing to start: APP_ENV=production but no API keys are configured. "
            "Set COMP_LENS_API_KEYS to enable authentication.")
    if settings.is_production and not settings.evidence_signing_key:
        raise RuntimeError(
            "Refusing to start: APP_ENV=production but EVIDENCE_SIGNING_KEY is not set. "
            "Evidence tamper-evidence would fall back to a world-known key.")
    if settings.autocreate_enabled():
        init_db()
        logger.info("tables auto-created (dev). Use Alembic in production.")
    start_background_runner()
    logger.info("Comp-Lens started env=%s scheduler=%s", settings.app_env, settings.enable_scheduler)
    yield
    stop_background_runner()


# Interactive docs / OpenAPI schema are disabled in production (unless explicitly
# exposed) so the full API surface isn't disclosed to anonymous callers.
_docs_on = (not settings.is_production) or getattr(settings, "expose_api_docs", False)
app = FastAPI(title=settings.app_name, version="1.2.0", lifespan=lifespan,
              docs_url="/docs" if _docs_on else None,
              redoc_url="/redoc" if _docs_on else None,
              openapi_url="/openapi.json" if _docs_on else None)

# ── production hardening stack (outermost first) ──

app.add_middleware(SecurityHeadersMiddleware, hsts=getattr(settings, "enable_hsts", True))
app.add_middleware(RateLimitMiddleware,
                   max_requests=(1_000_000 if getattr(settings, "app_env", "production") == "test"
                                 else getattr(settings, "rate_limit_per_minute", 120)),
                   window_seconds=60,
                   trusted_proxy_hops=getattr(settings, "trusted_proxy_hops", 0))
app.add_middleware(RequestContextMiddleware)
install_exception_handlers(app)

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
def ready() -> dict:
    checks = {}
    db_ok = True
    try:
        from sqlalchemy import text

        from app.database import SessionLocal
        with SessionLocal() as s:
            s.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001
        db_ok = False
        checks["database"] = f"unavailable: {type(exc).__name__}"
    return {"ready": db_ok, "status": "ready" if db_ok else "not_ready",
            "env": settings.app_env, "checks": checks}


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


# ── Connector framework v2 (marketplace) ──
@app.get("/connectors/catalog", tags=["connectors"])
def connectors_catalog(category: str | None = None,
                       _: Principal = Depends(require_principal)) -> list[dict]:
    from app.connectors import catalog as ccat
    items = ccat.by_category(category) if category else ccat.all_connectors()
    return [dict(c.items()) for c in items]


@app.get("/connectors/safety", tags=["connectors"])
def connectors_safety(_: Principal = Depends(require_principal)) -> dict:
    from app.connectors import safety as _sfty
    return _sfty.safety_state()


@app.get("/connectors/status", tags=["connectors"])
def connectors_status(tenant_id: str = "default", db: Session = Depends(get_db),
                      p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    from app.connectors import catalog as ccat
    from app.connectors import framework as cfw
    return [cfw.status_one(db, c, tenant_id) for c in ccat.all_connectors()]


# ── connector instances (labeled connections) ──
# NB: declared BEFORE /connectors/{name} so "/connectors/instances" isn't
# captured as name="instances".
class _InstanceCreate(_PydBase):
    tenant_id: str = "default"
    connector_key: str
    label: str = ""
    config: dict = {}


class _EphemeralReq(_PydBase):
    tenant_id: str = "default"
    connector_key: str
    config: dict = {}
    instance_id: str | None = None


@app.get("/connectors/instances", tags=["connectors"])
def list_connector_instances(tenant_id: str = "default", db: Session = Depends(get_db),
                             p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    from app.services import connector_instances as _ci
    return _ci.list_instances(db, tenant_id)


@app.post("/connectors/instances", tags=["connectors"])
def create_connector_instance(req: _InstanceCreate, db: Session = Depends(get_db),
                              p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    from app.services import connector_instances as _ci
    try:
        return _ci.create_instance(db, req.tenant_id, req.connector_key, req.label, req.config)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.post("/connectors/instances/ephemeral/sync", tags=["connectors"])
def ephemeral_sync_connector(req: _EphemeralReq, db: Session = Depends(get_db),
                             p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    from app.services import connector_instances as _ci
    try:
        return _ci.ephemeral_sync(db, req.tenant_id, req.connector_key, req.config)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.post("/connectors/instances/ephemeral/test", tags=["connectors"])
def ephemeral_test_connector(req: _EphemeralReq,
                             p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    from app.services import connector_instances as _ci
    try:
        return _ci.ephemeral_test(req.connector_key, req.config)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.post("/connectors/instances/{instance_id}/sync", tags=["connectors"])
def sync_connector_instance(instance_id: str, tenant_id: str = "default",
                            db: Session = Depends(get_db),
                            p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services import connector_instances as _ci
    try:
        return _ci.sync_instance(db, tenant_id, instance_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail="connector instance not found") from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.post("/connectors/instances/{instance_id}/test", tags=["connectors"])
def test_connector_instance(instance_id: str, tenant_id: str = "default",
                            db: Session = Depends(get_db),
                            p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services import connector_instances as _ci
    try:
        return _ci.test_instance(db, tenant_id, instance_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail="connector instance not found") from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.delete("/connectors/instances/{instance_id}", tags=["connectors"])
def delete_connector_instance(instance_id: str, tenant_id: str = "default",
                              db: Session = Depends(get_db),
                              p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services import connector_instances as _ci
    if not _ci.delete_instance(db, tenant_id, instance_id):
        raise HTTPException(status_code=404, detail="connector instance not found")
    return {"deleted": instance_id}


@app.get("/connectors/{name}", tags=["connectors"])
def connector_detail(name: str, tenant_id: str = "default", db: Session = Depends(get_db),
                     p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.connectors import catalog as ccat
    from app.connectors import framework as cfw
    c = ccat.get(name)
    if not c:
        raise HTTPException(404, f"unknown connector '{name}'")
    st = cfw.status_one(db, c, tenant_id)
    st["supported_controls"] = cfw.supported_controls(c)
    return st


@app.post("/connectors/{name}/test", tags=["connectors"])
def connector_test(name: str, p: Principal = Depends(require_principal)) -> dict:
    from app.connectors import catalog as ccat
    from app.connectors import framework as cfw
    c = ccat.get(name)
    if not c:
        raise HTTPException(404, f"unknown connector '{name}'")
    return cfw.test_connection(c)




class _SyncRequest(_PydBase):
    tenant_id: str = "default"
    force_demo: bool = False


@app.post("/connectors/{name}/sync", tags=["connectors"])
def connector_sync(name: str, req: _SyncRequest | None = None,
                   db: Session = Depends(get_db),
                   p: Principal = Depends(require_principal)) -> dict:
    req = req or _SyncRequest()
    authorize_tenant(p, req.tenant_id)
    from app.connectors import catalog as ccat
    from app.connectors import framework as cfw
    c = ccat.get(name)
    if not c:
        raise HTTPException(404, f"unknown connector '{name}'")
    return cfw.sync(db, c, req.tenant_id, req.force_demo)


@app.get("/connectors/{name}/evidence", tags=["connectors"])
def connector_evidence(name: str, tenant_id: str = "default",
                       db: Session = Depends(get_db),
                       p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    from app.connectors import framework as cfw
    return cfw.evidence_for(db, name, tenant_id)


@app.get("/evidence/by-connector/{name}", tags=["connectors"])
def evidence_by_connector(name: str, tenant_id: str = "default",
                          db: Session = Depends(get_db),
                          p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    from app.connectors import framework as cfw
    return cfw.evidence_for(db, name, tenant_id)


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
        logger.exception("assessment failed")
        raise _server_error() from None


@app.post("/assessment-jobs")
def create_batch(req: BatchAssessmentRequest, db: Session = Depends(get_db),
                 p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    try:
        return AssessmentService(db).run_batch(req.tenant_id, req.controls)
    except Exception:  # noqa: BLE001
        logger.exception("batch failed")
        raise _server_error() from None


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
        logger.exception("bulk failed")
        raise _server_error() from None


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
        return ScheduleService(db).run(tenant_id, schedule_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Schedule not found.") from None


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


@app.get("/evidence/{evidence_id}/verify", tags=["evidence-graph"])
def verify_evidence_record(evidence_id: str, tenant_id: str = "default",
                           db: Session = Depends(get_db),
                           p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services.integrity import IntegrityService
    res = IntegrityService(db).verify_one(tenant_id, evidence_id)
    if not res.get("found"):
        raise HTTPException(status_code=404, detail="evidence record not found")
    return res


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
    db.add(s)
    db.flush()
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


# ── dashboard-wired endpoints (policies list, evidence ledger, unified trust,
#    ai->risk, remediation tickets, enforcement control plane) ──
@app.get("/policies", tags=["policy-as-code"])
def list_policies(_: Principal = Depends(require_principal)) -> list[dict]:
    from app.policy_as_code import get_engine
    return get_engine().list_policies()


class _PolicyImport(_PydBase):
    tenant_id: str = "default"
    name: str = ""
    yaml: str | None = None


@app.post("/policies/import", tags=["policy-as-code"])
def import_policy(req: _PolicyImport, p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    # If policy YAML is supplied, validate it and reload the engine; otherwise the
    # import is acknowledged (the built-in catalog is file-managed, not persisted here).
    if req.yaml:
        from app.policy_as_code import reload_engine
        from app.policy_as_code.engine import load_policy, parse_policy_yaml
        try:
            # size-capped, alias-free parse: bounds body size and blocks the
            # billion-laughs anchor/alias expansion before it hits the evaluator
            doc = parse_policy_yaml(req.yaml)
            pol = load_policy(doc, source=req.name or "import")
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"invalid policy: {e}") from e
        reload_engine()
        return {"imported": True, "control_id": pol.control_id, "name": req.name}
    return {"imported": True, "name": req.name,
            "note": "acknowledged; supply 'yaml' to validate and load a policy"}


@app.get("/evidence", tags=["evidence-graph"])
def evidence_ledger(tenant_id: str = "default", limit: int = Query(200, ge=1, le=1000),
                    db: Session = Depends(get_db),
                    p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    from sqlalchemy import desc, select

    from app.models import EvidenceMeta
    rows = db.execute(select(EvidenceMeta).where(EvidenceMeta.tenant_id == tenant_id)
                      .order_by(desc(EvidenceMeta.created_at)).limit(limit)).scalars().all()
    return [{"id": r.evidence_id, "control": r.control_id, "framework": r.framework,
             "source": r.run_id, "hash": r.record_hash or r.telemetry_hash,
             "verified": bool(r.record_hash),
             "status": getattr(r.status, "value", r.status),
             "collected_at": r.created_at.isoformat() if r.created_at else None}
            for r in rows]


@app.post("/remediation/tickets", tags=["simulation"])
def create_remediation_ticket(req: dict, db: Session = Depends(get_db),
                              p: Principal = Depends(require_principal)) -> dict:
    tenant_id = (req or {}).get("tenant_id", "default")
    authorize_tenant(p, tenant_id)
    from app.policy_models import ObligationDispatch
    row = ObligationDispatch(
        tenant_id=tenant_id, control_id=(req or {}).get("control_id", ""),
        procedure="open_ticket", status="queued",
        severity=(req or {}).get("severity", "medium"),
        detail=(req or {}).get("detail", "") or "Remediation ticket",
        meta={"source": "dashboard"})
    db.add(row)
    db.commit()
    return {"id": row.id, "control_id": row.control_id, "status": row.status,
            "severity": row.severity, "detail": row.detail}


@app.get("/v1/grc-trust/unified", tags=["grc-trust-telemetry"])
def grc_trust_unified(tenant_id: str = "default", db: Session = Depends(get_db),
                      p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services.trust_telemetry import unified_trust
    return unified_trust(db, tenant_id)


@app.post("/v1/integrate/ai-systems/{system_id}/to-risk", tags=["integration"])
def integrate_ai_system_to_risk(system_id: str, req: dict | None = None,
                                db: Session = Depends(get_db),
                                p: Principal = Depends(require_principal)) -> dict:
    tenant_id = (req or {}).get("tenant_id", "default")
    authorize_tenant(p, tenant_id)
    from app.services import integration
    return integration.ai_system_to_risk(db, tenant_id, system_id)


# ── enforcement control plane (read views + mode toggle) ──
@app.get("/enforcement/status", tags=["enforcement"])
def enforcement_status(_: Principal = Depends(require_principal)) -> dict:
    from app.services import enforcement as _enf
    return _enf.status_snapshot()


@app.get("/enforcement/systems", tags=["enforcement"])
def enforcement_systems(_: Principal = Depends(require_principal)) -> list[dict]:
    from app.services import enforcement as _enf
    return _enf.systems_list()


@app.get("/enforcement/decisions", tags=["enforcement"])
def enforcement_decisions(limit: int = Query(100, ge=1, le=1000),
                          _: Principal = Depends(require_principal)) -> list[dict]:
    from app.services import enforcement as _enf
    return _enf.recent_decisions(limit)


@app.post("/enforcement/systems/{host}/mode", tags=["enforcement"])
def enforcement_set_mode(host: str, body: dict,
                         p: Principal = Depends(require_principal)) -> dict:
    # Flipping a system between shadow/enforce rewrites the shared policy bundle —
    # a fleet-wide privileged action, so require an admin (all-tenant) key.
    if not p.is_admin:
        raise HTTPException(status_code=403, detail="enforcement mode changes require an admin key")
    from app.services import enforcement as _enf
    try:
        return _enf.set_mode(host, (body or {}).get("mode"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except KeyError as e:
        raise HTTPException(status_code=404, detail=f"unknown system '{host}'") from e
    except OSError as e:
        raise HTTPException(status_code=503, detail="enforcement bundle unavailable") from e


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


@app.get("/reports/oscal-poam")
def report_oscal_poam(tenant_id: str = "default", db: Session = Depends(get_db),
                      p: Principal = Depends(require_principal)) -> dict:
    """OSCAL Plan of Action & Milestones — one item per open finding."""
    authorize_tenant(p, tenant_id)
    return ReportService(db).oscal_poam(tenant_id)


@app.get("/reports/oscal-components")
def report_oscal_components(tenant_id: str = "default", db: Session = Depends(get_db),
                            p: Principal = Depends(require_principal)) -> dict:
    """OSCAL Component Definition — components and the controls they implement."""
    authorize_tenant(p, tenant_id)
    return ReportService(db).oscal_components(tenant_id)


@app.get("/v1/posture/as-of", tags=["posture"])
def posture_as_of(at: str = Query(..., description="ISO 8601 timestamp, e.g. 2026-02-01T00:00:00Z"),
                  tenant_id: str = "default", db: Session = Depends(get_db),
                  p: Principal = Depends(require_principal)) -> dict:
    """Reconstruct compliance posture as it stood at a point in time."""
    from datetime import datetime
    authorize_tenant(p, tenant_id)
    try:
        t = datetime.fromisoformat(at.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "invalid 'at' timestamp; use ISO 8601") from None
    from app.services.posture_history import as_of
    return {"as_of": t.isoformat(), "controls": as_of(db, tenant_id, t)}


@app.get("/v1/posture/timeline", tags=["posture"])
def posture_timeline(control_id: str = Query(...), tenant_id: str = "default",
                     db: Session = Depends(get_db),
                     p: Principal = Depends(require_principal)) -> dict:
    """The full status-transition timeline for one control."""
    authorize_tenant(p, tenant_id)
    from app.services.posture_history import timeline
    return {"control_id": control_id, "intervals": timeline(db, tenant_id, control_id)}


@app.get("/v1/agents/actions", tags=["agents"])
def agent_actions(tenant_id: str = "default", limit: int = Query(100, ge=1, le=1000),
                  db: Session = Depends(get_db),
                  p: Principal = Depends(require_principal)) -> dict:
    """The append-only log of agent decisions (which agent did what, for whom)."""
    authorize_tenant(p, tenant_id)
    from app.services.agent_audit import list_actions
    return {"actions": list_actions(db, tenant_id, limit)}


@app.get("/v1/agents/actions/verify", tags=["agents"])
def agent_actions_verify(tenant_id: str = "default", db: Session = Depends(get_db),
                         p: Principal = Depends(require_principal)) -> dict:
    """Verify the tamper-evident hash chain of the agent-decision log."""
    authorize_tenant(p, tenant_id)
    from app.services.agent_audit import verify_chain
    return verify_chain(db, tenant_id)


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
        raise _server_error() from None


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


@app.post("/v1/evidence/ingest", tags=["evidence"])
def ingest_standard_evidence(
    payload: dict,
    format: str = Query(..., description="ocsf | sarif | cyclonedx | spdx | intoto | stix | sigstore"),
    tenant_id: str = "default",
    db: Session = Depends(get_db), p: Principal = Depends(require_principal),
) -> dict:
    """Ingest an open-standard evidence document into findings + posture.

    Body is the raw standard document (an OCSF event, SARIF log, CycloneDX or SPDX
    BOM, in-toto/SLSA statement, STIX bundle, or Sigstore bundle); `format` selects
    the adapter. Control verdicts and vulnerability findings are persisted (the
    latter mapped to their NIST control); positive/context evidence is counted only.
    """
    authorize_tenant(p, tenant_id)
    from app.services.standards_ingest import (
        StandardsIngestionService,
        UnsupportedFormat,
    )
    try:
        return StandardsIngestionService(db).ingest(tenant_id, format, payload)
    except UnsupportedFormat as exc:
        raise HTTPException(400, str(exc)) from None
    except Exception:  # noqa: BLE001
        logger.exception("standards evidence ingest failed")
        raise _server_error() from None


# ── static dashboard console ──


_STATIC_DIR = _os.path.join(_os.path.dirname(__file__), "static")
if _os.path.isdir(_STATIC_DIR):
    app.mount("/static", _StaticFiles(directory=_STATIC_DIR), name="static")

    @app.get("/dashboard", include_in_schema=False)
    def _serve_dashboard():
        return _FileResponse(_os.path.join(_STATIC_DIR, "dashboard.html"))


# ── framework catalog + attestation (full coverage) ──



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
        raise HTTPException(status_code=400, detail=str(e)) from e
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


# ── machine-verifiable coverage (capability surface × declarative checks) ──
@app.get("/coverage/automation", tags=["catalog"])
def automation_coverage(_: Principal = Depends(require_principal)) -> dict:
    """Which declarative controls can actually be machine-verified, and by whom.

    This is the platform's core health metric: a control the catalog advertises
    but no connector can observe is a promise that will break during an audit.
    """
    from app.services.control_checks import coverage_matrix

    return coverage_matrix()


@app.get("/connectors/capabilities", tags=["connectors"])
def connector_capabilities(source_system: str | None = None,
                           _: Principal = Depends(require_principal)) -> dict:
    """The probes each connector declares, and the controls they unlock.

    Reads class-level declarations only, so it works without credentials for
    any connector — including ones this deployment has not configured.
    """
    from app.services.control_checks import all_checks

    surfaces = registry.surfaces()
    if source_system:
        key = source_system.upper()
        surfaces = {k: v for k, v in surfaces.items() if k == key}
        if not surfaces:
            raise HTTPException(status_code=404,
                                detail=f"No capability surface for '{source_system}'.")

    checks = all_checks()
    out = []
    for _name, surface in sorted(surfaces.items()):
        satisfied = sorted(
            cid for cid, c in checks.items()
            if surface.resolve(c.asset_type, c.requires) is not None)
        out.append({**surface.as_dict(),
                    "controls_satisfied": satisfied,
                    "controls_satisfied_count": len(satisfied)})
    return {"connectors": out, "total_checks": len(checks)}


# ── evidence graph (LLM-grounded document → concept → control mindmap) ──


class _DocumentRequest(_BaseModel):
    tenant_id: str = "default"
    name: str | None = None
    content: str | None = None
    url: str | None = None
    content_base64: str | None = None
    filename: str | None = None
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


class _SimChange(_BaseModel):
    control_id: str
    state: str = "failed"


class _SimRequest(_BaseModel):
    framework: str = "NIST_800_53"
    changes: list[_SimChange]
    max_depth: int = 3
    min_weight: float = 0.0
    exclude_edges: list[list[str]] | None = None


@app.post("/simulate", tags=["simulation"])
def simulate_blast_radius(req: _SimRequest,
                          p: Principal = Depends(require_principal)) -> dict:
    from app.services.simulator import simulate
    result = simulate(req.framework, [c.model_dump() for c in req.changes],
                      max_depth=req.max_depth, min_weight=req.min_weight,
                      exclude_edges=req.exclude_edges)
    try:
        from app.services import threat_intel as _ti
        cids = [c["control_id"] for c in result.get("cascade", [])]
        cids += [c["control_id"] for c in result.get("directly_changed", [])]
        enrichment = _ti.enrich_controls(cids)
        if enrichment:
            for node in result.get("cascade", []):
                if node["control_id"] in enrichment:
                    node["threat_context"] = enrichment[node["control_id"]]
            result["threat_intel"] = {"enriched": len(enrichment),
                                      "pressure": _ti.threat_pressure()}
    except Exception:
        pass
    return result


@app.get("/controls/{control_id}/dependencies", tags=["simulation"])
def control_dependencies(control_id: str, p: Principal = Depends(require_principal)) -> dict:
    from app.services import dependency_graph as dg
    return {"control_id": control_id,
            "depends_on": dg.in_edges(control_id),
            "affects": dg.out_edges(control_id),
            "graph_stats": dg.stats()}


@app.get("/controls/{control_id}/fragility", tags=["simulation"])
def control_fragility(control_id: str, framework: str = "NIST_800_53",
                      tenant_id: str = "default", db: Session = Depends(get_db),
                      p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services.simulator import fragility
    return fragility(db, tenant_id, framework, control_id)


class _RemediationRequest(_BaseModel):
    framework: str = "NIST_800_53"
    failing_controls: list[str] | None = None
    available_connectors: list[str] | None = None
    tenant_id: str = "default"


@app.post("/remediation/plan", tags=["simulation"])
def remediation_plan(req: _RemediationRequest, db: Session = Depends(get_db),
                     p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, req.tenant_id)
    from app.services import remediation_optimizer
    return remediation_optimizer.plan(db, req.tenant_id, req.framework,
                                      req.failing_controls, req.available_connectors)


@app.get("/controls/{control_id}/remediation", tags=["simulation"])
def control_remediation(control_id: str, framework: str = "NIST_800_53",
                        tenant_id: str = "default", db: Session = Depends(get_db),
                        p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    from app.services import remediation_optimizer
    return remediation_optimizer.detail(db, tenant_id, framework, control_id)


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
    if req.content_base64:
        import base64 as _b64
        try:
            raw = _b64.b64decode(req.content_base64, validate=True)
        except Exception:
            raise HTTPException(status_code=422, detail="content_base64 is not valid base64") from None
        fn = (req.filename or "upload").lower()
        if fn.endswith(".pdf"):
            from app.services.doc_fetch import _pdf_to_text
            try:
                content = _pdf_to_text(raw)
            except Exception as e:
                raise HTTPException(status_code=422, detail=f"could not read PDF: {e}") from e
            stype = "upload:pdf"
        else:
            content = raw.decode("utf-8", errors="replace")
            stype = "upload:text"
        name = name or req.filename or "uploaded document"
    if req.url:
        from app.services.doc_fetch import FetchError, fetch_url_text
        try:
            content, stype = fetch_url_text(req.url.strip())
        except FetchError as e:
            raise HTTPException(status_code=400, detail=f"URL fetch failed: {e}") from e
        name = name or req.url.strip()[:120]
    if not content or not content.strip():
        raise HTTPException(status_code=400, detail="No content (provide 'content', 'content_base64', or a fetchable 'url').")
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
        raise HTTPException(status_code=404, detail=str(e)) from e


@app.delete("/evidence/documents/{doc_id}", tags=["evidence-graph"])
def delete_evidence_document(doc_id: str, db: Session = Depends(get_db),
                             p: Principal = Depends(require_principal)) -> dict:
    from app.models import EvidenceDocument
    doc = db.get(EvidenceDocument, doc_id)
    # Return 404 for both "missing" and "not yours" so the response can't be used
    # as a cross-tenant existence oracle for document ids.
    if not doc or not p.can_access(doc.tenant_id):
        raise HTTPException(status_code=404, detail="document not found")
    _EvidenceService(db).delete_document(doc_id, doc.tenant_id)
    return {"deleted": doc_id}


# ── ontology-driven resolver (telemetry / document / attestation routing) ──


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
        raise HTTPException(status_code=400, detail=str(e)) from e


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


_EVMAP_FILE = _os_evm.path.join(_os_evm.path.dirname(__file__), "static", "evidence-map.html")


@app.get("/evidence-map", include_in_schema=False)
def _serve_evidence_map():
    return _FileResponse_evm(_EVMAP_FILE, headers={"Cache-Control":"no-cache,no-store,must-revalidate","Pragma":"no-cache","Expires":"0"})



# ════════════════════════════════════════════════════════════════════
# GRC Risk Register + TPRM (Third-Party Risk Management)
# ════════════════════════════════════════════════════════════════════


@app.get("/grc/risks", tags=["grc"])
def grc_list_risks(tenant_id: str = "default", db: Session = Depends(get_db),
                   p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    return _RiskService(db).list(tenant_id)


@app.get("/grc/risks/summary", tags=["grc"])
def grc_risk_summary(tenant_id: str = "default", db: Session = Depends(get_db),
                     p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return _RiskService(db).summary(tenant_id)


@app.post("/grc/risks", tags=["grc"])
def grc_create_risk(data: _RiskIn, tenant_id: str = "default",
                    db: Session = Depends(get_db),
                    p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return _RiskService(db).create(tenant_id, data)


@app.patch("/grc/risks/{risk_id}", tags=["grc"])
def grc_update_risk(risk_id: str, patch: _RiskPatch, tenant_id: str = "default",
                    db: Session = Depends(get_db),
                    p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    out = _RiskService(db).update(tenant_id, risk_id, patch)
    if out is None:
        raise HTTPException(404, f"risk '{risk_id}' not found")
    return out


@app.delete("/grc/risks/{risk_id}", tags=["grc"])
def grc_delete_risk(risk_id: str, tenant_id: str = "default",
                    db: Session = Depends(get_db),
                    p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    if not _RiskService(db).delete(tenant_id, risk_id):
        raise HTTPException(404, f"risk '{risk_id}' not found")
    return {"deleted": risk_id}


@app.get("/tprm/vendors", tags=["tprm"])
def tprm_list_vendors(tenant_id: str = "default", db: Session = Depends(get_db),
                      p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    return _VendorService(db).list(tenant_id)


@app.get("/tprm/vendors/summary", tags=["tprm"])
def tprm_vendor_summary(tenant_id: str = "default", db: Session = Depends(get_db),
                        p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return _VendorService(db).summary(tenant_id)


@app.post("/tprm/vendors", tags=["tprm"])
def tprm_create_vendor(data: _VendorIn, tenant_id: str = "default",
                       db: Session = Depends(get_db),
                       p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return _VendorService(db).create(tenant_id, data)


@app.patch("/tprm/vendors/{vendor_id}", tags=["tprm"])
def tprm_update_vendor(vendor_id: str, patch: _VendorPatch, tenant_id: str = "default",
                       db: Session = Depends(get_db),
                       p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    out = _VendorService(db).update(tenant_id, vendor_id, patch)
    if out is None:
        raise HTTPException(404, f"vendor '{vendor_id}' not found")
    return out


@app.delete("/tprm/vendors/{vendor_id}", tags=["tprm"])
def tprm_delete_vendor(vendor_id: str, tenant_id: str = "default",
                       db: Session = Depends(get_db),
                       p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    if not _VendorService(db).delete(tenant_id, vendor_id):
        raise HTTPException(404, f"vendor '{vendor_id}' not found")
    return {"deleted": vendor_id}





@app.get("/trust/graph", tags=["trust"])
def trust_graph(tenant_id: str = "default", db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return _TrustGraph(db).graph(tenant_id)


@app.get("/trust/risk-telemetry", tags=["trust"])
def trust_risk_telemetry(tenant_id: str = "default", db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    return _TrustGraph(db).risk_telemetry(tenant_id)



# ════════════════════════════════════════════════════════════════════
# AUDIT MANAGEMENT  (engagement lifecycle + PBC requests + export package)
# ════════════════════════════════════════════════════════════════════


@app.get("/audits", tags=["audit"])
def audit_list(tenant_id: str = "default", db: Session = Depends(get_db),
               p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    return _AuditSvc(db).list(tenant_id)


@app.post("/audits", tags=["audit"])
def audit_create(data: _AuditIn, tenant_id: str = "default", db: Session = Depends(get_db),
                 p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return _AuditSvc(db).create(tenant_id, data)


@app.get("/audits/{audit_id}", tags=["audit"])
def audit_get(audit_id: str, tenant_id: str = "default", db: Session = Depends(get_db),
              p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    out = _AuditSvc(db).get(tenant_id, audit_id)
    if out is None:
        raise HTTPException(404, "audit not found")
    return out


@app.patch("/audits/{audit_id}", tags=["audit"])
def audit_update(audit_id: str, patch: _AuditPatch, tenant_id: str = "default",
                 db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    out = _AuditSvc(db).update(tenant_id, audit_id, patch)
    if out is None:
        raise HTTPException(404, "audit not found")
    return out


@app.delete("/audits/{audit_id}", tags=["audit"])
def audit_delete(audit_id: str, tenant_id: str = "default", db: Session = Depends(get_db),
                 p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    if not _AuditSvc(db).delete(tenant_id, audit_id):
        raise HTTPException(404, "audit not found")
    return {"deleted": audit_id}


@app.post("/audits/{audit_id}/refresh-posture", tags=["audit"])
def audit_refresh(audit_id: str, tenant_id: str = "default", db: Session = Depends(get_db),
                  p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return _AuditSvc(db).refresh_posture(tenant_id, audit_id)


@app.get("/audits/{audit_id}/controls", tags=["audit"])
def audit_controls(audit_id: str, tenant_id: str = "default", db: Session = Depends(get_db),
                   p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    return _AuditSvc(db).list_controls(tenant_id, audit_id)


@app.patch("/audits/controls/{control_row_id}", tags=["audit"])
def audit_review_control(control_row_id: str, patch: _CtrlPatch, tenant_id: str = "default",
                         db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    out = _AuditSvc(db).review_control(tenant_id, control_row_id, patch)
    if out is None:
        raise HTTPException(404, "control not found")
    return out


@app.get("/audits/{audit_id}/requests", tags=["audit"])
def audit_requests(audit_id: str, tenant_id: str = "default", db: Session = Depends(get_db),
                   p: Principal = Depends(require_principal)) -> list[dict]:
    authorize_tenant(p, tenant_id)
    return _AuditSvc(db).list_requests(tenant_id, audit_id)


@app.post("/audits/{audit_id}/requests", tags=["audit"])
def audit_create_request(audit_id: str, data: _ReqIn, tenant_id: str = "default",
                         db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    return _AuditSvc(db).create_request(tenant_id, audit_id, data)


@app.patch("/audits/requests/{req_id}", tags=["audit"])
def audit_update_request(req_id: str, patch: _ReqPatch, tenant_id: str = "default",
                         db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    out = _AuditSvc(db).update_request(tenant_id, req_id, patch)
    if out is None:
        raise HTTPException(404, "request not found")
    return out


@app.delete("/audits/requests/{req_id}", tags=["audit"])
def audit_delete_request(req_id: str, tenant_id: str = "default", db: Session = Depends(get_db),
                         p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    if not _AuditSvc(db).delete_request(tenant_id, req_id):
        raise HTTPException(404, "request not found")
    return {"deleted": req_id}


@app.get("/audits/{audit_id}/export", tags=["audit"])
def audit_export(audit_id: str, tenant_id: str = "default", db: Session = Depends(get_db),
                 p: Principal = Depends(require_principal)) -> dict:
    authorize_tenant(p, tenant_id)
    out = _AuditSvc(db).export_package(tenant_id, audit_id)
    if out is None:
        raise HTTPException(404, "audit not found")
    return out



# ════════════════════════════════════════════════════════════════════
# DOCUMENT → POLICY/TELEMETRY  (ingest a doc, auto-extract controls)
# ════════════════════════════════════════════════════════════════════


@app.post("/v1/documents/extract", tags=["documents"])
def doc_extract(payload: dict, tenant_id: str = "default",
                p: Principal = Depends(require_principal)) -> dict:
    """Doc text → markdown → controls → events (preview, does not persist).

    Body: {"text": "<document content>", "source": "soc2_report"}
    """
    authorize_tenant(p, tenant_id)
    text = payload.get("text", "")
    if not text:
        raise HTTPException(400, "provide 'text': document content")
    return _doc_ingest.ingest_document(text, tenant_id,
                                       payload.get("source", "document"))


@app.post("/v1/documents/ingest", tags=["documents"])
def doc_ingest_endpoint(payload: dict, tenant_id: str = "default",
                        db: Session = Depends(get_db),
                        p: Principal = Depends(require_principal)) -> dict:
    """Extract controls from a document AND persist the resulting events into
    telemetry (so they flow into the policy / posture layer).

    Body: {"text": "<document content>", "source": "soc2_report"}
    """
    authorize_tenant(p, tenant_id)
    text = payload.get("text", "")
    if not text:
        raise HTTPException(400, "provide 'text': document content")
    result = _doc_ingest.ingest_document(text, tenant_id, payload.get("source", "document"))
    # persist via the middleware pipeline if available; else return events to caller
    persisted = None
    try:
        from app.middleware_core import normalize as _norm
        from app.services.middleware_service import MiddlewareService as _MW
        events = _norm(result["events"], "canonical", tenant_id)
        persisted = _MW(db).ingest(events)
    except Exception:
        persisted = {"note": "middleware not available; events returned but not stored"}
    result["persisted"] = persisted
    return result


@app.post("/v1/documents/upload", tags=["documents"])
def doc_upload(payload: dict, tenant_id: str = "default",
               db: Session = Depends(get_db),
               p: Principal = Depends(require_principal)) -> dict:
    """Ingest a base64-encoded file (PDF/text/markdown) → extract → telemetry.

    Body: {"filename": "policy.pdf", "content_base64": "<b64>"}  — base64 keeps
    this dependency-free (no python-multipart needed on the host).
    """
    authorize_tenant(p, tenant_id)
    import base64
    name = (payload.get("filename") or "upload").lower()
    b64 = payload.get("content_base64", "")
    if not b64:
        raise HTTPException(400, "provide 'content_base64': base64-encoded file content")
    try:
        raw = base64.b64decode(b64)
    except Exception:
        raise HTTPException(422, "content_base64 is not valid base64") from None
    if name.endswith(".pdf"):
        from app.services.doc_fetch import _pdf_to_text
        text = _pdf_to_text(raw)
    else:
        text = raw.decode("utf-8", errors="replace")
    if not text.strip():
        raise HTTPException(422, "could not extract text from document")
    result = _doc_ingest.ingest_document(text, tenant_id, source=payload.get("filename", "upload"))
    try:
        from app.middleware_core import normalize as _norm
        from app.services.middleware_service import MiddlewareService as _MW
        events = _norm(result["events"], "canonical", tenant_id)
        result["persisted"] = _MW(db).ingest(events)
    except Exception:
        result["persisted"] = {"note": "middleware not available; events not stored"}
    return result



# ════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE  (CISA KEV + EPSS + NVD — external feeds)
# ════════════════════════════════════════════════════════════════════


@app.get("/v1/threat/summary", tags=["threat-intel"])
def threat_summary(p: Principal = Depends(require_principal)) -> dict:
    """Live threat posture from CISA KEV: actively-exploited count, ransomware, recent."""
    return _threat.kev_summary()


@app.get("/v1/threat/kev", tags=["threat-intel"])
def threat_kev(limit: int = 50, ransomware_only: bool = False, q: str = "",
               p: Principal = Depends(require_principal)) -> dict:
    """The CISA Known Exploited Vulnerabilities catalog (filterable)."""
    kev = _threat.get_kev()
    vulns = kev["vulnerabilities"]
    if ransomware_only:
        vulns = [v for v in vulns
                 if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"]
    if q:
        ql = q.lower()
        vulns = [v for v in vulns
                 if ql in str(v.get("vulnerabilityName", "")).lower()
                 or ql in str(v.get("product", "")).lower()
                 or ql in str(v.get("vendorProject", "")).lower()
                 or ql in str(v.get("cveID", "")).lower()]
    vulns = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)[:limit]
    return {"source": kev["source"], "count": len(vulns),
            "vulnerabilities": [{"cve": v.get("cveID"), "name": v.get("vulnerabilityName"),
                                 "vendor": v.get("vendorProject"), "product": v.get("product"),
                                 "date_added": v.get("dateAdded"),
                                 "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"}
                                for v in vulns]}


@app.post("/v1/threat/enrich", tags=["threat-intel"])
def threat_enrich(payload: dict, p: Principal = Depends(require_principal)) -> dict:
    """Enrich a set of controls with threat context. Body: {"controls": [...], "cve_map": {...}}"""
    controls = payload.get("controls", [])
    cve_map = payload.get("cve_map", {})
    if not controls:
        raise HTTPException(400, "provide 'controls': [control_ids]")
    return {"enrichment": _threat.enrich_controls(controls, cve_map),
            "pressure": _threat.threat_pressure()}




@app.get("/v1/policy/list", tags=["policy-as-code"])
def policy_list(p: Principal = Depends(require_principal)) -> dict:
    eng = _policy_engine()
    return {"count": len(eng.policies), "policies": eng.list_policies()}


@app.post("/v1/policy/evaluate", tags=["policy-as-code"])
def policy_evaluate(payload: dict, p: Principal = Depends(require_principal)) -> dict:
    """Evaluate evidence against a policy. Body: {"control":"SC-28","evidence":{...}}"""
    control = payload.get("control")
    if not control:
        raise HTTPException(400, "provide 'control'")
    return _policy_engine().evaluate(control, payload.get("evidence", {}),
                                     payload.get("dep_status")).to_dict()


@app.post("/v1/policy/evaluate-all", tags=["policy-as-code"])
def policy_evaluate_all(payload: dict, p: Principal = Depends(require_principal)) -> dict:
    """Evaluate all policies (two-pass, so composition `requires` resolve)."""
    decisions = _policy_engine().evaluate_all(payload.get("evidence", {}))
    return {"count": len(decisions),
            "passing": sum(1 for d in decisions if d.status == "pass"),
            "failing": sum(1 for d in decisions if d.status == "fail"),
            "decisions": [d.to_dict() for d in decisions]}


@app.post("/v1/policy/test", tags=["policy-as-code"])
def policy_test(p: Principal = Depends(require_principal)) -> dict:
    return _policy_engine().run_tests()


@app.post("/v1/policy/reload", tags=["policy-as-code"])
def policy_reload(p: Principal = Depends(require_principal)) -> dict:
    eng = _reload_policies()
    return {"reloaded": True, "count": len(eng.policies)}



# ════════════════════════════════════════════════════════════════════
# AI GOVERNANCE — privacy-enhancing technologies + dynamic risk
# ════════════════════════════════════════════════════════════════════



@app.get("/v1/ai-gov/pet-catalog", tags=["ai-governance"])
def pet_catalog(p: Principal = Depends(require_principal)) -> dict:
    """The catalog of privacy-enhancing technologies Comp-Lens can assess."""
    return {"count": len(_aigov.PET_CATALOG),
            "pets": [{"id": k, **{kk: vv for kk, vv in v.items() if kk != "frameworks"},
                      "frameworks": v["frameworks"]} for k, v in _aigov.PET_CATALOG.items()]}


@app.post("/v1/ai-gov/assess-pet", tags=["ai-governance"])
def assess_pet_endpoint(payload: dict, p: Principal = Depends(require_principal)) -> dict:
    """Assess one PET's strength. Body: {"pet":"differential_privacy","params":{"epsilon":0.5}}"""
    pet = payload.get("pet")
    if not pet:
        raise HTTPException(400, "provide 'pet'")
    return _aigov.assess_pet(pet, payload.get("params"))


@app.post("/v1/ai-gov/systems/{system_id}/pets", tags=["ai-governance"])
def add_system_pet(system_id: str, payload: dict, tenant_id: str = "default",
                   db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    """Attach a PET to an AI system. Body: {"pet":"...","params":{...},"data_sensitivity":"phi"}"""
    authorize_tenant(p, tenant_id)
    pet = payload.get("pet")
    if not pet or pet not in _aigov.PET_CATALOG:
        raise HTTPException(400, f"unknown pet; valid: {list(_aigov.PET_CATALOG.keys())}")
    row = _PET(tenant_id=tenant_id, system_id=system_id, pet=pet,
               params_json=_json.dumps(payload.get("params", {})),
               data_sensitivity=payload.get("data_sensitivity", "pii"))
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "system_id": system_id, "pet": pet,
            "assessment": _aigov.assess_pet(pet, payload.get("params"))}


@app.get("/v1/ai-gov/systems/{system_id}/risk", tags=["ai-governance"])
def system_privacy_risk(system_id: str, tenant_id: str = "default",
                        db: Session = Depends(get_db),
                        p: Principal = Depends(require_principal)) -> dict:
    """Dynamic privacy-risk score for an AI system, derived from its PETs."""
    authorize_tenant(p, tenant_id)
    rows = db.execute(select(_PET).where(_PET.system_id == system_id,
                                         _PET.tenant_id == tenant_id)).scalars().all()
    sensitivity = rows[0].data_sensitivity if rows else "pii"
    pets = [{"pet": r.pet, "params": _json.loads(r.params_json or "{}")} for r in rows]
    risk = _aigov.compute_privacy_risk(sensitivity, pets)
    # also pull EU AI Act obligations from the AI system record
    from app.models import AISystem
    sys = db.get(AISystem, system_id)
    if sys:
        risk["ai_act"] = _aigov.ai_act_obligations(sys.risk_tier, {
            "impact_assessment": sys.impact_assessment, "data_governance": sys.data_governance,
            "human_oversight": sys.human_oversight, "accuracy_tested": sys.accuracy_tested,
            "logging_enabled": sys.logging_enabled, "transparency_notice": sys.transparency_notice})
    return risk


@app.post("/v1/ai-gov/score", tags=["ai-governance"])
def score_adhoc(payload: dict, p: Principal = Depends(require_principal)) -> dict:
    """Score privacy risk ad-hoc without persisting.
    Body: {"data_sensitivity":"phi","pets":[{"pet":"differential_privacy","params":{"epsilon":0.5}}]}"""
    return _aigov.compute_privacy_risk(payload.get("data_sensitivity", "pii"),
                                       payload.get("pets", []))



# ════════════════════════════════════════════════════════════════════
# INTEGRATION — wires policy/AI-gov/threat into findings + risk register
# ════════════════════════════════════════════════════════════════════


@app.post("/v1/integrate/policy-to-findings", tags=["integration"])
def integrate_policy_findings(payload: dict, tenant_id: str = "default",
                              db: Session = Depends(get_db),
                              p: Principal = Depends(require_principal)) -> dict:
    """Evaluate policies against evidence and persist results as findings.
    Body: {"evidence": {"SC-28": {...}, "AC-2": {...}}, "framework": "ALL"}"""
    authorize_tenant(p, tenant_id)
    return _integ.evaluate_policies_to_findings(
        db, tenant_id, payload.get("evidence", {}), payload.get("framework", "ALL"))


@app.post("/v1/integrate/ai-systems/{system_id}/to-risk", tags=["integration"])
def integrate_ai_to_risk(system_id: str, tenant_id: str = "default",
                         db: Session = Depends(get_db),
                         p: Principal = Depends(require_principal)) -> dict:
    """Create a risk-register entry from an AI system's computed privacy risk."""
    authorize_tenant(p, tenant_id)
    return _integ.ai_system_to_risk(db, tenant_id, system_id)


@app.post("/v1/integrate/ai-to-risk", tags=["integration"])
def integrate_all_ai_risks(tenant_id: str = "default",
                           db: Session = Depends(get_db),
                           p: Principal = Depends(require_principal)) -> dict:
    """Push every AI system with PETs into the risk register."""
    authorize_tenant(p, tenant_id)
    return _integ.sync_all_ai_risks(db, tenant_id)


@app.post("/v1/integrate/threat-escalation", tags=["integration"])
def integrate_threat_escalation(tenant_id: str = "default",
                                db: Session = Depends(get_db),
                                p: Principal = Depends(require_principal)) -> dict:
    """Escalate risks on vuln controls under active KEV exploitation pressure."""
    authorize_tenant(p, tenant_id)
    return _integ.escalate_risks_from_threat(db, tenant_id)


@app.post("/v1/integrate/run", tags=["integration"])
def integrate_run_all(payload: dict | None = None, tenant_id: str = "default",
                      db: Session = Depends(get_db),
                      p: Principal = Depends(require_principal)) -> dict:
    """Run the whole integrated pipeline: policy→findings, AI→risk, threat→escalation."""
    authorize_tenant(p, tenant_id)
    payload = payload or {}
    return _integ.run_unified_pipeline(db, tenant_id, payload.get("evidence"))



# ════════════════════════════════════════════════════════════════════
# GRC-PLATFORM SYNC — separate connector set (Vanta / Drata / OneTrust)
# Inherited trust telemetry, kept in its own lane (source_kind=grc_platform)
# ════════════════════════════════════════════════════════════════════


@app.get("/v1/grc-sync/platforms", tags=["grc-platforms"])
def grc_platforms(p: Principal = Depends(require_principal)) -> dict:
    """The available GRC-platform connectors — a set distinct from native connectors."""
    return {"platforms": _GRC_REG,
            "note": "separate set from native connectors; evidence tagged source_kind=grc_platform"}


@app.post("/v1/grc-sync/{platform}", tags=["grc-platforms"])
def grc_sync(platform: str, tenant_id: str = "default",
             db: Session = Depends(get_db), p: Principal = Depends(require_principal)) -> dict:
    """Sync inherited attestations from a GRC platform (Vanta/Drata/OneTrust)."""
    authorize_tenant(p, tenant_id)
    from app.connectors.base import ConnectorError
    try:
        return _grc_svc.sync_platform(db, tenant_id, platform)
    except ConnectorError as e:
        raise HTTPException(400, str(e)) from e


@app.get("/v1/grc-sync/status", tags=["grc-platforms"])
def grc_status(tenant_id: str = "default", db: Session = Depends(get_db),
               p: Principal = Depends(require_principal)) -> dict:
    """Connected GRC platforms and their ingested attestation counts."""
    authorize_tenant(p, tenant_id)
    return _grc_svc.sync_status(db, tenant_id)


@app.get("/v1/grc-sync/multi-source", tags=["grc-platforms"])
def grc_multi_source(tenant_id: str = "default", db: Session = Depends(get_db),
                     p: Principal = Depends(require_principal)) -> dict:
    """Controls attested by multiple independent sources — agreement vs conflict."""
    authorize_tenant(p, tenant_id)
    return _grc_svc.multi_source_attestation(db, tenant_id)



@app.get("/v1/grc-sync/profiles", tags=["grc-platforms"])
def grc_profiles(p: Principal = Depends(require_principal)) -> dict:
    """The loaded platform profiles (built-in + YAML) and the shared crosswalk —
    the transparency layer for a unified, adaptive trust telemetry portal."""
    from app.grc_platforms import crosswalk as xw
    from app.grc_platforms.loader import load_all_profiles
    profs = load_all_profiles()
    return {
        "profiles": [{"platform": k, "name": v.name, "source": v.source,
                      "speaks_frameworks": v.speaks_frameworks, "auth": v.auth_method}
                     for k, v in profs.items()],
        "crosswalk_frameworks": list(xw.CROSSWALKS.keys()),
        "crosswalk_entries": {fw: len(m) for fw, m in xw.CROSSWALKS.items()},
        "note": "drop a YAML file in GRC_PROFILE_DIR to add a platform — no code change",
    }



# ════════════════════════════════════════════════════════════════════
# GRC TRUST TELEMETRY — dedicated inherited-trust scoring (separate lane)
# Tunable as code: weights come from a TrustPolicy (default / env / inline).
# ════════════════════════════════════════════════════════════════════



@app.get("/v1/grc-trust/score", tags=["grc-trust-telemetry"])
def grc_trust_score(tenant_id: str = "default", db: Session = Depends(get_db),
                    p: Principal = Depends(require_principal)) -> dict:
    """Aggregate inherited-trust score. Uses the active trust policy
    (defaults, or GRC_TRUST_POLICY env override). Separate from native trust graph."""
    authorize_tenant(p, tenant_id)
    return _GRCTrust(db, _resolve_trust_policy(tenant_id)).score(tenant_id)


@app.get("/v1/grc-trust/controls", tags=["grc-trust-telemetry"])
def grc_trust_controls(tenant_id: str = "default", db: Session = Depends(get_db),
                       p: Principal = Depends(require_principal)) -> dict:
    """Per-control inherited-trust scores (conflicts and lowest-trust first)."""
    authorize_tenant(p, tenant_id)
    return {"controls": _GRCTrust(db, _resolve_trust_policy(tenant_id)).by_control(tenant_id)}


@app.get("/v1/grc-trust/platforms", tags=["grc-trust-telemetry"])
def grc_trust_platforms(tenant_id: str = "default", db: Session = Depends(get_db),
                        p: Principal = Depends(require_principal)) -> dict:
    """Each GRC platform's standalone trust contribution."""
    authorize_tenant(p, tenant_id)
    return _GRCTrust(db, _resolve_trust_policy(tenant_id)).by_platform(tenant_id)


@app.get("/v1/grc-trust/policy", tags=["grc-trust-telemetry"])
def grc_trust_policy(p: Principal = Depends(require_principal)) -> dict:
    """The active trust-scoring policy (the tunable weights) + their meaning."""
    return {"active_policy": _asdict(_resolve_trust_policy()),
            "tunable_as": "GRC_TRUST_POLICY env var (JSON), or inline on /score-preview",
            "fields": {
                "fresh_days": "evidence at/below this age gets full trust",
                "stale_days": "evidence at/above this age hits the trust floor",
                "freshness_floor": "fraction of trust the oldest evidence retains (0..1)",
                "conflict_factor": "multiplier applied when platforms disagree (lower = harsher)",
                "corroboration_bonus": "trust multiplier by number of agreeing sources",
                "status_weights": "base trust per platform verdict"}}


@app.post("/v1/grc-trust/score-preview", tags=["grc-trust-telemetry"])
def grc_trust_preview(payload: dict, tenant_id: str = "default",
                      db: Session = Depends(get_db),
                      p: Principal = Depends(require_principal)) -> dict:
    """Preview the trust score under a DIFFERENT policy without persisting it.
    Body: {"policy": {"fresh_days": 1, "conflict_factor": 0.1}} — tune and see the impact."""
    authorize_tenant(p, tenant_id)
    pol = _resolve_trust_policy(tenant_id, inline=payload.get("policy"))
    return _GRCTrust(db, pol).score(tenant_id)
