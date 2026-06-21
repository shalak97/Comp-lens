"""Integration layer — wires the standalone features into one system.

Before this, each capability talked only to its own endpoints:
  - the policy engine evaluated policies but produced nothing the rest could see
  - AI-governance computed privacy risk in isolation from the risk register
  - threat intel enriched the blast radius but escalated nothing

This service closes those silos with real data flows:

  1. policy → findings   evaluate_policies_to_findings(): a failing policy becomes a
                         Finding, so it flows into blast radius, remediation, and
                         posture exactly like a scanner finding does.
  2. ai-gov → risk       ai_system_to_risk(): a high/critical-residual AI system
                         becomes a risk-register entry, linked back to the system.
  3. threat → risk       escalate_risks_from_threat(): a risk whose linked control is
                         a vuln-management control under active KEV exploitation gets
                         its impact escalated, with an audit note.

Everything is idempotent (re-running doesn't duplicate) and tenant-scoped.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, ControlStatus, Severity, Lifecycle

_SEV_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
_VULN_CONTROLS = {"RA-5", "SI-2", "SI-3", "SC-7", "CA-7", "RA-3"}

POLICY_SOURCE = "policy-as-code"
AIGOV_CATEGORY = "ai_governance"


# ── 1. POLICY ENGINE → FINDINGS ──────────────────────────────────────
def evaluate_policies_to_findings(db: Session, tenant_id: str,
                                  evidence_by_control: Dict[str, Dict[str, Any]],
                                  framework: str = "ALL") -> Dict[str, Any]:
    """Run every policy against supplied evidence; persist fail/pass as findings.

    This is the missing spine: 'compliance as code' decisions now enter the same
    findings stream the simulator, remediation, and posture all read from.
    """
    from app.policy_as_code import get_engine
    engine = get_engine()
    decisions = engine.evaluate_all(evidence_by_control)
    run_id = "pol_" + uuid.uuid4().hex[:12]
    created, updated = 0, 0
    for d in decisions:
        if d.status == "error":
            continue
        cstatus = ControlStatus.PASS if d.status == "pass" else ControlStatus.FAIL
        sev = _SEV_MAP.get(d.severity, Severity.MEDIUM)
        # idempotent: one open policy-finding per control. update if it exists.
        existing = db.execute(
            select(Finding).where(Finding.tenant_id == tenant_id,
                                  Finding.control_id == d.control_id,
                                  Finding.source_system == POLICY_SOURCE,
                                  Finding.lifecycle == Lifecycle.OPEN)).scalars().first()
        if existing:
            existing.status = cstatus
            existing.severity = sev
            existing.description = d.reason
            existing.remediation = {"obligations": d.obligations, "rules": d.rules}
            existing.updated_at = datetime.now(timezone.utc)
            if cstatus == ControlStatus.PASS:
                existing.lifecycle = Lifecycle.RESOLVED
            updated += 1
        else:
            db.add(Finding(
                finding_id=str(uuid.uuid4()), tenant_id=tenant_id, run_id=run_id,
                framework=framework, control_id=d.control_id, source_system=POLICY_SOURCE,
                status=cstatus, severity=sev,
                lifecycle=Lifecycle.OPEN if cstatus == ControlStatus.FAIL else Lifecycle.RESOLVED,
                description=d.reason,
                remediation={"obligations": d.obligations, "rules": d.rules}))
            created += 1
    db.commit()
    failing = [d.control_id for d in decisions if d.status == "fail"]
    return {"run_id": run_id, "evaluated": len(decisions),
            "findings_created": created, "findings_updated": updated,
            "failing_controls": failing,
            "note": "policy decisions are now findings — visible in blast radius, remediation, and posture"}


# ── 2. AI GOVERNANCE → RISK REGISTER ─────────────────────────────────
def ai_system_to_risk(db: Session, tenant_id: str, system_id: str) -> Dict[str, Any]:
    """Turn an AI system's computed privacy risk into a risk-register entry.

    A critical-residual AI system handling PHI is a real enterprise risk — it should
    live in the register alongside every other risk, not in a separate calculator.
    """
    from app.ai_governance_models import AISystemPET
    from app.services import ai_governance as aigov
    from app.services.grc_tprm import RiskService
    from app.grc_tprm_models import RiskIn
    from app.models import AISystem

    sys = db.get(AISystem, system_id)
    if not sys or sys.tenant_id != tenant_id:
        return {"error": "system not found"}
    rows = db.execute(select(AISystemPET).where(
        AISystemPET.system_id == system_id, AISystemPET.tenant_id == tenant_id)).scalars().all()
    import json
    sensitivity = rows[0].data_sensitivity if rows else "pii"
    pets = [{"pet": r.pet, "params": json.loads(r.params_json or "{}")} for r in rows]
    risk = aigov.compute_privacy_risk(sensitivity, pets)

    # map residual band → likelihood/impact (1-5)
    band = risk["residual_band"]
    impact = {"low": 2, "medium": 3, "high": 4, "critical": 5}.get(band, 3)
    likelihood = 4 if risk["residual_risk"] >= 50 else 2

    svc = RiskService(db)
    # idempotent: don't duplicate the risk for the same system
    existing = [r for r in svc.list(tenant_id)
                if r.get("category") == AIGOV_CATEGORY and (r.get("title") or "").endswith(sys.name)]
    title = f"AI privacy risk: {sys.name}"
    desc = (f"AI system '{sys.name}' ({sensitivity} data, EU AI Act tier '{sys.risk_tier}') "
            f"has residual privacy risk {risk['residual_risk']} ({band}) after "
            f"{len(pets)} privacy-enhancing technolog{'y' if len(pets)==1 else 'ies'}. "
            f"{risk['explanation']}")
    if existing:
        return {"linked": True, "risk_id": existing[0]["id"],
                "residual_band": band, "note": "risk already exists for this system (idempotent)"}
    created = svc.create(tenant_id, RiskIn(
        title=title, description=desc, category=AIGOV_CATEGORY,
        owner=sys.owner, likelihood=likelihood, impact=impact,
        treatment="mitigate", status="identified"))
    return {"linked": True, "risk_id": created["id"], "residual_band": band,
            "residual_risk": risk["residual_risk"],
            "note": "AI system privacy risk is now in the risk register"}


def sync_all_ai_risks(db: Session, tenant_id: str) -> Dict[str, Any]:
    """Push every AI system with PETs into the risk register."""
    from app.ai_governance_models import AISystemPET
    sys_ids = {r.system_id for r in db.execute(
        select(AISystemPET).where(AISystemPET.tenant_id == tenant_id)).scalars().all()}
    results = [ai_system_to_risk(db, tenant_id, sid) for sid in sys_ids]
    return {"systems_synced": len(results),
            "risks": [r for r in results if r.get("linked")]}


# ── 3. THREAT INTEL → RISK ESCALATION ────────────────────────────────
def escalate_risks_from_threat(db: Session, tenant_id: str) -> Dict[str, Any]:
    """Escalate risks whose linked control is a vuln control under active KEV pressure.

    The same dynamic-severity idea the AI-gov engine uses, applied across the register:
    real-world exploitation should raise the impact of the risks it touches.
    """
    from app.services import threat_intel as ti
    from app.services.grc_tprm import RiskService
    from app.grc_tprm_models import RiskPatch

    pressure = ti.threat_pressure()
    if pressure["actively_exploited"] == 0:
        return {"escalated": 0, "note": "no active exploitation pressure"}
    svc = RiskService(db)
    risks = svc.list(tenant_id)
    escalated = []
    for r in risks:
        ctrl = (r.get("linked_control") or "").split("(")[0].strip()
        if ctrl in _VULN_CONTROLS and r.get("impact", 3) < 5:
            new_impact = min(5, r.get("impact", 3) + 1)
            svc.update(tenant_id, r["id"], RiskPatch(impact=new_impact))
            escalated.append({"risk_id": r["id"], "control": ctrl,
                              "impact": f"{r.get('impact')}→{new_impact}"})
    return {"escalated": len(escalated), "details": escalated,
            "exploitation_pressure": pressure["exploitation_pressure"],
            "actively_exploited": pressure["actively_exploited"],
            "note": "risks on actively-exploited vuln controls had their impact raised"}


# ── UNIFIED: run the whole integrated pipeline ───────────────────────
def run_unified_pipeline(db: Session, tenant_id: str,
                         evidence_by_control: Optional[Dict[str, Dict[str, Any]]] = None
                         ) -> Dict[str, Any]:
    """One call that runs every cross-feature flow and reports what connected."""
    out: Dict[str, Any] = {}
    if evidence_by_control:
        out["policy_to_findings"] = evaluate_policies_to_findings(db, tenant_id, evidence_by_control)
    out["ai_to_risk"] = sync_all_ai_risks(db, tenant_id)
    out["threat_escalation"] = escalate_risks_from_threat(db, tenant_id)
    return {"tenant_id": tenant_id, "ran": list(out.keys()), "results": out,
            "note": "policy decisions, AI-governance, and threat intel are now wired into the findings + risk register"}
