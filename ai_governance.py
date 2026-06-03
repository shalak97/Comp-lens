"""AI-governance connector — assesses the organization's own AI systems against
ISO 42001 / NIST AI RMF / EU AI Act controls, reading the AI system register on
the data plane (not document collection).

source_system="AIGOV"; asset_id = the AI system id. The control evaluators read
the normalized governance attributes this returns.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.connectors.base import Asset, BaseConnector, ConnectorError


class AIGovernanceConnector(BaseConnector):
    source_system = "AIGOV"

    def healthcheck(self) -> bool:
        return True

    def _load(self, tenant_id: Optional[str], asset_id: Optional[str]):
        from app.database import SessionLocal
        from app.models import AISystem
        if not asset_id:
            raise ConnectorError("AIGOV requires asset_id (the AI system id).")
        db = SessionLocal()
        try:
            sysrec = db.get(AISystem, asset_id)
            if not sysrec:
                raise ConnectorError(f"AI system '{asset_id}' not registered.")
            # tenant scoping: refuse cross-tenant reads
            if tenant_id and sysrec.tenant_id != tenant_id:
                raise ConnectorError("AI system does not belong to this tenant.")
            return sysrec
        finally:
            db.close()

    def collect_telemetry(self, control_id: str, asset_id: Optional[str],
                          params: Dict[str, Any]) -> Dict[str, Any]:
        tenant_id = (params or {}).get("_tenant_id")
        s = self._load(tenant_id, asset_id)
        return {
            "ai_inventoried": bool(s.owner),
            "impact_assessment": s.impact_assessment,
            "data_governance": s.data_governance,
            "human_oversight": s.human_oversight,
            "transparency_notice": s.transparency_notice,
            "eval_report": s.eval_report,
            "logging_enabled": s.logging_enabled,
            "accuracy_tested": s.accuracy_tested,
            "owner": s.owner, "risk_tier": s.risk_tier, "asset": s.name,
        }

    def discover_assets(self, params: Dict[str, Any]) -> List[Asset]:
        from app.database import SessionLocal
        from app.models import AISystem
        from sqlalchemy import select
        tenant_id = (params or {}).get("_tenant_id")
        db = SessionLocal()
        try:
            stmt = select(AISystem)
            if tenant_id:
                stmt = stmt.where(AISystem.tenant_id == tenant_id)
            return [Asset(asset_id=s.id, asset_type="ai_system", source_system="AIGOV",
                          owner=s.owner, criticality=("critical" if s.risk_tier == "high" else "medium"))
                    for s in db.execute(stmt).scalars().all()]
        finally:
            db.close()
