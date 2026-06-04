"""Asset discovery + bulk assessment.

discover() asks a connector to enumerate its assets and upserts them into the
inventory. bulk_assess() runs one control against every discovered asset for a
given source system.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.registry import registry
from app.models import AssessmentRequest, AssetRecord
from app.services.assessment import AssessmentService

logger = logging.getLogger(__name__)


class InventoryService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def discover(self, tenant_id: str, source_system: str, params: Dict[str, Any]) -> int:
        connector = registry.get(source_system)
        assets = connector.discover_assets(params or {})
        count = 0
        for a in assets:
            exists = self.db.execute(
                select(AssetRecord).where(
                    AssetRecord.tenant_id == tenant_id,
                    AssetRecord.source_system == a.source_system,
                    AssetRecord.asset_id == a.asset_id,
                )
            ).scalar_one_or_none()
            if exists:
                exists.asset_type = a.asset_type
                exists.owner = a.owner
            else:
                self.db.add(AssetRecord(
                    tenant_id=tenant_id, asset_id=a.asset_id, asset_type=a.asset_type,
                    source_system=a.source_system, owner=a.owner, criticality=a.criticality,
                ))
                count += 1
        self.db.flush()
        logger.info("discovered tenant=%s source=%s new=%d total=%d", tenant_id, source_system, count, len(assets))
        return count

    def list(self, tenant_id: str, source_system: str | None = None) -> List[AssetRecord]:
        stmt = select(AssetRecord).where(AssetRecord.tenant_id == tenant_id)
        if source_system:
            stmt = stmt.where(AssetRecord.source_system == source_system.upper())
        return list(self.db.execute(stmt.order_by(AssetRecord.discovered_at.desc())).scalars().all())

    def bulk_assess(self, tenant_id: str, framework: str, control_id: str,
                    source_system: str, params: Dict[str, Any]) -> Dict[str, Any]:
        assets = self.list(tenant_id, source_system)
        svc = AssessmentService(self.db)
        results = {"assessed": 0, "failed": 0, "findings": []}
        for a in assets:
            try:
                f = svc.run_single(AssessmentRequest(
                    tenant_id=tenant_id, framework=framework, control_id=control_id,
                    source_system=source_system, asset_id=a.asset_id, params=params,
                ))
                results["assessed"] += 1
                results["findings"].append(f.finding_id)
            except Exception as exc:  # noqa: BLE001
                results["failed"] += 1
                logger.warning("bulk assess failed asset=%s: %s", a.asset_id, exc)
        return results
