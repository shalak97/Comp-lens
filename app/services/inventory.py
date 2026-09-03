"""Asset discovery + bulk assessment.

discover() asks a connector to enumerate its assets and upserts them into the
inventory. bulk_assess() runs one control against every discovered asset for a
given source system.
"""

from __future__ import annotations

import builtins
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.registry import registry
from app.models import AssessmentRequest, AssetRecord
from app.services.assessment import AssessmentService

logger = logging.getLogger(__name__)


class InventoryService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def discover(self, tenant_id: str, source_system: str, params: dict[str, Any]) -> int:
        """Upsert everything a connector can enumerate, in two queries.

        This used to issue one SELECT per discovered asset to ask whether it was
        already known. That was tolerable while connectors returned a single
        page: Okta and GitHub fetched fifty and the loop ran fifty times. Fixing
        those connectors to enumerate the whole estate turned the same loop into
        one round trip per user — three thousand queries for a three thousand
        seat org, on an endpoint a customer calls to get started. The correct
        shape was always to ask once.

        Loading the known keys up front also fixes a real bug in the old
        version: pending inserts are not visible to a later SELECT in the same
        flush, so a connector returning the same asset twice in one payload
        inserted it twice and violated nothing that would have caught it. The
        seen-set below is updated as rows are added, so a duplicate in the
        payload updates the row the first occurrence created.
        """
        connector = registry.get(source_system)
        assets = connector.discover_assets(params or {})
        if not assets:
            logger.info("discovered tenant=%s source=%s new=0 total=0", tenant_id, source_system)
            return 0

        # One read for everything already on file. Keyed the way the inventory
        # identifies an asset: an Asset carries its own source_system, which is
        # not always the connector that produced it.
        known: dict[tuple[str, str], AssetRecord] = {
            (r.source_system, r.asset_id): r
            for r in self.db.execute(
                select(AssetRecord).where(
                    AssetRecord.tenant_id == tenant_id,
                    AssetRecord.source_system.in_({a.source_system for a in assets}),
                )
            ).scalars().all()
        }

        count = 0
        for a in assets:
            key = (a.source_system, a.asset_id)
            existing = known.get(key)
            if existing is not None:
                existing.asset_type = a.asset_type
                existing.owner = a.owner
                continue
            record = AssetRecord(
                tenant_id=tenant_id, asset_id=a.asset_id, asset_type=a.asset_type,
                source_system=a.source_system, owner=a.owner, criticality=a.criticality,
            )
            self.db.add(record)
            known[key] = record
            count += 1
        self.db.flush()
        logger.info("discovered tenant=%s source=%s new=%d total=%d", tenant_id, source_system, count, len(assets))
        return count

    def list(self, tenant_id: str, source_system: str | None = None,
             asset_type: str | None = None, limit: int | None = None,
             offset: int = 0) -> builtins.list[AssetRecord]:
        from app import pagination

        stmt = select(AssetRecord).where(AssetRecord.tenant_id == tenant_id)
        if source_system:
            stmt = stmt.where(AssetRecord.source_system == source_system.upper())
        if asset_type:
            stmt = stmt.where(AssetRecord.asset_type == asset_type)
        # asset_id breaks ties: discovered_at alone is not unique, and a
        # non-deterministic order makes LIMIT/OFFSET drop or repeat rows
        # between pages.
        stmt = pagination.apply(
            stmt.order_by(AssetRecord.discovered_at.desc(), AssetRecord.asset_id),
            limit, offset)
        return list(self.db.execute(stmt).scalars().all())

    def bulk_assess(self, tenant_id: str, framework: str, control_id: str,
                    source_system: str, params: dict[str, Any]) -> dict[str, Any]:
        """Run one control against every asset it actually applies to.

        Declarative controls declare the asset type they inspect, so an
        object-storage control is run against object storage rather than against
        every asset the source system ever discovered. Without this filter,
        bulk-assessing a bucket control over an inventory of IAM users produced
        one failure per user and offered no way to express "assess my buckets".

        Hand-written controls carry no asset type; those keep the original
        behaviour of running against every asset for the source system.
        """
        from app.services import control_checks

        # Resolve the connector once, before assessing anything. An unknown
        # source system or one whose credentials are unset fails every asset
        # identically — that is a bad request or a deployment gap, not a
        # statement about the estate, and it should fail the call loudly rather
        # than write one "could not verify" finding per asset for it. Doing it
        # here also means every failure in the loop below is a genuine
        # per-asset collection failure.
        registry.get(source_system)

        check = control_checks.get(control_id)
        asset_type = check.asset_type if check else None
        assets = self.list(tenant_id, source_system, asset_type=asset_type)
        svc = AssessmentService(self.db)
        results: dict[str, Any] = {"assessed": 0, "failed": 0, "unverifiable": 0,
                                   "findings": [], "asset_type": asset_type,
                                   "eligible_assets": len(assets)}
        for a in assets:
            req = AssessmentRequest(
                tenant_id=tenant_id, framework=framework, control_id=control_id,
                source_system=source_system, asset_id=a.asset_id, params=params,
            )
            try:
                f = svc.run_single(req)
                results["assessed"] += 1
                results["findings"].append(f.finding_id)
            except Exception as exc:  # noqa: BLE001
                # An asset we could not read is not an asset that passed. It is
                # recorded as ERROR so it stays in posture and in the score;
                # dropping it here is what let a control that failed on most of
                # an estate report a healthy figure for the remainder.
                results["failed"] += 1
                if svc.record_unverifiable(req, error=exc) is not None:
                    results["unverifiable"] += 1
                logger.warning("bulk assess failed asset=%s: %s", a.asset_id, exc)
        return results
