"""GRC-platform sync service — ingest attestations and surface multi-source trust."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.grc_platforms.registry import get_grc_connector, GRC_PLATFORM_REGISTRY
from app.grc_platforms.models import GRCAttestation


def sync_platform(db: Session, tenant_id: str, platform: str) -> Dict[str, Any]:
    """Pull a GRC platform's results and persist them as attestations (idempotent)."""
    conn = get_grc_connector(platform)  # raises if not configured
    attestations = conn.bulk_ingest()
    key = platform.upper()
    # clear prior attestations for this platform+tenant (full refresh)
    db.query(GRCAttestation).filter(GRCAttestation.tenant_id == tenant_id,
                                    GRCAttestation.platform == key).delete()
    mapped = 0
    for a in attestations:
        if a.comp_lens_control_id:
            mapped += 1
        db.add(GRCAttestation(
            tenant_id=tenant_id, platform=key, external_test_id=a.external_test_id,
            external_control_ref=a.external_control_ref,
            comp_lens_control_id=a.comp_lens_control_id, status=a.status,
            freshness_days=a.evidence_freshness_days, confidence=a.confidence,
            title=a.title))
    db.commit()
    return {"platform": key, "ingested": len(attestations), "mapped": mapped,
            "unmapped": len(attestations) - mapped,
            "note": "inherited attestations stored in their own lane (source_kind=grc_platform)"}


def sync_status(db: Session, tenant_id: str) -> Dict[str, Any]:
    rows = db.execute(select(GRCAttestation).where(
        GRCAttestation.tenant_id == tenant_id)).scalars().all()
    by_platform: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        p = by_platform.setdefault(r.platform, {"total": 0, "pass": 0, "fail": 0, "mapped": 0})
        p["total"] += 1
        p["mapped"] += 1 if r.comp_lens_control_id else 0
        if r.status == "pass": p["pass"] += 1
        if r.status == "fail": p["fail"] += 1
    return {"available_platforms": GRC_PLATFORM_REGISTRY,
            "connected": list(by_platform.keys()), "by_platform": by_platform}


def multi_source_attestation(db: Session, tenant_id: str) -> Dict[str, Any]:
    """The USP view: which controls are attested by multiple independent sources.

    Inherited (GRC-platform) attestations are deliberately kept in a SEPARATE lane
    from native-connector evidence. This shows, per control, how many independent
    sources attest it — agreement is a trust signal, disagreement is a louder one.
    """
    rows = db.execute(select(GRCAttestation).where(
        GRCAttestation.tenant_id == tenant_id,
        GRCAttestation.comp_lens_control_id.isnot(None))).scalars().all()
    by_control: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        by_control.setdefault(r.comp_lens_control_id, []).append(
            {"source": r.platform, "kind": "grc_platform", "status": r.status,
             "freshness_days": r.freshness_days, "confidence": r.confidence})
    out = []
    for cid, sources in by_control.items():
        statuses = {s["status"] for s in sources}
        out.append({"control_id": cid, "source_count": len(sources), "sources": sources,
                    "agreement": "conflict" if len(statuses) > 1 else "agree",
                    "consensus": "fail" if "fail" in statuses else "pass"})
    out.sort(key=lambda x: (x["agreement"] != "conflict", -x["source_count"]))
    return {"controls_attested": len(out),
            "multi_source": sum(1 for c in out if c["source_count"] > 1),
            "conflicts": sum(1 for c in out if c["agreement"] == "conflict"),
            "attestations": out}
