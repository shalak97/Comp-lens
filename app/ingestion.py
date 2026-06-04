"""Ingest already-evaluated findings from external scanners.

Rather than hand-writing per-vendor control logic, stand on mature scanners and
normalize their output into Comp-Lens findings + posture:

  - AWS Security Hub (ASFF) via boto3
  - Prowler / Steampipe / Powerpipe JSON reports (uploaded)

Each external finding becomes a Comp-Lens finding (status already decided by the
scanner), is deduplicated by the scanner's finding id, written to evidence, and
folded into the posture current-state and drift tracking.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.models import ControlStatus, Severity
from app.services.assessment import AssessmentService

logger = logging.getLogger(__name__)

# external status -> our ControlStatus
_STATUS = {
    "PASSED": ControlStatus.PASS, "PASS": ControlStatus.PASS, "ok": ControlStatus.PASS,
    "FAILED": ControlStatus.FAIL, "FAIL": ControlStatus.FAIL, "alarm": ControlStatus.FAIL,
    "WARNING": ControlStatus.PENDING, "info": ControlStatus.NOT_APPLICABLE,
    "skip": ControlStatus.NOT_APPLICABLE, "NOT_AVAILABLE": ControlStatus.NOT_APPLICABLE,
}
_SEVERITY = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW, "INFORMATIONAL": Severity.INFO, "INFO": Severity.INFO,
}


def _status(v: str) -> ControlStatus:
    return _STATUS.get(str(v), _STATUS.get(str(v).upper(), ControlStatus.ERROR))


def _severity(v: str) -> Severity:
    return _SEVERITY.get(str(v).upper(), Severity.MEDIUM)


class IngestionService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.svc = AssessmentService(db)

    # ── AWS Security Hub (ASFF) ──
    def from_security_hub(self, tenant_id: str, max_findings: int = 100) -> Dict[str, Any]:
        import boto3
        from app.config import settings
        client = boto3.client("securityhub", region_name=settings.aws_region)
        ingested, skipped = 0, 0
        paginator = client.get_paginator("get_findings")
        for page in paginator.paginate(MaxResults=min(max_findings, 100)):
            for f in page.get("Findings", []):
                if self._ingest_asff(tenant_id, f):
                    ingested += 1
                else:
                    skipped += 1
                if ingested >= max_findings:
                    return {"ingested": ingested, "skipped": skipped}
        return {"ingested": ingested, "skipped": skipped}

    def _ingest_asff(self, tenant_id: str, f: Dict[str, Any]) -> bool:
        comp = f.get("Compliance", {}) or {}
        control_id = comp.get("SecurityControlId") or f.get("GeneratorId") or f.get("Title", "UNKNOWN")
        status = _status(comp.get("Status", "WARNING"))
        sev = _severity((f.get("Severity", {}) or {}).get("Label", "MEDIUM"))
        resources = f.get("Resources", []) or []
        asset = resources[0].get("Id") if resources else None
        result = self.svc.record_external_finding(
            tenant_id=tenant_id, framework="NIST", control_id=control_id,
            source_system="SECURITYHUB", asset_id=asset, status=status, severity=sev,
            description=f.get("Title", "")[:480], raw={"asff_id": f.get("Id"), "title": f.get("Title")},
            external_id=f.get("Id", ""),
        )
        return result is not None

    # ── Prowler / Steampipe / Powerpipe JSON ──
    def from_report(self, tenant_id: str, source_label: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        ingested, skipped = 0, 0
        for item in findings:
            # accept several common field spellings across tools
            control_id = (item.get("control_id") or item.get("check_id") or item.get("control")
                          or item.get("CheckID") or "UNKNOWN")
            raw_status = (item.get("status") or item.get("result") or item.get("Status") or "")
            asset = (item.get("asset_id") or item.get("resource") or item.get("resource_id")
                     or item.get("ResourceId"))
            sev = item.get("severity") or item.get("Severity") or "MEDIUM"
            ext_id = str(item.get("id") or item.get("finding_id")
                         or f"{control_id}:{asset}:{raw_status}")
            res = self.svc.record_external_finding(
                tenant_id=tenant_id, framework=item.get("framework", "NIST"),
                control_id=str(control_id), source_system=source_label.upper(),
                asset_id=asset, status=_status(raw_status), severity=_severity(sev),
                description=str(item.get("description") or item.get("title") or control_id)[:480],
                raw=item, external_id=ext_id,
            )
            if res is not None:
                ingested += 1
            else:
                skipped += 1
        return {"ingested": ingested, "skipped": skipped}
