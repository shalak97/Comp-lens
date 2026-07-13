"""Compliance report export: CSV and PDF audit packages.

CSV uses the stdlib. PDF uses reportlab (a real, dependency-light generator).
Both stream bytes back through the API as downloads.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.frameworks import crosswalk_for
from app.models import Finding
from app.services.assessment import AssessmentService


class ReportService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def _findings(self, tenant_id: str) -> list[Finding]:
        return AssessmentService(self.db).list_findings(tenant_id, limit=500)

    def csv_bytes(self, tenant_id: str) -> bytes:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["finding_id", "control_id", "source_system", "asset_id", "status",
                    "severity", "lifecycle", "owner", "created_at", "frameworks"])
        for f in self._findings(tenant_id):
            cw = crosswalk_for(f.control_id)
            fw = "; ".join(f"{k}:{','.join(v)}" for k, v in cw.items())
            w.writerow([f.finding_id, f.control_id, f.source_system, f.asset_id or "",
                        f.status.value, f.severity.value, f.lifecycle.value, f.owner or "",
                        f.created_at.isoformat(), fw])
        return buf.getvalue().encode("utf-8")

    def oscal_results(self, tenant_id: str) -> dict:
        """Export findings as a minimal OSCAL assessment-results document.

        OSCAL (NIST's Open Security Controls Assessment Language) is the
        machine-readable interchange format other GRC tools and auditors ingest.
        This is a lightweight, recognizable subset — not a full validated SSP.
        """
        import uuid as _uuid

        from app.frameworks import crosswalk_for
        findings = self._findings(tenant_id)
        observations, findings_out = [], []
        for f in findings:
            obs_uuid = str(_uuid.uuid4())
            observations.append({
                "uuid": obs_uuid, "description": f.description or f.control_id,
                "methods": ["TEST"],
                "subjects": [{"subject-uuid": f.asset_id or "n/a", "type": "inventory-item"}],
                "collected": f.created_at.isoformat(),
            })
            findings_out.append({
                "uuid": f.finding_id,
                "title": f"{f.control_id} on {f.source_system}",
                "target": {"type": "objective-id", "target-id": f.control_id,
                           "status": {"state": "satisfied" if f.status.value == "pass" else "not-satisfied"}},
                "related-observations": [{"observation-uuid": obs_uuid}],
                "props": [{"name": "framework-mapping", "value": str(crosswalk_for(f.control_id))}],
            })
        return {
            "assessment-results": {
                "uuid": str(_uuid.uuid4()),
                "metadata": {"title": f"Comp-Lens Assessment Results — {tenant_id}",
                             "version": "1.0", "oscal-version": "1.1.2"},
                "results": [{
                    "uuid": str(_uuid.uuid4()), "title": "Automated assessment",
                    "start": findings[0].created_at.isoformat() if findings else None,
                    "observations": observations, "findings": findings_out,
                }],
            }
        }

    def pdf_bytes(self, tenant_id: str) -> bytes:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        findings = self._findings(tenant_id)
        summary = AssessmentService(self.db).compliance_summary(tenant_id)

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter, title="Comp-Lens Compliance Report")
        styles = getSampleStyleSheet()
        story = []
        story.append(Paragraph("Comp-Lens Compliance Report", styles["Title"]))
        story.append(Paragraph(f"Tenant: {tenant_id}", styles["Normal"]))
        story.append(Paragraph(f"Generated: {datetime.now(UTC).isoformat()}", styles["Normal"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph(
            f"Compliance score: <b>{summary['compliance_score']}%</b> "
            f"({summary['by_status']['pass']} pass / {summary['by_status']['fail']} fail "
            f"/ {summary['total']} total)", styles["Heading2"]))
        story.append(Spacer(1, 12))

        data = [["Control", "Source", "Asset", "Status", "Severity", "Lifecycle"]]
        for f in findings[:200]:
            data.append([f.control_id, f.source_system, (f.asset_id or "")[:28],
                         f.status.value, f.severity.value, f.lifecycle.value])
        table = Table(data, repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
        ]
        # color the status cells
        for i, f in enumerate(findings[:200], start=1):
            col = {"pass": "#0a7d3a", "fail": "#b91c1c"}.get(f.status.value)
            if col:
                style.append(("TEXTCOLOR", (3, i), (3, i), colors.HexColor(col)))
        table.setStyle(TableStyle(style))
        story.append(table)
        doc.build(story)
        return buf.getvalue()
