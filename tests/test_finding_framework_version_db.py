"""findings.framework_version column (needs SQLAlchemy — runs in CI)."""
from __future__ import annotations

from sqlalchemy import select


def test_finding_pins_framework_version(db_session):
    from app.models import ControlStatus, Finding, Severity
    from app.services.assessment import AssessmentService
    AssessmentService(db_session).record_external_finding(
        tenant_id="tv", framework="NIST", control_id="AC-2", source_system="TEST",
        asset_id="a", status=ControlStatus.FAIL, severity=Severity.HIGH, external_id="e1")
    db_session.commit()
    f = db_session.execute(select(Finding).where(Finding.tenant_id == "tv")).scalar_one()
    assert f.framework_version == "rev5"   # NIST 800-53 rev5 pinned
