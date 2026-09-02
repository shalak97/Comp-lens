"""Reports must contain every finding, or say plainly that they do not.

`list_findings` is a paged API read and clamps to MAX_PAGE — correct for an
endpoint, which is meant to hand back one page. Reports were built on it, so
every export stopped at 500 findings and said nothing: the CSV, the OSCAL
assessment results, and — worst — the OSCAL POA&M, which is a formal document
an auditor treats as the tenant's complete statement of open findings. A POA&M
listing 500 of 2000 findings is not an incomplete report, it is a false one.

That is the same failure mode this codebase exists to prevent, one layer up:
claiming more than the evidence supports. So these tests build a tenant with
more findings than any internal limit and assert the exports carry all of them.

The PDF is deliberately different. It is a readable summary, not an interchange
format, and a 4000-row table is not something a person reads — so it caps the
detail table. The test for it therefore pins the honesty rather than the
completeness: when the cap bites, the document must say it bit.
"""
from __future__ import annotations

import csv
import io

import pytest

from app.models import ControlStatus, Severity
from app.services.assessment import MAX_PAGE, AssessmentService
from app.services.reporting import PDF_TABLE_ROWS, ReportService

#: Comfortably past MAX_PAGE and not a multiple of it, so a paging bug that
#: drops or repeats a boundary page shows up as a wrong count rather than
#: landing exactly on a page edge and looking fine.
TOTAL = MAX_PAGE * 2 + 37


@pytest.fixture
def loaded_tenant(db_session):
    """A tenant with more findings than any internal page limit."""
    from app.models import Finding

    tenant = "t-report-completeness"
    for i in range(TOTAL):
        db_session.add(Finding(
            finding_id=f"f-{i:05d}",
            tenant_id=tenant,
            run_id="run-completeness",
            framework="NIST",
            control_id="AC-2" if i % 2 else "AC-3",
            source_system="AWS",
            asset_id=f"asset-{i:05d}",
            # All open: a POA&M carries only unsatisfied findings, so an
            # all-failing estate is the case where "every finding must appear"
            # is an exact claim rather than one filtered down to a subset.
            status=ControlStatus.FAIL,
            severity=Severity.MEDIUM,
            description=f"finding {i}",
        ))
    db_session.commit()
    return tenant


def test_iter_findings_yields_every_row(db_session, loaded_tenant):
    """The primitive the reports rest on. If this truncates, they all do."""
    got = list(AssessmentService(db_session).iter_findings(loaded_tenant))
    assert len(got) == TOTAL
    assert len({f.finding_id for f in got}) == TOTAL, "paging returned duplicates"


def test_iter_findings_respects_the_control_filter(db_session, loaded_tenant):
    got = list(AssessmentService(db_session).iter_findings(loaded_tenant, control_id="AC-2"))
    assert got, "filter matched nothing"
    assert {f.control_id for f in got} == {"AC-2"}
    assert len(got) == TOTAL // 2


def test_list_findings_pages_without_gaps_or_repeats(db_session, loaded_tenant):
    """Ordering must be a total order.

    created_at is not unique — a bulk load writes many rows in the same
    microsecond — so without a tie-breaker the database may legitimately return
    a row on page 2 and again on page 3, or on neither. The pages then look
    fine individually and the union is wrong, which is exactly the kind of bug
    that only surfaces in a customer's export.
    """
    svc = AssessmentService(db_session)
    seen: list[str] = []
    for offset in range(0, TOTAL, MAX_PAGE):
        seen += [f.finding_id for f in svc.list_findings(loaded_tenant, limit=MAX_PAGE,
                                                         offset=offset)]
    assert len(seen) == TOTAL
    assert len(set(seen)) == TOTAL


def test_csv_export_contains_every_finding(db_session, loaded_tenant):
    raw = ReportService(db_session).csv_bytes(loaded_tenant).decode("utf-8")
    rows = list(csv.reader(io.StringIO(raw)))
    assert rows[0][0] == "finding_id"
    assert len(rows) - 1 == TOTAL
    assert len({r[0] for r in rows[1:]}) == TOTAL


def test_oscal_poam_lists_every_finding(db_session, loaded_tenant):
    """The formal deliverable. This is the one that must not be short."""
    poam = ReportService(db_session).oscal_poam(loaded_tenant)
    items = poam["plan-of-action-and-milestones"]["poam-items"]
    assert len(items) == TOTAL


def test_oscal_results_lists_every_finding(db_session, loaded_tenant):
    doc = ReportService(db_session).oscal_results(loaded_tenant)
    result = doc["assessment-results"]["results"][0]
    assert len(result["findings"]) == TOTAL
    assert len(result["observations"]) == TOTAL


def test_oscal_components_sees_every_source_system(db_session, loaded_tenant):
    """Derived from the full finding set, so a truncated read would drop whole
    source systems from the component definition — not just rows."""
    doc = ReportService(db_session).oscal_components(loaded_tenant)
    comps = doc["component-definition"]["components"]
    aws = next(c for c in comps if c["title"] == "AWS")
    reqs = aws["control-implementations"][0]["implemented-requirements"]
    # OSCAL control ids are lower-cased by the builder.
    assert {r["control-id"] for r in reqs} == {"ac-2", "ac-3"}


def test_reports_do_not_depend_on_the_api_page_limit(db_session, loaded_tenant):
    """A guard against the regression rather than the symptom.

    The bug was a report calling the paged read with an explicit limit. If
    someone reintroduces that, the counts above break — but only for a tenant
    over the limit, and only in a test that bothers to build one. This says the
    intent directly: the report path and the page limit are unrelated.
    """
    assert len(ReportService(db_session)._findings(loaded_tenant)) == TOTAL


def test_pdf_says_so_when_its_table_is_truncated(db_session, loaded_tenant):
    """The PDF may cap its table. It may not do so silently."""
    reportlab = pytest.importorskip("reportlab")
    assert reportlab
    pdf = ReportService(db_session).pdf_bytes(loaded_tenant)
    assert pdf.startswith(b"%PDF")
    assert TOTAL > PDF_TABLE_ROWS, "fixture no longer exercises the cap"
    # reportlab compresses page streams, so search the extracted text rather
    # than the raw bytes.
    text = _pdf_text(pdf)
    # Self-check first: if the extractor stops working, fail on that rather than
    # on the disclosure, so the failure message points at the right thing.
    assert "comp-lenscompliancereport" in text, "PDF text extraction found nothing"
    assert str(TOTAL) in text, "the PDF does not disclose the true finding count"
    assert "showingthefirst" in text


def _pdf_text(pdf: bytes) -> str:
    """Text of a reportlab PDF, without taking on a parser dependency.

    Page content streams are Flate-compressed, and the drawn strings are the
    parenthesised operands inside them. A line of prose can be split across
    several of those operands (kerning), so they are concatenated with no
    separator and matched against case- and whitespace-free — which is why the
    assertions above look for "showingthefirst".
    """
    import re
    import zlib

    out: list[str] = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", pdf, re.S):
        body = match.group(1)
        try:
            body = zlib.decompress(body)
        except zlib.error:
            pass  # reportlab can be configured not to compress; read it raw
        out += [m.group(1).decode("latin-1")
                for m in re.finditer(rb"\(((?:\\.|[^()\\])*)\)", body)]
    return "".join(out).replace(" ", "").replace("\\", "").lower()
