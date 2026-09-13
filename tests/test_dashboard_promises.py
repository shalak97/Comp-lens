"""The dashboard must not claim something it does not do.

A coverage audit of the console (UI-COVERAGE.md, tools/ui_coverage.py) found
that 60 of the app's 166 operations were wired into it. Most of the rest
legitimately need no UI. What mattered were five places where the interface
*said* something untrue — a success toast for a no-op, an instruction with no
control behind it, a link to a placeholder, totals computed from one page, and
a view reading fields the API does not return.

Those are all one failure mode: the UI asserting knowledge it does not have.
It is the same defect this codebase keeps finding on the server side — an
absent signal becoming a definite value — and it is worth a gate, because every
one of these passed every test that existed. They were invisible precisely
because nothing errored: a green toast, a zero, a blank chip.

These are static assertions against the shipped file, in the same spirit as
test_dashboard_xss.py. What they guard is the shape of the promise, not the
pixels. The behavioural half needs a browser and is in tools/ui_coverage.py
(every view renders) and tools/ui_interactions.py (every new control fires and
sends what it says it sends).
"""
from __future__ import annotations

import pathlib
import re

DASHBOARD = (pathlib.Path(__file__).resolve().parent.parent
             / "app" / "static" / "dashboard.html")
HTML = DASHBOARD.read_text()


def _sanity():
    """Every assertion below is 'this substring is present/absent'. If the file
    stopped being the dashboard, absence would read as success on half of them,
    so the shape is checked first."""
    assert "RENDER.policy" in HTML and "ACTION_NAMES" in HTML, (
        "this is not the dashboard; every absence check below would pass "
        "vacuously")


def _action_names() -> set[str]:
    block = re.search(r"ACTION_NAMES = new Set\(\[(.*?)\]\)", HTML, re.S)
    assert block, "the action allowlist is gone"
    return set(re.findall(r'"([^"]+)"', block.group(1)))


# ── the PDF button ──────────────────────────────────────────────────────────

def test_inserting_a_pdf_sends_the_document_not_just_its_name():
    """It used to POST {name: f.name} to /policies/import and toast
    'Imported "x.pdf" as a draft policy'. That endpoint acknowledges a bare name
    without importing anything — it even replies "supply 'yaml' to validate and
    load a policy" — so the file's bytes were never read, nothing was stored,
    and the UI said otherwise. /v1/documents/upload is the endpoint that takes
    the document.
    """
    _sanity()
    handler = re.search(r"function insertPolicyPdf\(input\)\{(.*?)\n\}", HTML, re.S)
    assert handler, "insertPolicyPdf is gone"
    body = handler.group(1)
    assert "/v1/documents/upload" in body, (
        "the PDF button does not send the document to /v1/documents/upload")
    assert "content_base64" in body, (
        "the request carries no file content, so nothing can be extracted "
        "from it — this is the original bug")
    assert "/policies/import" not in body, (
        "/policies/import takes policy YAML, not a document; posting a bare "
        "filename to it is acknowledged and does nothing")


def test_the_pdf_flow_does_not_announce_an_import():
    _sanity()
    handler = re.search(r"function insertPolicyPdf\(input\)\{(.*?)\n\}", HTML, re.S)
    assert "Imported" not in handler.group(1), (
        "the handler still reports an import; the endpoint it calls "
        "deliberately does not persist, and says so in persisted.reason")


def test_the_extraction_result_repeats_the_servers_own_non_persistence_note():
    """The server explains why extracted controls are not written to posture. A
    UI that paraphrases that into silence is how "reviewed evidence" and "a
    document mentioned this control" get confused."""
    _sanity()
    assert "persisted" in HTML and "Nothing was written to posture" in HTML, (
        "the extraction dialog no longer tells the reader that nothing was "
        "stored")


# ── instructions that need a control behind them ────────────────────────────

def test_the_audits_empty_state_has_a_way_to_create_an_audit():
    """The empty state has always said "Create one to start tracking evidence
    requests". Until this was fixed the dashboard had no action that created an
    audit at all, and POST /audits sat unreachable behind that sentence."""
    _sanity()
    assert "No audit engagements yet" in HTML, "the empty state is gone"
    assert "openNewAudit" in _action_names(), (
        "nothing in the allowlist opens a create-audit form, so the empty "
        "state instructs the reader to do something they cannot do")
    assert re.search(r'apiPOST\(withTenant\("/audits"\)', HTML), (
        "no call creates an audit")


def test_creating_an_audit_leaves_the_framework_default_alone():
    """An empty <select> yields "", and posting framework:"" overrides the
    server's own default rather than leaving it unset."""
    _sanity()
    submit = re.search(r"async function submitNewAudit\(\)\{(.*?)\n\}", HTML, re.S)
    assert submit, "submitNewAudit is gone"
    assert "if(fw)body.framework=fw" in submit.group(1).replace(" ", ""), (
        "the framework is sent unconditionally; an empty one blanks the "
        "server default")


# ── totals must not be counted off one page ─────────────────────────────────

def test_the_registers_ask_the_server_for_their_totals():
    """/grc/risks and /tprm/vendors return at most `limit` rows (default 100).
    The readout tiles and the 5x5 heat map were computed from that page and
    displayed as totals, so above 100 records every figure was wrong. Both
    registers have a /summary endpoint that counts every row."""
    _sanity()
    for path in ("/grc/risks/summary", "/tprm/vendors/summary"):
        assert path in HTML, f"{path} is not called; the tiles are counting one page"
    assert "function loadTotals(" in HTML, (
        "the helper that fetches server-side totals is gone")


def test_a_figure_derived_from_one_page_says_so():
    _sanity()
    assert "function partialNote(" in HTML, (
        "nothing marks a figure that could only be derived from the rows on "
        "screen")


# ── a view must read the shape its endpoint returns ─────────────────────────

def test_the_vendor_view_understands_the_api_shape():
    """GET /tprm/vendors returns stage / risk_tier / assessment_score /
    next_review; the view was written against the demo fixture's status / tier /
    score / review_due. Live, every row showed a blank tier, a trust score of 0,
    no certs and "Invalid Date" — and since `new Date(null) < Date.now()` is
    1970, every vendor was flagged review-overdue. Nothing errored. It just
    looked like a register full of zero-trust, overdue vendors.
    """
    _sanity()
    assert "function normVendors(" in HTML, (
        "nothing bridges the API's vendor shape to the shape this view reads")
    norm = re.search(r"function normVendors\(rows\)\{(.*?)\n\}", HTML, re.S).group(1)
    for field in ("risk_tier", "assessment_score", "next_review", "stage"):
        assert field in norm, f"normVendors ignores {field}"


def test_an_unassessed_vendor_is_not_scored_zero():
    """The through-line of this codebase: absent must not become a definite
    value. assessment_score is null until somebody assesses the vendor, and 0 is
    the worst score there is."""
    _sanity()
    norm = re.search(r"function normVendors\(rows\)\{(.*?)\n\}", HTML, re.S).group(1)
    assert "assessment_score==null?null" in norm.replace(" ", ""), (
        "a null assessment_score is being coerced to a number")
    assert "not assessed" in HTML, (
        "the table has no way to show that a vendor has no score yet")


def test_an_unscheduled_review_is_not_overdue():
    _sanity()
    assert "not scheduled" in HTML, (
        "a vendor with no review date still renders as a date, and an absent "
        "date parses as 1970 — which is always overdue")


# ── waivers ─────────────────────────────────────────────────────────────────

def test_waivers_have_a_view_because_the_product_says_they_matter():
    """The Reports view tells the reader that active exceptions are "excluded
    from the failing count", and the dashboard shipped a D.waivers demo fixture
    that no view read. So the product asserted that waivers exist and move the
    numbers, while giving nobody a way to see, grant or revoke one."""
    _sanity()
    assert "RENDER.waivers" in HTML, "there is no waivers view"
    assert '["waivers","Waivers"]' in HTML.replace(" ", ""), (
        "the waivers view is not in the navigation, so nothing reaches it")
    for name in ("openNewWaiver", "submitNewWaiver", "revokeWaiver"):
        assert name in _action_names(), f"{name} is not an allowed action"


def test_the_whole_waiver_lifecycle_is_reachable():
    _sanity()
    assert 'load(withTenant("/waivers")' in HTML, "waivers are never listed"
    assert 'apiPOST("/waivers"' in HTML, "no waiver can be granted"
    assert re.search(r'api\("/waivers/"\s*\+', HTML), "no waiver can be revoked"


def test_a_waiver_cannot_be_granted_without_an_approver_or_a_reason():
    """A waiver stops a control counting as failing. One with no named approver
    is an untracked gap wearing the costume of a decision."""
    _sanity()
    submit = re.search(r"async function submitNewWaiver\(\)\{(.*?)\n\}", HTML, re.S)
    assert submit, "submitNewWaiver is gone"
    body = submit.group(1)
    assert "if(!reason)" in body.replace(" ", ""), "a waiver can be granted with no reason"
    assert "if(!approver)" in body.replace(" ", ""), "a waiver can be granted with no approver"


def test_a_waiver_with_no_expiry_is_surfaced_rather_than_hidden():
    """An exception nobody revisits is how a temporary gap becomes permanent,
    and an open-ended waiver is the one case no reminder will ever catch."""
    _sanity()
    assert "No expiry set" in HTML, (
        "an open-ended waiver is not distinguished from one with a date")


# ── every action the markup names must exist and be allowed ─────────────────

def test_every_action_referenced_is_allowlisted_and_defined():
    """A button whose action is missing from ACTION_NAMES is dead: the
    delegated listener drops it silently, under a CSP that cannot report it.
    This is cheap to break when adding a view and invisible when broken."""
    _sanity()
    allowed = _action_names()
    referenced = set(re.findall(r'act\("([A-Za-z_$][\w$]*)"', HTML))
    assert not (referenced - allowed), (
        f"actions used in markup but not allowlisted: {sorted(referenced - allowed)}")
    declared = set(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", HTML))
    declared |= set(re.findall(r"window\.([A-Za-z_$][\w$]*)\s*=", HTML))
    missing = sorted(n for n in referenced if n not in declared)
    assert not missing, f"actions with no function behind them: {missing}"
