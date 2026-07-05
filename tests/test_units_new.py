"""Unit tests for the recently-added, under-covered modules: the guardrailed
crawler, unified trust telemetry, and the obligation dispatcher. Includes
regression tests for two issues found during this pass:

  BUG-1 (backend): crawler URL validation leaks UnicodeError (-> HTTP 500)
                   instead of a clean CrawlError (-> 400) for malformed hosts.
  These are marked xfail until fixed, so the suite stays green but the bug is
  documented and will flip to a failure the moment someone "fixes" it wrongly.
"""
import os

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("COMP_LENS_SECRET_KEY", "test-secret")
os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/complens_unit.db")

import pytest


@pytest.fixture(scope="module", autouse=True)
def _schema():
    """Ensure the full schema exists on whichever engine the app is bound to.
    Uses create_all (idempotent) rather than alembic upgrade, so it's safe when
    the full suite has already built the schema on a shared DB."""
    import app.models  # noqa: F401 — registers every model (incl. GRC/crawler) on Base
    from app.database import Base, engine
    Base.metadata.create_all(engine)
    yield


# ─────────────────────────── crawler guardrails ───────────────────────────
class TestCrawlerGuardrails:
    def test_ssrf_urls_rejected(self):
        from app.services.crawler import CrawlError, validate_target_url
        bad = [
            "http://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost/x",
            "http://10.0.0.1/internal",
            "http://[::1]/x",
            "ftp://example.com/x",
            "file:///etc/passwd",
        ]
        for u in bad:
            with pytest.raises(CrawlError):
                validate_target_url(u)

    def test_public_url_accepted(self):
        from app.services.crawler import validate_target_url
        assert validate_target_url("https://www.example.com/trust") == "www.example.com"

    def test_empty_and_garbage_rejected_cleanly(self):
        from app.services.crawler import CrawlError, validate_target_url
        for u in ["", "   ", "not-a-url", "https://"]:
            with pytest.raises(CrawlError):
                validate_target_url(u)

    @pytest.mark.xfail(reason="BUG-1: IDNA UnicodeError not normalised to CrawlError -> HTTP 500",
                       strict=True)
    def test_malformed_host_raises_crawlerror_not_unicodeerror(self):
        """A malformed host must surface as CrawlError (clean 400), never leak a
        raw UnicodeError (which becomes an unhandled 500 at the endpoint)."""
        from app.services.crawler import CrawlError, validate_target_url
        for u in ["http://.", "https://" + "a" * 300 + ".com"]:
            with pytest.raises(CrawlError):
                validate_target_url(u)


# ─────────────────────────── obligation dispatcher ───────────────────────────
class TestObligationNormalization:
    @pytest.mark.parametrize("raw,expected_proc", [
        ("open_jira_ticket", "open_ticket"),
        ("notify_security_slack", "notify"),
        ("open ticket", "open_ticket"),
        ("waiver-eligible", "waiver"),
        ("unknown_action", "unknown_action"),
    ])
    def test_string_obligations_route(self, raw, expected_proc):
        from app.policy_as_code.obligations import normalize_obligation
        assert normalize_obligation(raw)["procedure"] == expected_proc

    @pytest.mark.parametrize("raw", [None, 123, ["a"], {"no_procedure": 1}, {"procedure": ""}])
    def test_malformed_obligations_dont_crash(self, raw):
        from app.policy_as_code.obligations import normalize_obligation
        out = normalize_obligation(raw)
        assert "procedure" in out and "params" in out

    def test_notify_channel_inferred_from_name(self):
        from app.policy_as_code.obligations import normalize_obligation
        out = normalize_obligation("notify_security_slack")
        assert out["procedure"] == "notify"
        assert out["params"].get("channel") == "security"


# ─────────────────────────── unified trust telemetry ───────────────────────────
class TestUnifiedTrust:
    def test_empty_tenant_no_crash_no_divzero(self):
        """The weight-renormalisation must not divide by zero when a tenant has
        no signal in any lane."""
        from app.database import SessionLocal
        from app.services.trust_telemetry import unified_trust
        out = unified_trust(SessionLocal(), "tenant-with-no-data-xyz")
        assert out["unified_trust_score"] is None
        assert out["controls_scored"] == 0
        assert set(out["lanes_available"]) >= {"native", "policy", "enforcement"}

    def test_policy_lane_feeds_score(self):
        """A failing policy eval writes POLICY-AS-CODE posture, which the policy
        lane must pick up and fuse into a real score."""
        from app.database import SessionLocal
        from app.services import integration
        from app.services.trust_telemetry import unified_trust
        db = SessionLocal()
        tenant = "unit-trust-policy"
        integration.evaluate_policies_to_findings(
            db, tenant, {"AC-2": {"mfa_enforced": False, "dormant_accounts": 5}}, framework="NIST")
        out = unified_trust(db, tenant)
        assert out["controls_scored"] > 0
        assert out["lanes_available"]["policy"] > 0
        assert out["unified_trust_score"] is not None
        assert 0 <= out["unified_trust_score"] <= 100


# ─────────────────────────── enforcement ingestion ───────────────────────────
class TestEnforcementIngestion:
    @pytest.mark.parametrize("entry", [
        {},
        {"path": "other"},
        {"path": "envoy/authz/allow", "result": "notadict"},
        {"path": "envoy/authz/allow", "result": {"headers": None}},
    ])
    def test_malformed_decision_logs_dont_crash(self, entry):
        from app.services.enforcement import _ingest_entry
        _ingest_entry(entry)  # must not raise
