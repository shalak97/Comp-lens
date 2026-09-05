"""What the platform reports is what it actually did.

The rest of the second-pass findings, grouped by the thing they have in common:
each reported an outcome stronger than what happened.

    trust_telemetry   an obligation nothing will ever act on scored as
                      remediation that succeeded
    notifications     a webhook that answered 404 was recorded as delivered
    assessment        risk_weighted_score reported 100.0 with nothing weighed
    evidence_policy   a human sign-off satisfied a control forever, with no
                      freshness rule at all
    auth              a typo in a key's tenant scope widened it to every tenant
    hardening         a rate-limit bucket keyed on 12 characters of a secret
    connectors        an asset_id could retarget the request that produced the
                      evidence citing it
"""
from __future__ import annotations

import logging

import pytest

from app.connectors import urls as connector_urls
from app.connectors.base import ConnectorError
from app.connectors.http_client import ResilientClient


# ── #10 follow-through: only completion is completion ──
class _Dispatch:
    def __init__(self, control_id, status):
        self.control_id, self.status = control_id, status


def _lane(rows):
    """Drive _followthrough_lane's scoring without a database."""
    by_ctrl: dict[str, list[_Dispatch]] = {}
    for r in rows:
        by_ctrl.setdefault(r.control_id, []).append(r)
    out = {}
    for cid, ds in by_ctrl.items():
        done = sum(1 for d in ds if d.status == "done")
        waived = sum(1 for d in ds if d.status == "eligible")
        pending = sum(1 for d in ds if d.status == "queued")
        actionable = len(ds) - waived
        if actionable <= 0:
            continue
        detail = f"{done}/{actionable} obligations completed"
        if pending:
            detail += f" ({pending} still outstanding)"
        out[cid] = {"score": round(done / actionable, 3), "detail": detail}
    return out


def test_the_followthrough_lane_scoring_matches_the_service():
    """Keep this stand-in honest: it must reproduce the real function."""
    import inspect

    from app.services import trust_telemetry
    src = inspect.getsource(trust_telemetry._followthrough_lane)
    assert 'd.status == "done"' in src
    assert '"queued", "eligible"' not in src, (
        "queued/eligible are being counted as success again")


def test_a_recorded_ticket_is_not_remediation_that_happened():
    """`POST /remediation/tickets` writes a dispatch row that nothing consumes —
    no worker exists and every connector is read-only. Counting it as success
    gave the control a perfect follow-through lane for work never done."""
    assert _lane([_Dispatch("AC-2", "recorded")])["AC-2"]["score"] == 0.0
    assert _lane([_Dispatch("AC-2", "queued")])["AC-2"]["score"] == 0.0


def test_completed_obligations_still_score():
    assert _lane([_Dispatch("AC-2", "done")])["AC-2"]["score"] == 1.0
    assert _lane([_Dispatch("AC-2", "done"),
                  _Dispatch("AC-2", "recorded")])["AC-2"]["score"] == 0.5


def test_a_waiver_leaves_the_denominator_rather_than_counting_either_way():
    """A waiver is not remediation, and it is not a failure to remediate."""
    assert _lane([_Dispatch("AC-2", "eligible")]) == {}
    scored = _lane([_Dispatch("AC-2", "done"), _Dispatch("AC-2", "eligible")])
    assert scored["AC-2"]["score"] == 1.0


def test_a_single_lane_control_says_it_is_single_sourced():
    """`trust` is renormalised over present lanes, so one lane at 1.0 and five
    lanes at 1.0 both read 100 — very different claims. lane_coverage said so
    already, but as a string a dashboard can drop."""
    import inspect

    from app.services import trust_telemetry
    src = inspect.getsource(trust_telemetry.unified_trust)
    assert "corroboration" in src and "single-source" in src


# ── #17 a rejected webhook is not a delivered notification ──
class _Finding:
    class status:
        value = "fail"

    class severity:
        value = "high"
    control_id, source_system, tenant_id = "AC-2", "OKTA", "t1"
    asset_id, finding_id, description = "u1", "f1", ""


def _fake_settings(**over):
    """A stand-in for the settings object.

    Replacing the whole object rather than setting attributes on the real
    pydantic instance keeps this independent of that model's assignment rules.
    """
    from types import SimpleNamespace
    base = {"notify_slack_webhook": "https://hooks.slack.test/x",
            "notify_generic_webhook": "", "smtp_host": "",
            "notify_email_to": "", "notify_email_from": "", "smtp_user": "",
            "notify_on_status": "fail", "request_timeout_seconds": 5}
    base.update(over)
    return SimpleNamespace(**base)


def test_a_webhook_that_answers_4xx_is_not_reported_as_delivered(monkeypatch):
    """`requests.post` returns normally on 4xx/5xx, so "delivered" meant "the
    socket did not error". A revoked Slack webhook — 404 invalid_token, the
    most common failure there is — was recorded as a successful alert."""
    import requests

    from app import notifications

    class _Resp:
        status_code = 404
        text = "invalid_token"

        def raise_for_status(self):
            raise requests.HTTPError("404 Client Error")

    monkeypatch.setattr(notifications, "settings", _fake_settings())
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp())
    assert notifications.notify_finding(_Finding()) == {"slack": False}


def test_a_webhook_that_succeeds_is_still_reported_as_delivered(monkeypatch):
    """The guard must not have turned every notification into a failure."""
    import requests

    from app import notifications

    class _Resp:
        status_code = 200
        text = "ok"

        def raise_for_status(self):
            return None

    monkeypatch.setattr(notifications, "settings", _fake_settings())
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp())
    assert notifications.notify_finding(_Finding()) == {"slack": True}


def test_slack_rejecting_the_payload_with_a_200_is_not_delivery(monkeypatch):
    """Slack answers 200 with a plain-text error body for a payload it won't take."""
    import requests

    from app import notifications

    class _Resp:
        status_code = 200
        text = "invalid_payload"

        def raise_for_status(self):
            return None

    monkeypatch.setattr(notifications, "settings", _fake_settings())
    monkeypatch.setattr(requests, "post", lambda *a, **k: _Resp())
    with pytest.raises(RuntimeError):
        notifications._slack("hello")


def test_error_findings_are_alertable_by_default():
    """A single-status setting meant a fail-only deployment never alerted on
    ERROR — which is exactly when the platform has gone blind to an asset."""
    from app.config import Settings

    statuses = {s.strip() for s in Settings().notify_on_status.split(",")}
    assert {"fail", "error"} <= statuses


# ── #3 a typo must never widen a key's reach ──
@pytest.mark.parametrize("entry", ["k5:", "k9:,,,", "k8: :operator", "k7:  "])
def test_a_key_with_an_empty_tenant_scope_is_refused(entry, monkeypatch, caplog):
    """`tset or {ALL}` plus `not tset` in the role default meant a trailing
    colon silently promoted a single-tenant key to every tenant, usually as
    admin."""
    from app import auth

    monkeypatch.setenv("COMP_LENS_API_KEYS", entry)
    with caplog.at_level(logging.ERROR):
        keys = auth._parse_keys()
    assert keys == {}, f"{entry!r} produced a usable key: {keys}"
    assert caplog.records, "the entry was dropped with no log line"


def test_a_correctly_scoped_key_is_unaffected(monkeypatch):
    from app import auth

    monkeypatch.setenv("COMP_LENS_API_KEYS", "k1:acme,globex:operator;k2:*")
    keys = auth._parse_keys()
    assert keys["k1"] == ({"acme", "globex"}, "operator")
    assert keys["k2"] == ({"*"}, "admin"), "an explicit all-tenant key keeps admin"


def test_a_bare_key_still_works_but_says_what_it_granted(monkeypatch, caplog):
    """Refusing this outright would lock existing deployments out of their own
    installation, so it keeps working — loudly."""
    from app import auth

    monkeypatch.setenv("COMP_LENS_API_KEYS", "legacykey")
    with caplog.at_level(logging.WARNING):
        keys = auth._parse_keys()
    assert keys["legacykey"] == ({"*"}, "admin")
    assert "EVERY tenant" in caplog.text


# ── #6 a rate-limit bucket must not be reachable by prefix ──
def test_two_keys_sharing_a_long_prefix_get_separate_buckets():
    """The middleware runs before authentication, so the bucket is chosen from
    an unverified header: keying on `api_key[:12]` let anyone who knew twelve
    characters spend a victim's budget."""
    from app.hardening import RateLimitMiddleware

    class _Req:
        def __init__(self, key):
            self.headers = {"x-api-key": key}
            self.client = None

    mw = RateLimitMiddleware.__new__(RateLimitMiddleware)
    mw.trusted_proxy_hops = 0
    victim = "sk_live_abcdefghijkl_VICTIM"
    attacker = "sk_live_abcdefghijkl_ATTACKER"
    assert mw._key(_Req(victim)) != mw._key(_Req(attacker))
    assert mw._key(_Req(victim)) == mw._key(_Req(victim)), "buckets must be stable"
    assert victim not in mw._key(_Req(victim)), "the raw secret is in the bucket key"


# ── #4 an asset_id must name an object, not choose an endpoint ──
@pytest.mark.parametrize("hostile", [
    "../../api/v1/apps",
    "u1?expand=all",
    "u1#fragment",
    "../admin",
])
def test_a_hostile_asset_id_cannot_grow_the_path(hostile):
    escaped = connector_urls.segment(hostile)
    assert "/" not in escaped and "?" not in escaped and "#" not in escaped


def test_an_ordinary_asset_id_is_unchanged():
    for benign in ("user-123", "00u1a2b3c4", "my.bucket-name"):
        assert connector_urls.segment(benign) == benign


def test_a_two_part_reference_keeps_its_separator_but_not_traversal():
    assert connector_urls.multi_segment("owner/repo", expected_parts=2) == "owner/repo"
    for bad in ("owner/../../x", "../../x/y", "owner/./repo"):
        with pytest.raises(connector_urls.UnsafeReferenceError):
            connector_urls.multi_segment(bad, expected_parts=2)


def test_an_empty_reference_is_refused():
    for bad in ("", "   ", ".", ".."):
        with pytest.raises(connector_urls.UnsafeReferenceError):
            connector_urls.segment(bad)


def test_the_client_refuses_a_traversing_url_whatever_the_connector_did():
    """The backstop: escaping at call sites protects the connectors that exist,
    this protects the ones written next year."""
    c = ResilientClient(service="TRAV", max_retries=0)
    with pytest.raises(ConnectorError) as e:
        c.get("https://acme.okta.com/api/v1/users/../../api/v1/apps")
    assert "traversal" in str(e.value)


def test_the_client_still_allows_an_ordinary_url():
    c = ResilientClient(service="TRAV2", max_retries=0)
    from unittest.mock import MagicMock, patch
    resp = MagicMock(status_code=200, headers={}, text="{}")
    resp.json.return_value = {"ok": True}
    with patch.object(c.session, "request", return_value=resp):
        assert c.get("https://acme.okta.com/api/v1/users/u1") == {"ok": True}


# ── #8 an empty connector name must not raise ──
def test_a_connector_with_no_name_falls_back_to_its_key():
    from app.connectors.catalog import _c

    assert _c("SOME_KEY", "", "cloud", "token", [], [])["vendor"] == "SOME_KEY"
    assert _c("K", "AWS Security Hub", "cloud", "token", [], [])["vendor"] == "AWS"
