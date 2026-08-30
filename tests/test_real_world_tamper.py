"""Real-world scenario tests: an insider tampering with the audit trail.

Comp-Lens sells two tamper-evidence guarantees: the hash-chained agent decision
log, and the evidence store's record/telemetry hashes. The scenarios worth
testing are the ones an actual adversary would attempt — not "does the happy
path verify", but "what does someone with database access do to hide what
happened, and does verification catch it".

The realistic threat model here is an insider with write access to the
application database (a DBA, a compromised service account, or an operator
covering their tracks before an incident review) who wants a clean
verification report afterwards.
"""
from __future__ import annotations

from sqlalchemy import select


def _log_three_actions(db):
    """Three agent decisions, chained in order — a normal day's activity."""
    from app.services.agent_audit import record_action, register_agent

    agent = register_agent(db, name="policy-author", kind="llm", model="test-model")
    a1 = record_action(db, tenant_id="acme", agent=agent, action="propose_policy",
                       target="AC-2", confidence=0.91, outcome="done")
    a2 = record_action(db, tenant_id="acme", agent=agent, action="propose_policy",
                       target="SC-7", confidence=0.72, outcome="done")
    a3 = record_action(db, tenant_id="acme", agent=agent, action="approve_exception",
                       target="SC-28", confidence=0.55, outcome="done")
    db.commit()
    return a1, a2, a3


# ──────────────────────────────────────────────────────────────────────────
# What the chain already catches
# ──────────────────────────────────────────────────────────────────────────
def test_clean_log_verifies(db_session):
    from app.services.agent_audit import verify_chain

    _log_three_actions(db_session)
    report = verify_chain(db_session, "acme")
    assert report["ok"] is True
    assert report["actions"] == 3
    assert report["broken"] == []


def test_editing_a_record_is_detected(db_session):
    """Changing a logged decision after the fact must break its hash."""
    from app.models import AgentAction
    from app.services.agent_audit import verify_chain

    _, a2, _ = _log_three_actions(db_session)

    # An operator rewrites history: the low-confidence call becomes a confident one.
    row = db_session.get(AgentAction, a2.id)
    row.confidence = 0.99
    db_session.commit()

    report = verify_chain(db_session, "acme")
    assert report["ok"] is False
    assert a2.id in report["broken"]


def test_deleting_a_middle_record_is_detected(db_session):
    """Removing an entry from the middle orphans its successor's prev_hash."""
    from app.models import AgentAction
    from app.services.agent_audit import verify_chain

    _, a2, a3 = _log_three_actions(db_session)

    db_session.delete(db_session.get(AgentAction, a2.id))
    db_session.commit()

    report = verify_chain(db_session, "acme")
    assert report["ok"] is False, "a removed middle entry must break the chain"
    assert a3.id in report["broken"]


# ──────────────────────────────────────────────────────────────────────────
# What an adversary would actually do
# ──────────────────────────────────────────────────────────────────────────
def test_deleting_the_most_recent_record_is_detected(db_session):
    """Truncating the newest entries is the obvious way to hide a bad decision.

    An operator whose agent just auto-approved something it shouldn't have
    deletes the last entry before the incident review. Nothing dangles: every
    remaining record still has its predecessor present, and every hash still
    recomputes correctly. verify_chain walks the set and checks each record's
    prev_hash exists *somewhere* in that same set, so a truncated tail is
    indistinguishable from a log that simply ended there.

    A tamper-evident log that cannot detect truncation only protects entries an
    attacker has no reason to touch — the interesting ones are always the most
    recent.
    """
    from app.models import AgentAction
    from app.services.agent_audit import verify_chain

    _, _, a3 = _log_three_actions(db_session)
    before = verify_chain(db_session, "acme")
    assert before["ok"] is True and before["actions"] == 3

    db_session.delete(db_session.get(AgentAction, a3.id))
    db_session.commit()

    report = verify_chain(db_session, "acme")
    assert report["ok"] is False, (
        "deleting the newest agent action left the chain reporting 'Verified' — "
        "the log can be silently truncated")


def test_replacing_the_tail_record_is_detected(db_session):
    """The stronger version: swap the last decision for a flattering one.

    Delete the real tail, then append a replacement carrying the same
    prev_hash. Its own hash is computed honestly over the forged payload, so
    the recompute check passes, and its prev_hash still resolves. The forged
    entry is now the record of what the agent decided.
    """
    from app.models import AgentAction
    from app.services.agent_audit import record_hash, verify_chain

    _, a2, a3 = _log_three_actions(db_session)
    stolen_prev = a3.prev_hash
    tenant, agent_id, agent_name = a3.tenant_id, a3.agent_id, a3.agent_name

    db_session.delete(db_session.get(AgentAction, a3.id))
    db_session.flush()

    from datetime import UTC, datetime

    from app.services.agent_audit import _payload

    created = datetime.now(UTC)
    forged_payload = _payload(
        tenant_id=tenant, agent_id=agent_id, agent_name=agent_name,
        action="approve_exception", target="SC-28", on_behalf_of=None,
        confidence=0.99, outcome="done", detail={"note": "reviewed and approved"},
        created_at=created)
    forged = AgentAction(
        tenant_id=tenant, agent_id=agent_id, agent_name=agent_name,
        action="approve_exception", target="SC-28", on_behalf_of=None,
        confidence=0.99, outcome="done", detail={"note": "reviewed and approved"},
        prev_hash=stolen_prev, record_hash=record_hash(stolen_prev, forged_payload),
        created_at=created)
    db_session.add(forged)
    db_session.commit()

    report = verify_chain(db_session, "acme")
    assert report["ok"] is False, (
        "the tail record was replaced with a forged one carrying the same "
        "prev_hash and the chain still reports 'Verified'")
    assert a2 is not None  # (a2 remains the legitimate predecessor)


# ──────────────────────────────────────────────────────────────────────────
# Evidence store tampering — the auditor's other guarantee
# ──────────────────────────────────────────────────────────────────────────
def test_editing_evidence_metadata_is_detected(db_session):
    """Flipping a stored verdict from fail to pass must not verify."""
    from app.models import ControlStatus, EvidenceMeta, Severity
    from app.services.assessment import AssessmentService
    from app.services.integrity import IntegrityService

    AssessmentService(db_session).record_external_finding(
        tenant_id="tamper-ev", framework="NIST", control_id="SC-28",
        source_system="TEST", asset_id="bucket-1", status=ControlStatus.FAIL,
        severity=Severity.HIGH, external_id="ev-1")
    db_session.commit()
    assert IntegrityService(db_session).verify("tamper-ev")["intact"] is True

    row = db_session.execute(
        select(EvidenceMeta).where(EvidenceMeta.tenant_id == "tamper-ev")).scalar_one()
    row.status = ControlStatus.PASS
    db_session.commit()

    report = IntegrityService(db_session).verify("tamper-ev")
    assert report["intact"] is False
    assert report["broken"][0]["reason"] == "metadata_tampered"


def test_evidence_artifact_deleted_from_the_store_is_detected(db_session, monkeypatch):
    """If the stored artifact disappears, verification must say so rather than
    reporting the record as intact."""
    from app.models import ControlStatus, Severity
    from app.services import integrity as integrity_mod
    from app.services.assessment import AssessmentService
    from app.services.integrity import IntegrityService

    AssessmentService(db_session).record_external_finding(
        tenant_id="tamper-gone", framework="NIST", control_id="SC-28",
        source_system="TEST", asset_id="bucket-2", status=ControlStatus.FAIL,
        severity=Severity.HIGH, external_id="ev-2")
    db_session.commit()

    # the artifact is gone from the store (deleted object / wiped volume)
    monkeypatch.setattr(integrity_mod.evidence_store, "stored_hashes",
                        lambda tenant_id: {})

    report = IntegrityService(db_session).verify("tamper-gone")
    assert report["intact"] is False
    assert report["broken"][0]["reason"] == "missing_in_store"
