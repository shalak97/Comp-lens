"""Agent identity + decision log DB behaviour (needs SQLAlchemy — runs in CI)."""
from __future__ import annotations


def test_register_is_idempotent(db_session):
    from app.services.agent_audit import register_agent
    a = register_agent(db_session, name="policy-author", kind="deterministic", model="m")
    b = register_agent(db_session, name="policy-author", kind="deterministic", model="m")
    db_session.commit()
    assert a.id == b.id


def test_chain_records_and_verifies(db_session):
    from app.services.agent_audit import record_action, register_agent, verify_chain
    agent = register_agent(db_session, name="extractor", kind="llm", model="claude")
    a1 = record_action(db_session, tenant_id="ta", agent=agent, action="extract",
                       target="AC-2", on_behalf_of="alice", confidence=0.9)
    a2 = record_action(db_session, tenant_id="ta", agent=agent, action="extract",
                       target="SC-28", confidence=0.7)
    db_session.commit()
    assert a2.prev_hash == a1.record_hash            # chained
    assert verify_chain(db_session, "ta")["ok"] is True


def test_tampering_is_detected(db_session):
    from app.services.agent_audit import record_action, register_agent, verify_chain
    agent = register_agent(db_session, name="extractor", kind="llm")
    record_action(db_session, tenant_id="tb", agent=agent, action="extract", target="AC-2")
    a2 = record_action(db_session, tenant_id="tb", agent=agent, action="extract", target="SC-7")
    db_session.commit()
    # tamper with a stored field without updating the hash
    a2.target = "SC-999"
    db_session.commit()
    res = verify_chain(db_session, "tb")
    assert res["ok"] is False
    assert a2.id in res["broken"]


def test_policy_authoring_logs_an_agent_action(db_session):
    from app.models import PolicyDraftRequest
    from app.services.agent_audit import list_actions
    from app.services.policy_authoring import PolicyAuthoringService
    req = PolicyDraftRequest(tenant_id="tc", control_id="AC-7",
                             description="require mfa for all admins")
    PolicyAuthoringService(db_session).draft(req)
    db_session.commit()
    actions = list_actions(db_session, "tc")
    assert len(actions) == 1
    assert actions[0]["action"] == "propose_policy"
    assert actions[0]["agent"] == "policy-author"
    assert actions[0]["target"] == "AC-7"
