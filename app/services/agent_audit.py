"""Agent identity + append-only, tamper-evident agent-decision log.

Answers the governance question the architecture review flags (Singapore IMDA /
NIST CAISI): *which agent acted under whose authorization*. Every autonomous or
assistive action — an LLM proposing a policy, an extractor asserting a concept — is
attributed to a registered `AgentIdentity` and appended to a hash-chained log, so
the trail can be independently verified and no entry silently altered or removed.

The chain hash is a pure function (`record_hash`) so it is unit-testable without a
database; the DB helpers wrap it.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

# NOTE: SQLAlchemy and the ORM models are imported lazily inside the DB helpers so
# the pure chain hash (record_hash) stays importable without a database present.


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).isoformat()


def _payload(*, tenant_id: str, agent_id: str, agent_name: str, action: str,
             target: str | None, on_behalf_of: str | None, confidence: float | None,
             outcome: str, detail: dict | None, created_at: datetime) -> dict[str, Any]:
    # The exact, order-independent view of a record that the chain hash protects.
    return {
        "tenant_id": tenant_id, "agent_id": agent_id, "agent_name": agent_name,
        "action": action, "target": target, "on_behalf_of": on_behalf_of,
        "confidence": confidence, "outcome": outcome, "detail": detail,
        "created_at": _iso(created_at),
    }


def record_hash(prev_hash: str | None, payload: dict[str, Any]) -> str:
    """sha256(prev_hash || canonical(payload)). Pure and deterministic."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(((prev_hash or "") + "\n" + body).encode("utf-8")).hexdigest()


def register_agent(db: Any, *, name: str, kind: str,
                   model: str | None = None) -> Any:
    """Get-or-create a verifiable agent identity (idempotent by name+kind)."""
    from sqlalchemy import select

    from app.models import AgentIdentity
    a = db.execute(select(AgentIdentity).where(
        AgentIdentity.name == name, AgentIdentity.kind == kind)).scalar_one_or_none()
    if a:
        return a
    a = AgentIdentity(name=name, kind=kind, model=model)
    db.add(a)
    db.flush()
    return a


def record_action(db: Any, *, tenant_id: str, agent: Any, action: str,
                  target: str | None = None, on_behalf_of: str | None = None,
                  confidence: float | None = None, outcome: str = "done",
                  detail: dict | None = None) -> Any:
    """Append a tamper-evident action to the log, chained to the tenant's last one."""
    from sqlalchemy import desc, select

    from app.models import AgentAction
    prev = db.execute(
        select(AgentAction).where(AgentAction.tenant_id == tenant_id)
        .order_by(desc(AgentAction.created_at), desc(AgentAction.id)).limit(1)
    ).scalar_one_or_none()
    prev_hash = prev.record_hash if prev else None
    created = datetime.now(UTC)
    payload = _payload(tenant_id=tenant_id, agent_id=agent.id, agent_name=agent.name,
                       action=action, target=target, on_behalf_of=on_behalf_of,
                       confidence=confidence, outcome=outcome, detail=detail,
                       created_at=created)
    act = AgentAction(
        tenant_id=tenant_id, agent_id=agent.id, agent_name=agent.name, action=action,
        target=target, on_behalf_of=on_behalf_of, confidence=confidence, outcome=outcome,
        detail=detail, prev_hash=prev_hash, record_hash=record_hash(prev_hash, payload),
        created_at=created)
    db.add(act)
    db.flush()
    return act


def list_actions(db: Any, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
    from sqlalchemy import desc, select

    from app.models import AgentAction
    rows = db.execute(
        select(AgentAction).where(AgentAction.tenant_id == tenant_id)
        .order_by(desc(AgentAction.created_at)).limit(limit)
    ).scalars().all()
    return [{
        "id": r.id, "agent": r.agent_name, "agent_id": r.agent_id, "action": r.action,
        "target": r.target, "on_behalf_of": r.on_behalf_of, "confidence": r.confidence,
        "outcome": r.outcome, "detail": r.detail, "record_hash": r.record_hash,
        "prev_hash": r.prev_hash, "created_at": _iso(r.created_at),
    } for r in rows]


def verify_chain(db: Any, tenant_id: str) -> dict[str, Any]:
    """Recompute every record's hash and check its prev linkage — detects any
    tampered or removed entry."""
    from sqlalchemy import select

    from app.models import AgentAction
    rows = db.execute(
        select(AgentAction).where(AgentAction.tenant_id == tenant_id)).scalars().all()
    by_hash = {r.record_hash: r for r in rows}
    broken: list[str] = []
    for r in rows:
        payload = _payload(tenant_id=r.tenant_id, agent_id=r.agent_id, agent_name=r.agent_name,
                           action=r.action, target=r.target, on_behalf_of=r.on_behalf_of,
                           confidence=r.confidence, outcome=r.outcome, detail=r.detail,
                           created_at=r.created_at)
        if record_hash(r.prev_hash, payload) != r.record_hash:
            broken.append(r.id)          # payload doesn't match its hash
        elif r.prev_hash and r.prev_hash not in by_hash:
            broken.append(r.id)          # dangling chain link (predecessor removed)
    return {"ok": not broken, "actions": len(rows), "broken": broken}


__all__ = ["record_hash", "register_agent", "record_action", "list_actions", "verify_chain"]
