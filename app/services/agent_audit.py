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


def head_signature(tenant_id: str, head_hash: str, action_count: int) -> str:
    """HMAC over the chain tip, so the head cannot be repaired without the key.

    Uses the same server-side signing key as evidence signing. Pure function,
    kept here so the head can be verified without a database.
    """
    import hmac

    from app.services.evidence_sign import _key

    msg = f"{tenant_id}|{head_hash}|{action_count}".encode()
    return hmac.new(_key(), msg, hashlib.sha256).hexdigest()


def _upsert_head(db: Any, tenant_id: str, head_hash: str) -> None:
    """Advance the tenant's chain tip after an append."""
    from app.models import AgentChainHead

    head = db.get(AgentChainHead, tenant_id)
    count = (head.action_count if head else 0) + 1
    sig = head_signature(tenant_id, head_hash, count)
    if head:
        head.head_hash = head_hash
        head.action_count = count
        head.signature = sig
        head.updated_at = datetime.now(UTC)
    else:
        db.add(AgentChainHead(tenant_id=tenant_id, head_hash=head_hash,
                              action_count=count, signature=sig,
                              updated_at=datetime.now(UTC)))


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
    _upsert_head(db, tenant_id, act.record_hash)
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
    """Recompute every record's hash and check its linkage.

    Four distinct tampering shapes are checked, because hash-chaining alone
    only catches the first two:

      1. an edited record        -> its payload no longer matches its own hash
      2. a removed middle record -> its successor's prev_hash dangles
      3. a removed TAIL record   -> nothing dangles, so this is caught by
                                    comparing against the signed chain head
      4. a forked chain          -> two records claiming the same predecessor

    (3) is the one that matters most in practice: the entries an attacker wants
    gone are always the most recent ones, and before the head was recorded a
    truncated log verified as clean.
    """
    from sqlalchemy import select

    from app.models import AgentAction, AgentChainHead
    rows = db.execute(
        select(AgentAction).where(AgentAction.tenant_id == tenant_id)).scalars().all()
    by_hash = {r.record_hash: r for r in rows}
    broken: list[str] = []
    issues: list[str] = []

    for r in rows:
        payload = _payload(tenant_id=r.tenant_id, agent_id=r.agent_id, agent_name=r.agent_name,
                           action=r.action, target=r.target, on_behalf_of=r.on_behalf_of,
                           confidence=r.confidence, outcome=r.outcome, detail=r.detail,
                           created_at=r.created_at)
        if record_hash(r.prev_hash, payload) != r.record_hash:
            broken.append(r.id)          # payload doesn't match its hash
        elif r.prev_hash and r.prev_hash not in by_hash:
            broken.append(r.id)          # dangling chain link (predecessor removed)

    # (4) two records claiming the same predecessor means the chain forked.
    seen_prev: dict[str, str] = {}
    for r in rows:
        if not r.prev_hash:
            continue
        if r.prev_hash in seen_prev:
            issues.append("forked_chain")
            broken.extend([seen_prev[r.prev_hash], r.id])
            break
        seen_prev[r.prev_hash] = r.id

    # (3) compare against the signed head: the chain must end where it says it
    # ends, and contain as many entries as it says it contains.
    head = db.get(AgentChainHead, tenant_id)
    head_verified = False
    if head is not None:
        expected_sig = head_signature(tenant_id, head.head_hash, head.action_count)
        import hmac as _hmac
        if not _hmac.compare_digest(head.signature or "", expected_sig):
            issues.append("head_signature_invalid")
        elif head.head_hash not in by_hash:
            issues.append("tail_removed_or_replaced")
        elif len(rows) != head.action_count:
            issues.append("action_count_mismatch")
        else:
            head_verified = True
    elif rows:
        # Pre-existing data written before the head was introduced. The chain
        # checks still apply, but the tail cannot be attested — say so rather
        # than implying a stronger guarantee than is available.
        issues.append("no_recorded_head")

    return {
        "ok": not broken and not issues,
        "actions": len(rows),
        "broken": broken,
        "issues": issues,
        "head_verified": head_verified,
        "expected_actions": head.action_count if head is not None else None,
    }


__all__ = ["record_hash", "register_agent", "record_action", "list_actions", "verify_chain"]
