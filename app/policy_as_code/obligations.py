"""Obligation dispatcher.

The policy engine emits, for each failing control, a list of `obligations`.
This module is the *dispersion* layer: it routes each obligation to the
operational procedure that fulfils it, and records every action in the
obligation-dispatch ledger (and the audit log).

An obligation may be a bare string ("open ticket", "notify") or a structured
object ({"procedure": "open_ticket", "priority": "high"}). Both are supported.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.policy_models import ObligationDispatch

# Bare-string obligations → canonical procedure names.
_ALIASES = {
    "ticket": "open_ticket", "open ticket": "open_ticket", "open_ticket": "open_ticket",
    "remediate": "open_ticket", "remediation": "open_ticket",
    "notify": "notify", "alert": "notify", "page": "notify",
    "audit": "audit_event", "audit_event": "audit_event", "log": "audit_event",
    "retention": "retention_scan", "retention_scan": "retention_scan", "scan_retention": "retention_scan",
    "dsar": "open_dsar", "open_dsar": "open_dsar", "erasure": "open_dsar", "privacy_task": "open_dsar",
    "resync": "resync_connector", "re-sync": "resync_connector", "resync_connector": "resync_connector",
    "recollect": "resync_connector",
    "waiver": "waiver", "waiver-eligible": "waiver", "waiver_eligible": "waiver",
}

_SEV_PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P4"}


def _infer_procedure(name: str) -> tuple[str, dict]:
    """Best-effort routing for free-form obligation names not in _ALIASES.
    Returns (procedure, extra_params)."""
    n = name.lower()
    if any(k in n for k in ("jira", "ticket", "servicenow", "remediat")):
        return "open_ticket", {}
    if any(k in n for k in ("slack", "notify", "alert", "page", "email", "teams", "pagerduty")):
        params = {}
        for ch in ("security", "compliance", "privacy", "oncall", "on_call", "soc"):
            if ch in n:
                params["channel"] = ch.replace("_", "")
                break
        return "notify", params
    if "waiver" in n:
        return "waiver", {}
    if any(k in n for k in ("resync", "recollect", "re-collect", "recollection")):
        return "resync_connector", {}
    if "retention" in n:
        return "retention_scan", {}
    if any(k in n for k in ("dsar", "erasure", "rtbf")):
        return "open_dsar", {}
    return name.replace(" ", "_"), {}


def unroutable_obligations(obligations: list[Any]) -> list[str]:
    """Obligation names that no procedure will fulfil.

    A policy naming an obligation this module cannot route — `escalate_to_ciso`,
    say — used to be discovered only at dispatch time, as a `skipped` row in the
    ledger nobody reads. Surfacing them at load time turns a silent no-op into
    something the policy author sees. Returns the raw names, not the inferred
    procedure, since the name is what the author wrote.
    """
    out = []
    for raw in obligations or []:
        ob = normalize_obligation(raw)
        if ob["procedure"] not in _REGISTRY:
            out.append(str(ob["raw"]))
    return out


def normalize_obligation(o: Any) -> dict[str, Any]:
    """Return {procedure, params, raw} for a string or dict obligation."""
    if isinstance(o, str):
        key = o.strip().lower()
        if key in _ALIASES:
            return {"procedure": _ALIASES[key], "params": {}, "raw": o}
        proc, params = _infer_procedure(key)
        return {"procedure": proc, "params": params, "raw": o}
    if isinstance(o, dict):
        raw_proc = str(o.get("procedure") or o.get("do") or "").strip().lower()
        params = {k: v for k, v in o.items() if k not in ("procedure", "do")}
        if raw_proc in _ALIASES:
            return {"procedure": _ALIASES[raw_proc], "params": params, "raw": o}
        proc, extra = _infer_procedure(raw_proc)
        extra.update(params)  # explicit params win
        return {"procedure": proc, "params": extra, "raw": o}
    return {"procedure": "", "params": {}, "raw": o}


@dataclass
class _Ctx:
    db: Session
    tenant_id: str
    control_id: str
    severity: str
    reason: str
    evidence: dict[str, Any]
    params: dict[str, Any]
    finding: Any = None
    dry_run: bool = False


def _annotate_finding(finding, key: str, value: Any) -> None:
    if finding is None:
        return
    rem = dict(finding.remediation or {})
    rem[key] = value
    finding.remediation = rem


# ─────────────────────────── handlers ───────────────────────────
# Each returns (status, detail, meta). Handlers must be side-effect-free when
# ctx.dry_run is True.
def _open_ticket(ctx: _Ctx):
    pr = ctx.params.get("priority") or _SEV_PRIORITY.get(ctx.severity, "P3")
    assignee = ctx.params.get("assignee")
    detail = f"Remediation ticket ({pr}) recorded for {ctx.control_id}"
    meta = {"priority": pr, "assignee": assignee, "reason": ctx.reason}
    if not ctx.dry_run:
        _annotate_finding(ctx.finding, "ticket", {"priority": pr, "status": "open", "assignee": assignee})
    # `recorded`, not `queued`: nothing dequeues this. There is no worker and
    # every connector is read-only, so no ticket is created anywhere. Calling it
    # queued named a queue that does not exist, and the follow-through trust
    # lane read that as remediation which had happened.
    return ("recorded", detail, meta)


def _audit_event(ctx: _Ctx):
    detail = f"Policy violation on {ctx.control_id} written to audit log"
    if not ctx.dry_run:
        from app.services import privacy
        privacy.record_event(ctx.db, ctx.tenant_id, "policy.violation", entity_type="control",
                             entity_id=ctx.control_id, summary=(ctx.reason or "")[:240],
                             meta={"severity": ctx.severity})
    return ("done", detail, {})


def _notify(ctx: _Ctx):
    ch = ctx.params.get("channel", "default")
    detail = f"Alert raised to '{ch}' for {ctx.control_id}"
    if not ctx.dry_run:
        from app.services import privacy
        privacy.record_event(ctx.db, ctx.tenant_id, "alert.raised", entity_type="control",
                             entity_id=ctx.control_id, summary=f"[{ch}] {(ctx.reason or '')[:200]}",
                             meta={"channel": ch, "severity": ctx.severity})
    return ("done", detail, {"channel": ch})


def _retention_scan(ctx: _Ctx):
    if ctx.dry_run:
        return ("queued", "Would run a retention scan", {})
    from app.services import privacy
    res = privacy.scan_retention(ctx.db, ctx.tenant_id)
    n = res.get("total_expired", 0)
    return ("done", f"Retention scan complete: {n} record(s) past retention", {"total_expired": n})


def _open_dsar(ctx: _Ctx):
    email = ctx.params.get("subject_email") or ctx.params.get("subject")
    rtype = ctx.params.get("request_type", "erasure")
    if not email:
        return ("skipped", "No subject_email supplied for DSAR", {})
    if ctx.dry_run:
        return ("queued", f"Would open {rtype} DSAR for {email}", {"request_type": rtype})
    from app.services import privacy
    d = privacy.create_dsar(ctx.db, ctx.tenant_id, email, rtype,
                            f"Auto-opened by policy {ctx.control_id}")
    return ("done", f"{rtype.title()} DSAR opened for {email}", {"dsar_id": d["id"]})


def _resync_connector(ctx: _Ctx):
    target = (ctx.params.get("connector") or ctx.params.get("instance_id")
              or ctx.evidence.get("connector") or ctx.evidence.get("source") or "connector")
    detail = f"Re-sync requested for {target}; it will run on the next scheduled sync"
    # `recorded`, not `queued`: this enqueues nothing. The next scheduled sync
    # re-collects whether or not this obligation fired, so claiming a queue
    # overstated what happened.
    return ("recorded", detail, {"target": target})


def _waiver(ctx: _Ctx):
    detail = f"{ctx.control_id} marked waiver-eligible"
    if not ctx.dry_run:
        _annotate_finding(ctx.finding, "waiver_eligible", True)
    return ("eligible", detail, {})


_REGISTRY = {
    "open_ticket": _open_ticket,
    "audit_event": _audit_event,
    "notify": _notify,
    "retention_scan": _retention_scan,
    "open_dsar": _open_dsar,
    "resync_connector": _resync_connector,
    "waiver": _waiver,
}

PROCEDURES = sorted(_REGISTRY)


# ─────────────────────────── dispatch ───────────────────────────
def dispatch_for_decision(db: Session, tenant_id: str, decision, *,
                          evidence: dict[str, Any] | None = None,
                          finding=None, dry_run: bool = False) -> list[dict[str, Any]]:
    """Route every obligation on a (failing) decision to its procedure.

    `decision` is a PolicyDecision (has .control_id, .severity, .reason, .obligations).
    Returns one outcome dict per obligation. When dry_run, performs no writes.
    """
    evidence = evidence or {}
    outcomes: list[dict[str, Any]] = []
    for raw in (getattr(decision, "obligations", None) or []):
        ob = normalize_obligation(raw)
        proc = ob["procedure"]
        ctx = _Ctx(db=db, tenant_id=tenant_id, control_id=decision.control_id,
                   severity=decision.severity, reason=decision.reason, evidence=evidence,
                   params=ob["params"], finding=finding, dry_run=dry_run)
        handler = _REGISTRY.get(proc)
        if handler is None:
            status, detail, meta = "skipped", f"Unknown procedure '{proc}'", {}
        else:
            try:
                status, detail, meta = handler(ctx)
            except Exception as exc:  # noqa: BLE001 — one bad obligation must not abort the rest
                status, detail, meta = "error", f"{proc} failed: {exc}", {}
        outcomes.append({"procedure": proc, "status": status, "detail": detail,
                         "meta": meta, "control_id": decision.control_id,
                         "severity": decision.severity})
        if not dry_run:
            db.add(ObligationDispatch(
                tenant_id=tenant_id, control_id=decision.control_id, procedure=proc,
                status=status, severity=decision.severity, detail=detail, meta=meta,
                finding_id=(getattr(finding, "finding_id", None) if finding else None)))
    if not dry_run and outcomes:
        db.commit()
    return outcomes


def list_dispatches(db: Session, tenant_id: str, *, control_id: str | None = None,
                    procedure: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    q = select(ObligationDispatch).where(ObligationDispatch.tenant_id == tenant_id)
    if control_id:
        q = q.where(ObligationDispatch.control_id == control_id)
    if procedure:
        q = q.where(ObligationDispatch.procedure == procedure)
    q = q.order_by(desc(ObligationDispatch.created_at)).limit(limit)
    rows = db.execute(q).scalars().all()
    return [{"id": r.id, "control_id": r.control_id, "procedure": r.procedure,
             "status": r.status, "severity": r.severity, "detail": r.detail,
             "meta": r.meta or {}, "finding_id": r.finding_id,
             "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]
