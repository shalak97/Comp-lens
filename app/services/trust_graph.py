"""Trust graph + live telemetry engine.

Ties the four object types into one connected chain and lets live connector
telemetry flow into the governance layer:

    connector --collects--> evidence --satisfies--> control --mitigates--> risk
        vendor --is the service behind--> connector
        vendor posture --feeds--> its linked risks

Key idea: a risk's *residual* exposure should not be hand-typed — it should
reflect whether the controls that mitigate it are actually backed by passing,
recently-synced evidence. A control with no live evidence offers no real
mitigation, so the residual stays near inherent. A control fed by a healthy,
recently-synced connector pulls the residual down.

All computation is read-only and derived; nothing here mutates stored scores,
so it is safe to call on every request.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.grc_tprm_models import Risk, Vendor


def _now() -> datetime:
    return datetime.now(timezone.utc)


# How much a fully-evidenced, healthy control reduces the inherent risk it maps to.
_MAX_MITIGATION = 0.6           # at best, residual = 40% of inherent
_STALE_DAYS = 30                # evidence older than this counts as degraded


def _connector_health(db: Session, tenant_id: str) -> Dict[str, Dict[str, Any]]:
    """key -> {mode, synced_at, fresh, controls:set, vendor} from live sync state."""
    from app.connectors import catalog as ccat
    from app.connectors import framework as cfw
    out: Dict[str, Dict[str, Any]] = {}
    for c in ccat.all_connectors():
        try:
            st = cfw.status_one(db, c, tenant_id)
        except Exception:
            continue
        ctrls: set = set()
        for ids in cfw.supported_controls(c).values():
            ctrls.update(ids)
        synced = st.get("last_sync_at")
        fresh = False
        if synced:
            try:
                dt = datetime.fromisoformat(synced)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                fresh = (_now() - dt) < timedelta(days=_STALE_DAYS)
            except (ValueError, TypeError):
                fresh = False
        live = st.get("mode") in ("connected", "live") or st.get("last_sync_mode") == "live"
        out[c["key"]] = {
            "key": c["key"], "name": c["name"], "vendor": c.get("vendor", ""),
            "mode": st.get("mode"), "live": live, "synced_at": synced, "fresh": fresh,
            "evidence_count": st.get("evidence_count", 0), "controls": ctrls,
        }
    return out


def _control_strength(control_id: str, conns: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """How well-evidenced is a control, from connector telemetry? 0..1 strength."""
    backing = [c for c in conns.values() if control_id in c["controls"]]
    if not backing:
        return {"strength": 0.0, "backed_by": [], "reason": "no connector collects evidence for this control"}
    best = 0.0
    contributors = []
    for c in backing:
        s = 0.0
        if c["live"] and c["fresh"]:
            s = 1.0
        elif c["live"]:
            s = 0.6        # connected but evidence is stale
        elif c["evidence_count"] > 0:
            s = 0.3        # only demo/sample evidence present
        best = max(best, s)
        if s > 0:
            contributors.append({"key": c["key"], "name": c["name"], "strength": s})
    return {"strength": best, "backed_by": contributors,
            "reason": "live+fresh" if best >= 1 else "stale" if best >= 0.6 else "demo-only" if best > 0 else "unsynced"}


class TrustGraphService:
    def __init__(self, db: Session):
        self.db = db

    def _risks(self, tenant_id: str) -> List[Risk]:
        return self.db.execute(select(Risk).where(Risk.tenant_id == tenant_id)).scalars().all()

    def _vendors(self, tenant_id: str) -> List[Vendor]:
        return self.db.execute(select(Vendor).where(Vendor.tenant_id == tenant_id)).scalars().all()

    def computed_residual(self, risk: Risk, conns: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Derive a live residual score for a risk from the strength of the
        control that mitigates it. Falls back to inherent when no control linked."""
        inherent = risk.likelihood * risk.impact
        if not risk.linked_control:
            return {"inherent": inherent, "residual": inherent, "strength": 0.0,
                    "telemetry": "no control linked — residual = inherent", "backed_by": []}
        cs = _control_strength(risk.linked_control, conns)
        mitigation = _MAX_MITIGATION * cs["strength"]
        residual = round(inherent * (1 - mitigation))
        return {"inherent": inherent, "residual": max(1, residual),
                "strength": round(cs["strength"], 2),
                "telemetry": f"control {risk.linked_control}: {cs['reason']}",
                "backed_by": cs["backed_by"]}

    def vendor_live_posture(self, vendor: Vendor, conns: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """A vendor tied to a connector inherits that connector's live posture."""
        if not vendor.linked_connector_key or vendor.linked_connector_key not in conns:
            return {"linked": False, "signal": "no connector linked",
                    "live": False, "fresh": False}
        c = conns[vendor.linked_connector_key]
        return {"linked": True, "connector": c["name"], "live": c["live"],
                "fresh": c["fresh"], "synced_at": c["synced_at"],
                "evidence_count": c["evidence_count"],
                "signal": ("live evidence flowing" if c["live"] and c["fresh"]
                           else "connected but stale" if c["live"]
                           else "linked but not synced")}

    def graph(self, tenant_id: str) -> Dict[str, Any]:
        """Full node+edge graph of connector→control→risk + vendor links."""
        conns = _connector_health(self.db, tenant_id)
        risks = self._risks(tenant_id)
        vendors = self._vendors(tenant_id)
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        # vendor nodes
        for v in vendors:
            posture = self.vendor_live_posture(v, conns)
            nodes.append({"id": f"vendor:{v.id}", "type": "vendor", "label": v.name,
                          "stage": v.stage, "risk": v.risk_tier, "live": posture["live"]})
            if posture["linked"]:
                edges.append({"from": f"vendor:{v.id}", "to": f"connector:{v.linked_connector_key}",
                              "kind": "operates"})

        # connector nodes (only those that exist) + connector->control edges
        seen_controls: set = set()
        for key, c in conns.items():
            # only include connectors that are live or have a vendor link, to keep graph focused
            linked_by_vendor = any(v.linked_connector_key == key for v in vendors)
            if not (c["live"] or linked_by_vendor or c["evidence_count"] > 0):
                continue
            nodes.append({"id": f"connector:{key}", "type": "connector", "label": c["name"],
                          "live": c["live"], "fresh": c["fresh"], "vendor": c["vendor"]})
            for ctrl in c["controls"]:
                seen_controls.add(ctrl)
                edges.append({"from": f"connector:{key}", "to": f"control:{ctrl}",
                              "kind": "evidences", "strength": 1.0 if (c["live"] and c["fresh"]) else 0.5 if c["live"] else 0.3})

        # control nodes (those touched by a connector or a risk)
        risk_controls = {r.linked_control for r in risks if r.linked_control}
        for ctrl in sorted(seen_controls | risk_controls):
            cs = _control_strength(ctrl, conns)
            nodes.append({"id": f"control:{ctrl}", "type": "control", "label": ctrl,
                          "strength": round(cs["strength"], 2),
                          "status": "evidenced" if cs["strength"] >= 1 else "weak" if cs["strength"] > 0 else "unevidenced"})

        # risk nodes + control->risk edges
        for r in risks:
            res = self.computed_residual(r, conns)
            nodes.append({"id": f"risk:{r.id}", "type": "risk", "label": r.title,
                          "inherent": res["inherent"], "residual": res["residual"],
                          "strength": res["strength"]})
            if r.linked_control:
                edges.append({"from": f"control:{r.linked_control}", "to": f"risk:{r.id}",
                              "kind": "mitigates", "strength": res["strength"]})
            if r.linked_vendor_id:
                edges.append({"from": f"vendor:{r.linked_vendor_id}", "to": f"risk:{r.id}",
                              "kind": "owns"})

        return {"nodes": nodes, "edges": edges,
                "stats": {"vendors": len(vendors), "connectors": sum(1 for n in nodes if n["type"] == "connector"),
                          "controls": sum(1 for n in nodes if n["type"] == "control"),
                          "risks": len(risks),
                          "live_connectors": sum(1 for c in conns.values() if c["live"]),
                          "unevidenced_controls": sum(1 for n in nodes if n["type"] == "control" and n["status"] == "unevidenced")}}

    def risk_telemetry(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Per-risk: inherent vs live-computed residual, with the telemetry trail."""
        conns = _connector_health(self.db, tenant_id)
        out = []
        for r in self._risks(tenant_id):
            res = self.computed_residual(r, conns)
            out.append({"id": r.id, "title": r.title, "linked_control": r.linked_control,
                        "linked_vendor_id": r.linked_vendor_id,
                        "inherent_score": res["inherent"], "computed_residual": res["residual"],
                        "stored_residual": (r.residual_likelihood or r.likelihood) * (r.residual_impact or r.impact),
                        "evidence_strength": res["strength"], "telemetry": res["telemetry"],
                        "backed_by": res["backed_by"]})
        out.sort(key=lambda x: x["computed_residual"], reverse=True)
        return out
