"""Connector framework v2 — marketplace service over the existing registry.

Responsibilities:
  * status     – config completeness (env-var NAMES only, never values),
                 maturity, mode: connected | demo | not_configured | error
  * test       – live healthcheck when credentials + implementation exist;
                 demo-OK otherwise (so the dashboard works with zero creds)
  * sync       – collect evidence: LIVE via the registered BaseConnector's
                 collect_telemetry where possible, with realistic normalized
                 demo evidence as the universal fallback; persists items +
                 per-tenant sync state
  * normalize  – every item carries flat signals + multi-framework control
                 mappings from connector_control_map.json

Security: secrets are read only as os.environ presence checks; values are never
returned, logged, or stored. Live collection retries once before failing over.
"""
from __future__ import annotations

import json
import os
from datetime import timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.connectors import catalog as cat
from app.connectors.evidence_profiles import demo_evidence
from app.models import ConnectorEvidenceItem, ConnectorSyncState, utc_now

_DATA = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


@lru_cache(maxsize=1)
def _control_map() -> Dict[str, Dict[str, List[str]]]:
    with open(os.path.join(_DATA, "connector_control_map.json"), encoding="utf-8") as fh:
        return json.load(fh)["mappings"]


def _env_state(c: Dict[str, Any]) -> Dict[str, Any]:
    names = c.get("env_vars", [])
    set_names = [n for n in names if os.getenv(n)]
    return {"required": names, "set": set_names,
            "missing": [n for n in names if n not in set_names],
            "complete": len(set_names) == len(names)}


def _registry_connector(c: Dict[str, Any]):
    if not c.get("registry_key"):
        return None
    try:
        from app.connectors.registry import registry
        return registry.get(c["registry_key"])
    except Exception:
        return None


def status_one(db: Session, c: Dict[str, Any], tenant_id: str = "default") -> Dict[str, Any]:
    env = _env_state(c)
    mode = "not_configured"
    healthy: Optional[bool] = None
    if not c.get("env_vars"):
        mode = "demo"
    elif env["complete"] and c.get("registry_key"):
        inst = _registry_connector(c)
        if inst is not None:
            try:
                healthy = bool(inst.healthcheck())
                mode = "connected" if healthy else "error"
            except Exception:
                mode, healthy = "error", False
        else:
            mode = "error"
    elif env["complete"]:
        mode = "demo"  # creds set but no live client built yet
    sync = db.execute(select(ConnectorSyncState).where(
        ConnectorSyncState.tenant_id == tenant_id,
        ConnectorSyncState.connector_key == c["key"])).scalars().first()
    controls = supported_controls(c)
    return {
        "key": c["key"], "name": c["name"], "category": c["category"],
        "vendor": c["vendor"], "auth_method": c["auth_method"],
        "maturity": c["maturity"], "mode": mode, "healthy": healthy,
        "credentials": {"required": env["required"], "missing": env["missing"]},
        "evidence_types": c["evidence_types"],
        "controls_covered": sum(len(v) for v in controls.values()),
        "last_sync_at": sync.last_sync_at.isoformat() if sync and sync.last_sync_at else None,
        "last_sync_status": sync.status if sync else None,
        "last_sync_mode": sync.mode if sync else None,
        "evidence_count": sync.evidence_count if sync else 0,
        "last_error": sync.error if sync else None,
    }


def supported_controls(c: Dict[str, Any]) -> Dict[str, List[str]]:
    """framework -> sorted control ids this connector's evidence maps to."""
    out: Dict[str, set] = {}
    cm = _control_map()
    for et in c["evidence_types"]:
        for fw, ids in cm.get(et, {}).items():
            out.setdefault(fw, set()).update(ids)
    return {fw: sorted(ids) for fw, ids in sorted(out.items())}


def test_connection(c: Dict[str, Any]) -> Dict[str, Any]:
    env = _env_state(c)
    if env["complete"] and c.get("registry_key"):
        inst = _registry_connector(c)
        if inst is not None:
            try:
                ok = bool(inst.healthcheck())
                return {"key": c["key"], "ok": ok, "mode": "live",
                        "detail": "credentials valid" if ok else "healthcheck failed"}
            except Exception as exc:  # noqa: BLE001
                return {"key": c["key"], "ok": False, "mode": "live",
                        "detail": f"connection error: {type(exc).__name__}"}
    if env["missing"]:
        return {"key": c["key"], "ok": True, "mode": "demo",
                "detail": f"demo mode (set {', '.join(env['missing'][:4])} for live)"}
    return {"key": c["key"], "ok": True, "mode": "demo", "detail": "demo mode"}


def _normalize(c: Dict[str, Any], items: List[Dict[str, Any]], mode: str) -> List[Dict[str, Any]]:
    cm = _control_map()
    out = []
    for it in items:
        et = it["evidence_type"]
        out.append({
            "connector_key": c["key"], "category": c["category"],
            "evidence_type": et, "title": it.get("title", et),
            "signals": it.get("signals", {}), "status": it.get("status", "info"),
            "mode": mode,
            "controls": [{"framework": fw, "control_id": cid}
                         for fw, ids in cm.get(et, {}).items() for cid in ids],
        })
    return out


def _try_live_collect(c: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Best-effort live evidence via the registered connector's telemetry API.
    Retries once. Returns None to signal demo fallback."""
    inst = _registry_connector(c)
    if inst is None or not _env_state(c)["complete"]:
        return None
    cm = _control_map()
    items: List[Dict[str, Any]] = []
    for et in c["evidence_types"]:
        nist = cm.get(et, {}).get("NIST_800_53", [])
        if not nist:
            continue
        for attempt in (1, 2):
            try:
                tel = inst.collect_telemetry(nist[0], None, {})
                items.append({"evidence_type": et, "title": f"{c['name']} telemetry: {et}",
                              "signals": tel, "status": "info"})
                break
            except Exception:
                if attempt == 2:
                    return None  # any hard failure -> whole sync falls back to demo
    return items or None


def sync(db: Session, c: Dict[str, Any], tenant_id: str = "default",
         force_demo: bool = False) -> Dict[str, Any]:
    mode, items, error = "demo", None, None
    if not force_demo:
        try:
            live = _try_live_collect(c)
            if live is not None:
                mode, items = "live", live
        except Exception as exc:  # noqa: BLE001
            error = f"live collection failed: {type(exc).__name__}"
    if items is None:
        items = demo_evidence(c)
    norm = _normalize(c, items, mode)

    db.execute(delete(ConnectorEvidenceItem).where(
        ConnectorEvidenceItem.tenant_id == tenant_id,
        ConnectorEvidenceItem.connector_key == c["key"]))
    for n in norm:
        db.add(ConnectorEvidenceItem(
            tenant_id=tenant_id, connector_key=c["key"], category=n["category"],
            evidence_type=n["evidence_type"], title=n["title"], status=n["status"],
            mode=n["mode"], signals=n["signals"], controls=n["controls"]))
    st = db.execute(select(ConnectorSyncState).where(
        ConnectorSyncState.tenant_id == tenant_id,
        ConnectorSyncState.connector_key == c["key"])).scalars().first()
    if not st:
        st = ConnectorSyncState(tenant_id=tenant_id, connector_key=c["key"])
        db.add(st)
    st.last_sync_at = utc_now()
    st.status = "ok" if not error else "degraded"
    st.mode = mode
    st.evidence_count = len(norm)
    st.error = error
    db.commit()
    return {"key": c["key"], "mode": mode, "evidence_count": len(norm),
            "status": st.status, "error": error,
            "synced_at": st.last_sync_at.replace(tzinfo=timezone.utc).isoformat()}


def evidence_for(db: Session, key: str, tenant_id: str = "default") -> List[Dict[str, Any]]:
    rows = db.execute(select(ConnectorEvidenceItem).where(
        ConnectorEvidenceItem.tenant_id == tenant_id,
        ConnectorEvidenceItem.connector_key == key.upper())).scalars().all()
    return [{"id": r.id, "evidence_type": r.evidence_type, "title": r.title,
             "status": r.status, "mode": r.mode, "signals": r.signals,
             "controls": r.controls,
             "collected_at": r.collected_at.isoformat() if r.collected_at else None}
            for r in rows]
