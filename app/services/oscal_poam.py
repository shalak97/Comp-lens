"""OSCAL POA&M + Component-Definition builders — widening the OSCAL surface.

The existing `oscal_export.py` emits OSCAL Assessment Results (1 of the 7 OSCAL
models). This adds two more of the model set as pure builders:

  build_poam(...)                  Plan of Action & Milestones — one POA&M item per
                                   open (failing) finding, the artifact an auditor
                                   tracks remediation against.
  build_component_definition(...)  Component Definition — the components a system is
                                   built from and the controls they implement.

Pure functions over plain dicts (no DB), so they are unit-testable and can be fed
from either live findings or a fixture. Targets OSCAL 1.1.2.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

OSCAL_VERSION = "1.1.2"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _ctrl_to_oscal(control_id: str) -> str:
    # AC-2(7) -> ac-2.7 ; A.8.5 -> a.8.5 (mirrors oscal_export._ctrl_to_oscal)
    return str(control_id).lower().replace("(", ".").replace(")", "")


def _uuid() -> str:
    return str(uuid.uuid4())


def build_poam(tenant_id: str, findings: list[dict[str, Any]], *,
               framework: str = "NIST_800_53") -> dict[str, Any]:
    """Build an OSCAL POA&M from findings.

    Each finding is ``{control_id, status, severity?, description?, asset_id?,
    source_system?, finding_id?}``. Only failing/open findings become POA&M items
    (a POA&M tracks what is NOT yet satisfied).
    """
    items: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for f in findings:
        status = str(f.get("status") or "").lower()
        if status not in ("fail", "failed", "open", "error"):
            continue
        cid = str(f.get("control_id") or "UNKNOWN")
        obs_uuid = _uuid()
        observations.append({
            "uuid": obs_uuid,
            "description": str(f.get("description") or f"Finding on {cid}"),
            "methods": ["EXAMINE"],
            "collected": _now(),
            "props": [{"name": "source-system", "value": str(f.get("source_system") or "comp-lens")}]
                     + ([{"name": "asset", "value": str(f["asset_id"])}] if f.get("asset_id") else []),
        })
        items.append({
            "uuid": _uuid(),
            "title": f"Remediate {cid}",
            "description": str(f.get("description") or f"Control {cid} is not satisfied."),
            "props": [{"name": "severity", "value": str(f.get("severity") or "medium")}],
            "related-observations": [{"observation-uuid": obs_uuid}],
            "related-findings": ([{"finding-uuid": str(f["finding_id"])}] if f.get("finding_id") else []),
        })
    return {
        "plan-of-action-and-milestones": {
            "uuid": _uuid(),
            "metadata": {
                "title": f"Comp-Lens POA&M — {framework}",
                "last-modified": _now(), "version": "1.0", "oscal-version": OSCAL_VERSION,
                "props": [{"name": "tenant", "value": tenant_id},
                          {"name": "framework", "value": framework}],
            },
            "import-ssp": {"href": "#comp-lens-ssp"},
            "system-id": {"id": f"comp-lens/{tenant_id}"},
            "observations": observations,
            "poam-items": items,
        }
    }


def build_component_definition(components: list[dict[str, Any]], *,
                               framework: str = "NIST_800_53") -> dict[str, Any]:
    """Build an OSCAL Component Definition.

    Each component is ``{name, type?, description?, controls?: [control_id, ...]}``.
    """
    defined: list[dict[str, Any]] = []
    for c in components:
        controls = c.get("controls") or []
        implemented = [{
            "uuid": _uuid(),
            "control-id": _ctrl_to_oscal(cid),
            "description": f"{c.get('name', 'component')} implements {cid}",
        } for cid in controls]
        entry: dict[str, Any] = {
            "uuid": _uuid(),
            "type": str(c.get("type") or "software"),
            "title": str(c.get("name") or "component"),
            "description": str(c.get("description") or c.get("name") or "component"),
        }
        if implemented:
            entry["control-implementations"] = [{
                "uuid": _uuid(),
                "source": f"#{framework}",
                "description": f"{framework} controls implemented by {c.get('name', 'component')}",
                "implemented-requirements": implemented,
            }]
        defined.append(entry)
    return {
        "component-definition": {
            "uuid": _uuid(),
            "metadata": {
                "title": "Comp-Lens Component Definition",
                "last-modified": _now(), "version": "1.0", "oscal-version": OSCAL_VERSION,
            },
            "components": defined,
        }
    }


__all__ = ["OSCAL_VERSION", "build_poam", "build_component_definition"]
