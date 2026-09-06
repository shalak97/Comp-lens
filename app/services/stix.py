"""STIX interoperability adapter — threat intelligence at the evidence layer.

STIX 2.1 (OASIS) is the threat-intel interchange standard delivered over TAXII by
feeds like CISA AIS, MISP exports and commercial providers. For a GRC platform it is
context that sharpens vulnerability and monitoring controls: known-exploited
vulnerabilities, active indicators, malware families.

Pure functions (no DB, no network — unit-testable):

    from_stix(bundle)   a STIX bundle -> [NormalizedEvidence], one per intel object
                        (vulnerability / indicator / malware / attack-pattern),
                        mapped to the matching internal concept.
    stix_summary()      a bundle -> flat telemetry counts by object type.
    to_stix_bundle()/…  emit a minimal bundle (export/round-trip).

Targets STIX 2.1. Concept ids are the ones Comp-Lens speaks.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from app.services.ocsf import NormalizedEvidence
from app.services.shapes import as_list

STIX_SPEC = "2.1"

# STIX SDO type -> internal concept id (all present in the lexicon).
_TYPE_CONCEPTS = {
    "vulnerability": ["vulnerability_management", "threat_intelligence"],
    "indicator": ["threat_intelligence"],
    "malware": ["malware_protection", "threat_intelligence"],
    "attack-pattern": ["threat_intelligence"],
    "course-of-action": ["threat_intelligence"],
}
# object types that carry evidence (everything else, e.g. relationship/identity, is context)
_INTEL_TYPES = set(_TYPE_CONCEPTS)

# STIX makes no universal severity; map common indicator labels if present.
_LABEL_SEVERITY = {"malicious-activity": "high", "attribution": "medium",
                   "anomalous-activity": "medium", "benign": "info"}


def _cve_of(obj: dict[str, Any]) -> str | None:
    for ref in as_list(obj.get("external_references")):
        if isinstance(ref, dict) and str(ref.get("source_name", "")).lower() == "cve":
            return ref.get("external_id")
    return None


def _severity(obj: dict[str, Any]) -> str:
    for lab in obj.get("labels") or obj.get("indicator_types") or []:
        s = _LABEL_SEVERITY.get(str(lab).lower())
        if s:
            return s
    return "unknown" if obj.get("type") != "vulnerability" else "medium"


def from_stix(bundle: dict[str, Any]) -> list[NormalizedEvidence]:
    """One NormalizedEvidence per intel-bearing STIX object in the bundle."""
    if not isinstance(bundle, dict):
        return []
    out: list[NormalizedEvidence] = []
    now = datetime.now(UTC).isoformat()
    for obj in as_list(bundle.get("objects")):
        if not isinstance(obj, dict):
            continue
        # STIX `type` is a string by spec, but nothing stops a document
        # sending an object or a list — and looking that up in a set raised
        # `TypeError: unhashable type` out of the adapter, so a malformed
        # bundle became a 500 rather than a 400. A non-string type matches
        # nothing, which is the same outcome as an unrecognised one.
        otype = obj.get("type")
        if not isinstance(otype, str) or otype not in _INTEL_TYPES:
            continue
        name = obj.get("name") or _cve_of(obj) or obj.get("id")
        out.append(NormalizedEvidence(
            source_system="STIX", plane="vulnerability_threat", observed_at=now,
            asset_id=None, asset_type="threat", severity=_severity(obj),
            concepts=list(_TYPE_CONCEPTS[otype]),
            findings=[{
                "stix_type": otype, "name": name, "cve": _cve_of(obj),
                "pattern": obj.get("pattern"),
                "description": obj.get("description"),
                "stix_id": obj.get("id"),
            }],
            provenance={"stix_version": bundle.get("spec_version", STIX_SPEC),
                        "stix_id": obj.get("id"), "created": obj.get("created")},
        ))
    return out


def stix_summary(bundle: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        return {"threat_objects": 0}
    counts: dict[str, int] = {}
    for obj in as_list(bundle.get("objects")):
        t = obj.get("type") if isinstance(obj, dict) else None
        if isinstance(t, str) and t in _INTEL_TYPES:
            counts[t] = counts.get(t, 0) + 1
    return {
        "threat_objects": sum(counts.values()),
        "vulnerabilities": counts.get("vulnerability", 0),
        "indicators": counts.get("indicator", 0),
        "malware": counts.get("malware", 0),
        "attack_patterns": counts.get("attack-pattern", 0),
    }


def to_stix_bundle(objects: list[dict[str, Any]]) -> dict[str, Any]:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}",
            "spec_version": STIX_SPEC, "objects": list(as_list(objects))}


def vulnerability(*, name: str, cve: str | None = None,
                  description: str | None = None) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "type": "vulnerability", "spec_version": STIX_SPEC,
        "id": f"vulnerability--{uuid.uuid4()}",
        "created": datetime.now(UTC).isoformat(), "name": name,
    }
    if cve:
        obj["external_references"] = [{"source_name": "cve", "external_id": cve}]
    if description:
        obj["description"] = description
    return obj


def indicator(*, name: str, pattern: str, labels: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "indicator", "spec_version": STIX_SPEC,
        "id": f"indicator--{uuid.uuid4()}", "created": datetime.now(UTC).isoformat(),
        "name": name, "pattern": pattern, "pattern_type": "stix",
        "indicator_types": labels or ["malicious-activity"],
        "labels": labels or ["malicious-activity"],
    }


__all__ = [
    "STIX_SPEC", "from_stix", "stix_summary", "to_stix_bundle",
    "vulnerability", "indicator",
]
