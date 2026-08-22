"""CycloneDX interoperability adapter — SBOM, VEX, and the evidence primitive.

CycloneDX (OWASP) is the SBOM + VEX standard that Syft, Trivy, cdxgen and the build
ecosystem emit. For a GRC platform it matters for three things, in order of leverage:

  1. The component `evidence.identity` object (CycloneDX 1.5+) — a `field`, a
     numeric `confidence`, and named identification `methods[].technique`. This is
     exactly the "confidence + identification technique" primitive Comp-Lens's own
     mapping confidence has lacked; `to_cdx_evidence()` lets any internal confidence
     (e.g. a crosswalk edge's) be expressed in that standard shape, and
     `component_evidence()` reads it back.
  2. Vulnerabilities (+ VEX analysis) — findings behind RA-5 / flaw remediation,
     with severity from CVSS ratings and, crucially, VEX state so a `not_affected`
     or `false_positive` vuln is not counted as an open finding.
  3. Component inventory — dependency/asset evidence and a severity histogram the
     policy engine can read directly.

Directions, all pure functions (no DB, no network — unit-testable):

    from_cyclonedx(bom)     BOM -> [NormalizedEvidence], one per ACTIVE vulnerability
                            (VEX-suppressed ones excluded), severity from ratings.
    sbom_summary(bom)       BOM -> flat telemetry (component_count,
                            critical_vulnerabilities, ...) the policy engine reads.
    component_evidence(bom) BOM -> the identity evidence objects (field, confidence,
                            techniques) per component.
    to_cdx_evidence(...)    build a CycloneDX evidence.identity object from an
                            internal confidence + a named technique.
    to_cyclonedx(...)       emit a minimal valid BOM (components/vulnerabilities),
                            for export and round-trip.

Targets CycloneDX 1.6. Severity words and concept ids are the ones Comp-Lens speaks.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from app.services.ocsf import NormalizedEvidence

BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.6"

# CycloneDX rating severity -> Comp-Lens severity word (they align except none/unknown)
_CDX_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium",
                 "low": "low", "info": "info", "none": "info", "unknown": "unknown"}
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1,
                  "unknown": 0}
# Comp-Lens severity word -> representative CVSS base score (for emit)
_SEVERITY_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5,
                   "info": 0.0, "unknown": 0.0}

# VEX analysis.state values that mean the vulnerability is NOT an open finding.
_VEX_SUPPRESSED = {"not_affected", "false_positive", "resolved", "resolved_with_pedigree"}

# Recognised identification techniques (CycloneDX evidence.methods[].technique).
IDENTITY_TECHNIQUES = {
    "source-code-analysis", "binary-analysis", "manifest-analysis", "ast-fingerprint",
    "hash-comparison", "instrumentation", "dynamic-analysis", "filename", "attestation",
    "other",
}

_VULN_CONCEPTS = ["vulnerability_management", "dependency_management"]


def _severity_from_score(score: Any) -> str | None:
    try:
        v = float(score)
    except (TypeError, ValueError):
        return None
    if v >= 9.0:
        return "critical"
    if v >= 7.0:
        return "high"
    if v >= 4.0:
        return "medium"
    if v > 0.0:
        return "low"
    return "info"


def _vuln_severity(vuln: dict[str, Any]) -> tuple[str, Any, str | None]:
    """Highest severity across a vulnerability's ratings -> (word, score, method)."""
    best_word, best_score, best_method = "unknown", None, None
    for r in vuln.get("ratings") or []:
        if not isinstance(r, dict):
            continue
        word = _CDX_SEVERITY.get(str(r.get("severity") or "").lower())
        if word is None:
            word = _severity_from_score(r.get("score"))
        if word is None:
            continue
        if _SEVERITY_RANK.get(word, 0) >= _SEVERITY_RANK.get(best_word, 0):
            best_word, best_score, best_method = word, r.get("score"), r.get("method")
    return best_word, best_score, best_method


def _vex_state(vuln: dict[str, Any]) -> str | None:
    analysis = vuln.get("analysis")
    if isinstance(analysis, dict) and analysis.get("state"):
        return str(analysis["state"]).lower()
    return None


def _affected_refs(vuln: dict[str, Any]) -> list[str]:
    out = []
    for a in vuln.get("affects") or []:
        if isinstance(a, dict) and a.get("ref"):
            out.append(str(a["ref"]))
    return out


def _tool_name(bom: dict[str, Any]) -> str:
    meta = bom.get("metadata") or {}
    tools = meta.get("tools")
    # 1.5+ shape: {"components":[{"name":...}]}; legacy: [{"name":...}]
    if isinstance(tools, dict):
        comps = tools.get("components") or []
        if comps and isinstance(comps[0], dict) and comps[0].get("name"):
            return str(comps[0]["name"]).upper().replace(" ", "_")
    if isinstance(tools, list) and tools and isinstance(tools[0], dict) and tools[0].get("name"):
        return str(tools[0]["name"]).upper().replace(" ", "_")
    return "CYCLONEDX"


def from_cyclonedx(bom: dict[str, Any]) -> list[NormalizedEvidence]:
    """One NormalizedEvidence per ACTIVE vulnerability (VEX-suppressed excluded)."""
    if not isinstance(bom, dict):
        return []
    out: list[NormalizedEvidence] = []
    now = datetime.now(UTC).isoformat()
    source = _tool_name(bom)
    for vuln in bom.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        state = _vex_state(vuln)
        if state in _VEX_SUPPRESSED:
            continue  # VEX says this isn't an open finding
        sev, score, method = _vuln_severity(vuln)
        refs = _affected_refs(vuln)
        vid = str(vuln.get("id") or "")
        concepts = list(_VULN_CONCEPTS)
        # a fix being available makes it a patch/flaw-remediation signal too
        if vuln.get("recommendation") or vuln.get("workaround"):
            concepts.append("patch_management")
        out.append(NormalizedEvidence(
            source_system=source, plane="vulnerability_threat", observed_at=now,
            asset_id=(refs[0] if refs else None), asset_type="component", severity=sev,
            concepts=concepts,
            findings=[{
                "id": vid, "severity": sev, "cvss_score": score, "cvss_method": method,
                "vex_state": state, "affects": refs,
                "source": ((vuln.get("source") or {}).get("name")),
                "description": vuln.get("description"),
            }],
            provenance={"cyclonedx_spec": bom.get("specVersion", SPEC_VERSION),
                        "bom_serial": bom.get("serialNumber"), "vuln_id": vid},
        ))
    return out


def sbom_summary(bom: dict[str, Any]) -> dict[str, Any]:
    """Flat telemetry the policy engine reads directly. `critical_vulnerabilities`
    counts only ACTIVE criticals (VEX-suppressed excluded) — the RA-5 field."""
    if not isinstance(bom, dict):
        return {"sbom_present": False}
    components = [c for c in (bom.get("components") or []) if isinstance(c, dict)]
    licenses: set[str] = set()
    for c in components:
        for lic in c.get("licenses") or []:
            lo = (lic or {}).get("license") or {}
            lid = lo.get("id") or lo.get("name")
            if lid:
                licenses.add(str(lid))
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    vulnerable_refs: set[str] = set()
    for ev in from_cyclonedx(bom):
        counts[ev.severity if ev.severity in counts else "unknown"] += 1
        if ev.asset_id:
            vulnerable_refs.add(ev.asset_id)
    return {
        "sbom_present": True,
        "component_count": len(components),
        "vulnerable_components": len(vulnerable_refs),
        "critical_vulnerabilities": counts["critical"],
        "high_vulnerabilities": counts["high"],
        "total_vulnerabilities": sum(counts.values()),
        "license_count": len(licenses),
        "licenses": sorted(licenses),
    }


def component_evidence(bom: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the CycloneDX component `evidence.identity` objects — the
    field / confidence / named-technique primitive."""
    if not isinstance(bom, dict):
        return []
    out: list[dict[str, Any]] = []
    for c in bom.get("components") or []:
        if not isinstance(c, dict):
            continue
        identity = ((c.get("evidence") or {}).get("identity"))
        # 1.6 allows identity to be a list; 1.5 a single object
        identities = identity if isinstance(identity, list) else ([identity] if identity else [])
        for idn in identities:
            if not isinstance(idn, dict):
                continue
            techniques = [str(m.get("technique")) for m in (idn.get("methods") or [])
                          if isinstance(m, dict) and m.get("technique")]
            out.append({
                "ref": c.get("bom-ref") or c.get("purl") or c.get("name"),
                "field": idn.get("field"),
                "confidence": idn.get("confidence"),
                "techniques": techniques,
            })
    return out


def to_cdx_evidence(*, field: str, confidence: float, technique: str,
                    value: str | None = None) -> dict[str, Any]:
    """Express an internal confidence as a CycloneDX evidence.identity object.

    This is the bridge for Comp-Lens's own confidence numbers (e.g. a crosswalk
    edge's `Mapping.confidence`): they can now be emitted with a named
    identification technique instead of a bare float. `technique` is validated
    against the CycloneDX vocabulary.
    """
    tech = technique if technique in IDENTITY_TECHNIQUES else "other"
    conf = round(max(0.0, min(1.0, float(confidence))), 4)
    method: dict[str, Any] = {"technique": tech, "confidence": conf}
    if value is not None:
        method["value"] = str(value)
    return {"identity": {"field": field, "confidence": conf, "methods": [method]}}


def to_cyclonedx(*, components: list[dict[str, Any]] | None = None,
                 vulnerabilities: list[dict[str, Any]] | None = None,
                 product: str = "Comp-Lens") -> dict[str, Any]:
    """Emit a minimal valid CycloneDX 1.6 BOM (for export and round-trip)."""
    return {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": {"components": [{"type": "application", "name": product}]},
        },
        "components": list(components or []),
        "vulnerabilities": list(vulnerabilities or []),
    }


def vulnerability(*, vid: str, severity: str = "medium", affects_ref: str | None = None,
                  method: str = "CVSSv31", description: str | None = None,
                  vex_state: str | None = None) -> dict[str, Any]:
    """Build one CycloneDX vulnerability object (helper for emit / tests)."""
    sev = severity.lower()
    v: dict[str, Any] = {
        "id": vid,
        "ratings": [{"severity": sev if sev in _CDX_SEVERITY else "medium",
                     "score": _SEVERITY_SCORE.get(sev, 5.5), "method": method}],
    }
    if description:
        v["description"] = description
    if affects_ref:
        v["affects"] = [{"ref": affects_ref}]
    if vex_state:
        v["analysis"] = {"state": vex_state}
    return v


__all__ = [
    "BOM_FORMAT", "SPEC_VERSION", "IDENTITY_TECHNIQUES",
    "from_cyclonedx", "sbom_summary", "component_evidence",
    "to_cdx_evidence", "to_cyclonedx", "vulnerability",
]
