"""Wire the open-standard adapters into the evidence ingestion path.

The OCSF / SARIF / CycloneDX / SPDX / in-toto / STIX / Sigstore adapters each turn
a standard document into `NormalizedEvidence`. This module lands that evidence in
the database by reusing the proven, idempotent `AssessmentService.record_external_finding`
sink (the same one the Security Hub / Prowler ingestion uses) — so standard-format
evidence folds into posture, drift and the OSCAL export with no new write path.

Two layers, split so the decision logic is unit-testable without a database:

  normalize(fmt, payload) -> [NormalizedEvidence]      pure — dispatch to the adapter
  plan_findings(evidences) -> [FindingPlan]            pure — decide what to persist
  StandardsIngestionService(db).ingest(...)            thin loop over record_external_finding

Persistence policy (deliberately conservative — we never invent a control verdict):
  1. explicit control verdicts (OCSF Compliance Findings, `ne.controls`) become
     findings, with the control ref crosswalked into the canonical NIST namespace
     when the shared STRM crosswalk knows it;
  2. vulnerability findings (a `vulnerability_management` concept) become FAIL
     findings against the mapped NIST control (RA-5), one per finding id;
  3. positive attestations (build provenance -> SR-3, signatures -> SI-7) become
     PASS findings against their concept's canonical control;
  4. anything left — threat-intel context, non-vuln findings — is counted as
     observed-only and never turned into a control verdict.
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from app.grc_platforms import crosswalk as xw
from app.services import cyclonedx, intoto, ocsf, sarif, sigstore, spdx, stix
from app.services.ocsf import NormalizedEvidence

_LEXICON = os.path.join(os.path.dirname(__file__), "..", "data", "concept_lexicon.json")
_CANONICAL_FRAMEWORK = "NIST_800_53"
_VULN_CONCEPT = "vulnerability_management"

# Positive attestations: a truthy telemetry flag evidences a concept, persisted as a
# PASS finding against that concept's canonical NIST control. This is how build
# provenance (in-toto/SLSA) and signatures (Sigstore) land as evidence rather than
# being merely observed — the one thing that was previously counted but not persisted.
_POSITIVE_SIGNALS = {
    "build_provenance": "supply_chain_security",   # in-toto / SLSA  -> SR-3
    "evidence_signed": "data_integrity",           # Sigstore signature -> SI-7
}


def _wrap_single(fn: Callable[[dict], NormalizedEvidence | None]):
    def inner(payload: dict) -> list[NormalizedEvidence]:
        ev = fn(payload)
        return [ev] if ev is not None else []
    return inner


# format name -> adapter producing a list of NormalizedEvidence
_ADAPTERS: dict[str, Callable[[dict], list[NormalizedEvidence]]] = {
    "ocsf": _wrap_single(ocsf.from_ocsf),
    "sarif": sarif.from_sarif,
    "cyclonedx": cyclonedx.from_cyclonedx,
    "spdx": spdx.from_spdx,
    "intoto": _wrap_single(intoto.from_intoto),
    "stix": stix.from_stix,
    "sigstore": _wrap_single(sigstore.from_sigstore),
}

SUPPORTED_FORMATS = sorted(_ADAPTERS)


class UnsupportedFormat(ValueError):
    """Raised when an unknown evidence format is requested."""


def normalize(fmt: str, payload: dict[str, Any]) -> list[NormalizedEvidence]:
    """Dispatch a standard document to its adapter. Pure."""
    adapter = _ADAPTERS.get((fmt or "").lower())
    if adapter is None:
        raise UnsupportedFormat(f"unsupported evidence format: {fmt!r}; "
                                f"expected one of {SUPPORTED_FORMATS}")
    return adapter(payload)


@lru_cache(maxsize=1)
def _concept_nist_control() -> dict[str, str]:
    """concept id -> its canonical NIST 800-53 control id, from the lexicon. Pure."""
    try:
        with open(_LEXICON) as fh:
            lex = json.load(fh)
    except (OSError, ValueError):
        return {}
    out: dict[str, str] = {}
    for c in lex:
        for m in c.get("controls", []):
            if m.get("framework") == _CANONICAL_FRAMEWORK:
                out.setdefault(c["id"], m["control_id"])
                break
    return out


@dataclass
class FindingPlan:
    """One planned call to record_external_finding — status/severity as plain
    strings so this stays free of the (SQLAlchemy-bound) enum types."""
    framework: str
    control_id: str
    source_system: str
    asset_id: str | None
    status: str          # "pass" | "fail" | "error"
    severity: str        # comp-lens severity word
    description: str
    external_id: str
    raw: dict[str, Any]


def _finding_key(f: dict[str, Any]) -> str:
    """A stable, collision-resistant identity for one finding.

    Re-ingesting the SAME finding must dedup (idempotency), but two *different*
    findings must never share a key. Prefer a globally-unique id (CVE, STIX id,
    SARIF fingerprint, vuln id); when none exists, build a composite from the
    identifying fields so findings that share a rule or package but differ by
    location or version stay distinct — otherwise the idempotency check silently
    drops the second one.
    """
    for k in ("cve", "id", "stix_id", "fingerprint"):
        if f.get(k):
            return str(f[k])
    parts = [f"{k}={f[k]}" for k in ("rule_id", "package", "version", "name", "location", "line")
             if f.get(k) is not None]
    return "|".join(parts) or "finding"


def plan_for_evidence(ne: NormalizedEvidence,
                      concept_ctrl: dict[str, str] | None = None) -> list[FindingPlan]:
    """Plan the findings for a single evidence. Pure — no DB.

    Exactly one of three branches fires: explicit control verdicts, vulnerability
    findings, or positive attestations. This is the authoritative unit — both
    plan_findings() and the observed-only count derive from it, so they never drift.
    """
    concept_ctrl = concept_ctrl if concept_ctrl is not None else _concept_nist_control()
    out: list[FindingPlan] = []

    # 1. explicit control verdicts (crosswalked into the canonical namespace)
    if ne.controls:
        for c in ne.controls:
            ref = str(c.get("control_ref") or "")
            standards = c.get("standards") or []
            mapping, _fw = xw.resolve_best(ref, standards)
            if mapping:
                framework, control_id = _CANONICAL_FRAMEWORK, mapping.control_id
                raw_extra = {"source_control_ref": ref, "source_standards": standards,
                             "crosswalk_relationship": mapping.relationship.value,
                             "crosswalk_confidence": mapping.confidence}
            else:
                framework = (str(standards[0]) if standards else "NIST")
                control_id = ref or "UNKNOWN"
                raw_extra = {"source_control_ref": ref, "source_standards": standards}
            status = str(c.get("status") or "").lower()
            status = status if status in ("pass", "fail") else "error"
            out.append(FindingPlan(
                framework=framework, control_id=control_id,
                source_system=ne.source_system, asset_id=ne.asset_id,
                status=status, severity=ne.severity or "medium",
                description=f"{ne.source_system} {control_id}: {status}"[:480],
                external_id=f"{ne.source_system}:{ref}:{ne.asset_id or ''}",
                raw={**raw_extra, "plane": ne.plane}))
        return out

    # 2. vulnerability findings -> the mapped NIST control (RA-5), FAIL each
    if _VULN_CONCEPT in ne.concepts and ne.findings:
        control_id = concept_ctrl.get(_VULN_CONCEPT, "RA-5")
        for f in ne.findings:
            fid = _finding_key(f)
            desc = str(f.get("description") or f.get("message") or f.get("name") or fid)
            out.append(FindingPlan(
                framework=_CANONICAL_FRAMEWORK, control_id=control_id,
                source_system=ne.source_system, asset_id=ne.asset_id,
                status="fail", severity=ne.severity or "medium",
                description=f"{fid}: {desc}"[:480],
                external_id=f"{ne.source_system}:{fid}",
                raw={"finding": f, "concepts": ne.concepts, "plane": ne.plane}))
        return out

    # 3. positive attestations (build provenance / signatures) -> PASS
    for flag, concept in _POSITIVE_SIGNALS.items():
        if not ne.telemetry.get(flag) or concept not in ne.concepts:
            continue
        cid = concept_ctrl.get(concept)
        if not cid:
            continue
        out.append(FindingPlan(
            framework=_CANONICAL_FRAMEWORK, control_id=cid,
            source_system=ne.source_system, asset_id=ne.asset_id,
            status="pass", severity="info",
            description=f"{ne.source_system}: {concept} attested for {ne.asset_id or 'artifact'}"[:480],
            external_id=f"{ne.source_system}:{concept}:{ne.asset_id or ''}",
            raw={"attestation": concept, "telemetry": ne.telemetry, "plane": ne.plane}))
    return out


def _yields_finding(ne: NormalizedEvidence) -> bool:
    """Whether this evidence produces at least one persisted finding."""
    return bool(plan_for_evidence(ne))


def plan_findings(evidences: list[NormalizedEvidence]) -> list[FindingPlan]:
    """Decide what to persist from a batch of evidence. Pure — no DB."""
    concept_ctrl = _concept_nist_control()
    return [p for ne in evidences for p in plan_for_evidence(ne, concept_ctrl)]


class StandardsIngestionService:
    """DB-facing wiring: normalize -> plan -> persist via the proven sink."""

    def __init__(self, db) -> None:
        # Lazy import keeps this module importable (and its pure functions
        # testable) without SQLAlchemy present.
        from app.services.ingestion import IngestionService
        self._ing = IngestionService(db)

    def ingest(self, tenant_id: str, fmt: str, payload: dict[str, Any]) -> dict[str, Any]:
        from app.services.ingestion import _severity, _status

        evidences = normalize(fmt, payload)
        concept_ctrl = _concept_nist_control()
        plans: list[FindingPlan] = []
        observed_only = 0
        for ne in evidences:
            ep = plan_for_evidence(ne, concept_ctrl)
            if ep:
                plans.extend(ep)
            else:
                observed_only += 1  # threat context / non-vuln findings — no verdict
        ingested, skipped = 0, 0
        for pl in plans:
            res = self._ing.svc.record_external_finding(
                tenant_id=tenant_id, framework=pl.framework, control_id=pl.control_id,
                source_system=pl.source_system, asset_id=pl.asset_id,
                status=_status(pl.status), severity=_severity(pl.severity),
                description=pl.description, raw=pl.raw, external_id=pl.external_id)
            if res is not None:
                ingested += 1
            else:
                skipped += 1
        return {
            "format": fmt.lower(),
            "evidences": len(evidences),
            "planned": len(plans),
            "ingested": ingested,
            "skipped": skipped,
            "observed_only": observed_only,
        }


__all__ = [
    "SUPPORTED_FORMATS", "UnsupportedFormat", "normalize", "plan_findings",
    "plan_for_evidence", "FindingPlan", "StandardsIngestionService",
]
