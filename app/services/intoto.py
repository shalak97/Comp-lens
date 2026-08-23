"""in-toto / SLSA interoperability adapter — build provenance at the evidence layer.

in-toto Attestations (with SLSA Provenance as the flagship predicate) are how the
supply chain proves *how an artifact was built*: a signed Statement binding a subject
(an artifact + its digest) to a predicate (the build definition, builder identity,
and materials). This is positive evidence behind supply-chain and secure-development
controls, not a finding.

Pure functions (no DB, no network — unit-testable):

    from_intoto(stmt)       an in-toto Statement (or a DSSE envelope wrapping one)
                            -> NormalizedEvidence: subjects, predicate type, builder
                            id, and a coarse SLSA-provenance signal.
    to_intoto_statement()   build a Statement.
    dsse_encode/decode()    the DSSE envelope codec (shared with the Sigstore adapter).
    verify_subject_digest() structural check that a Statement covers (name, sha256).

Targets in-toto Statement v1 / SLSA Provenance v1. This is *structural* extraction;
cryptographic signature verification needs a signing library and is out of scope here.
"""
from __future__ import annotations

import base64
import binascii
import json
from datetime import UTC, datetime
from typing import Any

from app.services.ocsf import NormalizedEvidence

STATEMENT_TYPE_V1 = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

_PROVENANCE_CONCEPTS = ["supply_chain_security", "secure_development"]


def dsse_encode(payload: dict[str, Any], payload_type: str = DSSE_PAYLOAD_TYPE) -> dict[str, Any]:
    """Wrap a payload in a DSSE envelope (unsigned — signatures are added by a signer)."""
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return {"payloadType": payload_type,
            "payload": base64.b64encode(raw).decode("ascii"),
            "signatures": []}


def dsse_decode(envelope: dict[str, Any]) -> dict[str, Any] | None:
    """Return the decoded payload of a DSSE envelope, or None if it isn't one."""
    if not isinstance(envelope, dict) or "payload" not in envelope:
        return None
    try:
        raw = base64.b64decode(envelope["payload"], validate=True)
        return json.loads(raw)
    except (binascii.Error, ValueError, TypeError):
        return None


def _as_statement(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Accept a bare Statement or a DSSE envelope wrapping one."""
    if not isinstance(obj, dict):
        return None
    if obj.get("_type") == STATEMENT_TYPE_V1 or "predicateType" in obj:
        return obj
    decoded = dsse_decode(obj)
    if isinstance(decoded, dict):
        return decoded
    return None


def _subjects(stmt: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for s in stmt.get("subject") or []:
        if isinstance(s, dict) and s.get("name"):
            digest = s.get("digest") or {}
            out.append({"name": s["name"],
                        "sha256": digest.get("sha256") if isinstance(digest, dict) else None})
    return out


def _builder_id(stmt: dict[str, Any]) -> str | None:
    pred = stmt.get("predicate") or {}
    if not isinstance(pred, dict):
        return None
    # SLSA v1 shape
    rd = pred.get("runDetails") or {}
    builder = (rd.get("builder") or {}) if isinstance(rd, dict) else {}
    if isinstance(builder, dict) and builder.get("id"):
        return str(builder["id"])
    # SLSA v0.2 shape
    b2 = pred.get("builder") or {}
    if isinstance(b2, dict) and b2.get("id"):
        return str(b2["id"])
    return None


def from_intoto(obj: dict[str, Any]) -> NormalizedEvidence | None:
    """Map an in-toto Statement (or DSSE-wrapped one) to NormalizedEvidence."""
    stmt = _as_statement(obj)
    if stmt is None:
        return None
    predicate_type = stmt.get("predicateType")
    subjects = _subjects(stmt)
    builder = _builder_id(stmt)
    is_slsa = str(predicate_type or "").startswith("https://slsa.dev/provenance")
    ev = NormalizedEvidence(
        source_system=(builder.upper().replace(" ", "_")[:64] if builder else "IN_TOTO"),
        plane="change_delivery", observed_at=datetime.now(UTC).isoformat(),
        asset_id=(subjects[0]["name"] if subjects else None), asset_type="artifact",
        severity="info", concepts=list(_PROVENANCE_CONCEPTS),
        telemetry={"build_provenance": True,
                   "slsa_provenance": is_slsa,
                   "builder_id": builder},
        provenance={"predicate_type": predicate_type, "statement_type": stmt.get("_type"),
                    "subjects": subjects, "builder_id": builder},
    )
    return ev


def to_intoto_statement(*, subject_name: str, sha256: str,
                        predicate_type: str = SLSA_PROVENANCE_V1,
                        predicate: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build an in-toto Statement v1."""
    return {
        "_type": STATEMENT_TYPE_V1,
        "subject": [{"name": subject_name, "digest": {"sha256": sha256}}],
        "predicateType": predicate_type,
        "predicate": predicate or {},
    }


def verify_subject_digest(obj: dict[str, Any], name: str, sha256: str) -> bool:
    """Structural check that a Statement covers (name, sha256). Not a crypto check."""
    stmt = _as_statement(obj)
    if stmt is None:
        return False
    return any(s["name"] == name and s["sha256"] == sha256 for s in _subjects(stmt))


__all__ = [
    "STATEMENT_TYPE_V1", "SLSA_PROVENANCE_V1", "DSSE_PAYLOAD_TYPE",
    "from_intoto", "to_intoto_statement", "verify_subject_digest",
    "dsse_encode", "dsse_decode",
]
