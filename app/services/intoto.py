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

That caveat is enforced, not just documented. `build_provenance` — the telemetry
flag standards_ingest turns into a PASS finding against SR-3 — is set only when
the envelope actually carries a signature. An unsigned statement is still
reported, under `build_provenance_unverified`, because a build that shipped
without provenance signing is worth seeing; it just is not evidence that the
control holds. Signature *presence* is as far as this module goes:
`signature_verified` is always False here, and a signing library is what would
change that.
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
    """Subjects with every digest algorithm the statement carries.

    Only `sha256` was extracted, so a statement using sha512 or gitCommit — both
    normal in the wild — produced `sha256: None` and could never be verified,
    a result indistinguishable from "this artifact is not covered".
    """
    out = []
    for s in stmt.get("subject") or []:
        if isinstance(s, dict) and s.get("name"):
            digest = s.get("digest") if isinstance(s.get("digest"), dict) else {}
            digests = {str(k).lower(): str(v).lower()
                       for k, v in digest.items() if v is not None}
            out.append({"name": s["name"], "digests": digests,
                        "sha256": digests.get("sha256")})
    return out


def is_signed(obj: dict[str, Any]) -> bool:
    """Whether a DSSE envelope carries at least one signature.

    Structural only — it says a signature is *present*, never that it verifies.
    A bare Statement (not wrapped in an envelope) carries no signature at all.
    """
    if not isinstance(obj, dict):
        return False
    sigs = obj.get("signatures")
    return isinstance(sigs, list) and any(
        isinstance(s, dict) and s.get("sig") for s in sigs)


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
    signed = is_signed(obj)
    ev = NormalizedEvidence(
        source_system=(builder.upper().replace(" ", "_")[:64] if builder else "IN_TOTO"),
        plane="change_delivery", observed_at=datetime.now(UTC).isoformat(),
        asset_id=(subjects[0]["name"] if subjects else None), asset_type="artifact",
        severity="info", concepts=list(_PROVENANCE_CONCEPTS),
        # `build_provenance` means "provenance exists AND is signed". A
        # statement is a claim the payload makes about itself: an unsigned DSSE
        # envelope with `signatures: []` is anyone's assertion, and setting the
        # flag from a bare parse turned that into a PASS finding against SR-3
        # attributed to whatever builder id the payload named. The unsigned case
        # is still reported — as an observation, under its own flag — because a
        # missing signature is worth seeing.
        telemetry={"build_provenance": signed,
                   "build_provenance_unverified": not signed,
                   "slsa_provenance": is_slsa and signed,
                   "attestation_signed": signed,
                   "builder_id": builder},
        provenance={"predicate_type": predicate_type, "statement_type": stmt.get("_type"),
                    "subjects": subjects, "builder_id": builder,
                    "signed": signed,
                    # Structural only: a signature is present, not verified.
                    "signature_verified": False},
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


def verify_subject_digest(obj: dict[str, Any], name: str, digest: str,
                          algorithm: str = "sha256") -> bool:
    """Structural check that a Statement covers (name, digest). Not a crypto check.

    Hex digests are written in either case by different tools, so the comparison
    is case-insensitive: it used to return False for the same digest upper-cased,
    which reads as "not covered". `algorithm` selects which digest to compare,
    so a statement using sha512 or gitCommit can be checked too.
    """
    stmt = _as_statement(obj)
    if stmt is None:
        return False
    want_alg = str(algorithm).lower()
    want = str(digest).lower()
    return any(s["name"] == name and s["digests"].get(want_alg) == want
               for s in _subjects(stmt))


__all__ = [
    "STATEMENT_TYPE_V1", "SLSA_PROVENANCE_V1", "DSSE_PAYLOAD_TYPE",
    "from_intoto", "to_intoto_statement", "verify_subject_digest",
    "dsse_encode", "dsse_decode",
]
