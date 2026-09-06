"""Sigstore interoperability adapter — signed attestations + transparency evidence.

Sigstore is the keyless-signing ecosystem (Fulcio short-lived certs, the Rekor
transparency log, cosign bundles). It is how a build's attestation is *signed and
publicly logged* — the standards-based alternative to Comp-Lens's own shared-secret
`evidence_sign`. When a Sigstore bundle wraps an in-toto attestation, that attestation
plus a Rekor inclusion proof is strong, independently-verifiable integrity evidence.

Pure functions (no DB, no network — unit-testable):

    from_sigstore(bundle)     a Sigstore/cosign bundle -> NormalizedEvidence:
                              whether it is signed, whether it is in a transparency
                              log (Rekor), the wrapped predicate type and subjects.
    bundle_metadata(bundle)   the extractable facts (rekor log index/time, cert
                              presence, payload type) without verifying signatures.

IMPORTANT: this reads *structure and transparency metadata only*. Cryptographic
signature verification (Fulcio cert chain, Rekor inclusion proof, identity policy)
requires the sigstore libraries and network access and is deliberately out of scope;
`bundle_metadata()["cryptographically_verified"]` is always False here.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services.intoto import dsse_decode
from app.services.ocsf import NormalizedEvidence
from app.services.shapes import as_dict, as_list

_INTEGRITY_CONCEPTS = ["data_integrity", "audit_log_protection"]


def _dsse_envelope(bundle: dict[str, Any]) -> dict[str, Any] | None:
    env = bundle.get("dsseEnvelope") or bundle.get("dsse_envelope")
    return env if isinstance(env, dict) else None


def _tlog_entries(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    vm = bundle.get("verificationMaterial") or bundle.get("verification_material") or {}
    entries = vm.get("tlogEntries") or vm.get("tlog_entries") or []
    return [e for e in entries if isinstance(e, dict)]


def _has_certificate(bundle: dict[str, Any]) -> bool:
    vm = bundle.get("verificationMaterial") or bundle.get("verification_material") or {}
    return bool(vm.get("certificate") or vm.get("x509CertificateChain")
                or vm.get("x509_certificate_chain"))


def bundle_metadata(bundle: dict[str, Any]) -> dict[str, Any]:
    """Extract the verifiable-looking facts from a Sigstore bundle — structure and
    transparency metadata only, never a cryptographic verdict."""
    if not isinstance(bundle, dict):
        return {"signed": False, "cryptographically_verified": False}
    env = _dsse_envelope(bundle)
    payload = dsse_decode(env) if env else None
    tlogs = _tlog_entries(bundle)
    first = tlogs[0] if tlogs else {}
    return {
        "signed": bool(env and (env.get("signatures") or _has_certificate(bundle))),
        "has_certificate": _has_certificate(bundle),
        "in_transparency_log": bool(tlogs),
        "rekor_log_index": first.get("logIndex") or first.get("log_index"),
        "integrated_time": first.get("integratedTime") or first.get("integrated_time"),
        "payload_type": (as_dict(env)).get("payloadType"),
        "predicate_type": (as_dict(payload)).get("predicateType") if isinstance(payload, dict) else None,
        "media_type": bundle.get("mediaType") or bundle.get("media_type"),
        "cryptographically_verified": False,  # structural read only — never claim crypto proof
    }


def from_sigstore(bundle: dict[str, Any]) -> NormalizedEvidence | None:
    """Map a Sigstore bundle to integrity/non-repudiation evidence."""
    if not isinstance(bundle, dict):
        return None
    meta = bundle_metadata(bundle)
    env = _dsse_envelope(bundle)
    payload = dsse_decode(env) if env else None
    subjects = []
    if isinstance(payload, dict):
        for s in as_list(payload.get("subject")):
            if isinstance(s, dict) and s.get("name"):
                subjects.append(s["name"])
    return NormalizedEvidence(
        source_system="SIGSTORE", plane="activity_audit",
        observed_at=datetime.now(UTC).isoformat(),
        asset_id=(subjects[0] if subjects else None), asset_type="artifact",
        severity="info", concepts=list(_INTEGRITY_CONCEPTS),
        telemetry={"evidence_signed": meta["signed"],
                   "in_transparency_log": meta["in_transparency_log"]},
        provenance=meta,
    )


__all__ = ["from_sigstore", "bundle_metadata"]
