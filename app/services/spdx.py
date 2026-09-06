"""SPDX interoperability adapter — the other SBOM standard.

SPDX (ISO/IEC 5962) is the composition standard many toolchains emit alongside or
instead of CycloneDX (Syft, the Linux Foundation tooling, GitHub's dependency
export). Where CycloneDX carries rich vulnerability + VEX objects, SPDX is
inventory-first: packages, licenses, and security references via `externalRefs`.

Pure functions (no DB, no network — unit-testable):

    from_spdx(doc)      SPDX doc -> [NormalizedEvidence], one per package that
                        carries a SECURITY external reference (a known advisory /
                        CVE), as a vulnerability finding.
    spdx_summary(doc)   SPDX doc -> flat telemetry (package_count, license
                        inventory, packages_with_advisories, sbom_present).
    to_spdx(packages)   emit a minimal valid SPDX 2.3 document (export/round-trip).

Targets SPDX 2.3 (JSON). Concept ids are the ones Comp-Lens speaks.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from app.services.ocsf import NormalizedEvidence
from app.services.shapes import as_dict, as_list

SPDX_VERSION = "SPDX-2.3"

_INVENTORY_CONCEPTS = ["dependency_management", "asset_inventory", "supply_chain_security"]
_SECURITY_CONCEPTS = ["vulnerability_management", "dependency_management"]

# SPDX license fields that mean "no assertion" (excluded from the license set).
_LICENSE_NOISE = {"", "noassertion", "none"}


def _tool(doc: dict[str, Any]) -> str:
    creators = as_list((as_dict(doc.get("creationInfo"))).get("creators"))
    for c in creators:
        s = str(c)
        if s.lower().startswith("tool:"):
            return s.split(":", 1)[1].strip().upper().replace(" ", "_").replace("-", "_")
    return "SPDX"


def _security_refs(pkg: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for ref in as_list(pkg.get("externalRefs")):
        if isinstance(ref, dict) and str(ref.get("referenceCategory", "")).upper() == "SECURITY":
            out.append(ref)
    return out


def _licenses(pkg: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for key in ("licenseConcluded", "licenseDeclared"):
        val = pkg.get(key)
        if val and str(val).strip().lower() not in _LICENSE_NOISE:
            out.add(str(val).strip())
    return out


def from_spdx(doc: dict[str, Any]) -> list[NormalizedEvidence]:
    """One NormalizedEvidence per package carrying a SECURITY external reference."""
    if not isinstance(doc, dict):
        return []
    out: list[NormalizedEvidence] = []
    now = datetime.now(UTC).isoformat()
    source = _tool(doc)
    for pkg in as_list(doc.get("packages")):
        if not isinstance(pkg, dict):
            continue
        refs = _security_refs(pkg)
        if not refs:
            continue
        name = pkg.get("name") or pkg.get("SPDXID") or "unknown"
        version = pkg.get("versionInfo")
        asset = f"{name}@{version}" if version else str(name)
        out.append(NormalizedEvidence(
            source_system=source, plane="vulnerability_threat", observed_at=now,
            asset_id=asset, asset_type="package", severity="unknown",
            concepts=list(_SECURITY_CONCEPTS),
            findings=[{
                "package": str(name), "version": version,
                "advisories": [r.get("referenceLocator") for r in refs],
                "reference_types": [r.get("referenceType") for r in refs],
            }],
            provenance={"spdx_version": doc.get("spdxVersion", SPDX_VERSION),
                        "document": doc.get("name"), "spdx_id": pkg.get("SPDXID")},
        ))
    return out


def spdx_summary(doc: dict[str, Any]) -> dict[str, Any]:
    """Flat telemetry: inventory size, license set, and packages with advisories."""
    if not isinstance(doc, dict):
        return {"sbom_present": False}
    packages = [p for p in (as_list(doc.get("packages"))) if isinstance(p, dict)]
    licenses: set[str] = set()
    with_adv = 0
    for p in packages:
        licenses |= _licenses(p)
        if _security_refs(p):
            with_adv += 1
    return {
        "sbom_present": True,
        "package_count": len(packages),
        "packages_with_advisories": with_adv,
        "license_count": len(licenses),
        "licenses": sorted(licenses),
    }


def _spdx_timestamp(dt: datetime | None = None) -> str:
    """`YYYY-MM-DDThh:mm:ssZ`, which is the only shape SPDX 2.3 accepts.

    `datetime.isoformat()` produces `+00:00` and microseconds, so every document
    this module emitted was rejected by the SPDX validator on its timestamp
    alone.
    """
    return (dt or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _spdx_id(prefix: str, name: str, seq: int) -> str:
    """An SPDXID conforming to `SPDXRef-[a-zA-Z0-9.-]+`.

    Only letters, digits, `.` and `-` are legal in an SPDX element id, so
    `SPDXRef-Package-@babel/core` — any scoped npm package, and anything with an
    underscore or a space — was structurally invalid. Illegal characters are
    replaced and a sequence number keeps ids unique when two names normalise to
    the same string.
    """
    slug = re.sub(r"[^A-Za-z0-9.-]", "-", str(name)).strip("-") or "unnamed"
    return f"SPDXRef-{prefix}-{seq}-{slug}"[:200]


def to_spdx(*, packages: list[dict[str, Any]] | None = None,
            name: str = "comp-lens-export", creator: str = "Comp-Lens") -> dict[str, Any]:
    """Emit a minimal valid SPDX 2.3 document.

    "Valid" is meant literally: the timestamp is in SPDX's required form, every
    SPDXID conforms to the element-id charset, and the document declares what it
    describes — SPDX 2.3 requires a DESCRIBES relationship (or
    `documentDescribes`) and this emitted neither.
    """
    pkgs = list(as_list(packages))
    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": name,
        "documentNamespace": f"https://comp-lens/spdx/{quote(str(name), safe='')}",
        "creationInfo": {
            "created": _spdx_timestamp(),
            "creators": [f"Tool: {creator}"],
        },
        "packages": pkgs,
        "documentDescribes": [p["SPDXID"] for p in pkgs if p.get("SPDXID")],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT",
             "relationshipType": "DESCRIBES",
             "relatedSpdxElement": p["SPDXID"]}
            for p in pkgs if p.get("SPDXID")
        ],
    }


def package(*, name: str, version: str | None = None, license_concluded: str = "NOASSERTION",
            advisories: list[str] | None = None, seq: int = 0) -> dict[str, Any]:
    """Build one SPDX package (helper for emit / tests)."""
    p: dict[str, Any] = {
        "SPDXID": _spdx_id("Package", name, seq),
        "name": name, "downloadLocation": "NOASSERTION",
        "licenseConcluded": license_concluded,
    }
    if version:
        p["versionInfo"] = version
    if advisories:
        p["externalRefs"] = [{"referenceCategory": "SECURITY", "referenceType": "advisory",
                              "referenceLocator": a} for a in advisories]
    return p


__all__ = ["SPDX_VERSION", "from_spdx", "spdx_summary", "to_spdx", "package"]

