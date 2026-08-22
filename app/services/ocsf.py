"""OCSF interoperability adapter — the evidence-layer boundary.

The Open Cybersecurity Schema Framework (OCSF) is the vendor-neutral event schema
the ecosystem has converged on: AWS Security Lake, Datadog, SentinelOne, Panther and
others emit it natively. Comp-Lens normalises evidence to an internal concept/telemetry
model; this module is the seam between the two, so we ingest from the whole OCSF
ecosystem instead of writing a bespoke adapter per source, and we can hand an auditor
compliance results in a standard shape.

Two directions, both pure functions (no DB, no network — unit-testable):

    from_ocsf(event)                  OCSF event  -> NormalizedEvidence
                                      (flat telemetry dict + asset + evidenced
                                       concepts + control results + provenance),
                                      the same shape a native connector produces,
                                      so it flows straight into the policy/telemetry
                                      layer.

    to_ocsf_compliance_finding(...)   a Comp-Lens control decision
                                      -> OCSF Compliance Finding (class_uid 2003).

Targets OCSF 1.x. Every schema constant lives in a named table below, so a version
bump is a data edit, not a code change. Concept ids and telemetry field names are the
ones the rest of Comp-Lens already speaks (see concept_lexicon.json and the telemetry
fields the policy engine reads), so nothing downstream has to change to consume this.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

OCSF_VERSION = "1.4.0"

# ── OCSF category / class ids we understand ──────────────────────────────────
CAT_SYSTEM_ACTIVITY = 1
CAT_FINDINGS = 2
CAT_IAM = 3
CAT_NETWORK_ACTIVITY = 4
CAT_DISCOVERY = 5
CAT_APPLICATION_ACTIVITY = 6

CLASS_AUTHENTICATION = 3002       # IAM
CLASS_ACCOUNT_CHANGE = 3001       # IAM
CLASS_COMPLIANCE_FINDING = 2003   # Findings
CLASS_DETECTION_FINDING = 2004    # Findings
CLASS_DEVICE_INVENTORY = 5001     # Discovery

# ── severity: OCSF severity_id <-> Comp-Lens severity word ───────────────────
SEVERITY_NAME = {0: "unknown", 1: "info", 2: "low", 3: "medium",
                 4: "high", 5: "critical", 6: "fatal"}
SEVERITY_ID = {"info": 1, "informational": 1, "low": 2, "medium": 3,
               "high": 4, "critical": 5, "fatal": 6}

# ── finding activity_id (Findings category) ──────────────────────────────────
FINDING_ACTIVITY_CREATE = 1
FINDING_ACTIVITY_UPDATE = 2
FINDING_ACTIVITY_CLOSE = 3

# ── which internal evidence plane an OCSF category lands in ──────────────────
# (planes are defined in telemetry_ontology.json)
_CATEGORY_PLANE = {
    CAT_IAM: "identity_access",
    CAT_SYSTEM_ACTIVITY: "activity_audit",
    CAT_NETWORK_ACTIVITY: "activity_audit",
    CAT_DISCOVERY: "configuration",
    CAT_APPLICATION_ACTIVITY: "change_delivery",
    CAT_FINDINGS: "vulnerability_threat",
}
# compliance findings are posture, not threat — override by class
_CLASS_PLANE = {CLASS_COMPLIANCE_FINDING: "configuration"}

# ── boolean/numeric config signals -> canonical telemetry field names ────────
# The right-hand names are exactly the telemetry fields the policy engine reads,
# so an ingested OCSF inventory/config event plugs straight into a policy without
# a second translation. Keys are matched case-insensitively, anywhere shallow in
# the event (and inside its `unmapped` bag, where non-core producer fields live).
_CONFIG_SIGNAL_FIELDS = {
    "is_encrypted": "encryption_at_rest",
    "encryption_at_rest": "encryption_at_rest",
    "encryption_enabled": "encryption_at_rest",
    "disk_encryption": "disk_encrypted",
    "disk_encrypted": "disk_encrypted",
    "volume_encrypted": "disk_encrypted",
    "logging_enabled": "logging_enabled",
    "audit_logging": "logging_enabled",
    "is_public": "_public",                     # inverted below -> public_access_blocked
    "public_access": "_public",
    "publicly_accessible": "_public",
    "branch_protection": "branch_protection_enabled",
    "branch_protection_enabled": "branch_protection_enabled",
    "secret_scanning": "secret_scanning_enabled",
    "secret_scanning_enabled": "secret_scanning_enabled",
}

# ── OCSF class -> internal concept ids it can evidence ───────────────────────
# (concept ids must exist in concept_lexicon.json)
_CLASS_CONCEPTS = {
    CLASS_AUTHENTICATION: ["mfa"],
    CLASS_ACCOUNT_CHANGE: ["account_management"],
    CLASS_DETECTION_FINDING: ["vulnerability_management"],
}


def _epoch_ms(value: Any) -> int:
    if isinstance(value, (int, float)) and value > 0:
        # already epoch ms if it looks like ms, else seconds -> ms
        return int(value) if value > 1e11 else int(value * 1000)
    return int(datetime.now(UTC).timestamp() * 1000)


def _iso_from_ms(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, UTC).isoformat()


def _lower_keys_scan(obj: Any) -> dict[str, Any]:
    """Flatten one shallow level of a dict (plus its `unmapped` bag) to
    lowercase keys, for tolerant signal extraction across producers."""
    out: dict[str, Any] = {}
    if not isinstance(obj, dict):
        return out
    for k, v in obj.items():
        if isinstance(k, str):
            out.setdefault(k.lower(), v)
    extra = obj.get("unmapped")
    if isinstance(extra, dict):
        for k, v in extra.items():
            if isinstance(k, str):
                out.setdefault(k.lower(), v)
    return out


def _as_bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "yes", "enabled", "on", "1"):
            return True
        if s in ("false", "no", "disabled", "off", "0"):
            return False
    return None


@dataclass
class NormalizedEvidence:
    """Comp-Lens's internal view of one OCSF event.

    `telemetry` is the flat field->value dict the policy engine consumes; `concepts`
    are lexicon ids the event evidences; `controls` carries direct control results
    lifted from an OCSF Compliance Finding. `provenance` retains enough OCSF context
    to trace the evidence back to its source event.
    """
    source_system: str
    plane: str
    observed_at: str
    asset_id: str | None = None
    asset_type: str | None = None
    severity: str = "unknown"
    telemetry: dict[str, Any] = field(default_factory=dict)
    concepts: list[str] = field(default_factory=list)
    controls: list[dict[str, Any]] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_system": self.source_system, "plane": self.plane,
            "observed_at": self.observed_at, "asset_id": self.asset_id,
            "asset_type": self.asset_type, "severity": self.severity,
            "telemetry": self.telemetry, "concepts": self.concepts,
            "controls": self.controls, "provenance": self.provenance,
        }


def _source_system(event: dict[str, Any]) -> str:
    prod = ((event.get("metadata") or {}).get("product") or {})
    name = prod.get("name") or prod.get("vendor_name")
    return str(name).upper().replace(" ", "_") if name else "OCSF"


def _extract_asset(event: dict[str, Any]) -> tuple[str | None, str | None]:
    """Best-effort asset id + type across the several places OCSF can carry it."""
    resources = event.get("resources")
    if isinstance(resources, list) and resources:
        r = resources[0]
        if isinstance(r, dict):
            return (r.get("uid") or r.get("name")), r.get("type")
    for key in ("resource", "device"):
        r = event.get(key)
        if isinstance(r, dict):
            return (r.get("uid") or r.get("hostname") or r.get("name")), r.get("type")
    actor = event.get("actor")
    if isinstance(actor, dict):
        user = actor.get("user") or {}
        if isinstance(user, dict) and (user.get("uid") or user.get("name")):
            return (user.get("uid") or user.get("name")), "user"
    return None, None


def _severity_word(event: dict[str, Any]) -> str:
    sid = event.get("severity_id")
    if isinstance(sid, int) and sid in SEVERITY_NAME:
        return SEVERITY_NAME[sid]
    sev = event.get("severity")
    return str(sev).lower() if sev else "unknown"


def _config_signals(event: dict[str, Any]) -> dict[str, Any]:
    flat = _lower_keys_scan(event)
    out: dict[str, Any] = {}
    for src_key, field_name in _CONFIG_SIGNAL_FIELDS.items():
        if src_key not in flat:
            continue
        b = _as_bool(flat[src_key])
        if b is None:
            continue
        if field_name == "_public":
            out["public_access_blocked"] = (not b)  # public==True => blocked==False
        else:
            out[field_name] = b
    return out


def from_ocsf(event: dict[str, Any]) -> NormalizedEvidence | None:
    """Map one OCSF event to NormalizedEvidence, or None if it isn't a dict."""
    if not isinstance(event, dict):
        return None

    class_uid = event.get("class_uid")
    category_uid = event.get("category_uid")
    if category_uid is None and isinstance(class_uid, int):
        category_uid = class_uid // 1000  # class_uid encodes category as its thousands
    ms = _epoch_ms(event.get("time"))
    asset_id, asset_type = _extract_asset(event)
    plane = _CLASS_PLANE.get(class_uid) or _CATEGORY_PLANE.get(category_uid, "activity_audit")

    ev = NormalizedEvidence(
        source_system=_source_system(event), plane=plane,
        observed_at=_iso_from_ms(ms), asset_id=asset_id, asset_type=asset_type,
        severity=_severity_word(event),
        provenance={"ocsf_class_uid": class_uid, "ocsf_category_uid": category_uid,
                    "ocsf_version": (event.get("metadata") or {}).get("version"),
                    "time_ms": ms},
    )

    # concepts this class can evidence
    for cid in _CLASS_CONCEPTS.get(class_uid, []):
        ev.concepts.append(cid)

    # class-specific extraction
    if class_uid == CLASS_AUTHENTICATION:
        flat = _lower_keys_scan(event)
        mfa = flat.get("is_mfa", flat.get("mfa"))
        b = _as_bool(mfa)
        if b is not None:
            ev.telemetry["mfa_enforced"] = b

    elif class_uid == CLASS_COMPLIANCE_FINDING:
        comp = event.get("compliance") or {}
        if isinstance(comp, dict):
            status_raw = str(comp.get("status") or "").lower()
            status = "pass" if status_raw in ("pass", "passed", "compliant") else (
                "fail" if status_raw in ("fail", "failed", "non-compliant", "noncompliant")
                else status_raw or "unknown")
            standards = comp.get("standards")
            standards = standards if isinstance(standards, list) else (
                [standards] if standards else [])
            control = comp.get("control")
            if control:
                ev.controls.append({"control_ref": str(control), "status": status,
                                    "standards": [str(s) for s in standards]})

    elif class_uid == CLASS_DEVICE_INVENTORY:
        ev.telemetry.update(_config_signals(event))

    else:
        # generic: pick up any config/posture booleans the producer included
        ev.telemetry.update(_config_signals(event))

    return ev


def to_ocsf_compliance_finding(
    *, control_id: str, status: str, framework: str | None = None,
    standards: list[str] | None = None, severity: str = "medium",
    message: str | None = None, uid: str | None = None,
    observed_at: datetime | None = None, product: str = "Comp-Lens",
    activity_id: int = FINDING_ACTIVITY_CREATE,
) -> dict[str, Any]:
    """Render a Comp-Lens control decision as an OCSF Compliance Finding (2003).

    `status` is Comp-Lens's own word ("pass"/"fail"/…); it becomes the OCSF
    `compliance.status` ("Pass"/"Fail") and drives severity if the caller didn't
    pin one. The result validates against the OCSF 1.x Compliance Finding shape:
    class/category/type ids, epoch-ms `time`, `metadata.product`, and a
    `compliance` object carrying the standard and control.
    """
    s = (status or "").lower()
    comp_status = "Pass" if s in ("pass", "passed", "compliant") else (
        "Fail" if s in ("fail", "failed", "non-compliant", "noncompliant") else "Other")
    sev_word = severity.lower()
    if s == "pass" and severity == "medium":
        sev_word = "info"
    sev_id = SEVERITY_ID.get(sev_word, 3)
    ms = _epoch_ms(observed_at.timestamp() if isinstance(observed_at, datetime) else None)

    std_list = list(standards) if standards else ([framework] if framework else [])
    return {
        "class_uid": CLASS_COMPLIANCE_FINDING,
        "category_uid": CAT_FINDINGS,
        "activity_id": activity_id,
        "type_uid": CLASS_COMPLIANCE_FINDING * 100 + activity_id,
        "time": ms,
        "severity_id": sev_id,
        "severity": SEVERITY_NAME.get(sev_id, "medium").capitalize(),
        "status": "New" if activity_id == FINDING_ACTIVITY_CREATE else "Updated",
        "message": message or f"{control_id}: {comp_status}",
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": product, "vendor_name": product},
        },
        "finding_info": {
            "uid": uid or f"comp-lens:{control_id}",
            "title": f"{control_id} — {comp_status}",
            "types": ["Compliance"],
        },
        "compliance": {
            "status": comp_status,
            "control": control_id,
            "standards": [str(x) for x in std_list if x],
        },
    }


__all__ = [
    "OCSF_VERSION", "NormalizedEvidence", "from_ocsf", "to_ocsf_compliance_finding",
    "SEVERITY_NAME", "SEVERITY_ID", "CLASS_AUTHENTICATION", "CLASS_COMPLIANCE_FINDING",
    "CLASS_ACCOUNT_CHANGE", "CLASS_DETECTION_FINDING", "CLASS_DEVICE_INVENTORY",
]
