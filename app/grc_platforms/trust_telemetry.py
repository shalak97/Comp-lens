"""GRC Trust Telemetry — a dedicated, CONFIGURABLE trust-scoring layer.

The GRC platform connectors already retrieve the data. This layer is the value-add:
it turns "Vanta says control X passes" into an actual TRUST SCORE, kept in a SEPARATE
lane from the native trust graph so inherited trust is never silently merged with
directly-verified trust.

A trust score (0..100) per control is derived from four signals — all from data the
platforms already give us:

  1. status        the platform's own pass/fail verdict
  2. freshness     evidence decays with age (a 90-day "pass" < a 1-day "pass")
  3. confidence    how sure we are the control mapped correctly to ours
  4. corroboration two platforms agreeing RAISES trust; disagreeing TANKS it

TUNABLE AS CODE: every weight lives in a TrustPolicy (declarative config), with a
default profile that can be overridden per tenant. A regulated environment can set
fresh_days=1 and conflict_factor=0.1; the scoring engine reads the policy, nothing
is hardcoded. This keeps the trust telemetry itself tunable — in line with the
compliance-as-code model.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.grc_platforms.models import GRCAttestation


# ── the tunable trust policy (config, not constants) ──
@dataclass
class TrustPolicy:
    """Declarative weights for GRC trust scoring. Tune per risk appetite."""
    # status verdict -> base trust (0..1)
    status_weights: dict[str, float] = field(default_factory=lambda: {
        "pass": 1.0, "not_applicable": 0.5, "error": 0.3, "fail": 0.0})
    status_default: float = 0.3
    # freshness decay
    fresh_days: int = 7            # full trust at/below this age
    stale_days: int = 90           # trust floor reached at/above this age
    freshness_floor: float = 0.25  # oldest evidence still retains this fraction
    unknown_age_mult: float = 0.6  # multiplier when age is unknown
    # cross-platform agreement
    corroboration_bonus: dict[int, float] = field(default_factory=lambda: {
        1: 1.0, 2: 1.15, 3: 1.25})
    conflict_factor: float = 0.35  # disagreement multiplies trust down hard
    # band thresholds (0..100)
    band_high: int = 75
    band_medium: int = 50
    band_low: int = 25

    def validate(self) -> TrustPolicy:
        """Clamp to sane ranges so a bad override can't produce nonsense scores."""
        self.fresh_days = max(0, int(self.fresh_days))
        self.stale_days = max(self.fresh_days + 1, int(self.stale_days))
        self.freshness_floor = _clamp01(self.freshness_floor)
        self.unknown_age_mult = _clamp01(self.unknown_age_mult)
        self.conflict_factor = _clamp01(self.conflict_factor)
        self.status_weights = {k: _clamp01(v) for k, v in self.status_weights.items()}
        self.status_default = _clamp01(self.status_default)
        return self

    @classmethod
    def from_overrides(cls, overrides: dict[str, Any] | None) -> TrustPolicy:
        base = cls()
        if overrides:
            for k, v in overrides.items():
                if hasattr(base, k) and v is not None:
                    setattr(base, k, v)
        return base.validate()


def _clamp01(v: Any) -> float:
    try:
        return max(0.0, min(1.0, float(v)))
    except (TypeError, ValueError):
        return 0.0


DEFAULT_POLICY = TrustPolicy()


def resolve_policy(tenant_id: str = "default",
                   inline: dict[str, Any] | None = None) -> TrustPolicy:
    """Resolve the active trust policy.

    Precedence: inline override (request) > env var GRC_TRUST_POLICY (JSON) > defaults.
    Per-tenant policies can be layered here later (e.g. a DB-stored profile).
    """
    if inline:
        return TrustPolicy.from_overrides(inline)
    env = os.getenv("GRC_TRUST_POLICY")
    if env:
        try:
            return TrustPolicy.from_overrides(json.loads(env))
        except (ValueError, TypeError):
            pass
    return DEFAULT_POLICY


# ── scoring primitives (now policy-driven) ──
def _status_base(status: str, pol: TrustPolicy) -> float:
    return pol.status_weights.get(status, pol.status_default)


def _freshness_mult(days: Any, pol: TrustPolicy) -> float:
    if days is None:
        return pol.unknown_age_mult
    d = float(days)
    if d <= pol.fresh_days:
        return 1.0
    if d >= pol.stale_days:
        return pol.freshness_floor
    span = pol.stale_days - pol.fresh_days
    return 1.0 - (1.0 - pol.freshness_floor) * ((d - pol.fresh_days) / span)


def _band(score_0_100: float, pol: TrustPolicy) -> str:
    if score_0_100 >= pol.band_high:
        return "high"
    if score_0_100 >= pol.band_medium:
        return "medium"
    if score_0_100 >= pol.band_low:
        return "low"
    return "critical"


def _control_trust(attestations: list[GRCAttestation], pol: TrustPolicy) -> dict[str, Any]:
    """Trust score (0..100) for one control from all its GRC attestations."""
    if not attestations:
        return {"trust": 0, "reason": "no attestations"}
    statuses = {a.status for a in attestations}
    conflict = len(statuses) > 1

    per_source = []
    for a in attestations:
        base = _status_base(a.status, pol)
        fresh = _freshness_mult(a.freshness_days, pol)
        conf = a.confidence if a.confidence is not None else 0.5
        per_source.append({"platform": a.platform, "status": a.status,
                           "freshness_days": a.freshness_days,
                           "signal": round(base * fresh * conf, 3)})

    if conflict:
        weakest = min(s["signal"] for s in per_source)
        score = weakest * pol.conflict_factor
        agreement = "conflict"
    else:
        avg = sum(s["signal"] for s in per_source) / len(per_source)
        bonus = pol.corroboration_bonus.get(min(len(per_source), 3),
                                            max(pol.corroboration_bonus.values()))
        score = min(1.0, avg * bonus)
        agreement = "agree" if len(per_source) > 1 else "single"

    return {"trust": round(score * 100), "band": _band(score * 100, pol),
            "agreement": agreement, "source_count": len(attestations),
            "sources": per_source}


class GRCTrustTelemetry:
    """Computes inherited-trust telemetry from GRC-platform attestations."""

    def __init__(self, db: Session, policy: TrustPolicy | None = None):
        self.db = db
        self.policy = policy or DEFAULT_POLICY

    def _rows(self, tenant_id: str) -> list[GRCAttestation]:
        return list(self.db.execute(
            select(GRCAttestation).where(
                GRCAttestation.tenant_id == tenant_id,
                GRCAttestation.comp_lens_control_id.isnot(None))).scalars().all())

    def by_control(self, tenant_id: str) -> list[dict[str, Any]]:
        grouped: dict[str, list[GRCAttestation]] = {}
        for r in self._rows(tenant_id):
            grouped.setdefault(r.comp_lens_control_id, []).append(r)
        out = [{"control_id": cid, **_control_trust(atts, self.policy)}
               for cid, atts in grouped.items()]
        out.sort(key=lambda c: (c.get("agreement") != "conflict", c["trust"]))
        return out

    def score(self, tenant_id: str) -> dict[str, Any]:
        controls = self.by_control(tenant_id)
        if not controls:
            return {"grc_trust_score": None, "controls_scored": 0,
                    "policy": asdict(self.policy),
                    "note": "no mapped GRC attestations yet — connect a platform and sync"}
        avg = sum(c["trust"] for c in controls) / len(controls)
        conflicts = [c for c in controls if c.get("agreement") == "conflict"]
        corroborated = [c for c in controls if c.get("agreement") == "agree"]
        return {
            "grc_trust_score": round(avg), "band": _band(avg, self.policy),
            "controls_scored": len(controls),
            "corroborated": len(corroborated), "conflicts": len(conflicts),
            "conflict_controls": [c["control_id"] for c in conflicts],
            "lowest_trust": controls[0] if controls else None,
            "source_kind": "grc_platform",
            "policy": asdict(self.policy),
            "note": "inherited trust — derived from GRC-platform attestations, separate from native trust graph",
        }

    def by_platform(self, tenant_id: str) -> dict[str, Any]:
        rows = self._rows(tenant_id)
        byp: dict[str, list[GRCAttestation]] = {}
        for r in rows:
            byp.setdefault(r.platform, []).append(r)
        out = {}
        for plat, atts in byp.items():
            signals = [_status_base(a.status, self.policy)
                       * _freshness_mult(a.freshness_days, self.policy)
                       * (a.confidence or 0.5) for a in atts]
            avg = round((sum(signals) / len(signals)) * 100) if signals else 0
            out[plat] = {"trust": avg, "attestations": len(atts),
                         "passing": sum(1 for a in atts if a.status == "pass"),
                         "stale": sum(1 for a in atts
                                      if (a.freshness_days or 0) > self.policy.stale_days)}
        return {"by_platform": out,
                "note": "per-platform standalone trust (no cross-platform corroboration applied)"}
