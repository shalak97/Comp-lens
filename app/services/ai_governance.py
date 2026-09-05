"""AI governance: privacy-enhancing technologies (PETs) + dynamic risk scoring.

The existing AI inventory tracks EU AI Act governance booleans (impact assessment,
human oversight, transparency) and a hand-set risk tier. This adds the missing
technical layer — the actual privacy-enhancing technologies a model uses — and
computes governance risk DYNAMICALLY from them, the same way Comp-Lens derives all
its risk scores from real evidence rather than hand-typed numbers.

A model handling PII with no safeguards is high residual risk. The same model with
strong differential privacy (low epsilon) and homomorphic encryption is low residual
risk. The math is transparent and explainable.

PETs assessed:
  differential_privacy   ε (epsilon) budget + δ (delta) — the privacy/utility knob
  homomorphic_encryption scheme (BFV/BGV/CKKS/TFHE) — compute on encrypted data
  federated_learning     data never centralizes
  secure_mpc             multi-party computation, no party sees raw data
  k_anonymity            k value — each record indistinguishable among k
  synthetic_data         generated, not real subjects
  data_minimization      collect only what's needed
"""
from __future__ import annotations

from typing import Any

# ── PET catalog: each technology, what it protects, how to read its strength ──
PET_CATALOG: dict[str, dict[str, Any]] = {
    "differential_privacy": {
        "label": "Differential Privacy",
        "protects": "Prevents inference about any single individual in the dataset",
        "param": "epsilon",
        "frameworks": {"NIST_AI_RMF": ["MEASURE-2.7"], "ISO27001": ["A.8.11"], "GDPR": ["Art.25"]},
    },
    "homomorphic_encryption": {
        "label": "Homomorphic Encryption",
        "protects": "Computation on encrypted data — plaintext never exposed",
        "param": "scheme",
        "frameworks": {"NIST_AI_RMF": ["MANAGE-2.2"], "ISO27001": ["A.8.24"]},
    },
    "federated_learning": {
        "label": "Federated Learning",
        "protects": "Training data never leaves the source device/silo",
        "param": None,
        "frameworks": {"NIST_AI_RMF": ["MAP-4.1"], "GDPR": ["Art.25"]},
    },
    "secure_mpc": {
        "label": "Secure Multi-Party Computation",
        "protects": "Joint computation where no party sees others' raw inputs",
        "param": None,
        "frameworks": {"NIST_AI_RMF": ["MANAGE-2.2"]},
    },
    "k_anonymity": {
        "label": "k-Anonymity",
        "protects": "Each record indistinguishable from at least k-1 others",
        "param": "k",
        "frameworks": {"ISO27001": ["A.8.11"], "GDPR": ["Art.25"]},
    },
    "synthetic_data": {
        "label": "Synthetic Data",
        "protects": "Training on generated data, not real data subjects",
        "param": None,
        "frameworks": {"NIST_AI_RMF": ["MAP-4.1"]},
    },
    "data_minimization": {
        "label": "Data Minimization",
        "protects": "Only strictly necessary data is collected and retained",
        "param": None,
        "frameworks": {"GDPR": ["Art.5"], "ISO27001": ["A.5.34"]},
    },
}

# data sensitivity → inherent privacy risk (0..100)
_SENSITIVITY = {"none": 5, "internal": 20, "pii": 60, "phi": 80, "financial": 75,
                "biometric": 90, "special_category": 95}


def assess_pet(pet_id: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Assess one PET's strength from its parameters → a 0..1 effectiveness score."""
    params = params or {}
    meta = PET_CATALOG.get(pet_id)
    if not meta:
        return {"pet": pet_id, "known": False, "effectiveness": 0.0,
                "assessment": "unknown technology"}
    eff, note = 0.5, "present"

    if pet_id == "differential_privacy":
        # epsilon is the privacy budget: lower = stronger. ε<1 strong, 1-10 moderate, >10 weak
        eps = _num(params.get("epsilon"), default=None)
        if eps is None:
            eff, note = 0.4, "enabled but no epsilon budget declared"
        elif eps <= 0:
            eff, note = 0.0, "invalid epsilon"
        elif eps < 1:
            eff, note = 0.95, f"strong privacy (ε={eps}, ≤1)"
        elif eps <= 10:
            eff, note = 0.65, f"moderate privacy (ε={eps}, 1–10)"
        else:
            eff, note = 0.3, f"weak privacy (ε={eps}, >10 — little protection)"

    elif pet_id == "homomorphic_encryption":
        scheme = str(params.get("scheme", "")).upper()
        strong = {"CKKS", "BFV", "BGV", "TFHE", "FHE"}
        if scheme in strong:
            eff, note = 0.9, f"{scheme} — fully homomorphic"
        elif scheme in {"PAILLIER", "RSA", "PHE"}:
            eff, note = 0.6, f"{scheme} — partially homomorphic"
        else:
            eff, note = 0.5, "enabled (scheme unspecified)"

    elif pet_id == "k_anonymity":
        k = _num(params.get("k"), default=None)
        if k is None:
            eff, note = 0.4, "enabled but k not declared"
        elif k >= 10:
            eff, note = 0.8, f"strong (k={int(k)})"
        elif k >= 3:
            eff, note = 0.55, f"moderate (k={int(k)})"
        else:
            eff, note = 0.25, f"weak (k={int(k)} — easily re-identified)"

    elif pet_id in ("federated_learning", "secure_mpc"):
        eff, note = 0.85, "raw data never centralized"
    elif pet_id == "synthetic_data":
        eff, note = 0.8, "no real subjects in training data"
    elif pet_id == "data_minimization":
        eff, note = 0.5, "scope-limited collection"

    return {"pet": pet_id, "label": meta["label"], "known": True,
            "protects": meta["protects"], "effectiveness": round(eff, 2),
            "assessment": note, "frameworks": meta["frameworks"]}


def compute_privacy_risk(data_sensitivity: str, pets: list[dict[str, Any]]) -> dict[str, Any]:
    """Dynamic residual privacy risk = inherent (from data) reduced by PET strength.

    Mirrors the Comp-Lens telemetry philosophy: residual is DERIVED, not typed.
    Multiple PETs compound (defense in depth) with diminishing returns.
    """
    inherent = _SENSITIVITY.get(str(data_sensitivity).lower(), 40)
    assessed = [assess_pet(p.get("pet"), p.get("params")) for p in (pets or [])]
    # combined mitigation: each PET removes a fraction of remaining risk (compounding)
    remaining = 1.0
    for a in assessed:
        remaining *= (1 - a["effectiveness"])
    mitigation = 1 - remaining
    # honest floor: even strong PETs don't drop residual below a fraction of inherent,
    # since no privacy technology is a perfect guarantee in practice.
    floor = round(inherent * 0.08)
    residual = max(round(inherent * remaining), floor)
    band = ("low" if residual < 25 else "medium" if residual < 50
            else "high" if residual < 75 else "critical")
    return {
        "data_sensitivity": data_sensitivity,
        "inherent_risk": inherent,
        "mitigation_pct": round(mitigation * 100),
        "residual_risk": residual,
        "residual_band": band,
        "pets_assessed": assessed,
        "explanation": (f"Inherent risk {inherent} (from {data_sensitivity} data) reduced "
                        f"{round(mitigation*100)}% by {len(assessed)} privacy technolog"
                        f"{'y' if len(assessed)==1 else 'ies'} → residual {residual} ({band})."),
    }


# ── EU AI Act risk tiering + obligations ──
_AI_ACT_TIERS = {
    "prohibited": {"label": "Prohibited", "obligations": ["System must not be deployed"]},
    "high": {"label": "High-risk", "obligations": [
        "Conformity assessment", "Risk management system", "Data governance",
        "Technical documentation", "Human oversight", "Accuracy & robustness testing",
        "Logging & traceability", "Transparency to users"]},
    "limited": {"label": "Limited-risk", "obligations": [
        "Transparency obligations (disclose AI interaction)"]},
    "minimal": {"label": "Minimal-risk", "obligations": ["Voluntary codes of conduct"]},
}


def ai_act_obligations(risk_tier: str, governance: dict[str, bool]) -> dict[str, Any]:
    """Map an AI system to its EU AI Act obligations + which are met.

    The denominator is every obligation the tier carries, not just the ones this
    platform happens to model. Scoring only the modelled subset made an
    obligation the platform cannot check disappear from both the percentage and
    the gap list, so a **prohibited** system — the Act's "must not be deployed"
    tier — reported 100% compliant with no gaps, and a high-risk system with all
    six checkable boxes ticked reported 100% while *Conformity assessment* and
    *Technical documentation* had never been assessed at all.

    Obligations with no coverage signal are reported in their own `unassessed`
    list rather than being silently dropped or counted as failures: "we cannot
    observe this" and "we observed it and it is missing" are different claims.
    """
    key = str(risk_tier).lower()
    recognised = key in _AI_ACT_TIERS
    tier = _AI_ACT_TIERS.get(key, _AI_ACT_TIERS["limited"])
    # map governance booleans to obligation coverage (for high-risk)
    coverage = {
        "Risk management system": governance.get("impact_assessment", False),
        "Data governance": governance.get("data_governance", False),
        "Human oversight": governance.get("human_oversight", False),
        "Accuracy & robustness testing": governance.get("accuracy_tested", False),
        "Logging & traceability": governance.get("logging_enabled", False),
        "Transparency to users": governance.get("transparency_notice", False),
    }
    obligations = tier["obligations"]
    unassessed = [o for o in obligations if o not in coverage]
    met = [o for o in obligations if coverage.get(o, False)]
    gaps = [o for o in obligations if o in coverage and not coverage[o]]
    return {
        "tier": key if recognised else "unrecognised",
        "tier_label": tier["label"],
        "tier_recognised": recognised,
        "obligations": obligations,
        "coverage": coverage,
        # Denominator is every obligation, so an unassessable one cannot inflate
        # the score. None only when a tier carries no obligations at all.
        "compliance_pct": (round(100 * len(met) / len(obligations))
                           if obligations else None),
        "met": met,
        "gaps": gaps,
        "unassessed": unassessed,
        "assessable": len(obligations) - len(unassessed),
    }


def _num(v: Any, default: float | None = None) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default
