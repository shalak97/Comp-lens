"""Unified Trust Telemetry — one score per control, fused from EVERY signal
lane the platform now has, with the lanes kept visible so inherited trust is
never silently merged with directly-verified trust.

Lanes (each 0..1, each independently reported):

    native          connector evidence health (live/fresh > live/stale > demo)
                    — from the existing trust-graph connector telemetry
    inherited       GRC-platform attestations (Vanta/Drata/OneTrust), scored by the
                    existing policy-driven GRCTrustTelemetry (status × freshness ×
                    confidence × corroboration/conflict)
    policy          the policy-as-code verdict materialised in Posture, decayed by age
    enforcement     LIVE runtime proof from the PEP/PDP decision stream — a control
                    whose policy is enforcing real traffic with no would-blocks is
                    the strongest evidence a control actually works; a shadow-mode
                    system leaking would-blocks is direct evidence it doesn't
    followthrough   when violations dispatch obligations, did the operational
                    procedures succeed? (done/queued vs error)

Tenant-level (not per-control, reported in the summary):

    drift           recent crawler 'changed' detections on vendor-trust and
                    regulatory pages — external ground truth moving under you.

The composite is a weighted blend over the lanes a control actually HAS —
missing lanes are excluded and weights renormalised, so a control isn't
punished for a lane that doesn't apply to it, but per-control lane coverage
is always reported. All weights live in the same tunable TrustPolicy family
(env GRC_TRUST_POLICY / inline preview), extended with lane weights.
"""
from __future__ import annotations

import contextlib
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.grc_platforms.trust_telemetry import DEFAULT_POLICY, GRCTrustTelemetry, TrustPolicy, _band

_CONTROL_RE = re.compile(r"^([A-Z]{1,4}-\d+(?:\.\d+)?|CC\d+\.\d+)")

# Lane weights (fractions of the composite; renormalised over present lanes).
DEFAULT_LANE_WEIGHTS: dict[str, float] = {
    "native": 0.30,
    "inherited": 0.20,
    "policy": 0.25,
    "enforcement": 0.15,
    "followthrough": 0.10,
}
_POLICY_LANE_STALE_DAYS = 30  # policy verdict decays to floor by this age
_POLICY_LANE_FLOOR = 0.3
_ENF_MIN_REQUESTS = 5  # below this, runtime signal is too thin to score
_DRIFT_WINDOW_DAYS = 14
_DRIFT_PAGE = 200        # rows per read while counting drift; not a cap on the count
_DRIFT_SAMPLE = 10       # how many changes are described in the response

# The control-id namespace every lane must share for the fusion join to line up.
# Policies declare `control: AC-2`, enforcement parses the same, and inherited
# uses the canonical comp_lens id — all NIST-800-53. The connector→control map,
# by contrast, carries the same evidence under all 8 frameworks, so the native
# lane must be pinned to this namespace or its ISO/CIS/GDPR aliases never match
# another lane (mis-scoring those controls and double-counting every logical one).
_CANONICAL_FRAMEWORK = "NIST_800_53"


def _aware(dt):
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def _now():
    return datetime.now(UTC)


def _lane_weights(policy_overrides: dict | None) -> dict[str, float]:
    w = dict(DEFAULT_LANE_WEIGHTS)
    if policy_overrides and isinstance(policy_overrides.get("lane_weights"), dict):
        for k, v in policy_overrides["lane_weights"].items():
            if k in w:
                with contextlib.suppress(TypeError, ValueError):
                    w[k] = max(0.0, float(v))
    return w


# ─────────────────────────── lane collectors ───────────────────────────
def _canonical_control_ids() -> set[str]:
    """Control ids in the canonical framework across the whole connector catalog.

    The connector→control map carries each evidence type under all 8 frameworks;
    keeping only the canonical-framework ids keeps the native lane in the same
    namespace the other lanes speak (see _CANONICAL_FRAMEWORK).
    """
    from app.connectors import catalog as ccat
    from app.connectors.framework import supported_controls
    ids: set[str] = set()
    for c in ccat.all_connectors():
        ids.update(supported_controls(c).get(_CANONICAL_FRAMEWORK, []))
    return ids


def _native_lane(db: Session, tenant_id: str) -> dict[str, dict[str, Any]]:
    """control_id -> {score, detail} from connector evidence health, keyed in the
    canonical (NIST-800-53) namespace so it fuses with the other lanes."""
    from app.services.trust_graph import _connector_health, _control_strength
    conns = _connector_health(db, tenant_id)
    out = {}
    for cid in _canonical_control_ids():
        s = _control_strength(cid, conns)
        if s["strength"] > 0:
            out[cid] = {"score": s["strength"], "detail": s["reason"],
                        "backed_by": [b["key"] for b in s["backed_by"]]}
    return out


def _inherited_lane(db: Session, tenant_id: str, pol: TrustPolicy) -> dict[str, dict[str, Any]]:
    out = {}
    for c in GRCTrustTelemetry(db, pol).by_control(tenant_id):
        out[c["control_id"]] = {"score": c["trust"] / 100.0,
                                 "detail": c["agreement"],
                                 "sources": c["source_count"]}
    return out


def _policy_lane(db: Session, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Posture rows written by the policy-as-code path, decayed by age."""
    from app.models import Posture
    rows = db.execute(select(Posture).where(
        Posture.tenant_id == tenant_id,
        Posture.source_system == "POLICY-AS-CODE")).scalars().all()
    out = {}
    for p in rows:
        passing = str(getattr(p.status, "value", p.status)).lower() == "pass"
        age_days = None
        upd = _aware(p.updated_at)
        if upd:
            age_days = (_now() - upd).days
        if not passing:
            score = 0.0
        elif age_days is None:
            score = 0.6
        elif age_days <= 1:
            score = 1.0
        elif age_days >= _POLICY_LANE_STALE_DAYS:
            score = _POLICY_LANE_FLOOR
        else:
            score = 1.0 - (1.0 - _POLICY_LANE_FLOOR) * (age_days / _POLICY_LANE_STALE_DAYS)
        out[p.control_id] = {"score": round(score, 3),
                              "detail": ("pass" if passing else "fail") +
                              (f", {age_days}d old" if age_days is not None else ""),
                              "age_days": age_days}
    return out


def _enforcement_lane() -> dict[str, dict[str, Any]]:
    """control_id -> runtime-proof score from the live PEP/PDP counters.

    enforce mode, traffic flowing, nothing denied unexpectedly -> ~1.0
    enforce mode with denials (control actively blocking) -> still strong
    shadow mode, no would-blocks over real traffic -> 0.7 (clean rehearsal)
    shadow mode with would-blocks -> low (control not effective)
    too little traffic -> lane absent (not scored)
    """
    try:
        from app.services.enforcement import SYS_COUNTERS, _systems_config
        cfg = _systems_config()
    except Exception:  # noqa: BLE001 — enforcement plane optional
        return {}
    out: dict[str, dict[str, Any]] = {}
    for host, c in cfg.items():
        m = _CONTROL_RE.match(c.get("policy_id", "") or "")
        if not m:
            continue
        cid = m.group(1)
        ctr = SYS_COUNTERS.get(host, {})
        reqs = ctr.get("requests", 0)
        if reqs < _ENF_MIN_REQUESTS:
            continue
        wb = ctr.get("would_block", 0)
        mode = c.get("mode", "shadow")
        if mode == "enforce":
            score = 1.0
            detail = f"enforcing, {reqs} req, {ctr.get('denied', 0)} denied"
        else:
            wb_rate = wb / reqs
            score = max(0.1, 0.7 * (1.0 - wb_rate * 3))  # would-blocks tank shadow trust fast
            detail = f"shadow, {reqs} req, {wb} would-block"
        prev = out.get(cid)
        if not prev or score > prev["score"]:
            out[cid] = {"score": round(score, 3), "detail": detail, "system": host, "mode": mode}
    return out


def _followthrough_lane(db: Session, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Did dispatched obligations for a control's violations actually run?

    Optional plane: the obligations ledger may not be imported OR its table may
    not exist yet (no migration in some deployments), so any failure degrades to
    an absent lane rather than breaking the whole composite.
    """
    try:
        from app.policy_models import ObligationDispatch
        rows = db.execute(select(ObligationDispatch).where(
            ObligationDispatch.tenant_id == tenant_id)).scalars().all()
    except Exception:  # noqa: BLE001 — obligations plane optional (module or table absent)
        db.rollback()
        return {}
    by_ctrl: dict[str, list[ObligationDispatch]] = {}
    for r in rows:
        if r.control_id:
            by_ctrl.setdefault(r.control_id, []).append(r)
    out = {}
    for cid, ds in by_ctrl.items():
        ok = sum(1 for d in ds if d.status in ("done", "queued", "eligible"))
        score = ok / len(ds) if ds else 0.0
        out[cid] = {"score": round(score, 3),
                     "detail": f"{ok}/{len(ds)} obligations succeeded"}
    return out


def _drift_signal(db: Session, tenant_id: str) -> dict[str, Any]:
    """Tenant-level: recent external changes detected by the crawlers.

    Optional plane (see _followthrough_lane): missing module or table degrades to
    "no drift" instead of failing the composite.
    """
    try:
        from app.crawler_models import CrawlTarget
        cutoff = _now() - timedelta(days=_DRIFT_WINDOW_DAYS)
        total, sample = _changes_since(db, tenant_id, cutoff)
        targets = {t.id: t for t in db.execute(select(CrawlTarget).where(
            CrawlTarget.tenant_id == tenant_id)).scalars().all()}
    except Exception:  # noqa: BLE001 — crawler plane optional (module or table absent)
        db.rollback()
        return {"recent_changes": 0}
    detail = []
    for r in sample:
        t = targets.get(r.target_id)
        detail.append({"target": t.name if t else r.target_id,
                        "kind": t.kind if t else "?",
                        "fetched_at": r.fetched_at.isoformat() if r.fetched_at else None})
    return {"recent_changes": total, "window_days": _DRIFT_WINDOW_DAYS,
            "changes": detail}


def _changes_since(db: Session, tenant_id: str, cutoff) -> tuple[int, list]:
    """Count every 'changed' crawl result inside the window, plus a sample.

    This used to take the 50 most recent rows and filter them to the window in
    Python, so a tenant with more than 50 detections reported exactly 50 —
    capped, with nothing saying so. Drift is the signal that external ground
    truth is moving underneath the estate; understating it understates it in
    the reassuring direction, which is the one direction that matters.

    The count stays exact without an unbounded read. Rows come back newest
    first, so the first row older than the cutoff ends the walk: everything
    after it is older still. The window comparison is done in Python rather
    than in SQL because SQLite returns these timestamps naive, and comparing
    them against an aware cutoff in the query is how that bites.
    """
    from app.crawler_models import CrawlResult

    total, offset = 0, 0
    sample: list = []
    while True:
        page = db.execute(
            select(CrawlResult)
            .where(CrawlResult.tenant_id == tenant_id, CrawlResult.status == "changed")
            # id breaks ties: fetched_at is not unique across a batch run, and
            # without a total order a row can appear on two pages or neither.
            .order_by(desc(CrawlResult.fetched_at), desc(CrawlResult.id))
            .limit(_DRIFT_PAGE).offset(offset)).scalars().all()
        if not page:
            return total, sample
        for r in page:
            fetched = _aware(r.fetched_at)
            if fetched is None or fetched < cutoff:
                return total, sample
            total += 1
            if len(sample) < _DRIFT_SAMPLE:
                sample.append(r)
        if len(page) < _DRIFT_PAGE:
            return total, sample
        offset += _DRIFT_PAGE


# ─────────────────────────── fusion ───────────────────────────
def unified_trust(db: Session, tenant_id: str, pol: TrustPolicy | None = None,
                   policy_overrides: dict | None = None) -> dict[str, Any]:
    pol = pol or DEFAULT_POLICY
    weights = _lane_weights(policy_overrides)

    lanes = {
        "native": _native_lane(db, tenant_id),
        "inherited": _inherited_lane(db, tenant_id, pol),
        "policy": _policy_lane(db, tenant_id),
        "enforcement": _enforcement_lane(),
        "followthrough": _followthrough_lane(db, tenant_id),
    }
    all_controls = sorted(set().union(*[set(lane.keys()) for lane in lanes.values()]))

    controls = []
    for cid in all_controls:
        present = {name: lane[cid] for name, lane in lanes.items() if cid in lane}
        wsum = sum(weights[n] for n in present)
        composite = (sum(weights[n] * present[n]["score"] for n in present) / wsum
                     if wsum else 0.0)
        controls.append({
            "control_id": cid,
            "trust": round(composite * 100),
            "band": _band(composite * 100, pol),
            "lanes": {n: present[n] for n in present},
            "lane_coverage": f"{len(present)}/{len(lanes)}",
        })
    controls.sort(key=lambda c: c["trust"])

    drift = _drift_signal(db, tenant_id)
    avg = round(sum(c["trust"] for c in controls) / len(controls)) if controls else None
    return {
        "unified_trust_score": avg,
        "band": _band(avg, pol) if avg is not None else None,
        "controls_scored": len(controls),
        "lane_weights": weights,
        "lanes_available": {n: len(lane) for n, lane in lanes.items()},
        "drift": drift,
        "weakest": controls[:5],
        "controls": controls,
        "note": ("Composite fuses only the lanes each control actually has "
                 "(weights renormalised); every lane stays individually visible "
                 "so inherited trust is never silently merged with verified trust. "
                 "Drift is tenant-level context, not a per-control multiplier."),
    }
