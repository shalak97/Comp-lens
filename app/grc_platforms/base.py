"""Base contract for GRC-platform connectors — distinct from native connectors.

Native connectors answer: "collect telemetry for ONE control on ONE asset."
GRC platforms answer the opposite shape: "here are HUNDREDS of already-evaluated
test results, each pre-mapped to our taxonomy and frameworks." So this base has a
bulk_ingest() contract, plus a declarative PlatformProfile so adding a new platform
is writing config, not code.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


@dataclass
class ControlAttestation:
    """One control result inherited from a GRC platform."""
    platform: str                       # VANTA / DRATA / ONETRUST
    external_test_id: str               # their id for this test/control
    external_control_ref: str           # their control taxonomy ref
    comp_lens_control_id: Optional[str] # our control id (None = unmapped, still kept)
    status: str                         # pass | fail | error | not_applicable
    evidence_freshness_days: Optional[int]
    frameworks: Dict[str, List[str]]    # their framework refs (SOC2, ISO27001, …)
    confidence: float                   # 0..1 — how strongly we trust this mapping
    title: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    mapping_reason: str = ""    # WHY this got its control id + confidence

    def to_telemetry(self) -> Dict[str, Any]:
        """Re-express as Comp-Lens canonical evidence record."""
        return {
            "source_kind": "grc_platform",
            "source_system": self.platform,
            "control_id": self.comp_lens_control_id,
            "external_ref": self.external_control_ref,
            "status": self.status,
            "freshness_days": self.evidence_freshness_days,
            "frameworks": self.frameworks,
            "confidence": self.confidence,
            "title": self.title,
            "mapped": self.comp_lens_control_id is not None,
            "mapping_reason": self.mapping_reason,
        }


@dataclass
class PlatformProfile:
    """Declarative spec for a GRC platform — config, not code.

    Adding a new platform (e.g. Secureframe) = writing one of these. The field
    paths describe where in the JSON response each value lives (dotted paths).
    The crosswalk maps their control refs -> our control ids.
    """
    platform: str                       # VANTA
    name: str                           # "Vanta"
    base_url: str
    auth_method: str                    # oauth2 | api_key | bearer
    env_vars: List[str]                 # credential env var names (never values)
    results_path: str                   # "/v1/tests"
    items_key: Optional[str]            # JSON key holding the array, None = top-level
    pagination_key: Optional[str]       # cursor field, None = single page
    # dotted JSON paths into each result item:
    field_test_id: str
    field_status: str
    field_control_ref: str
    field_updated: Optional[str]        # last-evidence timestamp path
    field_title: Optional[str] = None
    field_frameworks: Optional[str] = None
    # status normalization: their status string -> ours
    status_map: Dict[str, str] = field(default_factory=dict)
    # taxonomy crosswalk: their control ref -> our control id (legacy/explicit overrides)
    control_crosswalk: Dict[str, str] = field(default_factory=dict)
    # which framework(s) this platform speaks — drives the SHARED standards crosswalk
    speaks_frameworks: List[str] = field(default_factory=list)
    version: str = "1"          # profile schema version, for honest drift tracking
    source: str = "builtin"     # builtin | yaml:<path>
    notes: str = ""

    @classmethod
    def from_dict(cls, d: Dict[str, Any], source: str = "yaml") -> "PlatformProfile":
        """Build a profile from a plain dict (loaded from YAML). Adding a platform
        is writing one of these files — no code change, no redeploy of logic."""
        known = {f.name for f in cls.__dataclass_fields__.values()}
        clean = {k: v for k, v in d.items() if k in known}
        clean["source"] = source
        # required minimal fields with sane fallbacks
        clean.setdefault("items_key", None)
        clean.setdefault("pagination_key", None)
        return cls(**clean)


def dotted(obj: Any, path: Optional[str], default: Any = None) -> Any:
    """Navigate a dotted JSON path safely."""
    if not path:
        return default
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


class GRCPlatformConnector(abc.ABC):
    """Base for all GRC-platform connectors. Read-only, fail-closed, profile-driven."""

    def __init__(self, profile: PlatformProfile, fetcher: Optional[Callable] = None):
        self.profile = profile
        self.platform = profile.platform
        self._fetch = fetcher  # injectable for testing; real impl uses ResilientClient

    @abc.abstractmethod
    def _authed_get(self, path: str, cursor: Optional[str] = None) -> Any:
        """Make an authenticated read-only GET. Raises if no credentials."""

    def healthcheck(self) -> bool:
        try:
            self._authed_get(self.profile.results_path)
            return True
        except Exception:
            return False

    def bulk_ingest(self, max_pages: int = 20) -> List[ControlAttestation]:
        """Pull all test results, paginate, and map to ControlAttestations."""
        out: List[ControlAttestation] = []
        cursor, pages = None, 0
        while pages < max_pages:
            resp = self._authed_get(self.profile.results_path, cursor)
            items = dotted(resp, self.profile.items_key, resp) if self.profile.items_key else resp
            if not isinstance(items, list):
                items = []
            for item in items:
                att = self._map_item(item)
                if att:
                    out.append(att)
            cursor = dotted(resp, self.profile.pagination_key) if self.profile.pagination_key else None
            pages += 1
            if not cursor:
                break
        return out

    def _map_item(self, item: Dict[str, Any]) -> Optional[ControlAttestation]:
        p = self.profile
        test_id = dotted(item, p.field_test_id)
        if test_id is None:
            return None
        raw_status = str(dotted(item, p.field_status, "")).lower()
        status = p.status_map.get(raw_status, raw_status if raw_status in
                                  ("pass", "fail", "error", "not_applicable") else "error")
        control_ref = str(dotted(item, p.field_control_ref, "") or "")
        freshness = self._freshness_days(dotted(item, p.field_updated))
        frameworks = dotted(item, p.field_frameworks, {}) or {}
        if not isinstance(frameworks, dict):
            frameworks = {}

        # ── resolve the control + WHY, with transparent confidence ──
        cl_control, confidence, reason = self._resolve_mapping(control_ref, frameworks)
        # freshness penalty (kept separate from mapping quality so reasons stay clear)
        if freshness is not None and freshness > 30:
            confidence *= 0.7
            reason += "; evidence >30d old"

        return ControlAttestation(
            platform=p.platform, external_test_id=str(test_id),
            external_control_ref=control_ref, comp_lens_control_id=cl_control,
            status=status, evidence_freshness_days=freshness,
            frameworks=frameworks, confidence=round(confidence, 2),
            title=str(dotted(item, p.field_title, "") or ""), raw=item,
            mapping_reason=reason)

    def _resolve_mapping(self, control_ref, frameworks):
        """Translate a control ref -> (comp_lens_id, confidence, human reason).

        Precedence: explicit profile override > shared standards crosswalk
        (declared frameworks) > inferred-framework fallback > unmapped-but-kept.
        """
        from app.grc_platforms import crosswalk as _xw
        p = self.profile
        # 1. explicit override on the profile (escape hatch)
        if control_ref in p.control_crosswalk:
            return p.control_crosswalk[control_ref], 0.92, "explicit profile override"
        # 2/3. shared standards crosswalk
        declared = list(p.speaks_frameworks) + list((frameworks or {}).keys())
        mapping, fw_used = _xw.resolve_best(control_ref, declared)
        if mapping:
            conf = _xw.QUALITY_CONFIDENCE.get(mapping.quality, 0.5)
            return mapping.control_id, conf, f"{fw_used} {mapping.quality} match — {mapping.note}"
        # 4. unmapped but kept (never dropped)
        return None, 0.35, "no crosswalk entry — evidenced but unmapped"

    @staticmethod
    def _freshness_days(ts: Any) -> Optional[int]:
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - dt).days
        except (ValueError, TypeError):
            return None
