"""Base contract for GRC-platform connectors — distinct from native connectors.

Native connectors answer: "collect telemetry for ONE control on ONE asset."
GRC platforms answer the opposite shape: "here are HUNDREDS of already-evaluated
test results, each pre-mapped to our taxonomy and frameworks." So this base has a
bulk_ingest() contract, plus a declarative PlatformProfile so adding a new platform
is writing config, not code.
"""
from __future__ import annotations

import abc
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.grc_platforms.crosswalk import QUALITY_CONFIDENCE, resolve_best


@dataclass
class ControlAttestation:
    """One control result inherited from a GRC platform."""
    platform: str                       # VANTA / DRATA / ONETRUST
    external_test_id: str               # their id for this test/control
    external_control_ref: str           # their control taxonomy ref
    comp_lens_control_id: str | None # our control id (None = unmapped, still kept)
    status: str                         # pass | fail | error | not_applicable
    evidence_freshness_days: int | None
    frameworks: dict[str, list[str]]    # their framework refs (SOC2, ISO27001, …)
    confidence: float                   # 0..1 — how strongly we trust this mapping
    title: str = ""
    mapping_reason: str = ""            # human-readable why-this-maps (or why not)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_telemetry(self) -> dict[str, Any]:
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
            "mapping_reason": self.mapping_reason,
            "mapped": self.comp_lens_control_id is not None,
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
    env_vars: list[str]                 # credential env var names (never values)
    results_path: str                   # "/v1/tests"
    items_key: str | None            # JSON key holding the array, None = top-level
    pagination_key: str | None       # cursor field, None = single page
    # dotted JSON paths into each result item:
    field_test_id: str
    field_status: str
    field_control_ref: str
    field_updated: str | None        # last-evidence timestamp path
    field_title: str | None = None
    field_frameworks: str | None = None
    # status normalization: their status string -> ours
    status_map: dict[str, str] = field(default_factory=dict)
    # taxonomy crosswalk: their control ref -> our control id (legacy per-platform
    # dict; profiles now prefer `speaks_frameworks` + the shared crosswalk instead).
    control_crosswalk: dict[str, str] = field(default_factory=dict)
    # frameworks this platform speaks — the shared crosswalk does the translation.
    speaks_frameworks: list[str] = field(default_factory=list)
    version: str = ""
    source: str = "builtin"             # "builtin" | "yaml:<file>"
    notes: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str = "builtin") -> PlatformProfile:
        """Build a profile from a declarative dict (a YAML doc or inline config).

        Only the platform's API shape + which frameworks it speaks are required;
        every optional key falls back to a sensible default so a minimal profile
        stays valid. Unknown keys are ignored so config can carry extra metadata.
        """
        return cls(
            platform=str(data["platform"]),
            name=str(data.get("name", data["platform"])),
            base_url=str(data.get("base_url", "")),
            auth_method=str(data.get("auth_method", "api_key")),
            env_vars=list(data.get("env_vars", []) or []),
            results_path=str(data.get("results_path", "")),
            items_key=data.get("items_key"),
            pagination_key=data.get("pagination_key"),
            field_test_id=str(data.get("field_test_id", "id")),
            field_status=str(data.get("field_status", "status")),
            field_control_ref=str(data.get("field_control_ref", "control")),
            field_updated=data.get("field_updated"),
            field_title=data.get("field_title"),
            field_frameworks=data.get("field_frameworks"),
            status_map=dict(data.get("status_map", {}) or {}),
            control_crosswalk=dict(data.get("control_crosswalk", {}) or {}),
            speaks_frameworks=list(data.get("speaks_frameworks", []) or []),
            version=str(data.get("version", "")),
            source=source,
            notes=str(data.get("notes", "")),
        )


def dotted(obj: Any, path: str | None, default: Any = None) -> Any:
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

    def __init__(self, profile: PlatformProfile, fetcher: Callable | None = None):
        self.profile = profile
        self.platform = profile.platform
        self._fetch = fetcher  # injectable for testing; real impl uses ResilientClient

    @abc.abstractmethod
    def _authed_get(self, path: str, cursor: str | None = None) -> Any:
        """Make an authenticated read-only GET. Raises if no credentials."""

    def healthcheck(self) -> bool:
        try:
            self._authed_get(self.profile.results_path)
            return True
        except Exception:
            return False

    def bulk_ingest(self, max_pages: int = 20) -> list[ControlAttestation]:
        """Pull all test results, paginate, and map to ControlAttestations."""
        out: list[ControlAttestation] = []
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

    def _map_item(self, item: dict[str, Any]) -> ControlAttestation | None:
        p = self.profile
        test_id = dotted(item, p.field_test_id)
        if test_id is None:
            return None
        raw_status = str(dotted(item, p.field_status, "")).lower()
        status = p.status_map.get(raw_status, raw_status if raw_status in
                                  ("pass", "fail", "error", "not_applicable") else "error")
        control_ref = str(dotted(item, p.field_control_ref, "") or "")
        cl_control, base_conf, reason = self._resolve_control(control_ref)
        # confidence: mapped + fresh = high; unmapped or stale = lower
        freshness = self._freshness_days(dotted(item, p.field_updated))
        confidence = base_conf
        if freshness is not None and freshness > 30:
            confidence *= 0.7
        frameworks = dotted(item, p.field_frameworks, {}) or {}
        if not isinstance(frameworks, dict):
            frameworks = {}
        return ControlAttestation(
            platform=p.platform, external_test_id=str(test_id),
            external_control_ref=control_ref, comp_lens_control_id=cl_control,
            status=status, evidence_freshness_days=freshness,
            frameworks=frameworks, confidence=round(confidence, 2),
            title=str(dotted(item, p.field_title, "") or ""),
            mapping_reason=reason, raw=item)

    def _resolve_control(self, control_ref: str) -> tuple[str | None, float, str]:
        """Map a platform control ref to a Comp-Lens control id.

        Precedence: an explicit per-platform crosswalk entry (legacy, highest
        confidence) wins; otherwise the shared standards crosswalk translates via
        the frameworks the platform speaks. Unmapped refs are kept, not dropped.
        Returns (control_id | None, base_confidence, mapping_reason).
        """
        p = self.profile
        if not control_ref:
            return None, 0.4, "unmapped: no control reference on this result"
        declared = p.control_crosswalk.get(control_ref)
        if declared:
            return declared, 0.9, f"exact match: platform-declared mapping {control_ref}→{declared}"
        mapping, fw = resolve_best(control_ref, p.speaks_frameworks or None)
        if mapping:
            conf = QUALITY_CONFIDENCE.get(mapping.quality, 0.5)
            return (mapping.control_id, conf,
                    f"{mapping.quality} match via {fw}: {control_ref}→{mapping.control_id}"
                    f" ({mapping.note})")
        fws = ", ".join(p.speaks_frameworks) or "none declared"
        return None, 0.4, f"unmapped: no crosswalk entry for {control_ref} (frameworks: {fws})"

    @staticmethod
    def _freshness_days(ts: Any) -> int | None:
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return (datetime.now(UTC) - dt).days
        except (ValueError, TypeError):
            return None
