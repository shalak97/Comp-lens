"""Framework revision registry — pin the version an assertion was made under.

Failure mode #4 (schema/framework drift): a stored finding records *which*
framework it was assessed against, but not which *revision* of that framework. When
a framework revises, past assertions lose the version they were made under. This is
the single source of truth for the current revision of each framework Comp-Lens
knows; `version_of()` normalises the many spellings a framework name takes.

Pure, stdlib only — unit-testable. Update the map here when a framework revises.
"""
from __future__ import annotations

FRAMEWORK_VERSIONS: dict[str, str] = {
    "NIST_800_53": "rev5",
    "ISO_27001_2022": "2022",
    "SOC2": "2017",
    "CIS": "v8",
    "ISO_42001": "2023",
    "NIST_AI_RMF": "1.0",
    "EU_AI_ACT": "2024",
}
DEFAULT_VERSION = "unversioned"

# Common aliases -> canonical registry key.
_ALIASES = {
    "NIST": "NIST_800_53", "NIST80053": "NIST_800_53", "NIST_800_53R5": "NIST_800_53",
    "ISO27001": "ISO_27001_2022", "ISO_27001": "ISO_27001_2022", "ISO270012022": "ISO_27001_2022",
    "SOC_2": "SOC2", "CISV8": "CIS", "ISO42001": "ISO_42001", "NISTAIRMF": "NIST_AI_RMF",
    "EUAIACT": "EU_AI_ACT",
}


def _canonical(framework: str) -> str:
    key = str(framework or "").upper().replace(" ", "_").replace("-", "_").replace(".", "_")
    return _ALIASES.get(key.replace("_", ""), _ALIASES.get(key, key))


def version_of(framework: str) -> str:
    """The pinned revision string for a framework name, or 'unversioned'."""
    return FRAMEWORK_VERSIONS.get(_canonical(framework), DEFAULT_VERSION)


__all__ = ["FRAMEWORK_VERSIONS", "DEFAULT_VERSION", "version_of"]
