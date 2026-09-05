"""SARIF interoperability adapter — static-analysis findings at the evidence layer.

SARIF (Static Analysis Results Interchange Format, OASIS 2.1.0) is what code
scanners emit: CodeQL, Semgrep, Bandit, Trivy, Grype, gitleaks, checkov and GitHub
code scanning all speak it. Where the OCSF adapter covers runtime/posture *events*,
this covers static-analysis *findings* — the evidence behind secure-development and
vulnerability controls (RA-5, SA-11, SA-15).

Two directions, both pure functions (no DB, no network — unit-testable):

    from_sarif(log)     a SARIF log -> [NormalizedEvidence], one per failing
                        result, each carrying a finding (rule, level, CVSS,
                        location, fingerprint), evidenced concepts, asset and
                        severity — the same internal shape the OCSF adapter and
                        native connectors produce.

    sarif_rollup(log)   a SARIF log -> flat telemetry the policy engine reads
                        directly ({critical_vulnerabilities, high_findings, ...}),
                        so a scan result can drive a numeric control (e.g.
                        RA-5: critical_vulnerabilities <= 0).

    to_sarif(results)   Comp-Lens control failures -> a SARIF 2.1.0 log, so our
                        findings can be uploaded to GitHub code scanning and read
                        by any SARIF viewer.

Targets SARIF 2.1.0. Severity words and concept ids are the ones the rest of
Comp-Lens speaks (see concept_lexicon.json); concept ids are validated by the tests.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services.ocsf import NormalizedEvidence

SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF result.level -> Comp-Lens severity word (fallback when no CVSS is given)
_LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low",
                   "none": "info"}
# Comp-Lens severity word -> SARIF result.level (for emit)
# `none` is absent on purpose: SARIF defines level "none" as "the rule was
# evaluated and no problem was found", so pairing it with kind "fail" is
# self-contradictory — and GitHub code scanning raises no alert at that level,
# which silently dropped every INFO-severity control failure on upload.
_SEVERITY_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                   "low": "note", "info": "note", "unknown": "warning"}
# Comp-Lens severity word -> representative GitHub "security-severity" (CVSS) score
_SEVERITY_CVSS = {"critical": "9.5", "high": "8.0", "medium": "5.5",
                  "low": "2.5", "info": "0.0"}

# Result kinds that are NOT findings (nothing to act on).
_NON_FINDING_KINDS = {"pass", "notapplicable", "informational", "open", "review"}

# Comp-Lens control status -> the SARIF result.kind that actually means it.
# SARIF has exact vocabulary for "could not evaluate" and "does not apply", and
# emitting both as `fail` uploaded them to GitHub code scanning as security
# alerts asserting a control was not satisfied.
_STATUS_KIND = {
    "pass": None, "passed": None, "compliant": None,          # not emitted at all
    "error": "open",                    # evaluated to no conclusion — needs a human
    "not_applicable": "notApplicable",
    "notapplicable": "notApplicable",
    "n/a": "notApplicable",
    "pending": "open",
    "unknown": "review",
}
#: `level` must be `none` for any kind other than `fail`, per SARIF 2.1.0.
_NON_FAIL_LEVEL = "none"

# Rule-tag / rule-id keyword -> internal concept id (all must exist in the lexicon).
# Every static-analysis finding evidences `security_testing`; these add specificity.
_TAG_CONCEPTS = {
    "dependency": "dependency_management", "sca": "dependency_management",
    "supply": "dependency_management", "component": "dependency_management",
    "cve": "vulnerability_management", "vuln": "vulnerability_management",
    "cwe": "vulnerability_management", "injection": "vulnerability_management",
    "secret": "secure_coding", "credential": "secure_coding", "hardcoded": "secure_coding",
    "review": "code_review",
}
_BASE_CONCEPT = "security_testing"


def _severity_from_cvss(score: Any) -> str | None:
    try:
        v = float(score)
    except (TypeError, ValueError):
        return None
    if v >= 9.0:
        return "critical"
    if v >= 7.0:
        return "high"
    if v >= 4.0:
        return "medium"
    if v > 0.0:
        return "low"
    return "info"


def _rule_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map ruleId -> rule object from a run's tool driver (+ extensions)."""
    idx: dict[str, dict[str, Any]] = {}
    tool = run.get("tool") or {}
    components = [tool.get("driver") or {}]
    components += [e for e in (tool.get("extensions") or []) if isinstance(e, dict)]
    for comp in components:
        for rule in comp.get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                idx.setdefault(str(rule["id"]), rule)
    return idx


def _security_severity(result: dict[str, Any], rule: dict[str, Any] | None) -> Any:
    for src in (result.get("properties") or {}, (rule or {}).get("properties") or {}):
        if isinstance(src, dict) and src.get("security-severity") is not None:
            return src["security-severity"]
    return None


def _result_severity(result: dict[str, Any], rule: dict[str, Any] | None) -> str:
    cvss = _severity_from_cvss(_security_severity(result, rule))
    if cvss:
        return cvss
    return _LEVEL_SEVERITY.get(str(result.get("level") or "warning").lower(), "medium")


def _location(result: dict[str, Any]) -> tuple[str | None, int | None]:
    locs = result.get("locations")
    if isinstance(locs, list) and locs:
        phys = (locs[0] or {}).get("physicalLocation") or {}
        uri = ((phys.get("artifactLocation") or {}).get("uri"))
        line = ((phys.get("region") or {}).get("startLine"))
        return uri, (line if isinstance(line, int) else None)
    return None, None


def _fingerprint(result: dict[str, Any]) -> str | None:
    for key in ("fingerprints", "partialFingerprints"):
        fp = result.get(key)
        if isinstance(fp, dict) and fp:
            # deterministic: first key's value
            return str(next(iter(sorted(fp.items())))[1])
    return None


def _rule_text(rule: dict[str, Any] | None) -> str:
    if not rule:
        return ""
    for k in ("shortDescription", "fullDescription"):
        t = (rule.get(k) or {}).get("text")
        if t:
            return str(t)
    return str(rule.get("name") or rule.get("id") or "")


def _concepts_for(rule_id: str, rule: dict[str, Any] | None) -> list[str]:
    blob = (rule_id + " " + _rule_text(rule)).lower()
    tags = (rule or {}).get("properties", {}).get("tags") or []
    blob += " " + " ".join(str(t).lower() for t in tags)
    concepts = [_BASE_CONCEPT]
    for kw, concept in _TAG_CONCEPTS.items():
        if kw in blob and concept not in concepts:
            concepts.append(concept)
    return concepts


def _is_suppressed(result: dict[str, Any]) -> bool:
    """Whether a result has been formally accepted or no longer exists.

    SARIF's `suppressions` is the same idea as CycloneDX's VEX `analysis.state`,
    which this codebase's CycloneDX adapter already honours: an accepted risk, a
    `# nosec`, a baseline entry or a dismissed code-scanning alert is not an
    open finding. Ignoring it meant a signed-off critical still drove RA-5 to
    FAIL and landed in the POA&M as live remediation work.

    Per the spec an `accepted`/`underReview` suppression suppresses the result;
    a suppression explicitly `rejected` does not. `baselineState: "absent"`
    means the result is gone as of this run.
    """
    sups = result.get("suppressions")
    if isinstance(sups, list) and sups:
        for s in sups:
            state = (str(s.get("status") or "accepted").lower()
                     if isinstance(s, dict) else "accepted")
            if state != "rejected":
                return True
    return str(result.get("baselineState") or "").lower() == "absent"


def _msg(result: dict[str, Any]) -> str:
    m = result.get("message")
    if isinstance(m, dict):
        return str(m.get("text") or "")
    return str(m or "")


def from_sarif(log: dict[str, Any]) -> list[NormalizedEvidence]:
    """Map a SARIF log to one NormalizedEvidence per failing result."""
    if not isinstance(log, dict):
        return []
    out: list[NormalizedEvidence] = []
    now = datetime.now(UTC).isoformat()
    for run in log.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        tool_name = str(driver.get("name") or "SARIF").upper().replace(" ", "_")
        rules = _rule_index(run)
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            kind = str(result.get("kind") or "fail").lower()
            if kind in _NON_FINDING_KINDS:
                continue
            if _is_suppressed(result):
                continue
            rule_id = str(result.get("ruleId") or "")
            rule = rules.get(rule_id)
            sev = _result_severity(result, rule)
            uri, line = _location(result)
            fp = _fingerprint(result)
            ev = NormalizedEvidence(
                source_system=tool_name, plane="vulnerability_threat",
                observed_at=now, asset_id=uri, asset_type="file", severity=sev,
                concepts=_concepts_for(rule_id, rule),
                findings=[{
                    "rule_id": rule_id, "severity": sev,
                    "level": str(result.get("level") or "warning").lower(),
                    "cvss": _security_severity(result, rule),
                    "message": _msg(result), "location": uri, "line": line,
                    "fingerprint": fp,
                }],
                provenance={"sarif_version": log.get("version", SARIF_VERSION),
                            "tool": driver.get("name"), "rule_id": rule_id},
            )
            out.append(ev)
    return out


def sarif_rollup(log: dict[str, Any]) -> dict[str, Any]:
    """Aggregate a SARIF log into flat telemetry the policy engine reads directly.

    ``critical_vulnerabilities`` is a real policy field (RA-5 evaluates
    ``critical_vulnerabilities <= 0``); the rest give a severity histogram.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    tools: list[str] = []
    for ev in from_sarif(log):
        counts[ev.severity if ev.severity in counts else "info"] += 1
        if ev.source_system not in tools:
            tools.append(ev.source_system)
    total = sum(counts.values())
    return {
        "critical_vulnerabilities": counts["critical"],
        "high_findings": counts["high"],
        "medium_findings": counts["medium"],
        "low_findings": counts["low"],
        "total_findings": total,
        "tools": tools,
    }


def to_sarif(results: list[dict[str, Any]], *, tool_name: str = "Comp-Lens",
             tool_version: str = "1.0", information_uri: str | None = None) -> dict[str, Any]:
    """Render Comp-Lens control failures as a SARIF 2.1.0 log.

    Each item in ``results`` is ``{control_id, status, severity?, message?,
    location?, line?}``; a non-failing status is skipped. The output uploads to
    GitHub code scanning and opens in any SARIF viewer.
    """
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    for r in results:
        status = str(r.get("status") or "fail").lower()
        # A control the platform could not evaluate, and one that does not
        # apply, are not failures. Emitting them as `kind: "fail"` uploaded them
        # to GitHub code scanning as alerts asserting the control was not
        # satisfied — the same tri-state erosion this codebase guards against
        # everywhere else, in the export most likely to be handed to someone
        # outside the company.
        kind = _STATUS_KIND.get(status, "fail")
        if kind is None:
            continue
        cid = str(r.get("control_id") or "UNKNOWN")
        sev = str(r.get("severity") or "medium").lower()
        if cid not in rules:
            rules[cid] = {
                "id": cid, "name": cid,
                "shortDescription": {"text": r.get("title") or f"Control {cid}"},
                "properties": {"security-severity": _SEVERITY_CVSS.get(sev, "5.5"),
                               "tags": ["compliance"]},
            }
        default_msg = (f"{cid}: control not satisfied" if kind == "fail"
                       else f"{cid}: {status.replace('_', ' ')}")
        entry: dict[str, Any] = {
            "ruleId": cid, "ruleIndex": list(rules).index(cid),
            # SARIF requires level `none` for any kind other than `fail`.
            "level": (_SEVERITY_LEVEL.get(sev, "warning") if kind == "fail"
                      else _NON_FAIL_LEVEL),
            "kind": kind,
            "message": {"text": r.get("message") or default_msg},
            "properties": {"security-severity": _SEVERITY_CVSS.get(sev, "5.5"),
                           "comp-lens-status": status},
        }
        loc = r.get("location")
        if loc:
            region = {"startLine": r["line"]} if isinstance(r.get("line"), int) else {}
            entry["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": str(loc)}, "region": region}}]
        sarif_results.append(entry)
    return {
        "$schema": _SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": tool_name, "version": tool_version,
                "informationUri": information_uri or "https://github.com/shalak97/Comp-lens",
                "rules": list(rules.values()),
            }},
            "results": sarif_results,
        }],
    }


__all__ = [
    "SARIF_VERSION", "from_sarif", "sarif_rollup", "to_sarif",
]
