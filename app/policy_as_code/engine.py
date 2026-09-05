"""Dynamic policy engine for compliance-as-code.

A policy is a version-controlled YAML file. Beyond a single pass/fail expression,
a mature policy supports:

  params:              named thresholds, so one policy is reused across environments
  rules:               multiple named rules, each with its own severity + fail reason
  severity_escalation: conditions that raise severity (e.g. failing + KEV = critical)
  obligations:         what to DO on fail (open ticket, notify, waiver-eligible)
  requires:            other controls that must also pass (executable composition)

The engine evaluates a policy against an evidence dict and returns a rich,
explainable decision. `pass_when` (single-rule shorthand) stays fully supported.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

import yaml

from app.policy_as_code.evaluator import (
    PolicyExpressionError,
    SafeEvaluator,
    free_names,
)

logger = logging.getLogger(__name__)

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class RuleResult:
    rule_id: str
    passed: bool
    severity: str
    reason: str


@dataclass
class PolicyDecision:
    control_id: str
    status: str                          # pass | fail | error
    severity: str
    reason: str
    rules: list[dict[str, Any]] = field(default_factory=list)
    obligations: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    frameworks: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"control_id": self.control_id, "status": self.status,
                "severity": self.severity, "reason": self.reason,
                "rules": self.rules, "obligations": self.obligations,
                "requires": self.requires, "frameworks": self.frameworks}


@dataclass
class Policy:
    control_id: str
    title: str
    base_severity: str
    frameworks: dict[str, list[str]]
    params: dict[str, Any]
    rules: list[dict[str, Any]]                 # [{id, when, else_fail, severity}]
    severity_escalation: list[dict[str, Any]]   # [{when, severity}]
    obligations: dict[str, list[str]]           # {on_fail: [...]}
    requires: list[str]
    description: str = ""
    source_file: str = ""
    tests: list[dict[str, Any]] = field(default_factory=list)
    #: Evidence signals every rule needs. Absent signals make the decision
    #: not_applicable rather than letting the expression answer from nothing.
    signals: list[str] = field(default_factory=list)

    def _absent_signals(self, evidence: dict[str, Any]) -> list[str]:
        return [s for s in self.signals if evidence.get(s) is None]

    def evaluate(self, evidence: dict[str, Any],
                 dep_status: dict[str, str] | None = None) -> PolicyDecision:  # noqa: C901
        # Tri-state, for the same reason the declarative check pack is
        # tri-state (app/services/control_checks.py): "we could not observe
        # this" and "we observed it and it is fine" are different claims, and a
        # boolean expression cannot tell them apart. Missing fields resolve to
        # None, and the natural way to write a compliance rule — `all(buckets,
        # ...)`, `len(admins) == 0`, `count(...) == 0`, `not backdoor` — is
        # vacuously TRUE over nothing. Without this guard a control with no
        # evidence at all returned "pass / all rules satisfied".
        absent = self._absent_signals(evidence)
        if absent:
            return PolicyDecision(
                self.control_id, "not_applicable", "info",
                f"Signal(s) unavailable in evidence: {', '.join(absent)}.",
                requires=self.requires, frameworks=self.frameworks)

        rule_results: list[RuleResult] = []
        try:
            for r in self.rules:
                ev = SafeEvaluator(evidence, self.params)
                passed = bool(ev.eval(r["when"]))
                rule_results.append(RuleResult(
                    rule_id=r.get("id", "rule"),
                    passed=passed,
                    severity=r.get("severity", self.base_severity),
                    reason="" if passed else r.get("else_fail", f"{r.get('id','rule')} not satisfied"),
                ))
        except PolicyExpressionError as exc:
            return PolicyDecision(self.control_id, "error", "info",
                                  f"policy expression error: {exc}",
                                  frameworks=self.frameworks)

        failed_rules = [r for r in rule_results if not r.passed]
        # Composition: required controls must also be passing. A control absent
        # from dep_status has no policy at all — `dep_status.get(c, "pass")`
        # used to read that absence as a pass, so `requires: [AC-2]` was
        # satisfied by AC-2 not existing. Absence is unknown, and unknown is not
        # satisfied. When no dep_status was supplied the caller is not
        # evaluating composition at all (the single-control path), which is
        # different from a dependency that is missing.
        if dep_status is None:
            failed_deps, unknown_deps, unassessed_deps = [], [], []
        else:
            failed_deps = [c for c in self.requires
                           if dep_status.get(c) in ("fail", "error")]
            unassessed_deps = [c for c in self.requires
                               if dep_status.get(c) == "not_applicable"]
            unknown_deps = [c for c in self.requires if c not in dep_status]

        # A composite whose dependencies were never assessed is unassessed too,
        # not failing: the same distinction the signal guard above draws.
        if unassessed_deps and not failed_rules and not failed_deps:
            return PolicyDecision(
                self.control_id, "not_applicable", "info",
                "required controls not assessed: " + ", ".join(unassessed_deps),
                requires=self.requires, frameworks=self.frameworks)

        if not failed_rules and not failed_deps and not unknown_deps:
            return PolicyDecision(
                self.control_id, "pass", "info",
                self.description or "all rules satisfied",
                rules=[{"rule": r.rule_id, "passed": True} for r in rule_results],
                requires=self.requires, frameworks=self.frameworks)

        # failing — compute severity from failing rules, then escalate
        sev = self.base_severity
        for r in failed_rules:
            if _SEV_ORDER.get(r.severity, 0) > _SEV_ORDER.get(sev, 0):
                sev = r.severity
        for esc in self.severity_escalation:
            try:
                if SafeEvaluator(evidence, self.params).eval(esc["when"]) and _SEV_ORDER.get(
                    esc.get("severity", "high"), 0
                ) > _SEV_ORDER.get(sev, 0):
                    sev = esc["severity"]
            except PolicyExpressionError:
                pass

        reasons = [r.reason for r in failed_rules if r.reason]
        if failed_deps:
            reasons.append("required controls failing: " + ", ".join(failed_deps))
        if unknown_deps:
            reasons.append("required controls not evaluated (no policy defined): "
                           + ", ".join(unknown_deps))
        return PolicyDecision(
            self.control_id, "fail", sev, "; ".join(reasons) or f"{self.control_id} failed",
            rules=[{"rule": r.rule_id, "passed": r.passed, "reason": r.reason}
                   for r in rule_results],
            obligations=self.obligations.get("on_fail", []),
            requires=self.requires, frameworks=self.frameworks)


class PolicyValidationError(Exception):
    pass


_MAX_POLICY_YAML_BYTES = 256 * 1024  # 256 KB — policies are small; bounds a memory-bomb body


class _NoAliasSafeLoader(yaml.SafeLoader):
    """SafeLoader that refuses YAML aliases. Anchors alone are harmless, but an
    alias that references an anchor repeatedly (and aliases-of-aliases) is the
    'billion laughs' expansion — a few KB that safe_load blows up into GBs. Real
    policies never need aliases, so we reject them outright."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.events.AliasEvent):
            event = self.get_event()
            raise PolicyValidationError(
                f"YAML aliases are not allowed in policies (anchor {event.anchor!r})")
        return super().compose_node(parent, index)


def parse_policy_yaml(text: str) -> dict[str, Any]:
    """Size-capped, alias-free YAML parse for untrusted policy documents.

    Guards POST /policies/import against oversized bodies and anchor/alias
    expansion DoS before the document ever reaches load_policy / the evaluator.
    """
    if not isinstance(text, str):
        raise PolicyValidationError("policy YAML must be a string")
    if len(text.encode("utf-8")) > _MAX_POLICY_YAML_BYTES:
        raise PolicyValidationError("policy YAML exceeds the 256 KB limit")
    try:
        doc = yaml.load(text, Loader=_NoAliasSafeLoader)
    except yaml.YAMLError as exc:
        raise PolicyValidationError(f"invalid policy YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise PolicyValidationError("policy YAML must be a mapping")
    return doc


def load_policy(data: dict[str, Any], source: str = "") -> Policy:
    if "control" not in data:
        raise PolicyValidationError(f"policy missing 'control' ({source})")
    # normalize: pass_when shorthand → a single rule
    rules = data.get("rules")
    if not rules:
        if "pass_when" not in data:
            raise PolicyValidationError(f"policy {data['control']} needs 'pass_when' or 'rules'")
        rules = [{"id": "main", "when": data["pass_when"],
                  "else_fail": data.get("fail_reason", "rule not satisfied"),
                  "severity": data.get("severity", "medium")}]
    # validate every expression parses safely at load time (fail fast)
    params = data.get("params", {}) or {}
    for r in rules:
        if "when" not in r:
            raise PolicyValidationError(f"{data['control']}: rule missing 'when'")
        _validate_expr(r["when"], data["control"], params)
    for esc in data.get("severity_escalation", []) or []:
        _validate_expr(esc.get("when", "false"), data["control"], params)

    # Which evidence fields must be present for the rules to mean anything.
    # Inferred from the expressions rather than hand-declared, so a policy
    # author cannot forget to list one and silently get vacuous passes; an
    # explicit `signals:` list overrides the inference where a policy genuinely
    # wants a field to be optional. Params are thresholds, not evidence, and
    # escalation expressions are excluded — a missing escalation signal should
    # not make the whole control unassessable.
    # An obligation no procedure fulfils is a silent no-op at dispatch time.
    # Warn at load, where the policy author can still see it.
    obligations = data.get("obligations", {}) or {}
    for trigger, names in obligations.items():
        from app.policy_as_code.obligations import unroutable_obligations

        stray = unroutable_obligations(names if isinstance(names, list) else [])
        if stray:
            logger.warning(
                "policy %s: obligation(s) on %s name no known procedure and will be "
                "skipped at dispatch: %s", data["control"], trigger, ", ".join(stray))

    declared = data.get("signals")
    if declared is None:
        inferred: set[str] = set()
        for r in rules:
            inferred |= free_names(r["when"])
        signals = sorted(inferred - set(params))
    else:
        signals = [str(s) for s in declared]

    return Policy(
        control_id=str(data["control"]),
        title=data.get("title", str(data["control"])),
        base_severity=str(data.get("severity", "medium")),
        frameworks=data.get("frameworks", {}) or {},
        params=params,
        rules=rules,
        severity_escalation=data.get("severity_escalation", []) or [],
        obligations=data.get("obligations", {}) or {},
        requires=data.get("requires", []) or [],
        description=data.get("description", ""),
        source_file=source,
        tests=data.get("tests", []) or [],
        signals=signals,
    )


def _validate_expr(expr: str, control: str, params: dict[str, Any]) -> None:
    try:
        SafeEvaluator({}, params).eval(expr)
    except PolicyExpressionError as exc:
        raise PolicyValidationError(f"invalid expression in {control}: {exc}") from exc


class PolicyEngine:
    def __init__(self, policies: dict[str, Policy] | None = None):
        self.policies: dict[str, Policy] = policies or {}

    @classmethod
    def from_dir(cls, path: str) -> PolicyEngine:
        policies: dict[str, Policy] = {}
        if os.path.isdir(path):
            for fn in sorted(os.listdir(path)):
                if not fn.endswith((".yaml", ".yml")):
                    continue
                with open(os.path.join(path, fn)) as fh:
                    for doc in yaml.safe_load_all(fh):
                        if doc:
                            p = load_policy(doc, source=fn)
                            policies[p.control_id] = p
        return cls(policies)

    def list_policies(self) -> list[dict[str, Any]]:
        return [{"control_id": p.control_id, "title": p.title, "severity": p.base_severity,
                 "frameworks": p.frameworks, "rules": len(p.rules),
                 "params": p.params, "requires": p.requires,
                 "has_escalation": bool(p.severity_escalation),
                 "obligations": p.obligations.get("on_fail", []),
                 "source_file": p.source_file, "test_count": len(p.tests)}
                for p in self.policies.values()]

    def evaluate(self, control_id: str, evidence: dict[str, Any],
                 dep_status: dict[str, str] | None = None) -> PolicyDecision:
        p = self.policies.get(control_id)
        if p is None:
            return PolicyDecision(control_id, "error", "info",
                                  f"no policy defined for {control_id}")
        return p.evaluate(evidence, dep_status)

    def evaluate_all(self, evidence_by_control: dict[str, dict[str, Any]]) -> list[PolicyDecision]:
        """Two-pass: evaluate base rules, then re-evaluate so `requires` see real dep status."""
        first = {cid: p.evaluate(evidence_by_control.get(cid, {}))
                 for cid, p in self.policies.items()}
        dep_status = {cid: d.status for cid, d in first.items()}
        out = []
        for cid, p in self.policies.items():
            out.append(p.evaluate(evidence_by_control.get(cid, {}), dep_status))
        return out

    def run_tests(self) -> dict[str, Any]:
        results, passed, failed = [], 0, 0
        for p in self.policies.values():
            for i, t in enumerate(p.tests):
                decision = p.evaluate(t.get("evidence", {}))
                exp = str(t.get("expect", "")).lower()
                ok = decision.status == exp
                passed += ok
                failed += not ok
                results.append({"control_id": p.control_id, "test": t.get("name", f"#{i+1}"),
                                "expected": exp, "got": decision.status, "ok": ok})
        return {"total": passed + failed, "passed": passed, "failed": failed, "results": results}
