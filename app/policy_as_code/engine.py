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

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

from app.policy_as_code.evaluator import SafeEvaluator, PolicyExpressionError

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
    rules: List[Dict[str, Any]] = field(default_factory=list)
    obligations: List[str] = field(default_factory=list)
    requires: List[str] = field(default_factory=list)
    frameworks: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"control_id": self.control_id, "status": self.status,
                "severity": self.severity, "reason": self.reason,
                "rules": self.rules, "obligations": self.obligations,
                "requires": self.requires, "frameworks": self.frameworks}


@dataclass
class Policy:
    control_id: str
    title: str
    base_severity: str
    frameworks: Dict[str, List[str]]
    params: Dict[str, Any]
    rules: List[Dict[str, Any]]                 # [{id, when, else_fail, severity}]
    severity_escalation: List[Dict[str, Any]]   # [{when, severity}]
    obligations: Dict[str, List[str]]           # {on_fail: [...]}
    requires: List[str]
    description: str = ""
    source_file: str = ""
    tests: List[Dict[str, Any]] = field(default_factory=list)

    def evaluate(self, evidence: Dict[str, Any],
                 dep_status: Optional[Dict[str, str]] = None) -> PolicyDecision:
        dep_status = dep_status or {}
        rule_results: List[RuleResult] = []
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
        # composition: required controls must also be passing
        failed_deps = [c for c in self.requires if dep_status.get(c, "pass") != "pass"]

        if not failed_rules and not failed_deps:
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
                if SafeEvaluator(evidence, self.params).eval(esc["when"]):
                    if _SEV_ORDER.get(esc.get("severity", "high"), 0) > _SEV_ORDER.get(sev, 0):
                        sev = esc["severity"]
            except PolicyExpressionError:
                pass

        reasons = [r.reason for r in failed_rules if r.reason]
        if failed_deps:
            reasons.append("required controls failing: " + ", ".join(failed_deps))
        return PolicyDecision(
            self.control_id, "fail", sev, "; ".join(reasons) or f"{self.control_id} failed",
            rules=[{"rule": r.rule_id, "passed": r.passed, "reason": r.reason}
                   for r in rule_results],
            obligations=self.obligations.get("on_fail", []),
            requires=self.requires, frameworks=self.frameworks)


class PolicyValidationError(Exception):
    pass


def load_policy(data: Dict[str, Any], source: str = "") -> Policy:
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
    )


def _validate_expr(expr: str, control: str, params: Dict[str, Any]) -> None:
    try:
        SafeEvaluator({}, params).eval(expr)
    except PolicyExpressionError as exc:
        raise PolicyValidationError(f"invalid expression in {control}: {exc}") from exc


class PolicyEngine:
    def __init__(self, policies: Optional[Dict[str, Policy]] = None):
        self.policies: Dict[str, Policy] = policies or {}

    @classmethod
    def from_dir(cls, path: str) -> "PolicyEngine":
        policies: Dict[str, Policy] = {}
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

    def list_policies(self) -> List[Dict[str, Any]]:
        return [{"control_id": p.control_id, "title": p.title, "severity": p.base_severity,
                 "frameworks": p.frameworks, "rules": len(p.rules),
                 "params": p.params, "requires": p.requires,
                 "has_escalation": bool(p.severity_escalation),
                 "obligations": p.obligations.get("on_fail", []),
                 "source_file": p.source_file, "test_count": len(p.tests)}
                for p in self.policies.values()]

    def evaluate(self, control_id: str, evidence: Dict[str, Any],
                 dep_status: Optional[Dict[str, str]] = None) -> PolicyDecision:
        p = self.policies.get(control_id)
        if p is None:
            return PolicyDecision(control_id, "error", "info",
                                  f"no policy defined for {control_id}")
        return p.evaluate(evidence, dep_status)

    def evaluate_all(self, evidence_by_control: Dict[str, Dict[str, Any]]) -> List[PolicyDecision]:
        """Two-pass: evaluate base rules, then re-evaluate so `requires` see real dep status."""
        first = {cid: p.evaluate(evidence_by_control.get(cid, {}))
                 for cid, p in self.policies.items()}
        dep_status = {cid: d.status for cid, d in first.items()}
        out = []
        for cid, p in self.policies.items():
            out.append(p.evaluate(evidence_by_control.get(cid, {}), dep_status))
        return out

    def run_tests(self) -> Dict[str, Any]:
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
