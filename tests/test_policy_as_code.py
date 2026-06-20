"""Dynamic policy-as-code: safe evaluator (functions, quantifiers, arithmetic) + engine."""
import os
import pytest
from app.policy_as_code.evaluator import SafeEvaluator, PolicyExpressionError, evaluate_expression as ev
from app.policy_as_code.engine import PolicyEngine, load_policy, PolicyValidationError

POLICY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policies")


# ── evaluator: dynamic capabilities ──
def test_arithmetic():
    assert ev("cost > budget * 1.4", {"cost": 150, "budget": 100}) is True

def test_nested_field_access():
    assert ev("resource.config.enabled == true", {"resource": {"config": {"enabled": True}}}) is True
    assert ev("a.b.missing == true", {"a": {"b": {}}}) is False

def test_functions():
    assert ev("len(x) >= 3", {"x": [1, 2, 3, 4]}) is True
    assert ev("startswith(r, 'us-')", {"r": "us-east-1"}) is True
    assert ev("matches(arn, 'arn:aws')", {"arn": "arn:aws:s3"}) is True
    assert ev("contains(lower(n), 'prod')", {"n": "PROD-DB"}) is True

def test_quantifiers():
    good = [{"enc": True}, {"enc": True}]
    bad = [{"enc": True}, {"enc": False}]
    assert ev("all(b, 'enc == true')", {"b": good}) is True
    assert ev("all(b, 'enc == true')", {"b": bad}) is False
    assert ev("count(b, 'enc == false') == 1", {"b": bad}) is True

def test_parameterized():
    assert SafeEvaluator({"age": 20}, {"max": 30}).eval("age < max") is True


@pytest.mark.parametrize("malicious", [
    '__import__("os")', 'eval("1")', 'exec("x=1")', 'open("/etc/passwd")',
    'foo.__class__', '().__class__.__bases__', '(lambda:1)()',
    '[x for x in range(9)]', 'getattr(x,"y")', 'compile("1","","eval")',
])
def test_injection_rejected(malicious):
    with pytest.raises(Exception):
        SafeEvaluator({"foo": {}, "x": {}}).eval(malicious)


# ── engine: dynamic structure ──
def test_multi_rule():
    eng = PolicyEngine.from_dir(POLICY_DIR)
    d = eng.evaluate("SC-28", {"storage": [{"encryption_at_rest": True}], "scan_age_days": 45})
    assert d.status == "fail"  # stale scan rule

def test_severity_escalation():
    eng = PolicyEngine.from_dir(POLICY_DIR)
    d = eng.evaluate("SC-28", {"storage": [{"encryption_at_rest": False, "public": True}], "scan_age_days": 5})
    assert d.severity == "critical"

def test_obligations_on_fail():
    eng = PolicyEngine.from_dir(POLICY_DIR)
    d = eng.evaluate("RA-5", {"critical_vulns": 3, "scan_age_days": 5})
    assert "open_jira_ticket" in d.obligations

def test_composition():
    eng = PolicyEngine.from_dir(POLICY_DIR)
    out = eng.evaluate_all({"AC-2": {"mfa_enforced": False, "dormant_accounts": 0},
                            "IA-2": {"mfa_enforced": True}, "CC6.1": {}})
    byid = {d.control_id: d for d in out}
    assert byid["CC6.1"].status == "fail"
    assert "AC-2" in byid["CC6.1"].reason

def test_all_inline_tests_pass():
    eng = PolicyEngine.from_dir(POLICY_DIR)
    res = eng.run_tests()
    assert res["failed"] == 0, [r for r in res["results"] if not r["ok"]]

def test_invalid_policy_rejected():
    with pytest.raises(PolicyValidationError):
        load_policy({"control": "X", "pass_when": "__import__('os')"})
