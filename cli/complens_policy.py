#!/usr/bin/env python3
"""complens-policy — test and evaluate dynamic compliance-as-code policies."""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.getcwd())


def _engine(d):
    from app.policy_as_code.engine import PolicyEngine
    return PolicyEngine.from_dir(d)


def cmd_test(a):
    res = _engine(a.policies).run_tests()
    print(f"\n  Policy tests: {res['passed']}/{res['total']} passed\n")
    for r in res["results"]:
        if not r["ok"] or a.verbose:
            print(f"    {'✓' if r['ok'] else '✗'} {r['control_id']} · {r['test']} "
                  f"(expected {r['expected']}, got {r['got']})")
    print()
    return 0 if res["failed"] == 0 else 1


def cmd_eval(a):
    d = _engine(a.policies).evaluate(a.control, json.loads(a.evidence or "{}"))
    print(f"\n  {d.control_id} → {d.status.upper()} ({d.severity})")
    print(f"  {d.reason}")
    if d.obligations:
        print(f"  obligations: {', '.join(d.obligations)}")
    print()
    return 0 if d.status == "pass" else 1


def cmd_list(a):
    eng = _engine(a.policies)
    print(f"\n  {len(eng.policies)} policies:\n")
    for p in eng.list_policies():
        fw = ", ".join(p["frameworks"].keys())
        extra = []
        if p["rules"] > 1:
            extra.append(f"{p['rules']} rules")
        if p["has_escalation"]:
            extra.append("escalation")
        if p["requires"]:
            extra.append("requires " + ",".join(p["requires"]))
        tail = f"  [{'; '.join(extra)}]" if extra else ""
        print(f"    {p['control_id']:8} {p['title']}  ({fw}){tail}")
    print()
    return 0


def main():
    ap = argparse.ArgumentParser(prog="complens-policy")
    ap.add_argument("--policies", default="./policies")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pt = sub.add_parser("test")
    pt.add_argument("-v", "--verbose", action="store_true")
    pe = sub.add_parser("eval")
    pe.add_argument("--control", required=True)
    pe.add_argument("--evidence", default="{}")
    sub.add_parser("list")
    a = ap.parse_args()
    return {"test": cmd_test, "eval": cmd_eval, "list": cmd_list}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
