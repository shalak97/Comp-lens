"""Natural-language → policy authoring (human-in-the-loop).

A plain-English control description is compiled into a Rego policy that the OPA
engine can evaluate. The compiler here is a deterministic keyword mapper onto
known telemetry fields — a transparent, testable stand-in for an LLM agent
(the same seam can POST the description to an LLM for richer drafting). Either
way the draft is PENDING and enforces nothing until a human approves it.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import PolicyDraft, PolicyDraftRequest

# telemetry field -> keywords that imply it
_FIELD_KEYWORDS: Dict[str, List[str]] = {
    "mfa_enforced": ["mfa", "multi-factor", "multi factor", "two-factor", "2fa"],
    "encryption_at_rest": ["encrypt", "encryption", "at rest"],
    "public_access_blocked": ["public access", "publicly", "not public", "no public"],
    "logging_enabled": ["logging", "audit log", "logs enabled"],
    "branch_protection_enabled": ["branch protection", "protected branch"],
    "secret_scanning_enabled": ["secret scanning", "secrets scan", "leaked secret"],
    "disk_encrypted": ["disk encryption", "disk encrypted", "volume encryption"],
    "human_oversight": ["human oversight", "human in the loop", "human-in-the-loop"],
    "impact_assessment": ["impact assessment", "risk assessment", "dpia"],
    "data_governance": ["data governance", "data quality", "training data"],
    "transparency_notice": ["transparency", "disclosure", "disclose", "inform users"],
    "eval_report": ["evaluation", "bias test", "bias testing", "model eval"],
    "accuracy_tested": ["accuracy", "robustness", "performance test"],
    "critical_vulnerabilities": ["vulnerab", "cve", "critical vuln"],
}

_NUMERIC_FIELDS = {"critical_vulnerabilities"}


def _best_field(description: str) -> Tuple[Optional[str], float]:
    text = description.lower()
    best, best_hits = None, 0
    for field, kws in _FIELD_KEYWORDS.items():
        hits = sum(1 for kw in kws if kw in text)
        if hits > best_hits:
            best, best_hits = field, hits
    if best is None:
        return None, 0.1
    confidence = min(0.5 + 0.2 * best_hits, 0.95)
    return best, round(confidence, 2)


def _threshold(description: str) -> int:
    m = re.search(r"(\d+)", description)
    if m:
        return int(m.group(1))
    if any(w in description.lower() for w in ("no ", "zero", "none", "without")):
        return 0
    return 0


def compile_to_rego(description: str, control_id: str) -> Tuple[str, Optional[str], float]:
    field, confidence = _best_field(description)
    if field is None:
        rego = ("package complens\n\n"
                "# Could not infer a telemetry field from the description.\n"
                "# A human must complete this rule before approval.\n"
                "default decision := {\"status\": \"error\", \"reason\": \"rule incomplete\"}\n")
        return rego, None, confidence

    if field in _NUMERIC_FIELDS:
        n = _threshold(description)
        rego = (f"package complens\n\n"
                f"default decision := {{\"status\": \"fail\", \"reason\": \"{field} exceeds {n}\"}}\n\n"
                f"decision := {{\"status\": \"pass\", \"reason\": \"{field} within limit\"}} if {{\n"
                f"    input.telemetry.{field} <= {n}\n}}\n")
    else:
        rego = (f"package complens\n\n"
                f"default decision := {{\"status\": \"fail\", \"reason\": \"{field} not satisfied\"}}\n\n"
                f"decision := {{\"status\": \"pass\", \"reason\": \"{field} satisfied\"}} if {{\n"
                f"    input.telemetry.{field} == true\n}}\n")
    return rego, field, confidence


class PolicyAuthoringService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def draft(self, req: PolicyDraftRequest) -> PolicyDraft:
        control_id = req.control_id or ("NL-" + re.sub(r"[^a-z0-9]+", "-", req.description.lower())[:24].strip("-"))
        rego, field, confidence = compile_to_rego(req.description, control_id)
        d = PolicyDraft(tenant_id=req.tenant_id, description=req.description, control_id=control_id,
                        rego=rego, telemetry_field=field, confidence=confidence, status="pending")
        self.db.add(d)
        self.db.flush()
        return d

    def decide(self, tenant_id: str, draft_id: str, approve: bool) -> Optional[PolicyDraft]:
        d = self.db.get(PolicyDraft, draft_id)
        if not d or d.tenant_id != tenant_id:
            return None
        d.status = "approved" if approve else "rejected"
        self.db.flush()
        return d

    def list(self, tenant_id: str) -> List[PolicyDraft]:
        return list(self.db.execute(
            select(PolicyDraft).where(PolicyDraft.tenant_id == tenant_id)
            .order_by(PolicyDraft.created_at.desc())
        ).scalars().all())
