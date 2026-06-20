"""Dynamic policy-as-code engine."""
import os
from app.policy_as_code.engine import PolicyEngine

_POLICY_DIR = os.getenv("POLICY_DIR", os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "policies"))
_engine = None


def get_engine() -> PolicyEngine:
    global _engine
    if _engine is None:
        _engine = PolicyEngine.from_dir(_POLICY_DIR)
    return _engine


def reload_engine() -> PolicyEngine:
    global _engine
    _engine = PolicyEngine.from_dir(_POLICY_DIR)
    return _engine
