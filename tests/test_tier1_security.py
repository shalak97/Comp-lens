"""Tier-1 security/correctness regressions.

1. SSH host-key policy must actually load the user's ~/.ssh/known_hosts and
   reject unknown hosts by default (a prior bound-method identity check was
   always False, so user known_hosts were never loaded).
2. Flipping enforcement mode rewrites the shared policy bundle — a fleet-wide
   privileged action that must require an admin (all-tenant) key.
"""
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:////tmp/test_tier1.db")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("ENABLE_SCHEDULER", "false")
os.environ.setdefault("EVIDENCE_SIGNING_KEY", "ci")


# ── SSH host-key policy ──
class _FakeSSHClient:
    def __init__(self):
        self.loaded = []
        self.policy = None

    def load_system_host_keys(self):
        self.loaded.append("system")

    def load_host_keys(self, path):
        self.loaded.append(path)

    def set_missing_host_key_policy(self, policy):
        self.policy = policy


def test_ssh_policy_loads_user_known_hosts_and_rejects(tmp_path, monkeypatch):
    import paramiko

    from app.connectors.safety import apply_ssh_host_key_policy
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    known = ssh_dir / "known_hosts"
    known.write_text("")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SSH_TRUST_UNKNOWN_HOSTS", raising=False)

    c = _FakeSSHClient()
    apply_ssh_host_key_policy(c)

    # the regression: the user's known_hosts is actually loaded now
    assert str(known) in c.loaded
    assert "system" in c.loaded
    # unknown hosts are rejected by default (MITM protection)
    assert isinstance(c.policy, paramiko.RejectPolicy)


def test_ssh_policy_autoadds_only_when_opted_in(tmp_path, monkeypatch):
    import paramiko

    from app.connectors.safety import apply_ssh_host_key_policy
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SSH_TRUST_UNKNOWN_HOSTS", "true")
    c = _FakeSSHClient()
    apply_ssh_host_key_policy(c)
    assert isinstance(c.policy, paramiko.AutoAddPolicy)


# ── enforcement mode admin guard ──
def test_enforcement_mode_requires_admin(monkeypatch):
    monkeypatch.setenv("COMP_LENS_API_KEYS", "adminkey:* ; scoped:tenantA")
    from app.main import app
    with TestClient(app) as c:
        # scoped (non-admin) key is authenticated but not admin -> 403
        r = c.post("/enforcement/systems/somehost/mode",
                   headers={"X-API-Key": "scoped"}, json={"mode": "enforce"})
        assert r.status_code == 403

        # admin key clears the guard (then fails downstream on the missing/unknown
        # bundle — anything but 403 proves the guard passed)
        r = c.post("/enforcement/systems/somehost/mode",
                   headers={"X-API-Key": "adminkey"}, json={"mode": "enforce"})
        assert r.status_code != 403
        assert r.status_code in (200, 400, 404, 503)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
