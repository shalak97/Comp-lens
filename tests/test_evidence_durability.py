"""Evidence has to outlive the container, and fail loudly when it cannot.

Two things were wrong in `render.yaml`, and both were about durability rather
than code:

  * `EVIDENCE_LOCAL_PATH=/tmp/evidence_store`. Render discards /tmp on every
    restart and every deploy, so each deploy destroyed the chain-of-custody
    records this product exists to produce. The file even carried a NOTE saying
    so.
  * `plan: free` on the database. A free Render Postgres expires 30 days after
    creation, allows 14 days' grace, and is then deleted with all of its data.

The evidence path is now a mounted disk, which introduces the failure this
module guards. `app/evidence.py` builds its store at import time
(`evidence_store = EvidenceStore()` at module scope) and calls
`mkdir(parents=True)` in the constructor — so an unwritable directory does not
produce a configuration error, it kills the import and prints a PermissionError
traceback from a module the operator has never heard of.

That is not hypothetical: this image drops to a non-root user, and a mounted
volume arrives owned by root. The fix is a one-line chown, but only if you can
tell that is what you are looking at.

The first version of `check_local_store` had this bug itself — its
PermissionError handler called `path.exists()`, which raises PermissionError
when an ancestor is unreadable, so the code meant to produce a helpful message
raised the unreadable traceback instead. It was only caught by running the test
as a non-root user; as root every permission check silently passes.
"""
from __future__ import annotations

import os
import pathlib

import pytest
import yaml

from app.storecheck import check_local_store

ROOT = pathlib.Path(__file__).resolve().parent.parent
RENDER = yaml.safe_load((ROOT / "render.yaml").read_text())
WEB = next(s for s in RENDER["services"] if s.get("name") == "comp-lens")


# ── the deployment config ──
# This blueprint is deliberately free-tier: Render disks need a paid instance
# and a paid Postgres is ~$6/month, which is not a trade every deployment wants
# to make. So these tests do NOT demand durability. They demand that the choice
# stays coherent and stays visible, because the failure mode of a free tier is
# not slowness — it is believing data is kept when it is not.
def test_a_local_evidence_path_is_either_durable_or_declared_ephemeral():
    """Ephemeral storage is a legitimate choice; a silent one is not. Either a
    disk backs the path, or the file says out loud that evidence does not
    survive a deploy."""
    backend = next(e["value"] for e in WEB["envVars"]
                   if e.get("key") == "EVIDENCE_BACKEND")
    if backend != "local":
        pytest.skip("evidence is on an object store, not container storage")

    path = next(e["value"] for e in WEB["envVars"]
                if e.get("key") == "EVIDENCE_LOCAL_PATH")
    disk = WEB.get("disk")
    if disk:
        assert path.startswith(disk["mountPath"]), (
            f"EVIDENCE_LOCAL_PATH={path} is not under the disk mounted at "
            f"{disk['mountPath']}, so the disk is paid for and unused")
        return
    raw = (ROOT / "render.yaml").read_text().upper()
    assert "EPHEMERAL" in raw, (
        "no persistent disk is declared, so evidence does not survive a "
        "deploy. That is fine for a hobby deployment, but render.yaml has to "
        "say so — the previous version buried it in a NOTE and it went "
        "unnoticed until a deploy destroyed the evidence.")


def test_the_s3_backend_is_never_half_configured():
    """The store raises at import when the backend is s3 with no bucket, which
    is a crash loop rather than a warning. Whoever uncomments that block must
    move both lines together."""
    keys = {e.get("key") for e in WEB["envVars"]}
    backend = next(e["value"] for e in WEB["envVars"]
                   if e.get("key") == "EVIDENCE_BACKEND")
    if backend == "s3":
        assert "EVIDENCE_S3_BUCKET" in keys


def test_the_free_database_expiry_is_written_down():
    """A free Render Postgres is deleted 30 days after creation, plus 14 days'
    grace. Staying on it is a valid choice for a hobby project; not knowing
    about the clock is not."""
    db = next(d for d in RENDER["databases"] if d["name"] == "comp-lens-db")
    if db.get("plan") != "free":
        return
    raw = (ROOT / "render.yaml").read_text()
    assert "30 days" in raw and "delete" in raw.lower(), (
        "the database is on the free plan, which expires and is deleted — "
        "render.yaml must say so where the plan is set")


def test_the_web_service_plan_is_not_pinned_here():
    """Naming a plan in the blueprint would silently change the instance type
    on the next sync — downgrading a larger one, or upgrading a free one into a
    bill nobody asked for. That belongs in the dashboard."""
    assert "plan" not in WEB, (
        "pinning the web service plan risks changing the running instance "
        "type, and the bill, on the next blueprint sync")


def test_an_s3_compatible_endpoint_is_configurable():
    """Durable evidence without paying anyone: R2 and B2 both have standing
    free tiers and both speak the S3 API. That is only reachable if the client
    can be pointed somewhere other than AWS."""
    import inspect

    from app import evidence
    assert "endpoint_url" in inspect.getsource(evidence.EvidenceStore._init_s3)
    from app.config import Settings
    assert "evidence_s3_endpoint" in Settings.model_fields


# ── the preflight ──
def test_a_writable_path_passes(tmp_path):
    ok, message = check_local_store(str(tmp_path / "evidence"))
    assert ok
    assert "writable" in message


def test_it_creates_the_directory_it_needs(tmp_path):
    target = tmp_path / "a" / "b" / "evidence"
    ok, _ = check_local_store(str(target))
    assert ok and target.is_dir()


@pytest.mark.skipif(os.getuid() == 0,
                    reason="root bypasses permission bits, so this proves nothing")
def test_an_unwritable_directory_is_reported_not_raised(tmp_path):
    """The whole point: a clear sentence instead of an import-time traceback."""
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o555)
    try:
        ok, message = check_local_store(str(locked))
        assert not ok
        assert "not writable" in message
    finally:
        locked.chmod(0o755)


@pytest.mark.skipif(os.getuid() == 0,
                    reason="root bypasses permission bits, so this proves nothing")
def test_diagnosing_an_unreadable_parent_does_not_itself_raise(tmp_path):
    """The bug this module had. Probing for the offending directory calls
    stat() on paths that raise PermissionError — the exact condition being
    diagnosed — so every probe must be guarded."""
    parent = tmp_path / "mount"
    parent.mkdir()
    parent.chmod(0o555)
    try:
        ok, message = check_local_store(str(parent / "evidence"))
        assert not ok
        assert "cannot create" in message
    finally:
        parent.chmod(0o755)


def test_the_container_checks_the_store_before_serving():
    dockerfile = (ROOT / "Dockerfile").read_text()
    cmd = next(ln for ln in dockerfile.splitlines() if ln.startswith("CMD"))
    assert "app.storecheck" in cmd
    assert cmd.index("app.storecheck") < cmd.index("uvicorn"), (
        "the check has to run before the server, or the app dies at import "
        "with the traceback this exists to replace")
