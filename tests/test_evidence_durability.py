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
def test_evidence_is_not_written_to_ephemeral_storage():
    """/tmp does not survive a restart on Render, so evidence written there is
    gone by the next deploy — including the deploy that wrote it."""
    path = next(e["value"] for e in WEB["envVars"]
                if e.get("key") == "EVIDENCE_LOCAL_PATH")
    assert not path.startswith("/tmp"), (
        f"EVIDENCE_LOCAL_PATH={path} is ephemeral on Render; point it at the "
        "mounted disk or move EVIDENCE_BACKEND to s3")


def test_the_evidence_path_is_on_the_mounted_disk():
    """A disk that nothing writes to is just a bill."""
    path = next(e["value"] for e in WEB["envVars"]
                if e.get("key") == "EVIDENCE_LOCAL_PATH")
    backend = next(e["value"] for e in WEB["envVars"]
                   if e.get("key") == "EVIDENCE_BACKEND")
    if backend != "local":
        pytest.skip("evidence is on an object store; the disk is not in play")
    disk = WEB.get("disk")
    assert disk, "EVIDENCE_BACKEND=local needs a persistent disk declared"
    assert path.startswith(disk["mountPath"]), (
        f"EVIDENCE_LOCAL_PATH={path} is not under the disk mounted at "
        f"{disk['mountPath']}, so it lands on ephemeral container storage")


def test_the_s3_backend_is_never_half_configured():
    """The store raises at import when the backend is s3 with no bucket, which
    is a crash loop rather than a warning. If the commented block above is ever
    uncommented, both lines have to move together."""
    keys = {e.get("key") for e in WEB["envVars"]}
    backend = next(e["value"] for e in WEB["envVars"]
                   if e.get("key") == "EVIDENCE_BACKEND")
    if backend == "s3":
        assert "EVIDENCE_S3_BUCKET" in keys


def test_the_database_is_not_on_a_plan_that_deletes_itself():
    """A free Render Postgres is deleted 30 days after creation (plus 14 days'
    grace). That is the findings, posture history and attestations — the system
    of record — on a countdown."""
    db = next(d for d in RENDER["databases"] if d["name"] == "comp-lens-db")
    assert db.get("plan") != "free", (
        "comp-lens-db is on the free plan, which expires and is then deleted "
        "with all of its data")


def test_the_web_service_plan_is_not_pinned_here():
    """Naming a plan in the blueprint would silently DOWNGRADE the service if
    it is running on something larger. The disk requires a paid instance, but
    which paid instance is the dashboard's business, not this file's."""
    assert "plan" not in WEB, (
        "pinning the web service plan risks downgrading a larger running "
        "instance on the next blueprint sync")


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
