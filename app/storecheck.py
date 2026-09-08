"""Startup gate: prove evidence can actually be written before serving.

    python -m app.storecheck

Runs alongside app.dbcheck in the container's start command, and exists for one
specific failure that is otherwise very hard to read.

`app/evidence.py` builds its store at import time (`evidence_store =
EvidenceStore()` at module scope), and the local backend does
`mkdir(parents=True, exist_ok=True)` in the constructor. So if the evidence
directory is not writable, the app does not start with a configuration error —
it dies during import, and what reaches the log is a PermissionError traceback
from inside a module the operator has never heard of.

The way that happens in practice: a mounted volume is owned by root, and this
image drops to a non-root user (`appuser`, see Dockerfile). The container built
and ran fine yesterday on ephemeral storage; today a disk is mounted over the
same path and nothing can write to it. The fix is a one-line `chown`, but only
if you can tell that is what you are looking at.

Evidence durability is the product's whole claim, so failing loudly here is
right: serving happily while every write throws would be worse than not
starting.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from app.config import settings


def check_local_store(path: str) -> tuple[bool, str]:
    """Can we create the evidence directory and write a file in it?

    Returns (ok, message). Never raises — reporting the problem is the job.
    """
    target = Path(path)
    try:
        target.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        # Finding the offending directory must not itself raise. `exists()` and
        # `stat()` both throw PermissionError when an ancestor is unreadable —
        # which is exactly the situation being diagnosed — so every probe here
        # is guarded. Getting this wrong replaced the helpful message with the
        # unreadable traceback this module exists to avoid.
        owner = ""
        for candidate in target.parents:
            try:
                st = os.stat(candidate)
            except OSError:
                continue
            owner = (f" {candidate} is owned by uid={st.st_uid} gid={st.st_gid}, "
                     f"mode={oct(st.st_mode & 0o777)};")
            break
        return False, (
            f"cannot create {target}.{owner} this process runs as "
            f"uid={os.getuid()}. On a mounted volume this is an ownership "
            f"mismatch: chown the mount to the container's user, or mount it "
            f"somewhere the user already owns.")
    except OSError as exc:
        return False, f"cannot create {target}: {exc}"

    try:
        with tempfile.NamedTemporaryFile(dir=target, prefix=".writetest-"):
            pass
    except OSError as exc:
        return False, (
            f"{target} exists but is not writable by uid={os.getuid()}: {exc}. "
            f"Evidence writes would fail at runtime, one record at a time, "
            f"while the service reported healthy.")
    return True, f"evidence store writable: {target}"


def main(argv: list[str] | None = None) -> int:
    quiet = "--quiet" in (argv if argv is not None else sys.argv[1:])

    if settings.evidence_backend == "s3":
        # The store raises its own clear error when the bucket is unset; the
        # useful check here is that the pair was configured together.
        if not settings.evidence_s3_bucket:
            print("Comp-Lens cannot start.\n\n  EVIDENCE_BACKEND=s3 but "
                  "EVIDENCE_S3_BUCKET is not set. Set both, or set the backend "
                  "back to 'local'.", file=sys.stderr)
            return 2
        if not quiet:
            print(f"evidence store: s3://{settings.evidence_s3_bucket}/"
                  f"{settings.evidence_s3_prefix}")
        return 0

    ok, message = check_local_store(settings.evidence_local_path)
    if not ok:
        print(f"Comp-Lens cannot start.\n\n  {message}\n", file=sys.stderr)
        print("Evidence durability is the point of this service, so it will "
              "not serve while evidence cannot be stored.", file=sys.stderr)
        return 1
    if not quiet:
        print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
