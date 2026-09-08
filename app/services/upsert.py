"""Insert a row that may already exist, without losing the race.

Six places in this codebase do the same thing: SELECT a row, branch on whether
it came back, and INSERT if it did not. Between that SELECT and that INSERT
another worker can insert the same row — a scheduled connector sync overlapping
a manual one, two operators uploading the same document, two policy runs
materialising the same posture cell.

The good news, established by checking rather than assuming: **every one of
those tables carries a UNIQUE constraint on exactly the key being upserted** —
`uq_sync_tenant_connector`, `uq_evidence_doc_hash`, the Posture tuple. So a
lost race has never corrupted data; the database refuses the second INSERT.

The bad news is what happens next. Nothing caught the refusal, so a race
surfaced as an unhandled IntegrityError — an HTTP 500 for an operation that
actually succeeded, just not in this transaction. The caller sees a failure and
retries, and the retry usually works, which is the most confusing possible
symptom.

`get_or_create` closes that: try the insert inside a SAVEPOINT, and if the
constraint rejects it, roll back to the savepoint and read the row the winner
wrote. The savepoint matters — without it the failed INSERT poisons the whole
transaction and everything already done in it is lost.

`app/services/assessment.py` already does this by hand for findings, and is
left alone: it needs to return the winning Finding rather than a generic row,
and rewriting a correct, well-commented race handler to share this helper would
be churn against working code.
"""
from __future__ import annotations

from typing import Any, TypeVar

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

T = TypeVar("T")


def get_or_create(db: Session, model: type[T], *, match: dict[str, Any],
                  defaults: dict[str, Any] | None = None) -> tuple[T, bool]:
    """Return `(row, created)` for the row identified by `match`.

    `match` must name the columns a UNIQUE constraint covers — otherwise a race
    inserts a duplicate rather than being refused, and this helper cannot tell.
    `defaults` are applied only when the row is created.
    """
    stmt = select(model)
    for column, value in match.items():
        stmt = stmt.where(getattr(model, column) == value)

    row = db.execute(stmt).scalars().first()
    if row is not None:
        return row, False

    row = model(**{**match, **(defaults or {})})
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
        return row, True
    except IntegrityError:
        # Someone else inserted it between our SELECT and our INSERT. The
        # savepoint has rolled back only the failed statement, so the rest of
        # this transaction is intact and the winner's row is now readable.
        db.expunge(row)
        winner = db.execute(stmt).scalars().first()
        if winner is None:
            # The constraint rejected the insert but no matching row exists, so
            # the violation was something other than the race this handles —
            # a different constraint on the same table. Do not swallow it.
            raise
        return winner, False
