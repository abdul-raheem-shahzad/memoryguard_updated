"""Tamper-evident audit log.

Every entry commits to the one before it:

    entry_hash = sha256(prev_hash || canonical_json(entry))

Editing a row changes its own hash; deleting one breaks the prev_hash link of the
next. Either way `verify()` names the first row that no longer checks out. This
makes edits *detectable*, not impossible -- an attacker with database write access
can still rewrite the whole chain. Export `head()` to an append-only store (or a
transparency log) if you need that gap closed too.
"""
from __future__ import annotations

import hashlib
import json

from datetime import timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import AuditLog, now

GENESIS = "0" * 64


def _ts(dt) -> str:
    """Stable timestamp string. SQLite drops tzinfo on read-back, so everything is
    normalized to naive UTC before hashing."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.isoformat(timespec="microseconds")


def _canonical(seq: int, actor: str, action: str, target: str, meta: dict, created_at) -> str:
    return json.dumps(
        {"seq": seq, "actor": actor, "action": action, "target": target,
         "meta": meta or {}, "created_at": _ts(created_at)},
        sort_keys=True, separators=(",", ":"), default=str)


def _digest(prev_hash: str, seq, actor, action, target, meta, created_at) -> str:
    payload = prev_hash + _canonical(seq, actor, action, target, meta, created_at)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _last(db: Session) -> AuditLog | None:
    return db.scalar(select(AuditLog).where(AuditLog.entry_hash.is_not(None))
                     .order_by(AuditLog.seq.desc()).limit(1))


def append(db: Session, actor: str, action: str, target: str, **meta) -> AuditLog:
    """Add one chained entry. Call inside the caller's transaction; autoflush keeps
    several appends in one request correctly ordered."""
    last = _last(db)
    seq = (last.seq or 0) + 1 if last else 1
    prev = last.entry_hash if last else GENESIS
    created = now()
    row = AuditLog(seq=seq, actor=actor, action=action, target=target, meta=meta,
                   created_at=created, prev_hash=prev,
                   entry_hash=_digest(prev, seq, actor, action, target, meta, created))
    db.add(row)
    return row


def head(db: Session) -> dict:
    last = _last(db)
    return {"seq": last.seq if last else 0, "entry_hash": last.entry_hash if last else GENESIS}


def verify(db: Session) -> dict:
    """Walk the chain. Rows written before the upgrade have no hash; they are
    reported as unverifiable rather than silently passed."""
    rows = list(db.scalars(select(AuditLog).order_by(AuditLog.id)))
    prev, checked, legacy, problems = GENESIS, 0, 0, []
    expected_seq = 0
    for r in rows:
        if r.entry_hash is None:
            legacy += 1
            continue
        expected_seq += 1
        if r.seq != expected_seq:
            problems.append({"id": r.id, "seq": r.seq, "problem": "sequence gap",
                             "detail": f"expected seq {expected_seq}"})
            expected_seq = r.seq or expected_seq
        if r.prev_hash != prev:
            problems.append({"id": r.id, "seq": r.seq, "problem": "broken link",
                             "detail": "an earlier entry was altered or removed"})
        calc = _digest(r.prev_hash or GENESIS, r.seq, r.actor, r.action, r.target,
                       r.meta, r.created_at)
        if calc != r.entry_hash:
            problems.append({"id": r.id, "seq": r.seq, "problem": "entry altered",
                             "detail": "the stored hash does not match this row's contents"})
        prev = r.entry_hash
        checked += 1
    return {"ok": not problems, "entries_checked": checked,
            "unchained_legacy_entries": legacy, "problems": problems,
            "head": head(db)}
