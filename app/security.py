"""Authentication, authorization and rate limiting.

Three rules this module exists to enforce:

1. A caller never picks its own trust level. The source type comes from the API
   key. A caller may declare a LOWER-trust type than its key allows (an agent
   ingesting a web page under a tool key) but never a higher one.
2. Roles are separated. An agent key can store, read, retrieve and ask for
   authorization. Only an admin key can quarantine, restore, roll back, delete,
   create agents or mint keys, so a compromised agent cannot release its own poison.
3. Keys are stored hashed, scoped to one agent, and rate limited.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import timedelta

from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import ApiKey, LoginSession, Setting, SessionLocal, now

SESSION_COOKIE = "mg_session"
SESSION_HOURS = int(os.getenv("MG_SESSION_HOURS", "8"))
COOKIE_SECURE = os.getenv("MG_COOKIE_SECURE", "0") == "1"

ROLES = ("agent", "admin")
SCOPES = {
    # agent keys: write memories, read their own agent, retrieve, ask permission
    "agent": {"memory:write", "memory:read", "retrieve", "authorize"},
    # admin keys: everything, including the review actions an agent must not have
    "admin": {"memory:write", "memory:read", "retrieve", "authorize", "review", "admin"},
}


# ---------------------------------------------------------------- key hashing
def _pepper(db: Session) -> str:
    """Server-side pepper for key hashing. From MG_SECRET, else generated once
    and stored. Rotating it invalidates every issued key."""
    env = os.getenv("MG_SECRET")
    if env:
        return env
    row = db.get(Setting, "key_pepper")
    if row is None:
        row = Setting(key="key_pepper", value=secrets.token_hex(32))
        db.add(row)
        db.commit()
    return row.value


def hash_key(db: Session, raw: str) -> str:
    return hmac.new(_pepper(db).encode(), raw.encode(), hashlib.sha256).hexdigest()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_key(role: str) -> str:
    return f"mg_{'adm' if role == 'admin' else 'agt'}_{secrets.token_urlsafe(32)}"


def preview_of(raw: str) -> str:
    return f"{raw[:10]}…{raw[-4:]}" if len(raw) > 18 else "…"


def create_key(db: Session, *, name: str, role: str, source_type: str,
               agent_id: str | None = None, rate_limit_per_min: int = 600,
               write_limit_per_min: int = 120, raw: str | None = None) -> tuple[ApiKey, str]:
    """Returns (record, plaintext). The plaintext is shown once and never stored."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    raw = raw or generate_key(role)
    rec = ApiKey(name=name, role=role, source_type=source_type, agent_id=agent_id,
                 key_hash=hash_key(db, raw), preview=preview_of(raw),
                 rate_limit_per_min=rate_limit_per_min, write_limit_per_min=write_limit_per_min)
    db.add(rec)
    db.commit()
    return rec, raw


# ---------------------------------------------------------------- rate limiting
class SlidingWindow:
    """Per-key request counter over a 60 s window. In-process: correct for one
    worker, approximate behind several. Move to Redis before scaling out."""

    def __init__(self, window: float = 60.0):
        self.window = window
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int) -> tuple[bool, int]:
        """(allowed, retry_after_seconds)."""
        if limit <= 0:
            return True, 0
        t = time.monotonic()
        with self._lock:
            q = self._hits.setdefault(key, deque())
            cutoff = t - self.window
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= limit:
                return False, max(1, int(self.window - (t - q[0])) + 1)
            q.append(t)
            return True, 0

    def reset(self, key: str | None = None):
        with self._lock:
            self._hits.pop(key, None) if key else self._hits.clear()


REQUESTS = SlidingWindow()
WRITES = SlidingWindow()
FAILED_AUTH = SlidingWindow()
FAILED_AUTH_LIMIT = int(os.getenv("MG_FAILED_AUTH_PER_MIN", "20"))


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------- principal
@dataclass
class Principal:
    key_id: str
    name: str
    role: str
    agent_id: str | None          # None = every agent (admin)
    source_type: str              # the highest source type this key may write as
    rate_limit: int
    write_limit: int
    via: str                      # api_key | session

    @property
    def actor(self) -> str:
        return f"{self.role}:{self.name}"

    def has(self, scope: str) -> bool:
        return scope in SCOPES.get(self.role, set())


def _db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def lookup_key(db: Session, raw: str) -> ApiKey | None:
    raw = raw.strip()          # a pasted key often carries a trailing space or newline
    if not raw:
        return None
    digest = hash_key(db, raw)
    rec = db.scalar(select(ApiKey).where(ApiKey.key_hash == digest))
    if rec is None or not rec.active:
        return None
    # constant-time compare even though the lookup was by hash
    return rec if hmac.compare_digest(rec.key_hash, digest) else None


def _from_session(db: Session, token: str) -> ApiKey | None:
    ses = db.scalar(select(LoginSession).where(LoginSession.token_hash == hash_token(token)))
    if ses is None:
        return None
    expires = ses.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=now().tzinfo)
    if expires < now():
        db.delete(ses)
        db.commit()
        return None
    rec = db.get(ApiKey, ses.key_id)
    if rec is None or not rec.active:
        return None
    ses.last_seen_at = now()
    db.commit()
    return rec


def current_principal(request: Request,
                      x_api_key: str = Header(default=""),
                      mg_session: str = Cookie(default=""),
                      db: Session = Depends(_db)) -> Principal:
    ip = _client_ip(request)
    rec, via = None, "api_key"
    if x_api_key:
        rec = lookup_key(db, x_api_key)
    elif mg_session:
        rec, via = _from_session(db, mg_session), "session"

    if rec is None:
        ok, retry = FAILED_AUTH.hit(f"ip:{ip}", FAILED_AUTH_LIMIT)
        if not ok:
            raise HTTPException(429, "Too many failed authentication attempts",
                                headers={"Retry-After": str(retry)})
        raise HTTPException(401, "Missing or invalid credentials",
                            headers={"WWW-Authenticate": "X-API-Key"})

    p = Principal(key_id=rec.id, name=rec.name, role=rec.role, agent_id=rec.agent_id,
                  source_type=rec.source_type, rate_limit=rec.rate_limit_per_min,
                  write_limit=rec.write_limit_per_min, via=via)
    ok, retry = REQUESTS.hit(p.key_id, p.rate_limit)
    if not ok:
        raise HTTPException(429, f"Rate limit exceeded ({p.rate_limit} requests/min for this key)",
                            headers={"Retry-After": str(retry)})
    rec.last_used_at = now()
    db.commit()
    return p


def require(scope: str):
    """Dependency factory. Use as: p: Principal = Depends(require("review"))."""
    def dep(p: Principal = Depends(current_principal)) -> Principal:
        if not p.has(scope):
            raise HTTPException(403, f"This key's role ({p.role}) is not allowed to {scope}. "
                                     "Review actions require an admin key.")
        return p
    return dep


def require_write(scope: str = "memory:write"):
    """Like require(), plus the stricter per-key write budget."""
    def dep(p: Principal = Depends(require(scope))) -> Principal:
        ok, retry = WRITES.hit(p.key_id, p.write_limit)
        if not ok:
            raise HTTPException(429, f"Write rate limit exceeded ({p.write_limit} writes/min "
                                     "for this key)", headers={"Retry-After": str(retry)})
        return p
    return dep


# ---------------------------------------------------------------- scoping
def scope_agent(p: Principal, agent_id: str | None) -> str | None:
    """Agent keys may only ever touch their own agent."""
    if p.agent_id is None:
        return agent_id
    if agent_id is not None and agent_id != p.agent_id:
        raise HTTPException(403, f"This key is scoped to agent '{p.agent_id}'")
    return p.agent_id


def resolve_source_type(p: Principal, requested: str | None, policy: dict) -> tuple[str, bool]:
    """Bind the source type to the key. Returns (source_type, escalation_attempted).

    The key's source_type is a ceiling, not a label: a caller may declare a
    lower-trust type but a request for anything more trusted is refused.
    """
    table = policy["source_trust"]
    ceiling = p.source_type
    if ceiling not in table:
        raise HTTPException(500, f"Key {p.key_id} is bound to unknown source_type '{ceiling}'")
    if requested is None or requested == ceiling:
        return ceiling, False
    if requested not in table:
        raise HTTPException(422, f"unknown source_type '{requested}'. Allowed: {sorted(table)}")
    if int(table[requested]) > int(table[ceiling]):
        return ceiling, True
    return requested, False


def new_session(db: Session, key_id: str) -> str:
    token = secrets.token_urlsafe(32)
    db.add(LoginSession(token_hash=hash_token(token), key_id=key_id,
                        expires_at=now() + timedelta(hours=SESSION_HOURS)))
    db.commit()
    return token


def end_session(db: Session, token: str):
    ses = db.scalar(select(LoginSession).where(LoginSession.token_hash == hash_token(token)))
    if ses:
        db.delete(ses)
        db.commit()


# ---------------------------------------------------------------- bootstrap
def bootstrap_admin_key() -> str | None:
    """Make sure one admin key exists. Returns the plaintext when it had to be
    created, so the caller can print it once. MG_ADMIN_KEY (or the legacy
    MG_API_KEY) pins the value; otherwise it is random."""
    db = SessionLocal()
    try:
        if db.scalar(select(ApiKey).where(ApiKey.role == "admin", ApiKey.active.is_(True))):
            return None
        # keys never contain whitespace; strip what a file or a .bat may leave behind
        raw = (os.getenv("MG_ADMIN_KEY") or os.getenv("MG_API_KEY") or "").strip() or None
        if raw and db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_key(db, raw))):
            # the pinned key exists but was revoked: never silently bring it back
            raise RuntimeError(
                "MG_ADMIN_KEY names an admin key that was revoked, and no other admin key is "
                "active. Unset MG_ADMIN_KEY to get a new key printed once, or run "
                "'python -m app.manage rotate-admin --yes'.")
        _, raw = create_key(db, name="bootstrap-admin", role="admin", source_type="system",
                            agent_id=None, raw=raw)
        return raw
    finally:
        db.close()
