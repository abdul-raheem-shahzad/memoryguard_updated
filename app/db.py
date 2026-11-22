"""Database layer. SQLite by default; set MG_DATABASE_URL for PostgreSQL,
e.g. postgresql+psycopg://user:pass@localhost/memoryguard"""
import os
import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Integer, String, Text,
                        create_engine, inspect, text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

DATABASE_URL = os.getenv("MG_DATABASE_URL", "sqlite:///./memoryguard.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def now() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


class Base(DeclarativeBase):
    pass


class Setting(Base):
    """Server-side values that must survive restarts, e.g. the key-hashing pepper."""
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class ApiKey(Base):
    """A credential. The plaintext key is never stored: only a peppered SHA-256.

    role        agent -> store, read, retrieve, authorize. admin -> also review and operate.
    agent_id    non-null pins the key to one agent; it can touch nothing else.
    source_type the highest source type this key may write as. A caller may declare a
                LOWER-trust type (an agent reading a web page), never a higher one.
    """
    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("key"))
    name: Mapped[str] = mapped_column(String(120))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    preview: Mapped[str] = mapped_column(String(32))
    role: Mapped[str] = mapped_column(String(16), index=True)          # agent | admin
    agent_id: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    source_type: Mapped[str] = mapped_column(String(32))
    rate_limit_per_min: Mapped[int] = mapped_column(Integer, default=600)
    write_limit_per_min: Mapped[int] = mapped_column(Integer, default=120)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


class LoginSession(Base):
    """Dashboard session. The cookie carries a random token; only its hash is stored."""
    __tablename__ = "login_sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ses"))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_id: Mapped[str] = mapped_column(ForeignKey("api_keys.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Memory(Base):
    __tablename__ = "memories"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("mem"))
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), index=True)
    user_id: Mapped[str] = mapped_column(String(128), nullable=True, index=True)
    content: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64))
    source_type: Mapped[str] = mapped_column(String(32))
    source_id: Mapped[str] = mapped_column(String(128), nullable=True)
    declared_trust: Mapped[int] = mapped_column(Integer)
    trust_score: Mapped[int] = mapped_column(Integer)
    risk_score: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), index=True)  # active|review|quarantined|superseded|deleted
    decision: Mapped[str] = mapped_column(String(16))
    signals: Mapped[dict] = mapped_column(JSON, default=dict)
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    facts: Mapped[list] = mapped_column(JSON, default=list)
    version: Mapped[int] = mapped_column(Integer, default=1)
    written_by_key: Mapped[str] = mapped_column(String(32), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class MemoryLink(Base):
    """Provenance edge: parent memory -> derived memory."""
    __tablename__ = "memory_links"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    parent_id: Mapped[str] = mapped_column(ForeignKey("memories.id"), index=True)
    child_id: Mapped[str] = mapped_column(ForeignKey("memories.id"), index=True)


class MemoryVersion(Base):
    __tablename__ = "memory_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    memory_id: Mapped[str] = mapped_column(ForeignKey("memories.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    content: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64))
    changed_by: Mapped[str] = mapped_column(String(64))
    change_reason: Mapped[str] = mapped_column(String(300), default="")
    risk_score: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16))
    # who wrote this text, so a rollback scores it at the writer's trust (null on legacy rows)
    source_type: Mapped[str] = mapped_column(String(32), nullable=True)
    written_by_key: Mapped[str] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    memory_id: Mapped[str] = mapped_column(String(32), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(10))
    description: Mapped[str] = mapped_column(Text)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditLog(Base):
    """Append-only, hash-chained. Each row commits to the one before it, so editing
    or deleting any row breaks every hash after it (see app/audit.py)."""
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    seq: Mapped[int] = mapped_column(Integer, nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(40))
    target: Mapped[str] = mapped_column(String(64))
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


# --------------------------------------------------------------- tiny migration
# Enough to upgrade a v0.1 SQLite file in place. Anything more structural should
# move to Alembic (roadmap 0.4).
_ADDED_COLUMNS = {
    "audit_logs": {"seq": "INTEGER", "prev_hash": "VARCHAR(64)", "entry_hash": "VARCHAR(64)"},
    "memories": {"written_by_key": "VARCHAR(32)"},
    "memory_versions": {"source_type": "VARCHAR(32)", "written_by_key": "VARCHAR(32)"},
}


def _add_missing_columns():
    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table, cols in _ADDED_COLUMNS.items():
            if table not in existing_tables:
                continue
            have = {c["name"] for c in insp.get_columns(table)}
            for col, ddl in cols.items():
                if col not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))


def init_db():
    _add_missing_columns()
    Base.metadata.create_all(engine)
