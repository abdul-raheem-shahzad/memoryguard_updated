"""Key and audit management from the command line.

    python -m app.manage bootstrap
    python -m app.manage create-key --name support --role agent --agent-id support-bot \
                                    --source-type tool_internal
    python -m app.manage list-keys
    python -m app.manage revoke-key key_abc123
    python -m app.manage rotate-admin
    python -m app.manage verify-audit
"""
import argparse
import json
import sys

from sqlalchemy import delete, select

from . import audit, engine as eng, security as sec
from .db import Agent, ApiKey, LoginSession, SessionLocal, init_db, now


KEY_FILE_HEADER = (
    "MemoryGuard admin key (your one permanent key)\n\n"
    "Use it to sign in at http://localhost:8000. The playground, live test and\n"
    "run_windows.bat read it from this file automatically.\n\n"
    "WARNING: anyone who has this file is the admin. Before you zip, upload, email or\n"
    "share this project folder, MOVE THIS FILE OUT of it first.\n\n"
    "Do NOT run rotate-admin unless this key was leaked: it replaces the key.\n\n")


def _rows(keys):
    for k in keys:
        scope = k.agent_id or "all agents"
        print(f"{k.id:18} {k.role:6} {scope:16} writes as {k.source_type:14} "
              f"{k.preview:20} {'active' if k.active else 'revoked'}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="app.manage")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("bootstrap", help="create the first admin key if none exists")
    b.add_argument("--save", metavar="FILE", default=None,
                   help="write a newly created key into FILE (with a warning header) "
                        "instead of printing it")

    c = sub.add_parser("create-key")
    c.add_argument("--name", required=True)
    c.add_argument("--role", choices=["agent", "admin"], default="agent")
    c.add_argument("--agent-id", default=None)
    c.add_argument("--source-type", required=True,
                   help="the highest source type this key may write as")
    c.add_argument("--rate-limit", type=int, default=600)
    c.add_argument("--write-limit", type=int, default=120)

    sub.add_parser("list-keys")
    r = sub.add_parser("revoke-key")
    r.add_argument("key_id")
    ra = sub.add_parser("rotate-admin",
                        help="REPLACE the admin key: mint a new one and revoke every other "
                             "(only if the current key is lost or leaked; needs --yes)")
    ra.add_argument("--yes", action="store_true",
                    help="confirm: the current admin key will stop working")
    sub.add_parser("verify-audit")

    a = ap.parse_args(argv)
    init_db()
    db = SessionLocal()
    try:
        if a.cmd == "bootstrap":
            raw = sec.bootstrap_admin_key()
            if not raw:
                print("An admin key already exists. Nothing to do.")
                return 0
            if a.save:
                with open(a.save, "w", encoding="utf-8", newline="\r\n") as f:
                    f.write(KEY_FILE_HEADER + raw + "\n")
                print(f"Created your admin key and saved it in: {a.save}")
                return 0
            print(raw)
            return 0

        if a.cmd == "create-key":
            policy = eng.load_policy()
            if a.source_type not in policy["source_trust"]:
                print(f"unknown source type. Allowed: {sorted(policy['source_trust'])}",
                      file=sys.stderr)
                return 2
            if a.role == "agent" and not a.agent_id:
                print("agent keys must be scoped with --agent-id", file=sys.stderr)
                return 2
            if a.agent_id and not db.get(Agent, a.agent_id):
                print(f"agent '{a.agent_id}' does not exist yet", file=sys.stderr)
                return 2
            rec, raw = sec.create_key(db, name=a.name, role=a.role, source_type=a.source_type,
                                      agent_id=a.agent_id, rate_limit_per_min=a.rate_limit,
                                      write_limit_per_min=a.write_limit)
            audit.append(db, "cli", "create_key", rec.id, role=rec.role,
                         agent_id=rec.agent_id, source_type=rec.source_type)
            db.commit()
            print(raw)
            print("Copy it now: only its hash is stored.", file=sys.stderr)
            return 0

        if a.cmd == "list-keys":
            _rows(db.scalars(select(ApiKey).order_by(ApiKey.created_at)))
            return 0

        if a.cmd == "revoke-key":
            k = db.get(ApiKey, a.key_id)
            if not k:
                print("no such key", file=sys.stderr)
                return 2
            k.active, k.revoked_at = False, now()
            db.execute(delete(LoginSession).where(LoginSession.key_id == k.id))
            audit.append(db, "cli", "revoke_key", k.id)
            db.commit()
            print(f"revoked {k.id}")
            return 0

        if a.cmd == "rotate-admin":
            if not a.yes:
                print("Not done. rotate-admin REPLACES your admin key: the key you use now "
                      "stops working everywhere.\nOnly do this if the key is lost or someone "
                      "else has seen it. To go ahead:\n"
                      "    python -m app.manage rotate-admin --yes", file=sys.stderr)
                return 2
            old = list(db.scalars(select(ApiKey).where(ApiKey.role == "admin",
                                                       ApiKey.active.is_(True))))
            rec, raw = sec.create_key(db, name=f"admin-{now():%Y%m%d-%H%M%S}", role="admin",
                                      source_type="system", agent_id=None)
            for k in old:
                k.active, k.revoked_at = False, now()
            ids = [k.id for k in old]
            if ids:
                db.execute(delete(LoginSession).where(LoginSession.key_id.in_(ids)))
            audit.append(db, "cli", "rotate_admin", rec.id, revoked=ids)
            db.commit()
            print(raw)
            print(f"New admin key {rec.id}. Revoked {len(ids)} old admin key(s) and signed out "
                  "their dashboard sessions. Copy the key now: only its hash is stored. "
                  "Do not save it in the project folder.", file=sys.stderr)
            return 0

        if a.cmd == "verify-audit":
            result = audit.verify(db)
            print(json.dumps(result, indent=2))
            return 0 if result["ok"] else 1
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
