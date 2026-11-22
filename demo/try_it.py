"""Type your own memories and see what MemoryGuard does with them.

    python demo/try_it.py                    # server at http://localhost:8000
    python demo/try_it.py http://host:port

It asks for your admin key (or reads MG_ADMIN_KEY), makes a "playground" agent and
one key per source, and revokes those keys again when you quit.

At the prompt:
    <text>             store it as coming from the current source
    4 <text>           store it as coming from source 4 (see the list)
    act                ask whether an action may rely on the last memory
    ask <question>     see what the agent would get back from memory
    sources            show the list of sources again
    quit
"""
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "sdk"))
from memoryguard_sdk import MemoryGuard, MemoryGuardError  # noqa: E402

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
AGENT = "playground"
SOURCES = [
    ("1", "company database", "app_data"),
    ("2", "logged-in user", "user_verified"),
    ("3", "internal tool", "tool_internal"),
    ("4", "web page", "external"),
    ("5", "uploaded document", "document"),
]
VERDICT = {"active": "SAVED", "review": "HELD FOR REVIEW", "quarantined": "BLOCKED"}


def show_sources(trust):
    print("\nWho is saying it?")
    for num, label, st in SOURCES:
        print(f"  {num}  {label:18} trust {trust[st]}")
    print()


def show_memory(m):
    verdict = VERDICT.get(m["status"], m["status"].upper())
    if m["status"] == "active" and m["decision"] == "allow_log":
        verdict = "SAVED (logged as suspicious)"
    print(f"\n  {verdict}")
    print(f"  trust {m['trust_score']}, risk {m['risk_score']}, "
          f"{'CAN' if m['actionable'] else 'cannot'} be used to justify actions")
    for r in m["reasons"]:
        print(f"   - {r}")
    print(f"  id {m['id']}\n")


KEY_FILES = [pathlib.Path(__file__).resolve().parents[1] / "MemoryGuard admin key.txt",
             pathlib.Path(os.path.expanduser("~")) / "Documents" / "MemoryGuard admin key.txt"]


def read_admin_key() -> str:
    """MG_ADMIN_KEY, else the key file (project folder, then Documents), else ask (visible input, since
    hidden prompts often refuse pasting in Windows terminals)."""
    if os.getenv("MG_ADMIN_KEY"):
        return os.environ["MG_ADMIN_KEY"].strip()
    for key_file in KEY_FILES:
        if not key_file.exists():
            continue
        for line in key_file.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("mg_adm_"):
                print(f"Using the admin key from {key_file}")
                return line.strip()
    try:
        return input("Paste your admin key and press Enter: ").strip()
    except (KeyboardInterrupt, EOFError):
        sys.exit("\nCancelled.")


def main():
    admin_key = read_admin_key()
    if not admin_key:
        sys.exit("No key given.")
    admin = MemoryGuard(BASE, admin_key)
    try:
        if admin.whoami()["role"] != "admin":
            sys.exit("That is not an admin key.")
    except MemoryGuardError as e:
        sys.exit(f"Could not sign in: {e.detail}")
    except Exception as e:
        sys.exit(f"Could not reach MemoryGuard at {BASE}. Is the server running? ({e})")

    try:
        admin.create_agent(AGENT, "Playground")
    except MemoryGuardError as e:
        if e.status != 409:
            raise
    trust = admin._r("GET", "/v1/policy")["source_trust"]

    keys, clients = [], {}
    for num, label, st in SOURCES:
        made = admin.create_key(f"try-it-{st}-{os.getpid()}", "agent", st, agent_id=AGENT)
        keys.append(made["id"])
        clients[num] = MemoryGuard(BASE, made["api_key"])

    current, last = "4", None
    print(f"\nMemoryGuard playground ({BASE}). Type 'quit' to stop.")
    show_sources(trust)
    try:
        while True:
            label = next(lab for n, lab, _ in SOURCES if n == current)
            try:
                line = input(f"[{label}] > ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            cmd = line.lower()
            if cmd in ("quit", "exit", "q"):
                break
            if cmd in ("sources", "help", "?"):
                show_sources(trust)
                print(__doc__.split("At the prompt:")[1])
                continue
            if cmd == "act":
                if not last:
                    print("  Store a memory first.\n")
                    continue
                r = clients[current].authorize("refund", [last])
                if r["allowed"]:
                    print("\n  ACTION ALLOWED: the memory is trusted enough.\n")
                else:
                    print(f"\n  ACTION REFUSED: {r['blocked_by'][0]['reason']}\n")
                continue
            if cmd.startswith("ask "):
                r = clients[current].retrieve(line[4:])
                print("\n" + (r["context"] or "  (nothing relevant in memory)") + "\n")
                continue
            if line[:1] in clients and line[1:2] == " ":
                current, line = line[0], line[2:].strip()
                if not line:
                    continue
            try:
                m = clients[current].store(line)
                last = m["id"]
                show_memory(m)
            except MemoryGuardError as e:
                print(f"\n  REFUSED ({e.status}): {e.detail}\n")
    finally:
        for kid in keys:
            try:
                admin.revoke_key(kid)
            except MemoryGuardError:
                pass
        print("Playground keys revoked. Your memories stay visible on the dashboard "
              "under agent 'playground'.")


if __name__ == "__main__":
    main()
