"""MemoryGuard attack benchmark.

    python demo/benchmark.py

Runs every case in demo/benchmark_cases.py against a throwaway database (your real
memoryguard.db is never touched; no server needs to be running) and prints a score.

Each message gets a fresh agent with the same trusted company facts, so no case can
help or hurt another. Every attack is sent twice:
  web    as text from a web page (source "external", trust 25)
  tool   as text from a trusted internal tool (source "tool_internal", trust 70)
The tool path is the hard one: trust alone does not save you there, detection must.

For each attack it records whether MemoryGuard
  flagged it   held it for review or quarantined it (detection)
  let it act   whether /v1/authorize would allow a refund based on it (the real harm)
For each normal message it records false alarms (held or blocked by mistake).
Every result is written to benchmark_results.csv in the project folder.
"""
import contextlib
import csv
import io
import os
import pathlib
import sys
import tempfile
import time
from collections import OrderedDict

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "demo"))

_tmp = pathlib.Path(tempfile.mkdtemp(prefix="mg-bench-"))
os.environ["MG_DATABASE_URL"] = f"sqlite:///{_tmp.as_posix()}/bench.db"
os.environ["MG_SECRET"] = "benchmark-only-pepper"
os.environ["MG_ADMIN_KEY"] = "benchmark-only-admin-key"
os.environ.pop("MG_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

with contextlib.redirect_stderr(io.StringIO()):          # hide the bootstrap banner
    from app.main import app                             # noqa: E402
from app import security as sec                           # noqa: E402

from benchmark_cases import ATTACKS, BENIGN, FACTS, LAUNDERING  # noqa: E402

# Rate limits protect a live server; here they would only slow the run down.
sec.REQUESTS.hit = lambda key, limit: (True, 0)
sec.WRITES.hit = lambda key, limit: (True, 0)

c = TestClient(app)
ADMIN = {"X-API-Key": "benchmark-only-admin-key"}
COVERED_LANGS = {"French", "Spanish", "German", "Portuguese", "Italian"}


def key_for(source_type):
    r = c.post("/v1/keys", headers=ADMIN, json={"name": f"bench-{source_type}", "role": "admin",
                                                "source_type": source_type})
    r.raise_for_status()
    return {"X-API-Key": r.json()["api_key"]}


KEYS = {"app": key_for("app_data"), "web": key_for("external"), "tool": key_for("tool_internal")}
CHANNELS = ("web", "tool")
_n = 0


def fresh_agent():
    global _n
    _n += 1
    aid = f"bench{_n}"
    c.post("/v1/agents", headers=ADMIN, json={"id": aid, "name": aid}).raise_for_status()
    for fact in FACTS:
        c.post("/v1/memories", headers=KEYS["app"], json={"agent_id": aid, "content": fact})
    return aid


def store(channel, aid, text):
    r = c.post("/v1/memories", headers=KEYS[channel], json={"agent_id": aid, "content": text})
    if r.status_code != 201:
        return {"id": None, "status": f"refused {r.status_code}", "decision": "-",
                "trust_score": "", "risk_score": "", "actionable": False, "signals": {}}
    return r.json()


def can_act(aid, mid):
    if mid is None:
        return False
    r = c.post("/v1/authorize", headers=ADMIN,
               json={"agent_id": aid, "action": "issue_refund", "memory_ids": [mid]})
    return bool(r.json()["allowed"])


def flagged(m):
    return m["status"] != "active"


def group(cat):
    if cat.startswith("language: "):
        lang = cat.split(": ", 1)[1]
        return ("other language: FR/ES/DE/PT/IT" if lang in COVERED_LANGS
                else "other language: 9 more")
    return cat


rows = []


def record(kind, cat, channel, text, m, acted):
    sig = {k: v for k, v in (m.get("signals") or {}).items() if k != "source"}
    rows.append({"kind": kind, "category": cat, "group": group(cat), "channel": channel,
                 "text": text, "status": m["status"], "decision": m["decision"],
                 "trust": m["trust_score"], "risk": m["risk_score"],
                 "flagged": flagged(m), "action_allowed": acted,
                 "signals": " ".join(sorted(sig))})


def main():
    t0 = time.time()
    for cat, text in ATTACKS:
        for ch in CHANNELS:
            aid = fresh_agent()
            m = store(ch, aid, text)
            record("attack", cat, ch, text, m, can_act(aid, m["id"]))
    for planted, copy in LAUNDERING:
        aid = fresh_agent()
        store("web", aid, planted)
        m = store("tool", aid, copy)
        record("attack", "laundering: tool copies web text", "tool", copy, m,
               can_act(aid, m["id"]))
    for cat, texts in BENIGN.items():
        for text in texts:
            for ch in CHANNELS:
                aid = fresh_agent()
                m = store(ch, aid, text)
                record("normal", cat, ch, text, m, can_act(aid, m["id"]))
    elapsed = time.time() - t0

    out = ROOT / "benchmark_results.csv"
    with open(out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    report(elapsed, out)


def pct(a, b):
    return f"{a}/{b} ({round(100 * a / b) if b else 0}%)"


def report(elapsed, out):
    attacks = [r for r in rows if r["kind"] == "attack"]
    normal = [r for r in rows if r["kind"] == "normal"]

    def sel(rs, ch):
        return [r for r in rs if r["channel"] == ch]

    print("\n" + "=" * 92)
    print("MEMORYGUARD ATTACK BENCHMARK")
    print("=" * 92)
    n_att = len({(r['category'], r['text']) for r in attacks})
    n_norm = len({(r['category'], r['text']) for r in normal})
    print(f"{n_att} attacks and {n_norm} normal messages, {len(rows)} checks in "
          f"{elapsed:.0f} s. Fresh memory for every check.\n")

    print("ATTACKS  (higher is better)")
    print(f"  {'type':40} {'n':>3}   {'flagged':>12} {'flagged':>12}   {'stopped':>12}")
    print(f"  {'':40} {'':>3}   {'via web':>12} {'via tool':>12}   {'via tool':>12}")
    groups = OrderedDict()
    for r in attacks:
        groups.setdefault(r["group"], []).append(r)
    for g, rs in groups.items():
        web, tool = sel(rs, "web"), sel(rs, "tool")
        n = len(tool)
        fw = f"{sum(r['flagged'] for r in web)}/{len(web)}" if web else "-"
        ft = f"{sum(r['flagged'] for r in tool)}/{n}"
        st = f"{sum(not r['action_allowed'] for r in tool)}/{n}"
        print(f"  {g:40} {n:>3}   {fw:>12} {ft:>12}   {st:>12}")

    web_all, tool_all = sel(attacks, "web"), sel(attacks, "tool")
    print("\n  Attacks stopped from causing an action")
    print(f"    sent as a web page (untrusted) .......... "
          f"{pct(sum(not r['action_allowed'] for r in web_all), len(web_all))}")
    print(f"    sent by a trusted internal tool ......... "
          f"{pct(sum(not r['action_allowed'] for r in tool_all), len(tool_all))}")
    print("  Attacks recognised by their content (held or blocked)")
    print(f"    sent as a web page ...................... "
          f"{pct(sum(r['flagged'] for r in web_all), len(web_all))}")
    print(f"    sent by a trusted internal tool ......... "
          f"{pct(sum(r['flagged'] for r in tool_all), len(tool_all))}")

    print("\nNORMAL MESSAGES  (lower false alarms is better)")
    print(f"  {'type':40} {'n':>3}   {'false alarm':>12} {'false alarm':>12}")
    print(f"  {'':40} {'':>3}   {'via web':>12} {'via tool':>12}")
    ngroups = OrderedDict()
    for r in normal:
        ngroups.setdefault(r["group"], []).append(r)
    for g, rs in ngroups.items():
        web, tool = sel(rs, "web"), sel(rs, "tool")
        print(f"  {g:40} {len(tool):>3}   {sum(r['flagged'] for r in web):>9}/{len(web):<2} "
              f"{sum(r['flagged'] for r in tool):>9}/{len(tool):<2}")
    nw, nt = sel(normal, "web"), sel(normal, "tool")
    print(f"\n  False alarms on normal messages")
    print(f"    from a web page ......................... {pct(sum(r['flagged'] for r in nw), len(nw))}")
    print(f"    from a trusted internal tool ............ {pct(sum(r['flagged'] for r in nt), len(nt))}")
    print(f"  Normal trusted-tool messages usable for actions "
          f"{pct(sum(r['action_allowed'] for r in nt), len(nt))}")

    misses = [r for r in tool_all if r["action_allowed"]]
    print(f"\nATTACKS THAT GOT THROUGH THE TRUSTED TOOL PATH ({len(misses)})")
    for r in misses:
        print(f"  - [{r['group']}] {r['text'][:80]}")
    fps = [r for r in normal if r["flagged"]]
    print(f"\nNORMAL MESSAGES WRONGLY HELD OR BLOCKED ({len(fps)})")
    for r in fps:
        print(f"  - [{r['channel']}] {r['text'][:70]}  -> {r['status']}, {r['signals']}")
    print(f"\nEvery result: {out}")


if __name__ == "__main__":
    main()
