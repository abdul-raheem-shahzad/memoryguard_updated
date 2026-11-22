# MemoryGuard v0.2

Security layer between an AI agent and its persistent memory.
Every write is analyzed, scored, and allowed, sent to review, or quarantined.
Every action an agent takes can be checked against the trust of the memories behind it.

> Working name. OWASP's Agent Memory Guard already ships a class called `MemoryGuard`. Rename before any public release.

## What changed in 0.2

v0.1 had two holes that let an attacker walk around the whole system. Both are closed.

| v0.1 | v0.2 |
|---|---|
| The caller chose its own `source_type`, so poison could arrive labelled `system` | The source type comes from the API key. A caller may declare a **lower**-trust type, never a higher one; attempts are refused and logged as `source_type_escalation_attempt` |
| One key did everything, so a compromised agent could restore its own quarantine | Two roles. Agent keys store, read, retrieve and ask for authorization. Only admin keys quarantine, restore, roll back, delete, create agents or mint keys |
| Plain shared key, key typed into the dashboard | Keys are hashed (HMAC-SHA-256 with a server pepper), scoped to one agent, revocable; the console logs in for a `HttpOnly` session cookie |
| Audit rows could be edited or removed silently | Each row hash-chains to the previous one. `GET /v1/audit/verify` names the first row that no longer checks out |
| No limits | Per-key request and write budgets, plus failed-auth throttling by IP |

### 0.2.1 security fixes
- An agent key can no longer `PUT` a memory that is quarantined, under review or superseded,
  so it cannot undo a human's quarantine. It also cannot overwrite a memory more trusted than
  itself. Both attempts are refused and logged as `update_denied`.
- An update now relabels the memory with the writer's source type, and rollback scores old text
  at the trust of whoever wrote that version, so re-analysis cannot restore a higher label.
- Nothing a key writes starts above that key's own trust level, including an `agent_generated`
  memory whose parents are more trusted than the key.
- Grounding raises trust only when every sentence in the memory is a confirmed fact. One true
  sentence no longer carries the rest of a web page up to an actionable level.
- `authorize` with no memory IDs is refused.
- Laundering closed for copies: a trusted key that relays untrusted text without `parent_ids` gets
  the source's trust (quarantined if the source is held), and is linked to it so quarantining the
  source cascades.
- The MCP server requires its own token and binds to `127.0.0.1` by default.
- `run_windows.bat` no longer writes the admin key to `admin_key.txt`; `manage rotate-admin` added.
- Detectors also run on de-obfuscated views of the text: Cyrillic/Greek look-alike letters mapped
  to Latin, spaced-out letters joined, base64 decoded. Words mixing scripts raise `obfuscation`.
- New patterns: "promoted to administrator", "superadmin", standing forwards to a bare domain,
  the override phrase in French/Spanish/German/Portuguese/Italian, and "Key: value" claims
  checked against ground truth. "system prompt" no longer trips `fake_system` when it is only
  mentioned. The red-team probes live in `tests/test_adversarial_probes.py`.

### Benchmark
`python demo/benchmark.py` runs 164 attacks and 105 normal messages (`demo/benchmark_cases.py`)
against a throwaway database and writes every result to `benchmark_results.csv`. Current score:

| | Result |
|---|---|
| Attacks from an untrusted source stopped from causing an action | 154/154 (100%) |
| Attacks through a trusted tool stopped from causing an action | 131/164 (80%) |
| Normal messages wrongly held or blocked | 0/210 (0%) |

What still gets through the trusted path: paraphrased attacks with no keywords (20), languages
without patterns (9), and a few odd wordings. That is the 0.3 work.

Since this benchmark, any memory that matches an attack pattern can never justify an action,
even from a trusted source (`flagged_max_trust` in policy.yaml, default one below
`actionable_trust`). Trade-off: a verified user's own standing rule such as "always send weekly
reports to me@acme.com" is still saved, but cannot authorise an action on its own.

## Run
    pip install -r requirements.txt
    uvicorn app.main:app --reload       # prints an admin key once, on first start
    python demo/seed.py http://localhost:8000 <admin key>
    open http://localhost:8000          # sign in with that key; API docs at /docs
    pytest -q                           # 108 tests; 3 xfail mark known detection limits

Pin the admin key instead of having one generated: `MG_ADMIN_KEY=... uvicorn app.main:app`
(`MG_API_KEY` from v0.1 is still honoured, and becomes an admin key).

PostgreSQL: `MG_DATABASE_URL=postgresql+psycopg://user:pass@host/db` (install `psycopg[binary]`).
A v0.1 SQLite file upgrades in place; rows written before the upgrade are reported as
`unchained_legacy_entries` by the verifier rather than passed as valid.

### Keys
    python -m app.manage bootstrap
    python -m app.manage create-key --name support-web --role agent \
                                    --agent-id support-bot --source-type external
    python -m app.manage list-keys
    python -m app.manage revoke-key key_abc123
    python -m app.manage rotate-admin --yes  # REPLACES the admin key (only if leaked); needs --yes
    python -m app.manage verify-audit

One permanent admin key: it lives in `MemoryGuard admin key.txt` in this folder.
`run_windows.bat` pins it as `MG_ADMIN_KEY`, so even a fresh database recreates the same
key, and `demo/try_it.py` and `demo/setup_live_test.py` read it from there.

**Move that file out before you zip, upload or share this folder.** The database holds the
key-hashing pepper unless `MG_SECRET` is set, so a copy of the folder that still contains
the key file is full admin access.

Mint one key per trust level an agent actually has: a `tool_internal` key for its own
tools, an `external` key for whatever it reads off the web. The web-reading path then
*cannot* produce a trusted memory, whatever the page says.

### Environment
| Variable | Default | Meaning |
|---|---|---|
| `MG_DATABASE_URL` | `sqlite:///./memoryguard.db` | database |
| `MG_ADMIN_KEY` / `MG_API_KEY` | generated | pins the bootstrap admin key |
| `MG_SECRET` | generated and stored | pepper for key hashing; changing it invalidates every key |
| `MG_SESSION_HOURS` | `8` | dashboard session lifetime |
| `MG_COOKIE_SECURE` | `0` | set to `1` behind HTTPS |
| `MG_FAILED_AUTH_PER_MIN` | `20` | failed auth attempts per IP per minute |

## Integrate
    from memoryguard_sdk import MemoryGuard
    mg   = MemoryGuard("http://localhost:8000", agent_key)   # key fixes agent and source type
    page = mg.store(web_text, source_id=url)                 # written as the key's source type
    note = mg.store(summary, source_type="agent_generated", parent_ids=[page["id"]])
    ctx  = mg.retrieve(user_question)["context"]             # untrusted items are fenced
    ok   = mg.authorize("send_email", [note["id"]])          # gate before any tool call

## MCP server (any agent framework)

`app/mcp_server.py` exposes MemoryGuard as Model Context Protocol tools -- `store`,
`retrieve`, `authorize`, `get_report` -- over Streamable HTTP, so Copilot Studio,
Azure AI Foundry, Semantic Kernel, VS Code or Claude can put their memory behind
the guard with no bespoke code. It is a thin layer: it forwards to the API using
one scoped **agent** key, so every rule (source binding, no review/admin tools,
rate limits) still holds through MCP.

    python -m app.manage create-key --role agent --agent-id support-bot \
                                     --source-type tool_internal
    export MG_MCP_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
    MG_BASE_URL=http://localhost:8000 MG_MCP_KEY=<that key> python -m app.mcp_server
    # serves http://127.0.0.1:8765/mcp; clients send Authorization: Bearer $MG_MCP_TOKEN

The MCP endpoint has its own credential. The server will not start without
`MG_MCP_TOKEN` and answers 401 to any request that lacks it, so a tunnel or an
exposed port does not hand the agent key to whoever finds it. It binds to
`127.0.0.1` unless `MG_MCP_HOST` is set. Needs `mcp` 1.x (`mcp>=1.8,<2`).

See `COPILOT_STUDIO.md` for the full Copilot Studio wiring and demo script.

## How decisions are made
| Step | Rule |
|---|---|
| Source | Taken from the API key. A request may name a lower-trust type; a higher one is refused. |
| Trust | From the source type (policy.yaml). A derived memory never exceeds its least trusted parent. |
| Detectors | Rules: instruction override, fake system text, privilege claims, exfiltration, concealment. |
| Facts | "X is Y" statements are checked against ground truth and existing memories. Role increases are flagged. |
| Tampering | An update by a lower-trust source raises risk. |
| Risk | `max(threat signals) * (0.6 + 0.4 * distrust)`; no threat -> `0.3 * distrust`. |
| Decision | <30 allow, <60 allow+log, <80 review, >=80 quarantine. Tainted lineage always quarantines. |
| Action gate | Only active memories with trust >= 70 can justify an action. Low risk alone is not enough. |
| Cascade | Quarantining or deleting a memory quarantines everything derived from it. |
| Review | Quarantine, restore, rollback and delete require an admin key and are hash-chained into the audit log. |

## API
Auth: `POST /v1/auth/login|logout`, `GET /v1/auth/me`
Keys (admin): `POST/GET /v1/keys`, `POST /v1/keys/{id}/revoke`
Agents: `POST /v1/agents` (admin), `GET /v1/agents`, `GET /v1/agents/{id}/risk`
Memories: `POST/GET /v1/memories`, `GET/PUT /v1/memories/{id}`,
`DELETE /v1/memories/{id}` (admin), `POST /{id}/analyze|quarantine|restore` (admin),
`GET /{id}/versions|provenance|events|report`, `POST /{id}/versions/{v}/restore` (admin)
Runtime: `POST /v1/retrieve`, `POST /v1/authorize`
Ops: `GET /v1/events`, `GET /v1/stats`, `GET /v1/policy`,
`GET /v1/audit`, `GET /v1/audit/verify` (admin)

## Known limits (v0.2)
- Detectors are regex. Paraphrased attacks will pass; trust gating is the backstop. This is the
  main weakness and the next piece of work (embeddings + LLM claim extraction).
- Fact extraction handles "X is Y" / "X = Y" only, and matches keys exactly.
- Retrieval uses token cosine, not embeddings.
- Rate limits are in-process: correct for one worker, approximate behind several. Redis before scaling out.
- The audit chain makes edits *detectable*, not impossible. Anyone with database write access can
  rewrite the whole chain; export the head hash off-box to close that.
- Provenance is still declared by the caller, but undeclared copying is now caught: a write that
  shares most of its 3-word phrases with a less trusted memory, or repeats an email address, URL or "X is Y" claim that
  only untrusted memories contain, inherits that memory's trust (see `laundering` in policy.yaml).
  A paraphrase that keeps no phrase and no address still passes at the key's own trust until
  embeddings land in 0.3. Honest corroboration is capped too: a trusted tool that repeats a web
  claim word for word gets the web claim's trust.
- Failed-auth throttling is per IP, so a shared egress IP can trip it for everyone behind it.
- No multi-tenancy. Roles are agent and admin only.
- Scores are heuristics, not calibrated probabilities.
- Tests are author-written scenarios. They prove the plumbing, not robustness against real attacks.

## Roadmap
0.3 embeddings (`bge-small` + pgvector), LLM claim extraction, semantic conflict matching,
    base64/homoglyph/multilingual detection, no credit for agreement among untrusted sources
0.4 benchmarks (MPBench, MemPoison, AgentPoison, MINJA; LongMemEval for utility loss) against
    OWASP Agent Memory Guard and A-MemGuard, with ASR, FPR, latency and utility reported
0.5 adapters (Mem0, LangGraph store, Letta, LangChain), MCP server, PostgreSQL + pgvector + Alembic
1.0 LLM incident write-ups, per-agent policy editor, provenance graph view, Slack/email/webhook
    alerts, expiry for stale untrusted memories, multi-tenant accounts
