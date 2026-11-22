"""Minimal MemoryGuard client. Only dependency: httpx.

The key decides what the caller is: its role (agent or admin), the agent it is
pinned to, and the highest source type it may write as. An agent key can leave
agent_id and source_type out entirely; passing a more trusted source_type than
the key allows is refused by the server, not silently downgraded.
"""
from urllib.parse import urlsplit

import httpx


def is_local(base_url: str) -> bool:
    """True for localhost / loopback servers. Those must not go through a system proxy:
    on Windows, Python picks up the proxy from Internet Settings but ignores its
    bypass list, so a local proxy (Clash, v2ray, ...) would answer with an empty 502."""
    host = (urlsplit(base_url).hostname or "").lower()
    return host in ("localhost", "::1") or host.startswith("127.") or host.endswith(".localhost")


class MemoryGuardError(RuntimeError):
    def __init__(self, status, detail):
        super().__init__(f"{status}: {detail}")
        self.status, self.detail = status, detail


class MemoryGuard:
    def __init__(self, base_url="http://localhost:8000", api_key=None, timeout=10.0):
        if not api_key:
            raise ValueError("an API key is required; mint one with python -m app.manage create-key")
        self._c = httpx.Client(base_url=base_url, headers={"X-API-Key": api_key}, timeout=timeout,
                               trust_env=not is_local(base_url))

    def _r(self, method, path, **kw):
        r = self._c.request(method, path, **kw)
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except Exception:
                detail = r.text
            if not detail:
                detail = f"HTTP {r.status_code} {r.reason_phrase} with an empty response"
            raise MemoryGuardError(r.status_code, detail)
        return r.json()

    # identity
    def whoami(self):
        return self._r("GET", "/v1/auth/me")

    # agents (admin)
    def create_agent(self, agent_id, name):
        return self._r("POST", "/v1/agents", json={"id": agent_id, "name": name})

    # keys (admin)
    def create_key(self, name, role, source_type, agent_id=None, **limits):
        return self._r("POST", "/v1/keys", json={"name": name, "role": role,
                                                 "source_type": source_type,
                                                 "agent_id": agent_id, **limits})

    def list_keys(self):
        return self._r("GET", "/v1/keys")

    def revoke_key(self, key_id):
        return self._r("POST", f"/v1/keys/{key_id}/revoke")

    # memory
    def store(self, content, agent_id=None, source_type=None, user_id=None,
              source_id=None, parent_ids=()):
        return self._r("POST", "/v1/memories", json={
            "agent_id": agent_id, "content": content, "source_type": source_type,
            "user_id": user_id, "source_id": source_id, "parent_ids": list(parent_ids)})

    def update(self, memory_id, content, source_type=None, reason=""):
        return self._r("PUT", f"/v1/memories/{memory_id}",
                       json={"content": content, "source_type": source_type, "reason": reason})

    def retrieve(self, query, agent_id=None, user_id=None, k=5, include_untrusted=True):
        return self._r("POST", "/v1/retrieve", json={
            "agent_id": agent_id, "query": query, "user_id": user_id, "k": k,
            "include_untrusted": include_untrusted})

    def authorize(self, action, memory_ids, agent_id=None):
        return self._r("POST", "/v1/authorize", json={
            "agent_id": agent_id, "action": action, "memory_ids": list(memory_ids)})

    # review (admin)
    def quarantine(self, memory_id, reason=""):
        return self._r("POST", f"/v1/memories/{memory_id}/quarantine", json={"reason": reason})

    def restore(self, memory_id, reason=""):
        return self._r("POST", f"/v1/memories/{memory_id}/restore", json={"reason": reason})

    def rollback(self, memory_id, version, reason=""):
        return self._r("POST", f"/v1/memories/{memory_id}/versions/{version}/restore",
                       json={"reason": reason})

    def report(self, memory_id):
        return self._r("GET", f"/v1/memories/{memory_id}/report")

    def provenance(self, memory_id):
        return self._r("GET", f"/v1/memories/{memory_id}/provenance")

    # audit (admin)
    def audit(self, limit=100):
        return self._r("GET", "/v1/audit", params={"limit": limit})

    def verify_audit(self):
        return self._r("GET", "/v1/audit/verify")
