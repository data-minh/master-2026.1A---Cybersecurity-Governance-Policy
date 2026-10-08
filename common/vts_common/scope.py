"""Scope-check client (shared, Người 3 - D1).

Core safety principle of the assignment: *every* service must call
GET /scope/check?target=<t> before acting on a target. If the target is not in
the confirmed scope, the action must be refused.
"""
from __future__ import annotations

import httpx

from .config import settings


class ScopeDenied(Exception):
    """Raised when a target is outside the confirmed scope."""


class ScopeUnavailable(ConnectionError):
    """The scope service could not give an answer (retryable, never 'allowed')."""


class OutOfScopeRequest(httpx.RequestError):
    """An outgoing HTTP request (including a redirect hop) left the scope."""


class ScopeClient:
    def __init__(self, base_url: str | None = None, token: str | None = None):
        self.base_url = (base_url or settings.SCOPE_SERVICE_URL).rstrip("/")
        self.token = token

    async def check(self, target: str) -> dict:
        """Return scope record if allowed.

        Raises ScopeDenied when the target is out of scope and ScopeUnavailable
        when the scope service cannot answer, so callers can tell a policy
        decision apart from an outage.
        """
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{self.base_url}/scope/check",
                    params={"target": target},
                    headers=headers,
                )
        except httpx.HTTPError as exc:
            raise ScopeUnavailable(f"scope service unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise ScopeUnavailable(f"scope service error: {resp.status_code}")
        body = resp.json()
        if not body.get("allowed"):
            raise ScopeDenied(f"target '{target}' is out of scope")
        return body

    async def permits(self, target: str) -> bool:
        """True/False for a policy decision; ScopeUnavailable propagates."""
        try:
            await self.check(target)
            return True
        except ScopeDenied:
            return False

    async def is_allowed(self, target: str) -> bool:
        try:
            await self.check(target)
            return True
        except (ScopeDenied, ScopeUnavailable):
            # Fail closed: if the scope service is unreachable, deny the action.
            return False


def scoped_http_client(
    scope: ScopeClient | None = None, **kwargs
) -> httpx.AsyncClient:
    """AsyncClient that scope-checks the host of every request it sends.

    httpx runs request hooks for each redirect hop, so an in-scope URL that
    redirects to an out-of-scope host is stopped before the second request.
    The refusal is an httpx.RequestError, so existing ``except httpx.HTTPError``
    handlers treat it like an unreachable endpoint.
    """
    checker = scope or ScopeClient()
    decisions: dict[str, bool] = {}

    async def enforce(request: httpx.Request) -> None:
        host = (request.url.host or "").lower()
        if host not in decisions:
            decisions[host] = await checker.permits(host)
        if not decisions[host]:
            raise OutOfScopeRequest(
                f"request to '{host}' is out of scope", request=request
            )

    hooks = kwargs.pop("event_hooks", {}) or {}
    hooks = {**hooks, "request": [*hooks.get("request", []), enforce]}
    return httpx.AsyncClient(event_hooks=hooks, **kwargs)
