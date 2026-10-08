"""Scope Management & Auth Gateway (Người 3 - D1 + D4).

Responsibilities:
  * Issue JWT tokens (login).
  * Maintain the confirmed scope list (CRUD, admin only, persisted in Redis).
  * Expose GET /scope/check?target=<t> that EVERY other service calls before
    acting on a target. This is the central safety control of the system:
    "Toàn bộ scan chỉ được chạy trong scope đã xác nhận".

Scope matching rules:
  * exact host match                 (example.com)
  * wildcard subdomain match         (*.example.com)
  * CIDR match for IP targets        (10.0.0.0/24)
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Literal

import redis.asyncio as redis_async
from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field

from vts_common.auth import create_token, require_auth, require_role
from vts_common.config import settings
from vts_common.service import make_app, redis_readiness_check

# Seed rules written once into an empty store (safe lab targets only).
SEED_SCOPE: list[dict] = [
    {"id": 1, "target": "*.example.com", "type": "domain", "note": "demo lab domain"},
    {"id": 2, "target": "example.com", "type": "domain", "note": "demo lab apex"},
    {"id": 3, "target": "scanme.nmap.org", "type": "domain", "note": "public scan target"},
    {"id": 4, "target": "127.0.0.0/8", "type": "cidr", "note": "loopback lab"},
    {"id": 5, "target": "vuln-target", "type": "domain", "note": "demo-only in-cluster target"},
]

# Demo users (username -> (password, role)). Replace with a real IdP in prod.
USERS = {
    "operator": ("operator123", "operator"),
    "approver": ("approver123", "approver"),
    "admin": ("admin123", "admin"),
}

# Changing the scope changes what every worker may touch, so only admins may.
SCOPE_ADMIN_ROLES = ("admin",)
# The scope list reveals what the platform is allowed to test: operators must not see it.
SCOPE_VIEW_ROLES = ("admin", "approver")


class LoginReq(BaseModel):
    username: str
    password: str


class LoginResp(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class ScopeItem(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    type: Literal["domain", "cidr"] = "domain"
    note: str = Field(default="", max_length=500)


class ScopeStore:
    """Durable scope rules in Redis, shared by every scope-auth replica."""

    def __init__(self, redis, namespace: str = "vts") -> None:
        self.redis = redis
        self.namespace = namespace.rstrip(":")
        self._seeded = False

    def key(self, suffix: str) -> str:
        return f"{self.namespace}:{suffix}"

    async def _ensure_seeded(self) -> None:
        if self._seeded:
            return
        if await self.redis.set(self.key("scope:seeded"), "1", nx=True):
            async with self.redis.pipeline(transaction=True) as pipe:
                for rule in SEED_SCOPE:
                    pipe.hset(self.key("scope:items"), str(rule["id"]), json.dumps(rule))
                pipe.set(self.key("scope:next_id"), max(rule["id"] for rule in SEED_SCOPE))
                await pipe.execute()
        self._seeded = True

    async def items(self) -> list[dict]:
        await self._ensure_seeded()
        raw = await self.redis.hgetall(self.key("scope:items"))
        return sorted((json.loads(value) for value in raw.values()), key=lambda rule: rule["id"])

    async def add(self, item: ScopeItem) -> dict:
        await self._ensure_seeded()
        rule = {"id": await self.redis.incr(self.key("scope:next_id")), **item.model_dump()}
        await self.redis.hset(self.key("scope:items"), str(rule["id"]), json.dumps(rule))
        return rule

    async def delete(self, item_id: int) -> bool:
        await self._ensure_seeded()
        return bool(await self.redis.hdel(self.key("scope:items"), str(item_id)))


def _host_matches(target: str, rule: dict) -> bool:
    rt = rule["target"]
    if rule["type"] == "cidr":
        try:
            net = ipaddress.ip_network(rt, strict=False)
            return ipaddress.ip_address(target) in net
        except ValueError:
            return False
    # domain rules
    t = target.lower().rstrip(".")
    rt = rt.lower().rstrip(".")
    if rt.startswith("*."):
        base = rt[2:]
        return t == base or t.endswith("." + base)
    return t == rt


def create_scope_app(store: ScopeStore):
    async def store_ready():
        return await redis_readiness_check(store.redis)

    app = make_app(
        title="VTS Scope & Auth Gateway",
        description="Người 3 - D1/D4: scope-check, JWT auth, central safety control.",
        readiness_checks=[store_ready],
    )
    app.state.scope_store = store

    @app.post("/auth/login", response_model=LoginResp, tags=["auth"])
    async def login(req: LoginReq):
        rec = USERS.get(req.username)
        if not rec or rec[0] != req.password:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        role = rec[1]
        return LoginResp(access_token=create_token(req.username, role=role), role=role)

    @app.get("/scope/check", tags=["scope"])
    async def scope_check(target: str):
        """Return {allowed: bool, matched_rule: ...} for a target host or IP.

        If the store is unavailable this raises (HTTP 500), which clients treat
        as "scope unavailable" and never as allowed.
        """
        for rule in await store.items():
            if _host_matches(target, rule):
                return {
                    "allowed": True,
                    "target": target,
                    "matched_rule": rule,
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                }
        return {"allowed": False, "target": target, "matched_rule": None,
                "checked_at": datetime.now(timezone.utc).isoformat()}

    @app.get("/scope", tags=["scope"])
    async def list_scope(claims: dict = Depends(require_auth)):
        require_role(claims, SCOPE_VIEW_ROLES)
        return {"items": await store.items()}

    @app.post("/scope", tags=["scope"], status_code=201)
    async def add_scope(item: ScopeItem, claims: dict = Depends(require_auth)):
        require_role(claims, SCOPE_ADMIN_ROLES)
        return await store.add(item)

    @app.delete("/scope/{item_id}", tags=["scope"])
    async def delete_scope(item_id: int, claims: dict = Depends(require_auth)):
        require_role(claims, SCOPE_ADMIN_ROLES)
        if not await store.delete(item_id):
            raise HTTPException(status_code=404, detail="scope item not found")
        return {"deleted": item_id}

    return app


app = create_scope_app(
    ScopeStore(redis_async.from_url(settings.REDIS_URL, decode_responses=True))
)
