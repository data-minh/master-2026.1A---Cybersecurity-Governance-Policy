"""Durable verification workers and manual approval policy gate."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Literal
from urllib.parse import urlparse
from uuid import UUID, uuid4, uuid5

import httpx
import redis.asyncio as redis_async
from fastapi import Depends, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from redis.exceptions import WatchError

from vts_common.auth import require_auth, require_role
from vts_common.config import settings
from vts_common.events import Event, EventBus, Topics
from vts_common.lifecycle import (
    LifecycleEnvelopeV1,
    WorkCommandData,
    WorkType,
    serialize_event,
    validate_work_input,
)
from vts_common.scope import ScopeClient, scoped_http_client
from vts_common.service import make_app, redis_readiness_check
from vts_common.util import host_from_url
from vts_common.worker import WorkContext, WorkerRunner, WorkResult

VTS_UUID_NAMESPACE = UUID("734ed946-af54-58ae-93a9-a429bb322868")
EVIDENCE_DIR = os.getenv("EVIDENCE_DIR", "/app/evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)
MAX_EVIDENCE_BYTES = 256 * 1024


class ApprovalConflict(RuntimeError):
    pass


class ApprovalNotFound(RuntimeError):
    pass


class IdempotencyKeyReused(RuntimeError):
    pass


class ApprovalSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str
    scan_id: str
    source_work_id: str
    stage_run_id: str | None = None
    source_attempt: int = 1
    execution_work_id: str
    finding_id: str
    finding: dict
    status: Literal[
        "pending",
        "approved",
        "rejected",
        "executing",
        "executed",
        "execution_failed",
        "timed_out",
    ]
    decision_deadline: datetime
    created_at: datetime
    updated_at: datetime
    actor: str | None = None
    reason: str = ""
    dry_run: bool = True
    outcome: dict | None = None
    revision: int = 1


class ExecutionAccepted(BaseModel):
    approval_id: str
    execution_work_id: str
    status: Literal["executing"] = "executing"
    status_url: str


def approval_identity(finding_id: str) -> str:
    return str(uuid5(VTS_UUID_NAMESPACE, f"approval|{finding_id}"))


def execution_identity(approval_id: str) -> str:
    return str(uuid5(VTS_UUID_NAMESPACE, f"execution|{approval_id}"))


def _event_id(approval_id: str, topic: str, revision: int) -> str:
    return str(uuid5(UUID(approval_id), f"{topic}:{revision}"))


class ApprovalStore:
    def __init__(self, redis, namespace: str = "vts", bus_stream: str = "vts.bus"):
        self.redis = redis
        self.namespace = namespace.rstrip(":")
        self.bus_stream = bus_stream
        self._action_locks: dict[str, asyncio.Lock] = {}

    def key(self, suffix: str) -> str:
        return f"{self.namespace}:{suffix}"

    async def get(self, approval_id: str) -> ApprovalSnapshot:
        raw = await self.redis.hgetall(self.key(f"approval:{approval_id}"))
        if not raw:
            raise ApprovalNotFound("approval not found")
        return _approval_from_hash(raw)

    async def create_requested(
        self,
        source: LifecycleEnvelopeV1,
        execution_work_id: str,
        decision_deadline: datetime | None = None,
    ) -> ApprovalSnapshot:
        finding_id = source.data["finding_id"]
        approval_id = approval_identity(finding_id)
        key = self.key(f"approval:{approval_id}")
        now = datetime.now(timezone.utc)
        deadline = decision_deadline or now + timedelta(seconds=settings.APPROVAL_DEADLINE_SECONDS)
        while True:
            async with self.redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    existing = await pipe.hgetall(key)
                    if existing:
                        return _approval_from_hash(existing)
                    approval = ApprovalSnapshot(
                        approval_id=approval_id,
                        scan_id=source.scan_id,
                        source_work_id=source.work_id,
                        stage_run_id=source.stage_run_id,
                        source_attempt=source.attempt,
                        execution_work_id=execution_work_id,
                        finding_id=finding_id,
                        finding=source.data,
                        status="pending",
                        decision_deadline=deadline,
                        created_at=now,
                        updated_at=now,
                        dry_run=settings.DRY_RUN,
                    )
                    event = self._event(source, approval, "approval.requested")
                    pipe.multi()
                    pipe.hset(key, mapping=_approval_hash(approval))
                    pipe.sadd(self.key(f"scan:{source.scan_id}:approvals"), approval_id)
                    pipe.sadd(self.key("approval:index"), approval_id)
                    pipe.xadd(self.bus_stream, {"payload": serialize_event(event)})
                    await pipe.execute()
                    return approval
                except WatchError:
                    continue

    async def approve(self, approval_id, actor, reason, idempotency_key):
        return await self._decision(approval_id, actor, reason, idempotency_key, "approved")

    async def reject(self, approval_id, actor, reason, idempotency_key):
        return await self._decision(approval_id, actor, reason, idempotency_key, "rejected")

    async def _decision(self, approval_id, actor, reason, idempotency_key, target):
        request = {"action": target, "approval_id": approval_id, "actor": actor, "reason": reason}
        allowed = {"pending"} if target == "approved" else {"pending", "approved"}
        return await self._run_action(
            approval_id,
            lambda: self._cas_action(
                approval_id,
                idempotency_key,
                request,
                allowed,
                target,
                actor,
                reason,
            ),
        )

    async def request_execution(self, approval_id, actor, dry_run, idempotency_key):
        request = {"action": "execute", "approval_id": approval_id, "actor": actor, "dry_run": dry_run}
        approval = await self._run_action(
            approval_id,
            lambda: self._cas_action(
                approval_id,
                idempotency_key,
                request,
                {"approved"},
                "executing",
                actor,
                "",
                dry_run,
            ),
        )
        return ExecutionAccepted(
            approval_id=approval.approval_id,
            execution_work_id=approval.execution_work_id,
            status_url=f"/approvals/{approval.approval_id}",
        )

    async def _run_action(self, approval_id, factory):
        lock = self._action_locks.setdefault(approval_id, asyncio.Lock())
        if lock.locked():
            raise ApprovalConflict("concurrent approval action already in progress")
        async with lock:
            return await factory()

    async def _cas_action(
        self,
        approval_id,
        idempotency_key,
        request,
        allowed,
        target,
        actor,
        reason,
        dry_run=None,
    ):
        key = self.key(f"approval:{approval_id}")
        idem_key = self.key(f"idempotency:approval:{idempotency_key}")
        request_hash = hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        while True:
            async with self.redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key, idem_key)
                    idem = await pipe.hgetall(idem_key)
                    if idem:
                        if idem.get("request_hash") != request_hash:
                            raise IdempotencyKeyReused("IDEMPOTENCY_KEY_REUSED")
                        return ApprovalSnapshot.model_validate_json(idem["response"])
                    raw = await pipe.hgetall(key)
                    if not raw:
                        raise ApprovalNotFound("approval not found")
                    current = _approval_from_hash(raw)
                    if current.status not in allowed:
                        raise ApprovalConflict(f"cannot {target} from state {current.status}")
                    updated = current.model_copy(update={
                        "status": target,
                        "actor": actor,
                        "reason": reason,
                        "dry_run": current.dry_run if dry_run is None else dry_run,
                        "updated_at": datetime.now(timezone.utc),
                        "revision": current.revision + 1,
                    })
                    topic = {
                        "approved": "approval.approved",
                        "rejected": "approval.rejected",
                        "executing": "approval.execution.requested",
                    }[target]
                    event = self._event_from_approval(updated, topic)
                    pipe.multi()
                    pipe.hset(key, mapping=_approval_hash(updated))
                    pipe.hset(idem_key, mapping={"request_hash": request_hash, "response": updated.model_dump_json()})
                    pipe.expire(idem_key, settings.DEDUPE_RETENTION_SECONDS)
                    pipe.xadd(self.bus_stream, {"payload": serialize_event(event)})
                    await pipe.execute()
                    return updated
                except WatchError as exc:
                    raise ApprovalConflict("concurrent approval action lost CAS") from exc

    async def mark_executed(self, event: LifecycleEnvelopeV1) -> ApprovalSnapshot:
        return await self._mark_terminal(event, "executed", "approval.executed")

    async def mark_execution_failed(self, event: LifecycleEnvelopeV1) -> ApprovalSnapshot:
        return await self._mark_terminal(event, "execution_failed", "approval.execution_failed")

    async def _mark_terminal(self, event, status, topic):
        approval_id = event.data["approval_id"]
        key = self.key(f"approval:{approval_id}")
        while True:
            async with self.redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    current = _approval_from_hash(await pipe.hgetall(key))
                    if current.status not in {"executing", "approved"}:
                        raise ApprovalConflict(f"cannot mark {status} from {current.status}")
                    updated = current.model_copy(update={"status": status, "outcome": event.data.get("outcome"), "updated_at": datetime.now(timezone.utc), "revision": current.revision + 1})
                    durable_event = event.model_copy(update={"event": topic, "event_id": _event_id(approval_id, topic, updated.revision)})
                    pipe.multi()
                    pipe.hset(key, mapping=_approval_hash(updated))
                    pipe.xadd(self.bus_stream, {"payload": serialize_event(durable_event)})
                    pipe.expire(key, settings.TERMINAL_RETENTION_SECONDS)
                    await pipe.execute()
                    return updated
                except WatchError:
                    continue

    async def expire_due(self, now: datetime) -> list[ApprovalSnapshot]:
        expired = []
        for approval_id in await self.redis.smembers(self.key("approval:index")):
            try:
                current = await self.get(approval_id)
            except ApprovalNotFound:
                continue
            if current.status in {"pending", "approved"} and current.decision_deadline <= now:
                updated = await self._expire_one(approval_id, now)
                if updated is not None:
                    expired.append(updated)
        return expired

    async def _expire_one(self, approval_id: str, now: datetime) -> ApprovalSnapshot | None:
        """CAS the deadline transition so it never overwrites a concurrent decision."""
        key = self.key(f"approval:{approval_id}")
        while True:
            async with self.redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.hgetall(key)
                    if not raw:
                        return None
                    current = _approval_from_hash(raw)
                    if current.status not in {"pending", "approved"} or current.decision_deadline > now:
                        return None
                    updated = current.model_copy(update={"status": "timed_out", "updated_at": now, "revision": current.revision + 1})
                    event = self._event_from_approval(
                        updated, "approval.execution_failed"
                    ).model_copy(
                        update={
                            "data": {
                                "approval_id": approval_id,
                                "execution_work_id": current.execution_work_id,
                                "error_code": "APPROVAL_DEADLINE",
                                "retryable": False,
                            }
                        }
                    )
                    pipe.multi()
                    pipe.hset(key, mapping=_approval_hash(updated))
                    pipe.xadd(self.bus_stream, {"payload": serialize_event(event)})
                    pipe.expire(key, settings.TERMINAL_RETENTION_SECONDS)
                    await pipe.execute()
                    return updated
                except WatchError:
                    continue

    async def list(self, scan_id=None, status=None, offset=0, limit=20):
        ids = sorted(await self.redis.smembers(self.key("approval:index")))
        items = []
        for approval_id in ids:
            try:
                approval = await self.get(approval_id)
            except ApprovalNotFound:
                continue
            if scan_id and approval.scan_id != scan_id:
                continue
            if status and approval.status != status:
                continue
            items.append(approval)
        return items[offset : offset + limit], offset + limit if offset + limit < len(items) else None

    def _event(self, source, approval, topic):
        return LifecycleEnvelopeV1.model_validate({
            "schema_version": 1,
            "event_id": _event_id(approval.approval_id, topic, approval.revision),
            "event": topic,
            "scan_id": source.scan_id,
            "stage_run_id": source.stage_run_id,
            "work_id": source.work_id,
            "parent_work_id": source.parent_work_id,
            "producer": "verification",
            "attempt": source.attempt,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": {"approval_id": approval.approval_id, "finding_id": approval.finding_id, "execution_work_id": approval.execution_work_id, "decision_deadline": approval.decision_deadline.isoformat()},
        })

    def _event_from_approval(self, approval, topic):
        return LifecycleEnvelopeV1.model_validate({
            "schema_version": 1,
            "event_id": _event_id(approval.approval_id, topic, approval.revision),
            "event": topic,
            "scan_id": approval.scan_id,
            "stage_run_id": approval.stage_run_id or str(uuid5(UUID(approval.scan_id), "verification-stage")),
            "work_id": approval.source_work_id,
            "parent_work_id": None,
            "producer": "verification",
            "attempt": approval.source_attempt,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": {"approval_id": approval.approval_id, "execution_work_id": approval.execution_work_id, "actor": approval.actor, "reason": approval.reason, "dry_run": approval.dry_run, "idempotency_key": "stored"},
        })


def _approval_hash(approval):
    values = approval.model_dump(mode="json")
    return {key: json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else int(value) if isinstance(value, bool) else value for key, value in values.items() if value is not None}


def _approval_from_hash(raw):
    values = dict(raw)
    for key in ("finding", "outcome"):
        if key in values:
            values[key] = json.loads(values[key])
    for key in ("revision", "source_attempt"):
        if key in values:
            values[key] = int(values[key])
    values["dry_run"] = str(values.get("dry_run", "1")) in {"1", "true", "True"}
    return ApprovalSnapshot.model_validate(values)


async def _safe_verify(url: str) -> dict:
    try:
        async with scoped_http_client(timeout=8.0, verify=False, follow_redirects=True) as client:
            response = await client.get(url)
        return {"reachable": True, "status": response.status_code, "evidence_len": len(response.content)}
    except httpx.HTTPError as exc:
        return {"reachable": False, "error": str(exc)}


async def handle_safe_verify(ctx: WorkContext, command) -> WorkResult:
    command_data = WorkCommandData.model_validate(command.data)
    work_input = validate_work_input(WorkType.VERIFICATION_SAFE_VERIFY, command_data.input)
    if not await ScopeClient().permits(host_from_url(work_input.url)):
        return WorkResult(0, {"skipped": "out_of_scope"})
    evidence = await _safe_verify(work_input.url)
    if not evidence.get("reachable"):
        return WorkResult(0, evidence)
    approval_id = approval_identity(work_input.finding_id)
    execution_work_id = execution_identity(approval_id)
    result_id = "sha256:" + hashlib.sha256(f"verified|{command.scan_id}|{work_input.finding_id}".encode()).hexdigest()
    data = {"result_id": result_id, "finding_id": work_input.finding_id, "url": work_input.url, "severity": work_input.severity, "approval_id": approval_id, "verification": evidence, "dry_run": settings.DRY_RUN}
    await ctx.publish_result(Topics.VULN_VERIFIED, data)
    source = LifecycleEnvelopeV1.model_validate({
        "schema_version": 1, "event_id": str(uuid4()), "event": Topics.VULN_VERIFIED,
        "scan_id": command.scan_id, "stage_run_id": command.stage_run_id,
        "work_id": command.work_id, "parent_work_id": command.parent_work_id,
        "producer": "verification", "attempt": command.attempt,
        "occurred_at": datetime.now(timezone.utc).isoformat(), "data": data,
    })
    await APPROVAL_STORE.create_requested(source, execution_work_id)
    return WorkResult(1, evidence)


async def handle_execute(ctx: WorkContext, command) -> WorkResult:
    command_data = WorkCommandData.model_validate(command.data)
    work_input = validate_work_input(WorkType.VERIFICATION_EXECUTE, command_data.input)
    approval = await APPROVAL_STORE.get(work_input.approval_id)
    if approval.status not in {"executing", "approved"}:
        raise ValueError("approval is not executable")

    def approval_event(topic, data):
        return LifecycleEnvelopeV1.model_validate({
            "schema_version": 1, "event_id": str(uuid4()), "event": topic,
            "scan_id": command.scan_id, "stage_run_id": command.stage_run_id,
            "work_id": command.work_id, "parent_work_id": command.parent_work_id,
            "producer": "verification", "attempt": command.attempt,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": {"approval_id": work_input.approval_id, "execution_work_id": command.work_id, **data},
        })

    try:
        outcome = {"mode": "dry-run" if work_input.dry_run else "live-safe-confirm", "performed": False, "note": "No destructive exploitation performed."}
        await APPROVAL_STORE.mark_executed(approval_event("approval.executed", {"outcome": outcome}))
        return WorkResult(1, outcome)
    except Exception as exc:
        # Same retry classification as WorkerRunner: only the final attempt of
        # a failure that will not be retried resolves the approval as failed.
        retryable = isinstance(exc, (OSError, ConnectionError, TimeoutError))
        if not retryable or command.attempt >= command_data.max_attempts:
            failure = approval_event(
                "approval.execution_failed",
                {"error_code": type(exc).__name__.upper(), "retryable": False, "outcome": {"error": str(exc)[:500]}},
            )
            try:
                await APPROVAL_STORE.mark_execution_failed(failure)
            except Exception:
                pass  # the work.failed terminal still fails the stage
        raise


class DecisionReq(BaseModel):
    reason: str = Field(default="", max_length=500)


class ExecuteReq(BaseModel):
    dry_run: bool = True


def _require_approver(claims):
    return require_role(claims, ("approver", "admin"))


def create_verification_app(store: ApprovalStore, bus: EventBus, runner: WorkerRunner | None = None):
    async def approval_deadline_reaper():
        while True:
            await store.expire_due(datetime.now(timezone.utc))
            await asyncio.sleep(1)

    app = make_app(
        title="VTS Verification & Approval",
        description="Durable Policy A approval gate.",
        command_runner=runner,
        workers=[approval_deadline_reaper],
        event_bus=bus,
    )

    @app.exception_handler(ApprovalNotFound)
    async def not_found(_request: Request, exc):
        return JSONResponse({"error": {"code": "NOT_FOUND", "message": str(exc)}}, status_code=404)

    @app.exception_handler(ApprovalConflict)
    async def conflict(_request: Request, exc):
        return JSONResponse({"error": {"code": "APPROVAL_CONFLICT", "message": str(exc)}}, status_code=409)

    @app.exception_handler(IdempotencyKeyReused)
    async def reused(_request: Request, exc):
        return JSONResponse({"error": {"code": "IDEMPOTENCY_KEY_REUSED", "message": str(exc)}}, status_code=422)

    async def durable():
        check = await redis_readiness_check(store.redis)
        if not check.healthy:
            raise HTTPException(status_code=503, detail="durable approval store unavailable")

    @app.get("/approvals", tags=["approval"])
    async def list_approvals(scan_id: str | None = None, status: str | None = None, cursor: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100), _claims: dict = Depends(require_auth)):
        items, next_cursor = await store.list(scan_id, status, cursor, limit)
        return {"items": [item.model_dump(mode="json") for item in items], "next_cursor": next_cursor}

    @app.get("/approvals/{aid}", tags=["approval"])
    async def get_approval(aid: str, _claims: dict = Depends(require_auth)):
        return await store.get(aid)

    @app.post("/approvals/{aid}/approve", tags=["approval"])
    async def approve(aid: str, req: DecisionReq, claims: dict = Depends(require_auth), key: str = Header(alias="Idempotency-Key")):
        _require_approver(claims); await durable()
        return await store.approve(aid, claims.get("sub", "unknown"), req.reason, key)

    @app.post("/approvals/{aid}/reject", tags=["approval"])
    async def reject(aid: str, req: DecisionReq, claims: dict = Depends(require_auth), key: str = Header(alias="Idempotency-Key")):
        _require_approver(claims); await durable()
        return await store.reject(aid, claims.get("sub", "unknown"), req.reason, key)

    @app.post("/approvals/{aid}/execute", tags=["approval"], status_code=202)
    async def execute(aid: str, req: ExecuteReq, claims: dict = Depends(require_auth), key: str = Header(alias="Idempotency-Key")):
        _require_approver(claims); await durable()
        return await store.request_execution(aid, claims.get("sub", "unknown"), req.dry_run, key)

    @app.get("/approvals/{aid}/evidence", tags=["approval"])
    async def download_evidence(aid: str, _claims: dict = Depends(require_auth)):
        approval = await store.get(aid)
        filename = (approval.outcome or {}).get("evidence_file")
        if not filename:
            raise HTTPException(status_code=404, detail="no evidence captured")
        path = os.path.join(EVIDENCE_DIR, filename)
        if not os.path.exists(path):
            raise HTTPException(status_code=404, detail="evidence file missing")
        return FileResponse(path, filename=filename, media_type="text/plain")

    @app.get("/preview", tags=["verification"])
    async def preview(url: str, _claims: dict = Depends(require_auth)):
        """Read-only preview of an in-scope resource.

        Fetches a single GET through the scope-checked client, so the host and
        every redirect hop must be in scope or the fetch is refused. It never
        sends an exploit payload and never performs a state-changing method; it
        is the same safe read the pipeline already does, exposed for review.
        """
        if "://" not in url or urlparse(url).scheme not in {"http", "https"} or len(url) > 2048:
            raise HTTPException(status_code=400, detail="url không hợp lệ")
        host = host_from_url(url)
        if not await ScopeClient().permits(host):
            raise HTTPException(status_code=403, detail="mục tiêu ngoài scope")
        try:
            async with scoped_http_client(timeout=8.0, verify=False, follow_redirects=True) as client:
                response = await client.get(url)
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"không tải được: {exc}")
        raw = response.content[:MAX_EVIDENCE_BYTES]
        body = raw.decode(response.encoding or "utf-8", "replace")
        return {
            "url": str(response.url),
            "status": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "bytes": len(response.content),
            "truncated": len(response.content) > len(raw),
            "body": body,
        }

    return app


_default_redis = redis_async.from_url(settings.REDIS_URL, decode_responses=True)
APPROVAL_STORE = ApprovalStore(_default_redis)
BUS = EventBus()
RUNNER = WorkerRunner("verification", BUS, {WorkType.VERIFICATION_SAFE_VERIFY: handle_safe_verify, WorkType.VERIFICATION_EXECUTE: handle_execute}, settings.MAX_CONCURRENCY)
app = create_verification_app(APPROVAL_STORE, BUS, RUNNER)
