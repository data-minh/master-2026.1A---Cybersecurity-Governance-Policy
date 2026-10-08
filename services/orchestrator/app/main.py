"""Authoritative VTS lifecycle API backed by the Redis work ledger."""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
import redis.asyncio as redis_async
import yaml
from fastapi import Depends, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from vts_common.auth import require_auth
from vts_common.config import settings
from vts_common.events import EventBus
from vts_common.lifecycle import (
    EventValidationError,
    LifecycleEnvelopeV1,
    ScanStatus,
    WorkStatus,
    validate_event,
)
from vts_common.scope import ScopeClient, ScopeDenied, ScopeUnavailable
from vts_common.service import DEFAULT_METRICS, ReadinessState, make_app

from . import notify
from .fanout import fan_out
from .history import HistoryStore, history_archiver
from .state_machine import LifecycleState, expire_due
from .ledger import (
    CursorError,
    IdempotencyConflict,
    LedgerError,
    RedisLifecycleLedger,
    RevisionConflict,
    StartScanSpec,
)

IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
HOST_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)
DEFAULT_PIPELINE = [
    {
        "stage": "recon",
        "steps": [
            "subdomain",
            "osint",
            "http_probe",
            "url_harvest",
            "port_scan",
            "content_fuzz",
        ],
    },
    {"stage": "scan", "steps": ["template_engine", "specialized_scanners"]},
    {"stage": "verification", "steps": ["verify_safe", "manual_approval"]},
]
DEFAULT_PIPELINE_YAML = yaml.safe_dump(
    {"target": "vuln-target", "pipeline": DEFAULT_PIPELINE}, sort_keys=False
)


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details=None):
        self.status = status
        self.code = code
        self.message = message
        self.details = details


class StartScanReq(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str | None = Field(default=None, min_length=1, max_length=2048)
    config_yaml: str | None = Field(default=None, max_length=65_536)
    mode: Literal["full", "recon", "recon-passive"] = "full"
    exec_mode: Literal["sequential", "parallel"] = "sequential"


class CancelScanReq(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=500)

    @field_validator("reason")
    @classmethod
    def strip_reason(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("reason is required")
        return value


def _error(code: str, message: str, details=None):
    payload = {"code": code, "message": message}
    if details is not None:
        payload["details"] = details
    return {"error": payload}


def _canonical_uuid(value: str, field: str = "scan_id") -> str:
    try:
        parsed = UUID(value)
    except (ValueError, TypeError) as exc:
        raise ApiError(422, "VALIDATION_ERROR", f"{field} không hợp lệ") from exc
    if str(parsed) != value:
        raise ApiError(422, "VALIDATION_ERROR", f"{field} không hợp lệ")
    return value


def _idempotency_key(value: str | None) -> str:
    if value is None:
        return str(uuid4())
    if not IDEMPOTENCY_RE.fullmatch(value):
        raise ApiError(
            422,
            "VALIDATION_ERROR",
            "Idempotency-Key phải dài 8–128 ký tự hợp lệ",
            {"field": "Idempotency-Key"},
        )
    return value


def _normalize_target(value: str) -> str:
    value = value.strip()
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ApiError(422, "VALIDATION_ERROR", "target scheme không hợp lệ")
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ApiError(422, "VALIDATION_ERROR", "target chứa userinfo/fragment")
        if not parsed.hostname:
            raise ApiError(422, "VALIDATION_ERROR", "target host không hợp lệ")
        value = parsed.hostname
    value = value.lower().rstrip(".")
    if not HOST_RE.fullmatch(value):
        raise ApiError(422, "VALIDATION_ERROR", "target host không hợp lệ")
    return value


def _resolve_request(req: StartScanReq) -> tuple[str, list[dict]]:
    yaml_target = None
    pipeline = DEFAULT_PIPELINE
    if req.config_yaml is not None:
        try:
            parsed = yaml.safe_load(req.config_yaml)
        except yaml.YAMLError as exc:
            raise ApiError(400, "INVALID_YAML", "config_yaml không hợp lệ") from exc
        if not isinstance(parsed, dict):
            raise ApiError(422, "VALIDATION_ERROR", "config_yaml phải là mapping")
        yaml_target = parsed.get("target")
        pipeline = parsed.get("pipeline", DEFAULT_PIPELINE)
        if pipeline != DEFAULT_PIPELINE:
            raise ApiError(
                422,
                "UNSUPPORTED_PIPELINE",
                "pipeline chưa thuộc graph chuẩn được hỗ trợ",
            )
    if req.target and yaml_target:
        if _normalize_target(req.target) != _normalize_target(str(yaml_target)):
            raise ApiError(422, "VALIDATION_ERROR", "target body và YAML xung đột")
    raw_target = req.target or yaml_target
    if not raw_target:
        raise ApiError(422, "VALIDATION_ERROR", "target là bắt buộc")
    return _normalize_target(str(raw_target)), pipeline


def _require_history(history: HistoryStore | None) -> HistoryStore:
    if history is None:
        raise ApiError(503, "HISTORY_UNAVAILABLE", "kho lịch sử chưa được cấu hình")
    return history


def _ensure_ready(readiness: ReadinessState) -> None:
    status, _ = readiness.response()
    if status != 200:
        raise ApiError(503, "SERVICE_UNAVAILABLE", "lifecycle store chưa sẵn sàng")


def retry_delay(attempt: int) -> int:
    if not 1 <= attempt <= len(settings.WORK_RETRY_BACKOFF_SECONDS):
        raise ValueError("attempt outside retry policy")
    return settings.WORK_RETRY_BACKOFF_SECONDS[attempt - 1]


SEVERITIES = ("critical", "high", "medium", "low", "info")
TERMINAL_SCAN_STATUSES = {
    ScanStatus.SUCCEEDED,
    ScanStatus.FAILED,
    ScanStatus.TIMED_OUT,
    ScanStatus.CANCELED,
}


def build_report(snapshot, findings) -> dict:
    """Aggregate report for one scan. Evidence and response bodies are excluded."""
    by_severity = {name: 0 for name in SEVERITIES}
    rows = []
    for record in findings:
        data = record.data or {}
        severity = str(data.get("severity", "info")).lower()
        by_severity[severity if severity in by_severity else "info"] += 1
        rows.append(
            {
                "template_id": data.get("template_id"),
                "name": data.get("name"),
                "severity": severity,
                "url": data.get("url"),
            }
        )
    rank = {name: index for index, name in enumerate(SEVERITIES)}
    rows.sort(key=lambda row: rank.get(row["severity"], len(SEVERITIES)))
    duration = None
    if snapshot.completed_at is not None:
        duration = int((snapshot.completed_at - snapshot.created_at).total_seconds())
    return {
        "scan_id": snapshot.scan_id,
        "target": snapshot.target,
        "mode": snapshot.mode,
        "status": snapshot.status.value,
        "outcome": snapshot.outcome,
        "revision": snapshot.revision,
        "created_at": snapshot.created_at.isoformat(),
        "completed_at": snapshot.completed_at.isoformat() if snapshot.completed_at else None,
        "duration_seconds": duration,
        "summary": snapshot.result_summary.model_dump(),
        "findings_by_severity": by_severity,
        "findings": rows,
        "approvals": snapshot.approval_summary.model_dump(),
        "stages": {
            name: {
                "status": stage.status.value,
                "total_work": stage.total_work,
                "completed_work": stage.completed_work,
                "failed_work": stage.failed_work,
                "result_count": stage.result_count,
            }
            for name, stage in snapshot.stages.items()
        },
    }


async def process_lifecycle_event(event: LifecycleEnvelopeV1, ledger) -> None:
    validate_event(event, stream="vts.bus")
    ingested_at = datetime.now(timezone.utc)
    result = await ledger.ingest(event, ingested_at)
    if result.duplicate or result.late:
        return
    snapshot = result.snapshot
    if snapshot.status in TERMINAL_SCAN_STATUSES:
        await notify.send_scan_finished(snapshot)
    for spec in fan_out(event, snapshot):
        registration = await ledger.register_work(
            spec,
            expected_revision=snapshot.revision,
            cause_work_id=event.work_id,
        )
        snapshot = registration.snapshot
    if (
        event.event == "work.failed"
        and event.data.get("retryable")
        and event.attempt < settings.WORK_MAX_ATTEMPTS
    ):
        await ledger.schedule_retry(
            event.work_id,
            event.attempt + 1,
            ingested_at.replace(microsecond=0)
            + __import__("datetime").timedelta(seconds=retry_delay(event.attempt)),
        )


async def handle_bus_delivery(delivery, ledger, bus) -> None:
    try:
        if not isinstance(delivery.event, LifecycleEnvelopeV1):
            raise EventValidationError("legacy_event_cannot_mutate_v1")
        await process_lifecycle_event(delivery.event, ledger)
    except (EventValidationError, ValueError) as exc:
        await bus.write_dlq(delivery, str(exc))
        await delivery.ack()
        return
    await delivery.ack()


def timeout_reaper_once(state: LifecycleState, now: datetime) -> LifecycleState:
    """Apply only explicit deadlines; elapsed silence can never create success."""
    return expire_due(state, now).state


async def recover_startup(ledger, readiness: ReadinessState):
    readiness.set("recovery", False, "active scan recovery in progress")
    try:
        active = await ledger.recover_active()
    except Exception:
        readiness.set("recovery", False, "active scan recovery failed")
        raise
    readiness.set("recovery", True)
    return active


def _stream_id(value: str) -> tuple[int, int]:
    first, second = value.split("-", 1)
    return int(first), int(second)


def _sse(event: str, stream_id: str, snapshot) -> str:
    return (
        f"id: {stream_id}\n"
        f"event: {event}\n"
        "retry: 1500\n"
        f"data: {snapshot.model_dump_json()}\n\n"
    )


async def scan_update_events(
    ledger,
    scan_id: str,
    last_event_id: str | None,
    *,
    once: bool = False,
):
    delivery_started = time.perf_counter()
    snapshot = await ledger.get_scan(scan_id)
    stream_key = ledger.key(f"scan:{scan_id}:updates")
    latest = await ledger.redis.xrevrange(stream_key, count=1)
    latest_id = latest[0][0] if latest else "0-0"
    cursor = last_event_id or latest_id
    if last_event_id is None:
        DEFAULT_METRICS.observe(
            "vts_snapshot_sse_delivery_seconds",
            {},
            time.perf_counter() - delivery_started,
        )
        yield _sse("snapshot", latest_id, snapshot)
        if once:
            return
    else:
        first = await ledger.redis.xrange(stream_key, count=1)
        if first and _stream_id(last_event_id) < _stream_id(first[0][0]):
            yield _sse("reset", latest_id, snapshot)
            cursor = latest_id
            if once:
                return
    try:
        while True:
            delivered = False
            async for update in ledger.read_updates(scan_id, cursor, 15_000):
                delivered = True
                cursor = update.stream_id
                yield _sse("snapshot", update.stream_id, update.snapshot)
                if once:
                    return
            if not delivered:
                yield ": heartbeat\n\n"
                if once:
                    return
    except asyncio.CancelledError:
        raise
    except Exception:
        yield "event: error\ndata: {\"error\":\"stream_unavailable\"}\n\n"


async def _retry_scheduler(ledger) -> None:
    while True:
        if hasattr(ledger, "dispatch_due_retries"):
            await ledger.dispatch_due_retries(datetime.now(timezone.utc))
        await asyncio.sleep(0.5)


async def _timeout_reaper(ledger) -> None:
    while True:
        if hasattr(ledger, "expire_due"):
            await ledger.expire_due(datetime.now(timezone.utc))
        await asyncio.sleep(1)


def create_api_app(
    ledger,
    scope,
    readiness: ReadinessState,
    *,
    enable_runtime: bool = False,
    history: HistoryStore | None = None,
):
    event_bus = EventBus(group="orchestrator-v1") if enable_runtime else None

    async def consume_event(event):
        if not isinstance(event, LifecycleEnvelopeV1):
            return
        await process_lifecycle_event(event, ledger)

    async def recovery_worker():
        await recover_startup(ledger, readiness)
        await asyncio.Event().wait()

    app = make_app(
        title="VTS Orchestration / Workflow Engine",
        description="Authoritative scan-stage-work lifecycle API.",
        readiness=readiness,
        consumer=(["*"], consume_event) if enable_runtime else None,
        workers=[
            recovery_worker,
            lambda: _retry_scheduler(ledger),
            lambda: _timeout_reaper(ledger),
            *([lambda: history_archiver(ledger, history)] if history is not None else []),
        ]
        if enable_runtime
        else None,
        event_bus=event_bus,
    )
    app.state.ledger = ledger
    app.state.scope = scope

    @app.exception_handler(ApiError)
    async def api_error_handler(_request: Request, exc: ApiError):
        return JSONResponse(
            _error(exc.code, exc.message, exc.details), status_code=exc.status
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError):
        return JSONResponse(
            _error("VALIDATION_ERROR", "Dữ liệu yêu cầu không hợp lệ", exc.errors()),
            status_code=422,
        )

    @app.exception_handler(IdempotencyConflict)
    async def idempotency_handler(_request: Request, exc: IdempotencyConflict):
        return JSONResponse(
            _error("IDEMPOTENCY_KEY_REUSED", str(exc)), status_code=422
        )

    @app.exception_handler(RevisionConflict)
    async def revision_handler(_request: Request, exc: RevisionConflict):
        return JSONResponse(_error("REVISION_CONFLICT", str(exc)), status_code=409)

    @app.exception_handler(CursorError)
    async def cursor_handler(_request: Request, exc: CursorError):
        return JSONResponse(_error("INVALID_CURSOR", str(exc)), status_code=400)

    @app.exception_handler(LedgerError)
    async def ledger_handler(_request: Request, exc: LedgerError):
        status = 404 if "not found" in str(exc).lower() else 409
        code = "NOT_FOUND" if status == 404 else "LIFECYCLE_CONFLICT"
        return JSONResponse(_error(code, str(exc)), status_code=status)

    @app.get("/pipeline/default", tags=["orchestration"])
    async def default_pipeline():
        return {"config_yaml": DEFAULT_PIPELINE_YAML}

    @app.post("/scans", tags=["orchestration"], status_code=201)
    async def start_scan(
        req: StartScanReq,
        claims: dict = Depends(require_auth),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    ):
        _ensure_ready(readiness)
        target, _pipeline = _resolve_request(req)
        try:
            await scope.check(target)
        except ScopeDenied as exc:
            raise ApiError(403, "SCOPE_DENIED", "target ngoài scope") from exc
        except (ScopeUnavailable, httpx.HTTPError, TimeoutError) as exc:
            raise ApiError(503, "SCOPE_UNAVAILABLE", "scope service không sẵn sàng") from exc
        key = _idempotency_key(idempotency_key)
        snapshot = await ledger.create_scan(
            StartScanSpec(
                target=target,
                mode=req.mode,
                exec_mode=req.exec_mode,
                created_at=datetime.now(timezone.utc),
            ),
            claims.get("sub", "unknown"),
            key,
        )
        payload = snapshot.model_dump(mode="json")
        payload["idempotency_key"] = key
        return payload

    @app.get("/scans", tags=["orchestration"])
    async def list_scans(
        status: ScanStatus | None = None,
        cursor: str | None = Query(default=None, max_length=256),
        limit: int = Query(default=20, ge=1, le=100),
        _claims: dict = Depends(require_auth),
    ):
        page = await ledger.list_scans(status, cursor, limit)
        return {
            "items": [item.model_dump(mode="json") for item in page.items],
            "next_cursor": page.next_cursor,
        }

    @app.get("/scans/{scan_id}", tags=["orchestration"])
    async def get_scan(scan_id: str, _claims: dict = Depends(require_auth)):
        _canonical_uuid(scan_id)
        return await ledger.get_scan(scan_id)

    @app.get("/scans/{scan_id}/report", tags=["orchestration"])
    async def scan_report(scan_id: str, _claims: dict = Depends(require_auth)):
        _canonical_uuid(scan_id)
        snapshot = await ledger.get_scan(scan_id)
        findings = []
        cursor = None
        while True:
            page = await ledger.list_results(scan_id, "findings", cursor, 100)
            findings.extend(page.items)
            if page.next_cursor is None:
                break
            cursor = page.next_cursor
        return build_report(snapshot, findings)

    @app.get("/history", tags=["history"])
    async def list_history(
        status: ScanStatus | None = None,
        target: str | None = Query(default=None, max_length=253),
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        _claims: dict = Depends(require_auth),
    ):
        store = _require_history(history)
        items, total = await store.alist(
            status=status.value if status else None, target=target, limit=limit, offset=offset
        )
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    @app.get("/history/{scan_id}", tags=["history"])
    async def history_detail(scan_id: str, _claims: dict = Depends(require_auth)):
        _canonical_uuid(scan_id)
        record = await _require_history(history).aget(scan_id)
        if record is None:
            raise ApiError(404, "NOT_FOUND", "Không có bản ghi lịch sử cho scan này")
        return record

    @app.get("/scans/{scan_id}/work", tags=["orchestration"])
    async def list_work(
        scan_id: str,
        stage: Literal["recon", "scan", "verification"] | None = None,
        status: WorkStatus | None = None,
        cursor: str | None = Query(default=None, max_length=256),
        limit: int = Query(default=20, ge=1, le=100),
        _claims: dict = Depends(require_auth),
    ):
        _canonical_uuid(scan_id)
        page = await ledger.list_work(scan_id, stage, status, cursor, limit)
        return {
            "items": [item.model_dump(mode="json") for item in page.items],
            "next_cursor": page.next_cursor,
        }

    @app.get("/scans/{scan_id}/results", tags=["orchestration"])
    async def list_results(
        scan_id: str,
        kind: Literal["assets", "findings", "verified", "execution"],
        cursor: str | None = Query(default=None, max_length=256),
        limit: int = Query(default=20, ge=1, le=100),
        _claims: dict = Depends(require_auth),
    ):
        _canonical_uuid(scan_id)
        page = await ledger.list_results(scan_id, kind, cursor, limit)
        return {"items": page.items, "next_cursor": page.next_cursor}

    @app.post("/scans/{scan_id}/cancel", tags=["orchestration"])
    async def cancel_scan(
        scan_id: str,
        req: CancelScanReq,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        _claims: dict = Depends(require_auth),
    ):
        _ensure_ready(readiness)
        _canonical_uuid(scan_id)
        was_open = (await ledger.get_scan(scan_id)).status not in TERMINAL_SCAN_STATUSES
        snapshot = await ledger.cancel_scan(
            scan_id, req.reason, _idempotency_key(idempotency_key)
        )
        # An idempotent replay returns the already-terminal scan: notify once only.
        if was_open and snapshot.status in TERMINAL_SCAN_STATUSES:
            await notify.send_scan_finished(snapshot)
        return snapshot

    @app.get("/scans/{scan_id}/stream", tags=["orchestration"])
    async def stream_scan(
        scan_id: str,
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
        _claims: dict = Depends(require_auth),
    ):
        _canonical_uuid(scan_id)
        if last_event_id is not None and (
            len(last_event_id) > 64
            or re.fullmatch(r"\d+-\d+", last_event_id) is None
        ):
            raise ApiError(400, "INVALID_LAST_EVENT_ID", "Last-Event-ID không hợp lệ")
        try:
            if hasattr(ledger, "redis"):
                await ledger.redis.ping()
            await ledger.get_scan(scan_id)
        except LedgerError:
            raise
        except Exception as exc:
            raise ApiError(503, "STREAM_UNAVAILABLE", "update stream chưa sẵn sàng") from exc
        return StreamingResponse(
            scan_update_events(ledger, scan_id, last_event_id),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/scans/{scan_id}/stage/{stage}/complete", tags=["orchestration"])
    async def manual_complete_removed(
        scan_id: str, stage: str, _claims: dict = Depends(require_auth)
    ):
        _canonical_uuid(scan_id)
        raise ApiError(
            410,
            "STAGE_MANUAL_COMPLETION_REMOVED",
            "Manual stage completion đã bị loại bỏ",
        )

    return app


_default_redis = redis_async.from_url(settings.REDIS_URL, decode_responses=True)
_default_readiness = ReadinessState(("redis", "recovery"))
_default_readiness.set("redis", False, "Redis not probed")
_default_readiness.set("recovery", False, "Recovery not started")
app = create_api_app(
    RedisLifecycleLedger(_default_redis),
    ScopeClient(),
    _default_readiness,
    enable_runtime=True,
    history=HistoryStore(os.getenv("HISTORY_DB_PATH", "/data/history.db")),
)
