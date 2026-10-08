"""Redis-backed authoritative lifecycle ledger with optimistic CAS mutations."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Generic, TypeVar
from uuid import UUID, uuid4, uuid5

from pydantic import ValidationError
from redis.exceptions import WatchError

from vts_common.config import settings
from vts_common.events import BUS_STREAM, command_stream
from vts_common.service import log_event
from vts_common.lifecycle import (
    ApprovalSummary,
    LifecycleEnvelopeV1,
    ResultSummary,
    ScanSnapshot,
    ScanStatus,
    StageSnapshot,
    StageStatus,
    WorkSnapshot,
    WorkStatus,
    WorkType,
    serialize_event,
)

from .fanout import WorkSpec, make_stage_run_id, make_work_id
from .state_machine import (
    LifecycleState,
    ScanRecord,
    StageRecord,
    WorkRecord,
)

T = TypeVar("T")
TERMINAL_SCAN_VALUES = {"succeeded", "failed", "timed_out", "canceled"}
TERMINAL_WORK_VALUES = {"completed", "failed", "timed_out", "canceled"}


class LedgerError(RuntimeError):
    pass


class RevisionConflict(LedgerError):
    pass


class IdempotencyConflict(LedgerError):
    pass


class CursorError(ValueError):
    pass


class ReplayWindowExpired(LedgerError):
    pass


@dataclass(frozen=True, slots=True)
class StartScanSpec:
    target: str
    mode: str
    exec_mode: str
    scan_id: str | None = None
    created_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    snapshot: ScanSnapshot
    work_id: str
    created: bool
    command_message_id: str | None = None


@dataclass(frozen=True, slots=True)
class ResultRecord:
    result_id: str
    scan_id: str
    kind: str
    event: str
    work_id: str
    ingested_at: datetime
    data: dict[str, Any]


@dataclass(frozen=True, slots=True)
class IngestResult:
    snapshot: ScanSnapshot
    duplicate: bool = False
    late: bool = False
    result: ResultRecord | None = None


@dataclass(frozen=True, slots=True)
class SnapshotUpdate:
    stream_id: str
    revision: int
    snapshot: ScanSnapshot


@dataclass(frozen=True, slots=True)
class Page(Generic[T]):
    items: list[T]
    next_cursor: str | None


def encode_cursor(offset: int) -> str:
    raw = f"offset:{offset}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> int:
    if cursor is None:
        return 0
    if len(cursor) > 256:
        raise CursorError("cursor is too long")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        prefix, value = raw.split(":", 1)
        if prefix != "offset" or int(value) < 0:
            raise ValueError
        return int(value)
    except (ValueError, UnicodeDecodeError, base64.binascii.Error) as exc:
        raise CursorError("invalid cursor") from exc


class RedisLifecycleLedger:
    def __init__(self, redis, namespace: str = "vts") -> None:
        self.redis = redis
        self.namespace = namespace.rstrip(":")

    def key(self, suffix: str) -> str:
        return f"{self.namespace}:{suffix}"

    async def create_scan(
        self,
        spec: StartScanSpec,
        actor: str,
        idempotency_key: str,
    ) -> ScanSnapshot:
        scan_id = spec.scan_id or str(uuid4())
        created_at = spec.created_at or datetime.now(timezone.utc)
        # A generated scan_id differs on every call, so only a caller-supplied
        # one may take part in the request fingerprint; otherwise a genuine
        # replay of the same request would always look like key reuse.
        request = {
            "target": spec.target,
            "mode": spec.mode,
            "exec_mode": spec.exec_mode,
        }
        if spec.scan_id is not None:
            request["scan_id"] = spec.scan_id
        request_hash = _hash_json(request)
        idem_key = self.key(f"idempotency:scan:{idempotency_key}")
        snapshot_key = self.key(f"scan:{scan_id}:snapshot")

        while True:
            async with self.redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(idem_key, snapshot_key)
                    existing = await pipe.hgetall(idem_key)
                    if existing:
                        if existing.get("request_hash") != request_hash:
                            raise IdempotencyConflict("IDEMPOTENCY_KEY_REUSED")
                        stored = await self.redis.get(existing["snapshot_key"])
                        if stored is None:
                            raise ReplayWindowExpired("REPLAY_WINDOW_EXPIRED")
                        return ScanSnapshot.model_validate_json(stored)
                    if await pipe.exists(snapshot_key):
                        raise IdempotencyConflict("scan already exists")

                    stages = _initial_stages(scan_id, spec.mode)
                    root_id = make_work_id(
                        scan_id,
                        WorkType.RECON_BOOTSTRAP,
                        spec.target,
                        "default",
                    )
                    root = WorkSnapshot(
                        work_id=root_id,
                        scan_id=scan_id,
                        stage_run_id=stages["recon"].stage_run_id,
                        work_type=WorkType.RECON_BOOTSTRAP,
                        service="recon-subdomain",
                        status=WorkStatus.QUEUED,
                        attempt=1,
                        max_attempts=settings.WORK_MAX_ATTEMPTS,
                        result_count=0,
                        queued_at=created_at,
                    )
                    stages["recon"] = stages["recon"].model_copy(
                        update={
                            "status": StageStatus.RUNNING,
                            "total_work": 1,
                            "open_work": 1,
                            "started_at": created_at,
                        }
                    )
                    queued = ScanSnapshot(
                        scan_id=scan_id,
                        revision=1,
                        status=ScanStatus.QUEUED,
                        target=spec.target,
                        mode=spec.mode,
                        exec_mode=spec.exec_mode,
                        created_at=created_at,
                        queued_at=created_at,
                        updated_at=created_at,
                        stages=stages,
                        approval_summary=ApprovalSummary(),
                        result_summary=ResultSummary(),
                    )
                    running = queued.model_copy(
                        update={
                            "revision": 2,
                            "status": ScanStatus.RUNNING,
                            "started_at": created_at,
                            "updated_at": created_at,
                        }
                    )
                    command = _command_for_work(
                        root,
                        spec.target,
                        {"target": spec.target, "mode": spec.mode},
                        settings.WORK_BOOTSTRAP_TIMEOUT_SECONDS,
                        None,
                    )
                    pipe.multi()
                    pipe.set(snapshot_key, running.model_dump_json())
                    pipe.zadd(
                        self.key("scan:index"),
                        {scan_id: created_at.timestamp()},
                    )
                    pipe.sadd(self.key(f"scan:{scan_id}:works"), root_id)
                    pipe.hset(self.key(f"scan:{scan_id}:meta"), mapping={"actor": actor})
                    root_mapping = _work_mapping(root)
                    root_mapping.update({
                        "input": json.dumps({"target": spec.target, "mode": spec.mode}),
                        "variant": "default",
                        "timeout_seconds": settings.WORK_BOOTSTRAP_TIMEOUT_SECONDS,
                    })
                    pipe.hset(self.key(f"work:{root_id}"), mapping=root_mapping)
                    for stage in stages.values():
                        pipe.hset(
                            self.key(f"stage:{stage.stage_run_id}"),
                            mapping=_stage_mapping(stage),
                        )
                    pipe.hset(
                        idem_key,
                        mapping={
                            "request_hash": request_hash,
                            "snapshot_key": snapshot_key,
                            "actor": actor,
                        },
                    )
                    pipe.expire(idem_key, settings.DEDUPE_RETENTION_SECONDS)
                    pipe.xadd(
                        command_stream("recon-subdomain"),
                        {"payload": serialize_event(command)},
                    )
                    pipe.xadd(
                        self.key(f"scan:{scan_id}:updates"),
                        {"revision": 1, "snapshot": queued.model_dump_json()},
                        maxlen=settings.UPDATE_STREAM_MAXLEN,
                        approximate=True,
                    )
                    pipe.xadd(
                        self.key(f"scan:{scan_id}:updates"),
                        {"revision": 2, "snapshot": running.model_dump_json()},
                        maxlen=settings.UPDATE_STREAM_MAXLEN,
                        approximate=True,
                    )
                    await pipe.execute()
                    return running
                except WatchError:
                    continue

    async def register_work(
        self,
        spec: WorkSpec,
        *,
        expected_revision: int,
        cause_work_id: str | None,
    ) -> RegistrationResult:
        snapshot_key = self.key(f"scan:{spec.scan_id}:snapshot")
        work_key = self.key(f"work:{spec.work_id}")
        causes_key = self.key(f"work:{spec.work_id}:causes")
        while True:
            async with self.redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(snapshot_key, work_key)
                    raw_snapshot = await pipe.get(snapshot_key)
                    if raw_snapshot is None:
                        raise LedgerError("scan not found")
                    snapshot = ScanSnapshot.model_validate_json(raw_snapshot)
                    if snapshot.revision != expected_revision:
                        raise RevisionConflict("expected revision does not match")
                    if snapshot.status.value in TERMINAL_SCAN_VALUES:
                        raise LedgerError("scan is terminal")
                    if await pipe.exists(work_key):
                        pipe.multi()
                        if cause_work_id:
                            pipe.sadd(causes_key, cause_work_id)
                        await pipe.execute()
                        return RegistrationResult(snapshot, spec.work_id, False)

                    stage = snapshot.stages[spec.stage]
                    updated_stage = stage.model_copy(
                        update={
                            "status": StageStatus.RUNNING
                            if stage.status is StageStatus.PENDING
                            else stage.status,
                            "total_work": stage.total_work + 1,
                            "open_work": stage.open_work + 1,
                            "started_at": stage.started_at
                            or datetime.now(timezone.utc),
                        }
                    )
                    revision = snapshot.revision + 1
                    updated = snapshot.model_copy(
                        update={
                            "revision": revision,
                            "updated_at": datetime.now(timezone.utc),
                            "stages": {
                                **snapshot.stages,
                                spec.stage: updated_stage,
                            },
                        }
                    )
                    work = WorkSnapshot(
                        work_id=spec.work_id,
                        scan_id=spec.scan_id,
                        stage_run_id=spec.stage_run_id,
                        parent_work_id=spec.parent_work_id,
                        work_type=spec.work_type,
                        service=spec.service,
                        status=WorkStatus.QUEUED,
                        attempt=1,
                        max_attempts=spec.max_attempts,
                        dispatch_state=spec.dispatch_state,
                        result_count=0,
                        queued_at=datetime.now(timezone.utc),
                    )
                    command = None
                    if spec.dispatch_state == "ready":
                        command = _command_for_work(
                            work,
                            spec.variant,
                            spec.input,
                            spec.timeout_seconds,
                            spec.parent_work_id,
                        )
                    pipe.multi()
                    pipe.set(snapshot_key, updated.model_dump_json())
                    pipe.sadd(self.key(f"scan:{spec.scan_id}:works"), spec.work_id)
                    work_mapping = _work_mapping(work)
                    work_mapping.update({
                        "input": json.dumps(spec.input, ensure_ascii=False),
                        "variant": spec.variant,
                        "timeout_seconds": spec.timeout_seconds,
                    })
                    pipe.hset(work_key, mapping=work_mapping)
                    pipe.hset(
                        self.key(f"stage:{spec.stage_run_id}"),
                        mapping=_stage_mapping(updated_stage),
                    )
                    if cause_work_id:
                        pipe.sadd(causes_key, cause_work_id)
                    command_result_index = None
                    if command is not None:
                        command_result_index = len(pipe.command_stack)
                        pipe.xadd(
                            command_stream(spec.service),
                            {"payload": serialize_event(command)},
                        )
                    pipe.xadd(
                        self.key(f"scan:{spec.scan_id}:updates"),
                        {
                            "revision": revision,
                            "snapshot": updated.model_dump_json(),
                        },
                        maxlen=settings.UPDATE_STREAM_MAXLEN,
                        approximate=True,
                    )
                    results = await pipe.execute()
                    command_id = (
                        results[command_result_index]
                        if command_result_index is not None
                        else None
                    )
                    return RegistrationResult(
                        updated, spec.work_id, True, command_id
                    )
                except WatchError:
                    continue

    async def ingest(
        self,
        event: LifecycleEnvelopeV1,
        ingested_at: datetime,
    ) -> IngestResult:
        snapshot_key = self.key(f"scan:{event.scan_id}:snapshot")
        event_ids_key = self.key(f"scan:{event.scan_id}:event_ids")
        work_key = self.key(f"work:{event.work_id}")
        result_ids_key = self.key(f"scan:{event.scan_id}:result_ids")
        while True:
            async with self.redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(
                        snapshot_key, event_ids_key, work_key, result_ids_key
                    )
                    raw_snapshot = await pipe.get(snapshot_key)
                    if raw_snapshot is None:
                        raise LedgerError("scan not found")
                    snapshot = ScanSnapshot.model_validate_json(raw_snapshot)
                    if await pipe.hexists(event_ids_key, event.event_id):
                        return IngestResult(snapshot, duplicate=True)
                    if snapshot.status.value in TERMINAL_SCAN_VALUES:
                        await pipe.reset()
                        await self._write_late(event, "scan_terminal", ingested_at)
                        return IngestResult(snapshot, late=True)
                    work_raw = await pipe.hgetall(work_key)
                    if not work_raw:
                        await pipe.reset()
                        await self._write_late(event, "unknown_work", ingested_at)
                        return IngestResult(snapshot, late=True)
                    work = _work_from_mapping(work_raw)
                    if event.attempt != work.attempt:
                        await pipe.reset()
                        await self._write_late(event, "stale_attempt", ingested_at)
                        return IngestResult(snapshot, late=True)
                    if event.event.startswith("approval."):
                        return await self._commit_approval_event(
                            pipe,
                            snapshot,
                            work,
                            work_raw,
                            event,
                            ingested_at,
                            snapshot_key,
                            event_ids_key,
                        )
                    if work.status.value in TERMINAL_WORK_VALUES:
                        await pipe.reset()
                        await self._write_late(event, "work_terminal", ingested_at)
                        return IngestResult(snapshot, late=True)

                    if event.event.startswith(("asset.", "vuln.")):
                        result_id = event.data.get("result_id")
                        if not result_id:
                            raise LedgerError("result_id required")
                        if await pipe.hexists(result_ids_key, result_id):
                            pipe.multi()
                            pipe.hset(event_ids_key, event.event_id, ingested_at.timestamp())
                            await pipe.execute()
                            return IngestResult(snapshot, duplicate=True)
                        return await self._commit_result(
                            pipe,
                            snapshot,
                            work,
                            event,
                            result_id,
                            ingested_at,
                            snapshot_key,
                            event_ids_key,
                            result_ids_key,
                        )
                    return await self._commit_work_event(
                        pipe,
                        snapshot,
                        work,
                        event,
                        ingested_at,
                        snapshot_key,
                        event_ids_key,
                        work_key,
                    )
                except WatchError:
                    continue

    async def _commit_approval_event(
        self,
        pipe,
        snapshot,
        source_work,
        source_work_raw,
        event,
        ingested_at,
        snapshot_key,
        event_ids_key,
    ) -> IngestResult:
        values = snapshot.approval_summary.model_dump()
        topic = event.event
        execution_id = event.data.get("execution_work_id")
        execution_key = self.key(f"work:{execution_id}") if execution_id else None
        execution_raw = {}
        if execution_key:
            await pipe.watch(execution_key)
            execution_raw = await pipe.hgetall(execution_key)

        if topic == "approval.requested":
            values["total"] += 1
            values["pending"] += 1
        elif topic == "approval.approved":
            values["pending"] = max(0, values["pending"] - 1)
            values["approved_awaiting_execution"] += 1
        elif topic == "approval.rejected":
            if values["pending"]:
                values["pending"] -= 1
            else:
                values["approved_awaiting_execution"] = max(
                    0, values["approved_awaiting_execution"] - 1
                )
            values["rejected"] += 1
        elif topic == "approval.execution.requested":
            values["approved_awaiting_execution"] = max(
                0, values["approved_awaiting_execution"] - 1
            )
            values["executing"] += 1
        elif topic == "approval.executed":
            if values["executing"]:
                values["executing"] -= 1
            else:
                values["approved_awaiting_execution"] = max(
                    0, values["approved_awaiting_execution"] - 1
                )
            values["executed"] += 1
        elif topic == "approval.execution_failed":
            if values["executing"]:
                values["executing"] -= 1
            elif values["approved_awaiting_execution"]:
                values["approved_awaiting_execution"] -= 1
            else:
                values["pending"] = max(0, values["pending"] - 1)
            values["failed"] += 1
        else:
            pipe.multi()
            pipe.hset(event_ids_key, event.event_id, ingested_at.timestamp())
            await pipe.execute()
            return IngestResult(snapshot, duplicate=True)

        summary = ApprovalSummary(**values)
        stages = dict(snapshot.stages)
        updated_execution = None
        command = None
        if execution_raw:
            updated_execution = _work_from_mapping(execution_raw)
            verification = stages["verification"]
            if topic == "approval.rejected" and updated_execution.status is WorkStatus.QUEUED:
                updated_execution = updated_execution.model_copy(
                    update={
                        "status": WorkStatus.CANCELED,
                        "completed_at": ingested_at,
                        "outcome": {
                            "type": "canceled",
                            "code": "approval_rejected",
                        },
                    }
                )
                stages["verification"] = verification.model_copy(
                    update={"open_work": max(0, verification.open_work - 1)}
                )
            elif topic == "approval.execution.requested" and updated_execution.status is WorkStatus.QUEUED:
                updated_execution = updated_execution.model_copy(
                    update={"dispatch_state": "ready"}
                )
                input_data = json.loads(execution_raw.get("input", "{}"))
                input_data["dry_run"] = bool(event.data.get("dry_run", True))
                command = _command_for_work(
                    updated_execution,
                    execution_raw.get("variant", "default"),
                    input_data,
                    int(
                        execution_raw.get(
                            "timeout_seconds", settings.WORK_EXECUTE_TIMEOUT_SECONDS
                        )
                    ),
                    updated_execution.parent_work_id,
                )

        force_timeout = (
            topic == "approval.execution_failed"
            and event.data.get("error_code") == "APPROVAL_DEADLINE"
        )
        if force_timeout:
            verification = stages["verification"]
            stages["verification"] = verification.model_copy(
                update={
                    "status": StageStatus.TIMED_OUT,
                    "open_work": max(0, verification.open_work - 1),
                    "timed_out_work": verification.timed_out_work + 1,
                    "completed_at": ingested_at,
                    "outcome": {"type": "timeout", "code": "APPROVAL_DEADLINE"},
                }
            )
            if updated_execution is not None and updated_execution.status not in {
                WorkStatus.COMPLETED,
                WorkStatus.FAILED,
                WorkStatus.TIMED_OUT,
                WorkStatus.CANCELED,
            }:
                updated_execution = updated_execution.model_copy(
                    update={
                        "status": WorkStatus.TIMED_OUT,
                        "completed_at": ingested_at,
                        "outcome": {"type": "timeout", "code": "APPROVAL_DEADLINE"},
                    }
                )

        unresolved = (
            summary.pending
            + summary.approved_awaiting_execution
            + summary.executing
        )
        status = (
            ScanStatus.TIMED_OUT
            if force_timeout
            else ScanStatus.AWAITING_APPROVAL
            if unresolved
            else ScanStatus.RUNNING
        )
        candidate = snapshot.model_copy(
            update={
                "status": status,
                "approval_summary": summary,
                "stages": stages,
            }
        )
        if not unresolved:
            status, stages = _reconcile_snapshot(candidate, stages, ingested_at)
        closed = []
        if status in {ScanStatus.TIMED_OUT, ScanStatus.FAILED}:
            code = "APPROVAL_DEADLINE" if force_timeout else "STAGE_FAILED"
            stages = _abort_stages(stages, "verification", ingested_at, code)
            closed = await self._close_open_work(
                pipe,
                snapshot.scan_id,
                ingested_at,
                code,
                {source_work.work_id, execution_id or ""},
            )
            stages = _release_closed_work(stages, closed)
        revision = snapshot.revision + 1
        updated = candidate.model_copy(
            update={
                "revision": revision,
                "status": status,
                "stages": stages,
                "awaiting_approval_at": snapshot.awaiting_approval_at
                or (ingested_at if unresolved else None),
                "updated_at": ingested_at,
                "last_progress_at": ingested_at,
                "completed_at": ingested_at
                if status.value in TERMINAL_SCAN_VALUES
                else snapshot.completed_at,
                "outcome": {
                    "type": "timeout",
                    "code": "APPROVAL_DEADLINE",
                }
                if force_timeout
                else {
                    "type": "success",
                    "code": "SCAN_SUCCEEDED",
                }
                if status is ScanStatus.SUCCEEDED
                else {"type": "failure", "code": "STAGE_FAILED"}
                if status is ScanStatus.FAILED
                else snapshot.outcome,
            }
        )
        pipe.multi()
        pipe.hset(event_ids_key, event.event_id, ingested_at.timestamp())
        self._queue_closed_work(pipe, closed)
        if execution_key and updated_execution is not None:
            pipe.hset(execution_key, mapping=_work_mapping(updated_execution))
            if topic == "approval.execution.requested":
                pipe.hset(
                    execution_key,
                    mapping={
                        "input": json.dumps(input_data, ensure_ascii=False),
                        "dispatch_state": "ready",
                    },
                )
        if command is not None:
            pipe.xadd(
                command_stream(updated_execution.service),
                {"payload": serialize_event(command)},
            )
        pipe.set(snapshot_key, updated.model_dump_json())
        for stage in stages.values():
            pipe.hset(
                self.key(f"stage:{stage.stage_run_id}"),
                mapping=_stage_mapping(stage),
            )
        pipe.xadd(
            self.key(f"scan:{snapshot.scan_id}:updates"),
            {"revision": revision, "snapshot": updated.model_dump_json()},
            maxlen=settings.UPDATE_STREAM_MAXLEN,
            approximate=True,
        )
        await pipe.execute()
        if updated.status.value in TERMINAL_SCAN_VALUES:
            await self._apply_terminal_ttls(updated.scan_id)
        return IngestResult(updated)

    async def _commit_result(
        self,
        pipe,
        snapshot,
        work,
        event,
        result_id,
        ingested_at,
        snapshot_key,
        event_ids_key,
        result_ids_key,
    ) -> IngestResult:
        kind = _result_kind(event.event)
        stage = snapshot.stages[work.work_type.value.split(".", 1)[0]]
        updated_stage = stage.model_copy(
            update={"result_count": stage.result_count + 1}
        )
        summary_values = snapshot.result_summary.model_dump()
        summary_values[kind] += 1
        revision = snapshot.revision + 1
        updated = snapshot.model_copy(
            update={
                "revision": revision,
                "updated_at": ingested_at,
                "last_progress_at": ingested_at,
                "stages": {**snapshot.stages, updated_stage.name: updated_stage},
                "result_summary": ResultSummary(**summary_values),
            }
        )
        record = ResultRecord(
            result_id=result_id,
            scan_id=snapshot.scan_id,
            kind=kind,
            event=event.event,
            work_id=work.work_id,
            ingested_at=ingested_at,
            data=event.data,
        )
        pipe.multi()
        pipe.hset(event_ids_key, event.event_id, ingested_at.timestamp())
        pipe.hset(result_ids_key, result_id, event.event_id)
        pipe.set(
            self.key(f"result:{result_id}"),
            json.dumps(_result_mapping(record), ensure_ascii=False),
        )
        pipe.zadd(
            self.key(f"scan:{snapshot.scan_id}:results:{kind}"),
            {result_id: ingested_at.timestamp()},
        )
        pipe.set(snapshot_key, updated.model_dump_json())
        pipe.hset(
            self.key(f"stage:{updated_stage.stage_run_id}"),
            mapping=_stage_mapping(updated_stage),
        )
        pipe.xadd(
            self.key(f"scan:{snapshot.scan_id}:updates"),
            {"revision": revision, "snapshot": updated.model_dump_json()},
            maxlen=settings.UPDATE_STREAM_MAXLEN,
            approximate=True,
        )
        await pipe.execute()
        return IngestResult(updated, result=record)

    async def _commit_work_event(
        self,
        pipe,
        snapshot,
        work,
        event,
        ingested_at,
        snapshot_key,
        event_ids_key,
        work_key,
    ) -> IngestResult:
        stage_name = work.work_type.value.split(".", 1)[0]
        stage = snapshot.stages[stage_name]
        updated_work = work
        updated_stage = stage
        if event.event == "work.started":
            updated_work = work.model_copy(
                update={"status": WorkStatus.RUNNING, "started_at": ingested_at}
            )
            if stage.status is StageStatus.PENDING:
                updated_stage = stage.model_copy(
                    update={"status": StageStatus.RUNNING, "started_at": ingested_at}
                )
        elif event.event == "work.progress":
            updated_work = work.model_copy(
                update={"last_progress_at": ingested_at}
            )
        elif event.event == "work.completed":
            count = int(event.data.get("result_count", 0))
            updated_work = work.model_copy(
                update={
                    "status": WorkStatus.COMPLETED,
                    "result_count": count,
                    "completed_at": ingested_at,
                    "outcome": {"type": "success"},
                }
            )
            updated_stage = stage.model_copy(
                update={
                    "open_work": max(0, stage.open_work - 1),
                    "completed_work": stage.completed_work + 1,
                    # result_count is already incremented per accepted result
                    # event in _commit_result; adding `count` again double-counted.
                }
            )
        elif event.event == "work.failed":
            if event.data.get("retryable") and work.attempt < work.max_attempts:
                updated_work = work.model_copy(
                    update={
                        "status": WorkStatus.QUEUED,
                        "attempt": work.attempt + 1,
                        "started_at": None,
                    }
                )
            else:
                updated_work = work.model_copy(
                    update={
                        "status": WorkStatus.FAILED,
                        "completed_at": ingested_at,
                        "outcome": {
                            "type": "failure",
                            "code": event.data.get("error_code"),
                        },
                    }
                )
                updated_stage = stage.model_copy(
                    update={
                        "status": StageStatus.FAILED,
                        "open_work": max(0, stage.open_work - 1),
                        "failed_work": stage.failed_work + 1,
                        "completed_at": ingested_at,
                    }
                )
        else:
            pipe.multi()
            pipe.hset(event_ids_key, event.event_id, ingested_at.timestamp())
            await pipe.execute()
            return IngestResult(snapshot, duplicate=True)

        stages = {**snapshot.stages, stage_name: updated_stage}
        updated_status, stages = _reconcile_snapshot(snapshot, stages, ingested_at)
        closed = []
        outcome = snapshot.outcome
        if updated_status is ScanStatus.SUCCEEDED:
            outcome = {"type": "success", "code": "SCAN_SUCCEEDED"}
        elif updated_status is ScanStatus.FAILED:
            outcome = {"type": "failure", "code": "STAGE_FAILED"}
            stages = _abort_stages(stages, stage_name, ingested_at, "STAGE_FAILED")
            closed = await self._close_open_work(
                pipe, snapshot.scan_id, ingested_at, "STAGE_FAILED", {work.work_id}
            )
            stages = _release_closed_work(stages, closed)
        revision = snapshot.revision + 1
        updated = snapshot.model_copy(
            update={
                "revision": revision,
                "status": updated_status,
                "updated_at": ingested_at,
                "last_progress_at": ingested_at,
                "completed_at": ingested_at
                if updated_status.value in TERMINAL_SCAN_VALUES
                else snapshot.completed_at,
                "outcome": outcome,
                "stages": stages,
            }
        )
        pipe.multi()
        pipe.hset(event_ids_key, event.event_id, ingested_at.timestamp())
        pipe.hset(work_key, mapping=_work_mapping(updated_work))
        for stage in stages.values():
            pipe.hset(
                self.key(f"stage:{stage.stage_run_id}"),
                mapping=_stage_mapping(stage),
            )
        self._queue_closed_work(pipe, closed)
        pipe.set(snapshot_key, updated.model_dump_json())
        pipe.xadd(
            self.key(f"scan:{snapshot.scan_id}:updates"),
            {"revision": revision, "snapshot": updated.model_dump_json()},
            maxlen=settings.UPDATE_STREAM_MAXLEN,
            approximate=True,
        )
        await pipe.execute()
        if updated.status.value in TERMINAL_SCAN_VALUES:
            await self._apply_terminal_ttls(updated.scan_id)
        return IngestResult(updated)

    async def get_scan(self, scan_id: str) -> ScanSnapshot:
        raw = await self.redis.get(self.key(f"scan:{scan_id}:snapshot"))
        if raw is None:
            raise LedgerError("scan not found")
        return ScanSnapshot.model_validate_json(raw)

    async def _close_open_work(
        self,
        pipe,
        scan_id: str,
        now: datetime,
        code: str,
        exclude: set[str] = frozenset(),
    ) -> list[tuple[str, WorkSnapshot]]:
        """Read (before MULTI) every non-terminal work of a scan becoming terminal.

        A terminal scan accepts no further events, so any work still queued or
        running would otherwise stay open forever in the authoritative ledger.
        """
        closed = []
        for work_id in await pipe.smembers(self.key(f"scan:{scan_id}:works")):
            if work_id in exclude:
                continue
            raw = await pipe.hgetall(self.key(f"work:{work_id}"))
            if not raw:
                continue
            work = _work_from_mapping(raw)
            if work.status.value in TERMINAL_WORK_VALUES:
                continue
            closed.append(
                (
                    work_id,
                    work.model_copy(
                        update={
                            "status": WorkStatus.CANCELED,
                            "completed_at": now,
                            "outcome": {"type": "canceled", "code": code},
                        }
                    ),
                )
            )
        return closed

    def _queue_closed_work(self, pipe, closed) -> None:
        """Queue (after MULTI) the writes for work returned by _close_open_work."""
        for work_id, work in closed:
            pipe.hset(self.key(f"work:{work_id}"), mapping=_work_mapping(work))
            pipe.zrem(self.key("retry"), work_id)

    async def _indexed_snapshot(self, scan_id: str) -> ScanSnapshot | None:
        """Load a scan listed in the index, skipping expired or foreign records.

        One unreadable entry must not take down listing, recovery or the
        reapers for every other scan.
        """
        raw = await self.redis.get(self.key(f"scan:{scan_id}:snapshot"))
        if raw is None:
            return None
        try:
            return ScanSnapshot.model_validate_json(raw)
        except ValidationError:
            log_event("error", "skipping invalid scan snapshot", scan_id=scan_id)
            return None

    async def list_scans(
        self,
        status: ScanStatus | None,
        cursor: str | None,
        limit: int,
    ) -> Page[ScanSnapshot]:
        _validate_limit(limit)
        offset = decode_cursor(cursor)
        ids = await self.redis.zrevrange(self.key("scan:index"), 0, -1)
        items = []
        for scan_id in ids:
            snapshot = await self._indexed_snapshot(scan_id)
            if snapshot is None:
                continue
            if status is None or snapshot.status is status:
                items.append(snapshot)
        selected = items[offset : offset + limit]
        next_cursor = (
            encode_cursor(offset + limit) if offset + limit < len(items) else None
        )
        return Page(selected, next_cursor)

    async def list_work(
        self,
        scan_id: str,
        stage: str | None,
        status: WorkStatus | None,
        cursor: str | None,
        limit: int,
    ) -> Page[WorkSnapshot]:
        _validate_limit(limit)
        offset = decode_cursor(cursor)
        ids = sorted(await self.redis.smembers(self.key(f"scan:{scan_id}:works")))
        items = []
        for work_id in ids:
            raw = await self.redis.hgetall(self.key(f"work:{work_id}"))
            if not raw:
                continue
            work = _work_from_mapping(raw)
            work_stage = work.work_type.value.split(".", 1)[0]
            if stage is not None and work_stage != stage:
                continue
            if status is not None and work.status is not status:
                continue
            items.append(work)
        selected = items[offset : offset + limit]
        next_cursor = (
            encode_cursor(offset + limit) if offset + limit < len(items) else None
        )
        return Page(selected, next_cursor)

    async def list_results(
        self,
        scan_id: str,
        kind: str,
        cursor: str | None,
        limit: int,
    ) -> Page[ResultRecord]:
        _validate_limit(limit)
        offset = decode_cursor(cursor)
        ids = await self.redis.zrange(
            self.key(f"scan:{scan_id}:results:{kind}"), 0, -1
        )
        records = []
        for result_id in ids[offset : offset + limit]:
            raw = await self.redis.get(self.key(f"result:{result_id}"))
            if raw:
                value = json.loads(raw)
                value["ingested_at"] = datetime.fromisoformat(value["ingested_at"])
                records.append(ResultRecord(**value))
        next_cursor = (
            encode_cursor(offset + limit) if offset + limit < len(ids) else None
        )
        return Page(records, next_cursor)

    async def cancel_scan(
        self, scan_id: str, reason: str, idempotency_key: str
    ) -> ScanSnapshot:
        snapshot_key = self.key(f"scan:{scan_id}:snapshot")
        idem_key = self.key(f"idempotency:scan:{idempotency_key}")
        request_hash = _hash_json({"scan_id": scan_id, "reason": reason})
        while True:
            async with self.redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(snapshot_key, idem_key)
                    existing = await pipe.hgetall(idem_key)
                    if existing:
                        if existing.get("request_hash") != request_hash:
                            raise IdempotencyConflict("IDEMPOTENCY_KEY_REUSED")
                        return await self.get_scan(scan_id)
                    snapshot = await self.get_scan(scan_id)
                    if snapshot.status.value in TERMINAL_SCAN_VALUES:
                        return snapshot
                    stages = {}
                    for name, stage in snapshot.stages.items():
                        if stage.status is StageStatus.PENDING:
                            stages[name] = stage.model_copy(
                                update={
                                    "status": StageStatus.SKIPPED,
                                    "sealed": True,
                                    "completed_at": datetime.now(timezone.utc),
                                }
                            )
                        elif stage.status is StageStatus.RUNNING:
                            stages[name] = stage.model_copy(
                                update={
                                    "status": StageStatus.FAILED,
                                    "completed_at": datetime.now(timezone.utc),
                                    "outcome": {"type": "canceled"},
                                }
                            )
                        else:
                            stages[name] = stage
                    now = datetime.now(timezone.utc)
                    closed = await self._close_open_work(
                        pipe, scan_id, now, "SCAN_CANCELED"
                    )
                    stages = _release_closed_work(stages, closed)
                    updated = snapshot.model_copy(
                        update={
                            "revision": snapshot.revision + 1,
                            "status": ScanStatus.CANCELED,
                            "outcome": {"type": "canceled", "code": reason},
                            "updated_at": now,
                            "completed_at": now,
                            "stages": stages,
                        }
                    )
                    pipe.multi()
                    pipe.set(snapshot_key, updated.model_dump_json())
                    for stage in stages.values():
                        pipe.hset(
                            self.key(f"stage:{stage.stage_run_id}"),
                            mapping=_stage_mapping(stage),
                        )
                    self._queue_closed_work(pipe, closed)
                    pipe.hset(
                        idem_key,
                        mapping={
                            "request_hash": request_hash,
                            "snapshot_key": snapshot_key,
                        },
                    )
                    pipe.expire(idem_key, settings.DEDUPE_RETENTION_SECONDS)
                    pipe.hset(
                        self.key(f"scan:{scan_id}:event_ids"),
                        "_terminal",
                        now.timestamp(),
                    )
                    pipe.xadd(
                        self.key(f"scan:{scan_id}:updates"),
                        {
                            "revision": updated.revision,
                            "snapshot": updated.model_dump_json(),
                        },
                        maxlen=settings.UPDATE_STREAM_MAXLEN,
                        approximate=True,
                    )
                    await pipe.execute()
                    await self._apply_terminal_ttls(scan_id)
                    return updated
                except WatchError:
                    continue

    async def schedule_retry(
        self, work_id: str, attempt: int, not_before: datetime
    ) -> None:
        await self.redis.zadd(
            self.key("retry"), {work_id: not_before.timestamp()}
        )
        await self.redis.hset(
            self.key(f"work:{work_id}"), mapping={"attempt": attempt}
        )

    async def dispatch_due_retries(self, now: datetime) -> int:
        retry_key = self.key("retry")
        due = await self.redis.zrangebyscore(retry_key, "-inf", now.timestamp())
        dispatched = 0
        for work_id in due:
            work_key = self.key(f"work:{work_id}")
            while True:
                async with self.redis.pipeline(transaction=True) as pipe:
                    try:
                        await pipe.watch(retry_key, work_key)
                        score = await pipe.zscore(retry_key, work_id)
                        raw = await pipe.hgetall(work_key)
                        if score is None or score > now.timestamp() or not raw:
                            break
                        work = _work_from_mapping(raw)
                        snapshot = await self.get_scan(work.scan_id)
                        if (
                            snapshot.status.value in TERMINAL_SCAN_VALUES
                            or work.status is not WorkStatus.QUEUED
                        ):
                            pipe.multi()
                            pipe.zrem(retry_key, work_id)
                            await pipe.execute()
                            break
                        input_data = json.loads(raw.get("input", "{}"))
                        command = _command_for_work(
                            work,
                            raw.get("variant", "default"),
                            input_data,
                            int(raw.get("timeout_seconds", 60)),
                            work.parent_work_id,
                        )
                        pipe.multi()
                        pipe.xadd(
                            command_stream(work.service),
                            {"payload": serialize_event(command)},
                        )
                        pipe.zrem(retry_key, work_id)
                        await pipe.execute()
                        dispatched += 1
                        break
                    except WatchError:
                        continue
        return dispatched

    async def recover_active(self) -> list[LifecycleState]:
        active = []
        ids = await self.redis.zrange(self.key("scan:index"), 0, -1)
        for scan_id in ids:
            snapshot = await self._indexed_snapshot(scan_id)
            if snapshot is None or snapshot.status.value in TERMINAL_SCAN_VALUES:
                continue
            work_items = []
            work_cursor = None
            while True:
                works_page = await self.list_work(
                    scan_id, None, None, work_cursor, 100
                )
                work_items.extend(works_page.items)
                if works_page.next_cursor is None:
                    break
                work_cursor = works_page.next_cursor
            works = {
                work.work_id: WorkRecord(
                    work_id=work.work_id,
                    scan_id=work.scan_id,
                    stage_run_id=work.stage_run_id,
                    stage=work.work_type.value.split(".", 1)[0],
                    work_type=work.work_type,
                    service=work.service,
                    status=work.status,
                    attempt=work.attempt,
                    max_attempts=work.max_attempts,
                    parent_work_id=work.parent_work_id,
                    dispatch_state=work.dispatch_state,
                    result_count=work.result_count,
                    queued_at=work.queued_at,
                    started_at=work.started_at,
                    last_progress_at=work.last_progress_at,
                    completed_at=work.completed_at,
                    outcome=work.outcome,
                )
                for work in work_items
            }
            stages = {
                name: StageRecord(
                    stage_run_id=stage.stage_run_id,
                    name=name,
                    status=stage.status,
                    enabled=stage.status is not StageStatus.SKIPPED
                    or name == "recon",
                    sealed=stage.sealed,
                    total_work=stage.total_work,
                    open_work=stage.open_work,
                    completed_work=stage.completed_work,
                    failed_work=stage.failed_work,
                    timed_out_work=stage.timed_out_work,
                    result_count=stage.result_count,
                    started_at=stage.started_at,
                    completed_at=stage.completed_at,
                    outcome=stage.outcome,
                )
                for name, stage in snapshot.stages.items()
            }
            active.append(
                LifecycleState(
                    scan=ScanRecord(
                        scan_id=snapshot.scan_id,
                        status=snapshot.status,
                        revision=snapshot.revision,
                        target=snapshot.target,
                        mode=snapshot.mode,
                        exec_mode=snapshot.exec_mode,
                        created_at=snapshot.created_at,
                        queued_at=snapshot.queued_at,
                        updated_at=snapshot.updated_at,
                        started_at=snapshot.started_at,
                        awaiting_approval_at=snapshot.awaiting_approval_at,
                        last_progress_at=snapshot.last_progress_at,
                        completed_at=snapshot.completed_at,
                        outcome=snapshot.outcome,
                    ),
                    stages=stages,
                    works=works,
                )
            )
        return active

    async def expire_due(self, now: datetime) -> int:
        expired = 0
        for scan_id in await self.redis.zrange(self.key("scan:index"), 0, -1):
            snapshot_key = self.key(f"scan:{scan_id}:snapshot")
            while True:
                async with self.redis.pipeline(transaction=True) as pipe:
                    try:
                        await pipe.watch(snapshot_key)
                        raw = await pipe.get(snapshot_key)
                        if not raw:
                            break
                        try:
                            snapshot = ScanSnapshot.model_validate_json(raw)
                        except ValidationError:
                            break
                        if snapshot.status.value in TERMINAL_SCAN_VALUES or snapshot.status is ScanStatus.AWAITING_APPROVAL:
                            break
                        if (now - snapshot.created_at).total_seconds() < settings.TECHNICAL_WATCHDOG_SECONDS:
                            break
                        stages = {}
                        for name, stage in snapshot.stages.items():
                            if stage.status is StageStatus.RUNNING:
                                stages[name] = stage.model_copy(
                                    update={
                                        "status": StageStatus.TIMED_OUT,
                                        "completed_at": now,
                                        "outcome": {
                                            "type": "timeout",
                                            "code": "TECHNICAL_WATCHDOG",
                                        },
                                    }
                                )
                            elif stage.status is StageStatus.PENDING:
                                stages[name] = stage.model_copy(
                                    update={
                                        "status": StageStatus.SKIPPED,
                                        "sealed": True,
                                        "completed_at": now,
                                        "outcome": {
                                            "type": "skipped",
                                            "code": "UPSTREAM_TIMED_OUT",
                                        },
                                    }
                                )
                            else:
                                stages[name] = stage
                        updated = snapshot.model_copy(
                            update={
                                "revision": snapshot.revision + 1,
                                "status": ScanStatus.TIMED_OUT,
                                "outcome": {
                                    "type": "timeout",
                                    "code": "TECHNICAL_WATCHDOG",
                                },
                                "updated_at": now,
                                "completed_at": now,
                                "stages": stages,
                            }
                        )
                        work_updates = []
                        for work_id in await self.redis.smembers(
                            self.key(f"scan:{scan_id}:works")
                        ):
                            work_raw = await self.redis.hgetall(
                                self.key(f"work:{work_id}")
                            )
                            if not work_raw:
                                continue
                            work = _work_from_mapping(work_raw)
                            if work.status.value not in TERMINAL_WORK_VALUES:
                                work_updates.append(
                                    (
                                        work_id,
                                        work.model_copy(
                                            update={
                                                "status": WorkStatus.TIMED_OUT,
                                                "completed_at": now,
                                                "outcome": {
                                                    "type": "timeout",
                                                    "code": "TECHNICAL_WATCHDOG",
                                                },
                                            }
                                        ),
                                    )
                                )
                        pipe.multi()
                        pipe.set(snapshot_key, updated.model_dump_json())
                        for stage in stages.values():
                            pipe.hset(
                                self.key(f"stage:{stage.stage_run_id}"),
                                mapping=_stage_mapping(stage),
                            )
                        for work_id, work in work_updates:
                            pipe.hset(
                                self.key(f"work:{work_id}"),
                                mapping=_work_mapping(work),
                            )
                        pipe.xadd(
                            self.key(f"scan:{scan_id}:updates"),
                            {
                                "revision": updated.revision,
                                "snapshot": updated.model_dump_json(),
                            },
                            maxlen=settings.UPDATE_STREAM_MAXLEN,
                            approximate=True,
                        )
                        await pipe.execute()
                        await self._apply_terminal_ttls(scan_id)
                        expired += 1
                        break
                    except WatchError:
                        continue
        return expired

    async def expire_terminal(self, now: datetime) -> None:
        ids = await self.redis.zrange(self.key("scan:index"), 0, -1)
        for scan_id in ids:
            snapshot = await self._indexed_snapshot(scan_id)
            if snapshot is not None and snapshot.status.value in TERMINAL_SCAN_VALUES:
                await self._apply_terminal_ttls(scan_id)

    async def read_updates(
        self, scan_id: str, after_id: str, block_ms: int
    ) -> AsyncIterator[SnapshotUpdate]:
        response = await self.redis.xread(
            {self.key(f"scan:{scan_id}:updates"): after_id},
            count=100,
            block=block_ms,
        )
        for _, entries in response:
            for stream_id, fields in entries:
                yield SnapshotUpdate(
                    stream_id,
                    int(fields["revision"]),
                    ScanSnapshot.model_validate_json(fields["snapshot"]),
                )

    def ensure_replayable(self, ingested_at: datetime, now: datetime) -> None:
        if now - ingested_at > timedelta(seconds=settings.TERMINAL_RETENTION_SECONDS):
            raise ReplayWindowExpired("REPLAY_WINDOW_EXPIRED")

    async def _write_late(
        self, event: LifecycleEnvelopeV1, reason: str, ingested_at: datetime
    ) -> None:
        await self.redis.xadd(
            self.key("late"),
            {
                "original_payload": serialize_event(event),
                "reason": reason,
                "ingested_at": ingested_at.isoformat(),
            },
        )

    async def _apply_terminal_ttls(self, scan_id: str) -> None:
        terminal = settings.TERMINAL_RETENTION_SECONDS
        dedupe = settings.DEDUPE_RETENTION_SECONDS
        keys = [
            self.key(f"scan:{scan_id}:snapshot"),
            self.key(f"scan:{scan_id}:works"),
            self.key(f"scan:{scan_id}:updates"),
        ]
        for key in keys:
            await self.redis.expire(key, terminal)
        await self.redis.expire(self.key(f"scan:{scan_id}:meta"), terminal)
        await self.redis.expire(self.key(f"scan:{scan_id}:event_ids"), dedupe)
        await self.redis.expire(self.key(f"scan:{scan_id}:result_ids"), dedupe)
        for work_id in await self.redis.smembers(self.key(f"scan:{scan_id}:works")):
            await self.redis.expire(self.key(f"work:{work_id}"), terminal)
            await self.redis.expire(self.key(f"work:{work_id}:causes"), terminal)


def _initial_stages(scan_id: str, mode: str) -> dict[str, StageSnapshot]:
    enabled = {"recon"}
    if mode == "full":
        enabled.update({"scan", "verification"})
    stages = {}
    for name in ("recon", "scan", "verification"):
        is_enabled = name in enabled
        stages[name] = StageSnapshot(
            stage_run_id=make_stage_run_id(scan_id, name),
            name=name,
            status=StageStatus.PENDING if is_enabled else StageStatus.SKIPPED,
            sealed=not is_enabled,
            completed_at=None,
            outcome={"type": "skipped", "code": "disabled_by_mode"}
            if not is_enabled
            else None,
        )
    return stages


def _command_for_work(work, variant, input_data, timeout, parent_work_id):
    event_id = str(uuid5(UUID(work.work_id), f"command:{work.attempt}"))
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": event_id,
            "event": "work.command",
            "scan_id": work.scan_id,
            "stage_run_id": work.stage_run_id,
            "work_id": work.work_id,
            "parent_work_id": parent_work_id,
            "producer": "orchestrator",
            "attempt": work.attempt,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": {
                "work_type": work.work_type.value,
                "input": input_data,
                "timeout_seconds": timeout,
                "max_attempts": work.max_attempts,
                "dispatch_not_before": datetime.now(timezone.utc).isoformat(),
                "variant": variant,
            },
        }
    )


def _work_mapping(work: WorkSnapshot) -> dict[str, str | int]:
    values = work.model_dump(mode="json")
    mapping = {}
    for key, value in values.items():
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            mapping[key] = json.dumps(value, ensure_ascii=False)
        elif isinstance(value, bool):
            mapping[key] = int(value)
        else:
            mapping[key] = value
    return mapping


def _work_from_mapping(raw: dict[str, str]) -> WorkSnapshot:
    values: dict[str, Any] = dict(raw)
    for metadata in ("input", "variant", "timeout_seconds"):
        values.pop(metadata, None)
    for key in ("attempt", "max_attempts", "result_count"):
        if key in values:
            values[key] = int(values[key])
    if "outcome" in values:
        values["outcome"] = json.loads(values["outcome"])
    return WorkSnapshot.model_validate(values)


def _stage_mapping(stage: StageSnapshot) -> dict[str, str | int]:
    values = stage.model_dump(mode="json")
    mapping = {}
    for key, value in values.items():
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            mapping[key] = json.dumps(value, ensure_ascii=False)
        elif isinstance(value, bool):
            mapping[key] = int(value)
        else:
            mapping[key] = value
    return mapping


def _result_kind(topic: str) -> str:
    if topic.startswith("asset."):
        return "assets"
    if topic == "vuln.detected":
        return "findings"
    if topic == "vuln.verified":
        return "verified"
    return "execution"


def _result_mapping(record: ResultRecord) -> dict[str, Any]:
    return {
        "result_id": record.result_id,
        "scan_id": record.scan_id,
        "kind": record.kind,
        "event": record.event,
        "work_id": record.work_id,
        "ingested_at": record.ingested_at.isoformat(),
        "data": record.data,
    }


def _reconcile_snapshot(snapshot, stages, now):
    ordered = ("recon", "scan", "verification")
    for name in ordered:
        stage = stages[name]
        if stage.status in {StageStatus.SKIPPED, StageStatus.SUCCEEDED, StageStatus.FAILED, StageStatus.TIMED_OUT}:
            continue
        upstream = name == "recon" or (
            name == "scan"
            and stages["recon"].status in {StageStatus.SUCCEEDED, StageStatus.SKIPPED}
        ) or (
            name == "verification"
            and stages["scan"].status in {StageStatus.SUCCEEDED, StageStatus.SKIPPED}
        )
        approvals_resolved = name != "verification" or snapshot.approval_summary.pending == 0 and snapshot.approval_summary.approved_awaiting_execution == 0 and snapshot.approval_summary.executing == 0
        if upstream and stage.open_work == 0 and approvals_resolved:
            stages[name] = stage.model_copy(
                update={
                    "status": StageStatus.SUCCEEDED,
                    "sealed": True,
                    "completed_at": now,
                    "outcome": {"type": "success"},
                }
            )
    if any(stage.status is StageStatus.FAILED for stage in stages.values()):
        return ScanStatus.FAILED, stages
    enabled = [stage for stage in stages.values() if not (stage.status is StageStatus.SKIPPED and stage.outcome and stage.outcome.get("code") == "disabled_by_mode")]
    if enabled and all(stage.status in {StageStatus.SUCCEEDED, StageStatus.SKIPPED} for stage in enabled):
        return ScanStatus.SUCCEEDED, stages
    return snapshot.status, stages


def _abort_stages(stages, terminal_name, now, code):
    """Mirror state_machine._reconcile_raw: a terminal stage ends its siblings."""
    result = dict(stages)
    for name, stage in stages.items():
        if name == terminal_name:
            continue
        if stage.status is StageStatus.PENDING:
            result[name] = stage.model_copy(
                update={
                    "status": StageStatus.SKIPPED,
                    "sealed": True,
                    "completed_at": now,
                    "outcome": {"type": "skipped", "code": code},
                }
            )
        elif stage.status is StageStatus.RUNNING:
            result[name] = stage.model_copy(
                update={
                    "status": StageStatus.FAILED,
                    "completed_at": now,
                    "outcome": {
                        "type": "failure",
                        "code": "scan_aborted_due_to_stage_failure",
                    },
                }
            )
    return result


def _release_closed_work(stages, closed):
    """Drop work closed by _close_open_work from each stage's open counter."""
    result = dict(stages)
    for _work_id, work in closed:
        name = work.work_type.value.split(".", 1)[0]
        stage = result[name]
        result[name] = stage.model_copy(
            update={"open_work": max(0, stage.open_work - 1)}
        )
    return result


def _hash_json(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _validate_limit(limit: int) -> None:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
