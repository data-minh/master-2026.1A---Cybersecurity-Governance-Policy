"""Redis Streams event bus with explicit delivery acknowledgement."""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import AsyncIterator, Awaitable, Callable, Optional

import redis.asyncio as aioredis
from redis.exceptions import ResponseError

from .config import settings
from .lifecycle import (
    EventValidationError,
    LegacyEventV0,
    LifecycleEnvelopeV1,
    parse_event,
    serialize_event,
)

BUS_STREAM = "vts.bus"
BUS_MAXLEN = 10_000
DLQ_STREAM = "vts.dlq"
LATE_STREAM = "vts.late"
COMMAND_STREAM_PREFIX = "vts.commands."


def command_stream(service: str) -> str:
    return f"{COMMAND_STREAM_PREFIX}{service}"


class Topics:
    SUBDOMAIN_DISCOVERED = "asset.subdomain.discovered"
    OSINT_COLLECTED = "asset.osint.collected"
    ENDPOINT_ALIVE = "asset.endpoint.alive"
    URL_COLLECTED = "asset.url.collected"
    PORT_OPEN = "asset.port.open"
    PATH_FOUND = "asset.path.found"
    VULN_DETECTED = "vuln.detected"
    VULN_VERIFIED = "vuln.verified"
    EXPLOIT_APPROVED = "exploit.approved"
    EXPLOIT_EXECUTED = "exploit.executed"
    SCAN_STAGE_COMPLETED = "scan.stage.completed"
    SCAN_STARTED = "scan.started"
    SCAN_FINISHED = "scan.finished"
    TEMPLATE_REGISTERED = "template.registered"
    TEMPLATE_DELETED = "template.deleted"
    WORK_COMMAND = "work.command"
    WORK_QUEUED = "work.queued"
    WORK_STARTED = "work.started"
    WORK_PROGRESS = "work.progress"
    WORK_COMPLETED = "work.completed"
    WORK_FAILED = "work.failed"
    WORK_TIMED_OUT = "work.timed_out"
    WORK_CANCELED = "work.canceled"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_APPROVED = "approval.approved"
    APPROVAL_REJECTED = "approval.rejected"
    APPROVAL_EXECUTION_REQUESTED = "approval.execution.requested"
    APPROVAL_EXECUTED = "approval.executed"
    APPROVAL_EXECUTION_FAILED = "approval.execution_failed"


@dataclass
class Event:
    """Legacy v0 event retained for one compatibility release."""

    event: str
    data: dict
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @staticmethod
    def from_json(raw: str) -> Event:
        obj = json.loads(raw)
        return Event(
            event=obj["event"],
            data=obj.get("data", {}),
            scan_id=obj.get("scan_id", ""),
            timestamp=obj.get("timestamp", ""),
        )


@dataclass(slots=True)
class Delivery:
    message_id: str
    stream: str
    raw: str
    event: LifecycleEnvelopeV1 | LegacyEventV0 | None
    redis: object
    group: str
    consumer: str
    _acked: bool = False

    @property
    def legacy(self) -> bool:
        return isinstance(self.event, LegacyEventV0)

    async def ack(self) -> None:
        if not self._acked:
            await self.redis.xack(self.stream, self.group, self.message_id)
            self._acked = True

    async def touch(self) -> None:
        if self._acked:
            return
        await self.redis.xclaim(
            self.stream,
            self.group,
            self.consumer,
            min_idle_time=0,
            message_ids=[self.message_id],
            justid=True,
        )


async def _write_audit(
    delivery: Delivery,
    audit_stream: str,
    reason: str,
    ingested_at: datetime,
) -> str:
    return await delivery.redis.xadd(
        audit_stream,
        {
            "original_stream": delivery.stream,
            "original_message_id": delivery.message_id,
            "original_payload": delivery.raw,
            "reason": reason,
            "ingested_at": ingested_at.astimezone(timezone.utc).isoformat(),
        },
    )


async def write_dlq(
    delivery: Delivery, reason: str, ingested_at: datetime
) -> str:
    return await _write_audit(delivery, DLQ_STREAM, reason, ingested_at)


async def write_late(
    delivery: Delivery, reason: str, ingested_at: datetime
) -> str:
    return await _write_audit(delivery, LATE_STREAM, reason, ingested_at)


class EventBus:
    def __init__(
        self,
        redis_url: Optional[str] = None,
        group: Optional[str] = None,
        *,
        dlq_stream: str = DLQ_STREAM,
        late_stream: str = LATE_STREAM,
        readiness_callback: Callable[[bool], None] | None = None,
    ):
        self._url = redis_url or settings.REDIS_URL
        self._group = group or settings.SERVICE_NAME or "vts-consumer"
        self._redis: Optional[aioredis.Redis] = None
        self._connect_lock = asyncio.Lock()
        self.dlq_stream = dlq_stream
        self.late_stream = late_stream
        self._readiness_callback = readiness_callback

    @property
    def redis(self):
        return self._redis

    async def connect(self) -> None:
        async with self._connect_lock:
            if self._redis is not None:
                try:
                    await self._redis.ping()
                    return
                except Exception:
                    with contextlib.suppress(Exception):
                        await self._redis.aclose()
                    self._redis = None
            self._redis = aioredis.from_url(
                self._url,
                decode_responses=True,
                socket_timeout=None,
                health_check_interval=30,
            )
            await self._redis.ping()

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    async def publish(
        self,
        event: Event | LifecycleEnvelopeV1 | LegacyEventV0,
        *,
        stream: str = BUS_STREAM,
        maxlen: int | None = None,
    ) -> str:
        await self.connect()
        assert self._redis is not None
        if isinstance(event, Event):
            raw = event.to_json()
        else:
            raw = serialize_event(event)
        options = {}
        if maxlen is not None or stream == BUS_STREAM:
            options = {
                "maxlen": BUS_MAXLEN if maxlen is None else maxlen,
                "approximate": True,
            }
        return await self._redis.xadd(stream, {"payload": raw}, **options)

    async def ensure_group(self, stream: str, group: str, start_id: str) -> None:
        await self.connect()
        assert self._redis is not None
        try:
            await self._redis.xgroup_create(
                stream, group, id=start_id, mkstream=True
            )
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def _ensure_group(self) -> None:
        await self.ensure_group(BUS_STREAM, self._group, "0-0")

    async def persist_terminal(
        self,
        event: LifecycleEnvelopeV1,
        journal_key: str,
        journal: dict[str, str | int],
    ) -> str:
        """Atomically persist the terminal journal and append its bus event."""
        await self.connect()
        assert self._redis is not None
        raw = serialize_event(event)
        async with self._redis.pipeline(transaction=True) as pipeline:
            pipeline.hset(journal_key, mapping=journal)
            pipeline.xadd(
                BUS_STREAM,
                {"payload": raw},
                maxlen=BUS_MAXLEN,
                approximate=True,
            )
            result = await pipeline.execute()
        return result[-1]

    async def write_dlq(self, delivery: Delivery, reason: str) -> str:
        return await _write_audit(
            delivery,
            self.dlq_stream,
            reason,
            datetime.now(timezone.utc),
        )

    async def subscribe(
        self,
        patterns: list[str],
        *,
        stream: str = BUS_STREAM,
        group: str | None = None,
        consumer: str | None = None,
    ) -> AsyncIterator[Delivery]:
        await self.connect()
        assert self._redis is not None
        selected_group = group or self._group
        selected_consumer = consumer or f"{selected_group}-main"
        await self.ensure_group(stream, selected_group, "0-0")
        cursor = "0"

        while True:
            try:
                response = await self._redis.xreadgroup(
                    selected_group,
                    selected_consumer,
                    {stream: cursor},
                    count=50,
                    block=5000,
                )
            except ResponseError as exc:
                if "NOGROUP" not in str(exc):
                    raise
                if self._readiness_callback is not None:
                    self._readiness_callback(False)
                await self.ensure_group(stream, selected_group, "0-0")
                cursor = "0"
                continue

            entries = response[0][1] if response else []
            if not entries:
                if cursor != ">":
                    cursor = ">"
                continue

            for message_id, fields in entries:
                raw = fields.get("payload", "")
                try:
                    parsed = parse_event(raw)
                except EventValidationError as exc:
                    delivery = Delivery(
                        message_id,
                        stream,
                        raw,
                        None,
                        self._redis,
                        selected_group,
                        selected_consumer,
                    )
                    await _write_audit(
                        delivery,
                        self.dlq_stream,
                        str(exc),
                        datetime.now(timezone.utc),
                    )
                    await delivery.ack()
                    continue

                delivery = Delivery(
                    message_id,
                    stream,
                    raw,
                    parsed,
                    self._redis,
                    selected_group,
                    selected_consumer,
                )
                if any(fnmatch.fnmatch(parsed.event, pattern) for pattern in patterns):
                    yield delivery
                else:
                    await delivery.ack()

            if cursor != ">":
                cursor = ">"
            if self._readiness_callback is not None:
                self._readiness_callback(True)


async def consume_deliveries(
    bus: EventBus,
    patterns: list[str],
    handler: Callable[[LifecycleEnvelopeV1 | LegacyEventV0], Awaitable[None]],
) -> None:
    async for delivery in bus.subscribe(patterns):
        assert delivery.event is not None
        await handler(delivery.event)
        await delivery.ack()


def run_consumer(
    patterns: list[str],
    handler: Callable[[LifecycleEnvelopeV1 | LegacyEventV0], Awaitable[None] | None],
):
    async def _loop():
        bus = EventBus()
        try:
            async for delivery in bus.subscribe(patterns):
                assert delivery.event is not None
                result = handler(delivery.event)
                if asyncio.iscoroutine(result):
                    await result
                await delivery.ack()
        finally:
            await bus.close()

    asyncio.run(_loop())
