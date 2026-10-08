"""Durable worker command runner with fencing and terminal-before-ACK."""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping
from uuid import UUID, uuid4, uuid5

from .config import settings
from .events import Delivery, EventBus, command_stream
from .lifecycle import (
    EventValidationError,
    LifecycleEnvelopeV1,
    WorkCommandData,
    WorkType,
    parse_event,
    validate_event,
)


@dataclass(frozen=True, slots=True)
class WorkResult:
    result_count: int
    outcome: dict[str, Any] | None = None


WorkHandler = Callable[["WorkContext", LifecycleEnvelopeV1], Awaitable[WorkResult]]


def _metrics_registry():
    # Imported lazily because service supervision imports WorkerRunner.
    from . import service as service_module

    return getattr(service_module, "DEFAULT_METRICS", None)


class WorkContext:
    def __init__(
        self,
        runner: "WorkerRunner",
        command: LifecycleEnvelopeV1,
        lease_token: str,
    ) -> None:
        self.runner = runner
        self.command = command
        self.lease_token = lease_token
        self.lease_key = f"vts:lease:work:{command.work_id}"
        self._last_sequence = -1

    async def publish_result(self, topic: str, data: dict) -> str:
        if not await self.runner._lease_is_current(self.lease_key, self.lease_token):
            raise RuntimeError("stale fencing token")
        event = self.runner._event(self.command, topic, data)
        return await self.runner.bus.publish(event)

    async def progress(
        self,
        sequence: int,
        percent: float | None,
        message: str,
        counters: dict,
    ) -> str:
        if sequence <= self._last_sequence:
            raise ValueError("progress sequence must increase monotonically")
        if not await self.runner._lease_is_current(self.lease_key, self.lease_token):
            raise RuntimeError("stale fencing token")
        self._last_sequence = sequence
        return await self.runner.bus.publish(
            self.runner._event(
                self.command,
                "work.progress",
                {
                    "sequence": sequence,
                    "percent": percent,
                    "message": message,
                    "counters": counters,
                },
            )
        )


class WorkerRunner:
    default_heartbeat_seconds = 5

    def __init__(
        self,
        service: str,
        bus: EventBus,
        handlers: Mapping[WorkType, WorkHandler],
        max_concurrency: int,
        *,
        heartbeat_seconds: float | None = None,
        lease_ttl_seconds: int | None = None,
        reclaim_idle_ms: int | None = None,
    ) -> None:
        self.service = service
        self.bus = bus
        self.handlers = dict(handlers)
        self.max_concurrency = max_concurrency
        self.heartbeat_seconds = (
            settings.WORK_HEARTBEAT_SECONDS
            if heartbeat_seconds is None
            else heartbeat_seconds
        )
        self.lease_ttl_seconds = (
            settings.WORK_LEASE_TTL_SECONDS
            if lease_ttl_seconds is None
            else lease_ttl_seconds
        )
        self.reclaim_idle_ms = (
            settings.WORK_RECLAIM_IDLE_SECONDS * 1000
            if reclaim_idle_ms is None
            else reclaim_idle_ms
        )
        self.stream = command_stream(service)
        self.group = f"worker-{service}"
        self.consumer = f"{service}-{uuid4().hex[:12]}"
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._tasks: set[asyncio.Task] = set()
        self._stopping = asyncio.Event()

    @property
    def in_flight(self) -> int:
        return len(self._tasks)

    async def run(self) -> None:
        await self.reclaim_once()
        reclaimer = asyncio.create_task(self._reclaim_loop())
        try:
            async for delivery in self.bus.subscribe(
                ["work.command"],
                stream=self.stream,
                group=self.group,
                consumer=self.consumer,
            ):
                if self._stopping.is_set():
                    break
                await self._semaphore.acquire()
                task = asyncio.create_task(self._run_delivery(delivery))
                self._tasks.add(task)
                task.add_done_callback(self._task_done)
        finally:
            reclaimer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reclaimer

    async def _reclaim_loop(self) -> None:
        """Keep reclaiming entries a crashed consumer left pending.

        Running only at startup would leave another replica's abandoned work
        stuck until this process restarted.
        """
        interval = max(self.reclaim_idle_ms / 1000, 0.05)
        while not self._stopping.is_set():
            await asyncio.sleep(interval)
            try:
                await self.reclaim_once()
            except Exception:
                # A transient Redis error must not end reclaiming for good.
                continue

    async def stop(self) -> None:
        self._stopping.set()
        if self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)

    def _task_done(self, task: asyncio.Task) -> None:
        self._tasks.discard(task)
        self._semaphore.release()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            task.result()

    async def _run_delivery(self, delivery: Delivery) -> None:
        await self.handle_delivery(delivery)

    async def handle_delivery(self, delivery: Delivery) -> None:
        command = delivery.event
        try:
            if not isinstance(command, LifecycleEnvelopeV1):
                raise EventValidationError("legacy_command_not_supported")
            validate_event(command, stream=delivery.stream)
            if command.event != "work.command":
                raise EventValidationError("not_work_command")
            command_data = WorkCommandData.model_validate(command.data)
            handler = self.handlers.get(command_data.work_type)
            if handler is None:
                raise EventValidationError("unknown_work_type_for_service")
        except Exception as exc:
            await self.bus.write_dlq(delivery, str(exc))
            await delivery.ack()
            return

        journal_key = self._journal_key(command)
        journal = await self.bus.redis.hgetall(journal_key)
        if journal.get("terminal_event_id"):
            await delivery.ack()
            return

        lease_key = f"vts:lease:work:{command.work_id}"
        lease_token = f"{command.attempt}:{uuid4().hex}"
        acquired = await self.bus.redis.set(
            lease_key,
            lease_token,
            nx=True,
            ex=self.lease_ttl_seconds,
        )
        if not acquired:
            return

        context = WorkContext(self, command, lease_token)
        metric_labels = {
            "service": self.service,
            "work_type": command_data.work_type.value,
        }
        metrics = _metrics_registry()
        started = time.monotonic()
        await self.bus.publish(
            self._event(
                command,
                "work.queued",
                {
                    "command_event_id": command.event_id,
                    "command_message_id": delivery.message_id,
                    "lease_token": lease_token,
                },
            )
        )
        if metrics is not None:
            metrics.counter("vts_work_queued_total", metric_labels)
        await self.bus.publish(
            self._event(
                command,
                "work.started",
                {
                    "lease_token": lease_token,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        )
        if metrics is not None:
            metrics.counter("vts_work_started_total", metric_labels)
            metrics.gauge("vts_work_in_flight", metric_labels, 1)

        heartbeat = asyncio.create_task(
            self._heartbeat(delivery, lease_key, lease_token)
        )
        try:
            try:
                result = await asyncio.wait_for(
                    handler(context, command),
                    timeout=command_data.timeout_seconds,
                )
                if not isinstance(result, WorkResult):
                    raise TypeError("worker handler must return WorkResult")
                topic = "work.completed"
                terminal_data = {
                    "result_count": result.result_count,
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "lease_token": lease_token,
                }
                journal_data: dict[str, str | int] = {
                    "outcome": "completed",
                    "result_count": result.result_count,
                }
            except asyncio.TimeoutError:
                topic = "work.failed"
                terminal_data = {
                    "error_code": "WORK_TIMEOUT",
                    "retryable": True,
                    "message": "work attempt exceeded its deadline",
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "lease_token": lease_token,
                }
                journal_data = {
                    "outcome": "failed",
                    "error_code": "WORK_TIMEOUT",
                }
            except Exception as exc:
                topic = "work.failed"
                retryable = isinstance(
                    exc, (OSError, ConnectionError, TimeoutError)
                )
                terminal_data = {
                    "error_code": type(exc).__name__.upper(),
                    "retryable": retryable,
                    "message": str(exc)[:1000],
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "lease_token": lease_token,
                }
                journal_data = {
                    "outcome": "failed",
                    "error_code": type(exc).__name__.upper(),
                }

            if not await self._lease_is_current(lease_key, lease_token):
                return
            terminal = self._event(
                command,
                topic,
                terminal_data,
                event_id=self._terminal_event_id(command, topic),
            )
            journal_data.update(
                {
                    "terminal_event_id": terminal.event_id,
                    "terminal_topic": topic,
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            await self.bus.persist_terminal(terminal, journal_key, journal_data)
            if metrics is not None:
                counter = (
                    "vts_work_completed_total"
                    if topic == "work.completed"
                    else "vts_work_failed_total"
                )
                metrics.counter(counter, metric_labels)
                metrics.observe(
                    "vts_work_duration_seconds",
                    metric_labels,
                    terminal_data["duration_ms"] / 1000,
                )
                metrics.gauge("vts_work_in_flight", metric_labels, 0)
            await delivery.ack()
        finally:
            heartbeat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat
            if await self._lease_is_current(lease_key, lease_token):
                await self.bus.redis.delete(lease_key)

    async def _heartbeat(
        self,
        delivery: Delivery,
        lease_key: str,
        lease_token: str,
    ) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_seconds)
            if not await self._lease_is_current(lease_key, lease_token):
                return
            await self.bus.redis.expire(lease_key, self.lease_ttl_seconds)
            await delivery.touch()

    async def _lease_is_current(self, lease_key: str, token: str) -> bool:
        return await self.bus.redis.get(lease_key) == token

    async def reclaim_once(self) -> int:
        await self.bus.ensure_group(self.stream, self.group, "0-0")
        redis = self.bus.redis
        response = await redis.xautoclaim(
            self.stream,
            self.group,
            self.consumer,
            self.reclaim_idle_ms,
            "0-0",
            count=100,
        )
        entries = response[1] if len(response) > 1 else []
        reclaimed = 0
        for message_id, fields in entries:
            raw = fields.get("payload", "")
            try:
                event = parse_event(raw)
            except EventValidationError:
                continue
            delivery = Delivery(
                message_id,
                self.stream,
                raw,
                event,
                redis,
                self.group,
                self.consumer,
            )
            if not isinstance(event, LifecycleEnvelopeV1):
                await self.bus.write_dlq(delivery, "legacy_command_not_supported")
                await delivery.ack()
                reclaimed += 1
                continue
            journal_key = self._journal_key(event)
            journal = await redis.hgetall(journal_key)
            if journal.get("terminal_event_id"):
                await delivery.ack()
                reclaimed += 1
                continue
            lease_key = f"vts:lease:work:{event.work_id}"
            if await redis.get(lease_key):
                continue
            lease_token = f"reclaim:{event.attempt}:{uuid4().hex}"
            terminal = self._event(
                event,
                "work.failed",
                {
                    "error_code": "WORKER_LEASE_EXPIRED",
                    "retryable": True,
                    "message": "worker lease expired before terminal event",
                    "duration_ms": 0,
                    "lease_token": lease_token,
                },
                event_id=self._terminal_event_id(event, "work.failed"),
            )
            await self.bus.persist_terminal(
                terminal,
                journal_key,
                {
                    "terminal_event_id": terminal.event_id,
                    "terminal_topic": "work.failed",
                    "outcome": "failed",
                    "error_code": "WORKER_LEASE_EXPIRED",
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            await delivery.ack()
            reclaimed += 1
        return reclaimed

    def _journal_key(self, command: LifecycleEnvelopeV1) -> str:
        return (
            f"vts:worker:{self.service}:{command.work_id}:{command.attempt}"
        )

    def _terminal_event_id(
        self, command: LifecycleEnvelopeV1, topic: str
    ) -> str:
        return str(uuid5(UUID(command.work_id), f"attempt:{command.attempt}:{topic}"))

    def _event(
        self,
        command: LifecycleEnvelopeV1,
        topic: str,
        data: dict,
        *,
        event_id: str | None = None,
    ) -> LifecycleEnvelopeV1:
        return LifecycleEnvelopeV1.model_validate(
            {
                "schema_version": 1,
                "event_id": event_id or str(uuid4()),
                "event": topic,
                "scan_id": command.scan_id,
                "stage_run_id": command.stage_run_id,
                "work_id": command.work_id,
                "parent_work_id": command.parent_work_id,
                "producer": self.service,
                "attempt": command.attempt,
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "data": data,
            }
        )
