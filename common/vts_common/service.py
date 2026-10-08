"""Shared service supervision, readiness, logging, and metrics."""

from __future__ import annotations

import asyncio
import json
import random
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable, Mapping, TypeAlias
from uuid import uuid4

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse

from .config import settings
from .events import EventBus
from .lifecycle import LegacyEventV0, LifecycleEnvelopeV1
from .worker import WorkerRunner


@dataclass(frozen=True, slots=True)
class ReadinessCheck:
    name: str
    healthy: bool
    detail: str | None = None


class ReadinessState:
    def __init__(self, required: tuple[str, ...] = ()) -> None:
        self.checks: dict[str, ReadinessCheck] = {
            name: ReadinessCheck(name, False, "not initialized")
            for name in required
        }

    def set(
        self, reason: str, healthy: bool, detail: str | None = None
    ) -> None:
        self.checks[reason] = ReadinessCheck(reason, healthy, detail)

    def response(self) -> tuple[int, dict]:
        unhealthy = [
            check.detail or check.name
            for check in self.checks.values()
            if not check.healthy
        ]
        if unhealthy:
            return 503, {"status": "not_ready", "reasons": unhealthy}
        return 200, {"status": "ready", "reasons": []}


class MetricsRegistry:
    _minimum_names = (
        "vts_work_queued_total",
        "vts_work_started_total",
        "vts_work_completed_total",
        "vts_work_failed_total",
        "vts_work_timed_out_total",
        "vts_work_retried_total",
        "vts_work_reclaimed_total",
        "vts_event_duplicate_total",
        "vts_event_late_total",
        "vts_event_dlq_total",
        "vts_transition_rejected_total",
    )
    _minimum_gauges = (
        "vts_work_in_flight",
        "vts_command_pending",
        "vts_consumer_lag",
    )
    _minimum_histograms = (
        "vts_work_queue_wait_seconds",
        "vts_work_duration_seconds",
        "vts_snapshot_sse_delivery_seconds",
    )

    def __init__(self) -> None:
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._observations: dict[
            tuple[str, tuple[tuple[str, str], ...]], list[float]
        ] = {}
        for name in self._minimum_names:
            self.counter(name, {}, 0)
        for name in self._minimum_gauges:
            self.gauge(name, {}, 0)
        for name in self._minimum_histograms:
            self._observations[(name, ())] = []

    @staticmethod
    def _key(name: str, labels: Mapping[str, str]):
        allowed = {"service", "work_type", "stage", "outcome"}
        clean = tuple(sorted((key, str(value)) for key, value in labels.items()))
        if any(key not in allowed for key, _ in clean):
            raise ValueError("metric labels are restricted to bounded dimensions")
        return name, clean

    def counter(
        self,
        name: str,
        labels: Mapping[str, str],
        amount: float = 1,
    ) -> None:
        key = self._key(name, labels)
        self._counters[key] = self._counters.get(key, 0.0) + amount

    def gauge(
        self, name: str, labels: Mapping[str, str], value: float
    ) -> None:
        self._gauges[self._key(name, labels)] = float(value)

    def observe(
        self, name: str, labels: Mapping[str, str], value: float
    ) -> None:
        self._observations.setdefault(self._key(name, labels), []).append(
            float(value)
        )

    def render_prometheus(self) -> str:
        lines: list[str] = []
        for (name, labels), value in sorted(self._counters.items()):
            lines.append(f"{name}{_render_labels(labels)} {value}")
        for (name, labels), value in sorted(self._gauges.items()):
            lines.append(f"{name}{_render_labels(labels)} {value}")
        for (name, labels), values in sorted(self._observations.items()):
            label_text = _render_labels(labels)
            lines.append(f"{name}_count{label_text} {len(values)}")
            lines.append(f"{name}_sum{label_text} {sum(values)}")
        return "\n".join(lines) + "\n"


DEFAULT_METRICS = MetricsRegistry()


def _render_labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    rendered = ",".join(
        f'{key}="{value.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'
        for key, value in labels
    )
    return "{" + rendered + "}"


_CORRELATION_KEYS = (
    "event_id",
    "scan_id",
    "stage_run_id",
    "work_id",
    "parent_work_id",
    "attempt",
    "revision",
)


def log_event(level: str, message: str, **correlation) -> None:
    record = {
        "service": settings.SERVICE_NAME,
        "level": level,
        "message": message,
        **{key: correlation.get(key) for key in _CORRELATION_KEYS},
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
    print(json.dumps(record, ensure_ascii=False), flush=True)


async def supervise(
    name: str,
    factory: Callable[[], Awaitable[None]],
    readiness: ReadinessState,
    backoff: tuple[int | float, ...] = (1, 2, 5, 10, 30),
) -> None:
    attempt = 0
    while True:
        readiness.set(name, True)
        try:
            await factory()
            readiness.set(name, False, f"{name} exited unexpectedly")
        except asyncio.CancelledError:
            readiness.set(name, False, f"{name} stopped")
            raise
        except Exception as exc:
            readiness.set(name, False, f"{name} failed")
            log_event("error", f"supervised task {name} failed: {type(exc).__name__}")
        delay = backoff[min(attempt, len(backoff) - 1)]
        attempt += 1
        if delay:
            jitter = random.uniform(0, min(float(delay) * 0.1, 0.25))
            await asyncio.sleep(float(delay) + jitter)


async def redis_readiness_check(redis) -> ReadinessCheck:
    key = f"vts:readiness:{uuid4().hex}"
    try:
        await redis.ping()
        await redis.set(key, "ok", ex=10)
        if await redis.get(key) != "ok":
            return ReadinessCheck("redis", False, "Redis write probe failed")
        await redis.delete(key)
        persistence = await redis.info("persistence")
        if int(persistence.get("aof_enabled", 0)) != 1:
            return ReadinessCheck("redis", False, "Redis AOF is not enabled")
        if persistence.get("aof_last_write_status", "err") != "ok":
            return ReadinessCheck("redis", False, "Redis AOF write is unhealthy")
        return ReadinessCheck("redis", True)
    except Exception:
        return ReadinessCheck("redis", False, "Redis unavailable")


ConsumerSpec: TypeAlias = tuple[
    list[str],
    Callable[
        [LifecycleEnvelopeV1 | LegacyEventV0],
        Awaitable[None],
    ],
]


def make_app(
    title: str,
    description: str = "",
    version: str = "1.0.0",
    consumer: ConsumerSpec | None = None,
    workers: list[Callable[[], Awaitable[None]]] | None = None,
    command_runner: WorkerRunner | None = None,
    readiness_checks: list[Callable[[], Awaitable[ReadinessCheck]]] | None = None,
    *,
    readiness: ReadinessState | None = None,
    metrics: MetricsRegistry | None = None,
    event_bus: EventBus | None = None,
) -> FastAPI:
    needs_redis = consumer is not None or command_runner is not None
    required: list[str] = []
    if needs_redis:
        required.append("redis")
    if consumer is not None:
        required.append("consumer")
    if command_runner is not None:
        required.append("command_runner")
    for index, _ in enumerate(workers or []):
        required.append(f"worker-{index}")

    readiness_state = readiness or ReadinessState(tuple(required))
    metrics_registry = metrics or DEFAULT_METRICS
    bus = command_runner.bus if command_runner is not None else (event_bus or EventBus())
    tasks: list[asyncio.Task] = []

    async def consume() -> None:
        assert consumer is not None
        patterns, handler = consumer
        async for delivery in bus.subscribe(patterns):
            if delivery.event is None:
                continue
            await handler(delivery.event)
            await delivery.ack()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if needs_redis:
            await bus.connect()
            probe = await redis_readiness_check(bus.redis)
            readiness_state.set(probe.name, probe.healthy, probe.detail)
        app.state.bus = bus
        app.state.readiness = readiness_state
        app.state.metrics = metrics_registry

        if consumer is not None:
            tasks.append(
                asyncio.create_task(
                    supervise("consumer", consume, readiness_state)
                )
            )
        for index, worker in enumerate(workers or []):
            tasks.append(
                asyncio.create_task(
                    supervise(f"worker-{index}", worker, readiness_state)
                )
            )
        if command_runner is not None:
            tasks.append(
                asyncio.create_task(
                    supervise(
                        "command_runner", command_runner.run, readiness_state
                    )
                )
            )
        try:
            yield
        finally:
            if command_runner is not None:
                await command_runner.stop()
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if needs_redis:
                await bus.close()

    app = FastAPI(
        title=title,
        description=description,
        version=version,
        lifespan=lifespan,
    )
    app.state.readiness = readiness_state
    app.state.metrics = metrics_registry

    @app.get("/healthz", tags=["meta"])
    async def healthz():
        return {"status": "ok", "service": title}

    @app.get("/readyz", tags=["meta"])
    async def readyz():
        if needs_redis and bus.redis is not None:
            probe = await redis_readiness_check(bus.redis)
            readiness_state.set(probe.name, probe.healthy, probe.detail)
        for check_factory in readiness_checks or []:
            check = await check_factory()
            readiness_state.set(check.name, check.healthy, check.detail)
        status_code, payload = readiness_state.response()
        return JSONResponse(payload, status_code=status_code)

    @app.get("/metrics", tags=["meta"])
    async def metrics_endpoint():
        return PlainTextResponse(
            metrics_registry.render_prometheus(),
            media_type="text/plain; version=0.0.4",
        )

    return app
