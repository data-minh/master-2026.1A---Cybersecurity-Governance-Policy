import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import redis.asyncio as redis_async

from vts_common.events import EventBus, command_stream
from vts_common.lifecycle import LifecycleEnvelopeV1, WorkType
from vts_common.worker import WorkerRunner

REDIS_URL = "redis://localhost:16379/15"


def _command(service, work_id=None):
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": "work.command",
            "scan_id": str(uuid4()),
            "stage_run_id": str(uuid4()),
            "work_id": work_id or str(uuid4()),
            "parent_work_id": None,
            "producer": "orchestrator",
            "attempt": 1,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": {
                "work_type": "scan.template_url",
                "input": {"url": "http://vuln-target/", "class": "page"},
                "timeout_seconds": 120,
                "max_attempts": 3,
                "dispatch_not_before": datetime.now(timezone.utc).isoformat(),
            },
        }
    )


async def _pending(redis, stream, group):
    return (await redis.xpending(stream, group))["pending"]


def test_crash_after_terminal_before_ack_reclaim_only_acks():
    async def scenario():
        service = f"reclaim-{uuid4().hex}"
        stream, group = command_stream(service), f"worker-{service}"
        redis = redis_async.from_url(REDIS_URL, decode_responses=True)
        bus = EventBus(REDIS_URL)
        try:
            command = _command(service)
            await bus.ensure_group(stream, group, "0-0")
            await bus.publish(command, stream=stream)
            await redis.xreadgroup(group, "dead", {stream: ">"}, count=1)
            journal = f"vts:worker:{service}:{command.work_id}:1"
            await redis.hset(journal, mapping={"terminal_event_id": str(uuid4())})
            runner = WorkerRunner(service, bus, {}, 1, reclaim_idle_ms=0)
            assert await runner.reclaim_once() == 1
            assert await _pending(redis, stream, group) == 0
            assert await redis.xlen("vts.bus") >= 0
        finally:
            await bus.close()
            await redis.delete(stream, journal)
            await redis.aclose()

    asyncio.run(scenario())


def test_running_worker_periodically_reclaims_entries_abandoned_after_startup():
    async def scenario():
        service = f"reclaim-{uuid4().hex}"
        stream, group = command_stream(service), f"worker-{service}"
        redis = redis_async.from_url(REDIS_URL, decode_responses=True)
        bus = EventBus(REDIS_URL)
        command = _command(service)
        journal = f"vts:worker:{service}:{command.work_id}:1"
        lease = f"vts:lease:work:{command.work_id}"
        runner = WorkerRunner(service, bus, {}, 1, reclaim_idle_ms=100)
        task = None
        try:
            await bus.ensure_group(stream, group, "0-0")
            await bus.publish(command, stream=stream)
            await redis.xreadgroup(group, "dead", {stream: ">"}, count=1)
            await redis.set(lease, "dead-owner")
            task = asyncio.create_task(runner.run())
            await asyncio.sleep(0.4)
            assert await _pending(redis, stream, group) == 1  # lease still held
            await redis.delete(lease)  # the dead owner's lease expires
            deadline = asyncio.get_running_loop().time() + 3
            while await _pending(redis, stream, group):
                assert asyncio.get_running_loop().time() < deadline, "not reclaimed"
                await asyncio.sleep(0.05)
            assert (await redis.hgetall(journal))["error_code"] == "WORKER_LEASE_EXPIRED"
        finally:
            await runner.stop()
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await bus.close()
            await redis.delete(stream, journal, lease)
            await redis.aclose()

    asyncio.run(scenario())


def test_lease_expiry_emits_retryable_failure_then_acks_old_attempt():
    async def scenario():
        service = f"reclaim-{uuid4().hex}"
        stream, group = command_stream(service), f"worker-{service}"
        redis = redis_async.from_url(REDIS_URL, decode_responses=True)
        bus = EventBus(REDIS_URL)
        command = _command(service)
        journal = f"vts:worker:{service}:{command.work_id}:1"
        lease = f"vts:lease:work:{command.work_id}"
        try:
            await bus.ensure_group(stream, group, "0-0")
            await bus.publish(command, stream=stream)
            await redis.xreadgroup(group, "dead", {stream: ">"}, count=1)
            runner = WorkerRunner(service, bus, {}, 1, reclaim_idle_ms=0)
            assert await runner.reclaim_once() == 1
            assert await _pending(redis, stream, group) == 0
            stored = await redis.hgetall(journal)
            assert stored["outcome"] == "failed"
            assert stored["error_code"] == "WORKER_LEASE_EXPIRED"
        finally:
            await bus.close()
            await redis.delete(stream, journal, lease)
            await redis.aclose()

    asyncio.run(scenario())
