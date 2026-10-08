import asyncio
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
import redis.asyncio as redis_async

from vts_common.events import Delivery, EventBus, write_dlq
from vts_common.lifecycle import LegacyEventV0, LifecycleEnvelopeV1

REDIS_URL = "redis://localhost:16379/15"


def _v1(topic="work.started"):
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": topic,
            "scan_id": str(uuid4()),
            "stage_run_id": str(uuid4()),
            "work_id": str(uuid4()),
            "parent_work_id": None,
            "producer": "scan-engine",
            "attempt": 1,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": {"lease_token": "token"},
        }
    )


async def _pending(redis, stream, group):
    return (await redis.xpending(stream, group))["pending"]


async def _cleanup(redis, *keys):
    if keys:
        await redis.delete(*keys)
    await redis.aclose()


def test_connect_replaces_stale_redis_client(monkeypatch):
    class BrokenRedis:
        def __init__(self):
            self.closed = False

        async def ping(self):
            raise ConnectionError("stale socket")

        async def aclose(self):
            self.closed = True

    class HealthyRedis:
        async def ping(self):
            return True

    async def scenario():
        broken = BrokenRedis()
        healthy = HealthyRedis()
        bus = EventBus(REDIS_URL)
        bus._redis = broken
        monkeypatch.setattr(
            "vts_common.events.aioredis.from_url", lambda *args, **kwargs: healthy
        )
        await bus.connect()
        return broken, bus

    broken, bus = asyncio.run(scenario())
    assert broken.closed is True
    assert bus.redis.__class__.__name__ == "HealthyRedis"


def test_delivery_stays_pending_until_explicit_ack():
    async def scenario():
        suffix = uuid4().hex
        stream, group = f"vts:test:{suffix}:bus", f"g-{suffix}"
        redis = redis_async.from_url(REDIS_URL, decode_responses=True)
        bus = EventBus(REDIS_URL)
        try:
            await bus.ensure_group(stream, group, "0-0")
            await bus.publish(_v1(), stream=stream)
            subscription = bus.subscribe(
                ["work.*"], stream=stream, group=group, consumer="c"
            )
            delivery = await anext(subscription)
            assert isinstance(delivery, Delivery)
            assert await _pending(redis, stream, group) == 1
            await delivery.ack()
            assert await _pending(redis, stream, group) == 0
            await subscription.aclose()
        finally:
            await bus.close()
            await _cleanup(redis, stream)

    asyncio.run(scenario())


def test_touch_refreshes_pending_idle():
    async def scenario():
        suffix = uuid4().hex
        stream, group = f"vts:test:{suffix}:bus", f"g-{suffix}"
        redis = redis_async.from_url(REDIS_URL, decode_responses=True)
        bus = EventBus(REDIS_URL)
        try:
            await bus.ensure_group(stream, group, "0-0")
            await bus.publish(_v1(), stream=stream)
            subscription = bus.subscribe(
                ["work.*"], stream=stream, group=group, consumer="c"
            )
            delivery = await anext(subscription)
            await asyncio.sleep(0.02)
            before = (await redis.xpending_range(stream, group, "-", "+", 1))[0][
                "time_since_delivered"
            ]
            await delivery.touch()
            after = (await redis.xpending_range(stream, group, "-", "+", 1))[0][
                "time_since_delivered"
            ]
            assert before >= after
            await delivery.ack()
            await subscription.aclose()
        finally:
            await bus.close()
            await _cleanup(redis, stream)

    asyncio.run(scenario())


def test_handler_exception_does_not_ack():
    async def scenario():
        suffix = uuid4().hex
        stream, group = f"vts:test:{suffix}:bus", f"g-{suffix}"
        redis = redis_async.from_url(REDIS_URL, decode_responses=True)
        bus = EventBus(REDIS_URL)
        try:
            await bus.ensure_group(stream, group, "0-0")
            await bus.publish(_v1(), stream=stream)
            subscription = bus.subscribe(
                ["work.*"], stream=stream, group=group, consumer="c"
            )
            await anext(subscription)
            try:
                raise RuntimeError("handler failed")
            except RuntimeError:
                pass
            await subscription.aclose()
            assert await _pending(redis, stream, group) == 1
        finally:
            await bus.close()
            await _cleanup(redis, stream)

    asyncio.run(scenario())


def test_malformed_is_acked_only_after_dlq_write():
    async def scenario():
        suffix = uuid4().hex
        stream, group = f"vts:test:{suffix}:bus", f"g-{suffix}"
        redis = redis_async.from_url(REDIS_URL, decode_responses=True)
        bus = EventBus(REDIS_URL, dlq_stream=f"vts:test:{suffix}:dlq")
        try:
            await bus.ensure_group(stream, group, "0-0")
            await redis.xadd(stream, {"payload": "{"})
            task = asyncio.create_task(
                anext(
                    bus.subscribe(
                        ["*"], stream=stream, group=group, consumer="c"
                    )
                )
            )
            deadline = asyncio.get_running_loop().time() + 1
            while await redis.xlen(bus.dlq_stream) != 1:
                if asyncio.get_running_loop().time() >= deadline:
                    raise AssertionError("malformed delivery was not quarantined")
                await asyncio.sleep(0.01)
            # The ACK is issued right after the DLQ write; wait for it to land so
            # the check does not race the (correct) DLQ-before-ACK ordering.
            while await _pending(redis, stream, group) != 0:
                if asyncio.get_running_loop().time() >= deadline:
                    raise AssertionError("malformed delivery was not acked after DLQ")
                await asyncio.sleep(0.01)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            await bus.close()
            await _cleanup(redis, stream, bus.dlq_stream)

    asyncio.run(scenario())


def test_dlq_failure_keeps_original_pending():
    class FailingAuditRedis:
        def __init__(self, real):
            self.real = real

        async def xadd(self, *args, **kwargs):
            raise RuntimeError("disk full")

        async def xack(self, *args, **kwargs):
            return await self.real.xack(*args, **kwargs)

    async def scenario():
        suffix = uuid4().hex
        stream, group = f"vts:test:{suffix}:bus", f"g-{suffix}"
        redis = redis_async.from_url(REDIS_URL, decode_responses=True)
        try:
            await redis.xgroup_create(stream, group, id="0-0", mkstream=True)
            message_id = await redis.xadd(stream, {"payload": "{"})
            await redis.xreadgroup(group, "c", {stream: ">"}, count=1)
            delivery = Delivery(
                message_id=message_id,
                stream=stream,
                raw="{",
                event=None,
                redis=FailingAuditRedis(redis),
                group=group,
                consumer="c",
            )
            with pytest.raises(RuntimeError, match="disk full"):
                await write_dlq(delivery, "malformed", datetime.now(timezone.utc))
            assert await _pending(redis, stream, group) == 1
        finally:
            await _cleanup(redis, stream)

    asyncio.run(scenario())


def test_nogroup_recreates_command_group_from_zero():
    async def scenario():
        suffix = uuid4().hex
        stream, group = f"vts.commands.test-{suffix}", f"worker-{suffix}"
        redis = redis_async.from_url(REDIS_URL, decode_responses=True)
        bus = EventBus(REDIS_URL)
        try:
            await bus.connect()
            await bus.publish(_v1(), stream=stream)
            subscription = bus.subscribe(
                ["work.*"], stream=stream, group=group, consumer="c"
            )
            delivery = await asyncio.wait_for(anext(subscription), timeout=1)
            assert delivery.event.event == "work.started"
            await delivery.ack()
            await subscription.aclose()
        finally:
            await bus.close()
            await _cleanup(redis, stream)

    asyncio.run(scenario())


def test_v0_delivery_is_marked_legacy():
    async def scenario():
        suffix = uuid4().hex
        stream, group = f"vts:test:{suffix}:bus", f"g-{suffix}"
        redis = redis_async.from_url(REDIS_URL, decode_responses=True)
        bus = EventBus(REDIS_URL)
        try:
            await bus.ensure_group(stream, group, "0-0")
            await redis.xadd(
                stream,
                {
                    "payload": json.dumps(
                        {
                            "event": "scan.started",
                            "scan_id": str(uuid4()),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "data": {},
                        }
                    )
                },
            )
            subscription = bus.subscribe(
                ["scan.*"], stream=stream, group=group, consumer="c"
            )
            delivery = await anext(subscription)
            assert isinstance(delivery.event, LegacyEventV0)
            assert delivery.legacy is True
            await delivery.ack()
            await subscription.aclose()
        finally:
            await bus.close()
            await _cleanup(redis, stream)

    asyncio.run(scenario())
