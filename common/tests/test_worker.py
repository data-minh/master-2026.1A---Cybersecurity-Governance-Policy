import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from vts_common.lifecycle import LifecycleEnvelopeV1, WorkType
from vts_common.worker import WorkContext, WorkerRunner, WorkResult


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.hashes = {}

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def hset(self, key, mapping=None, **kwargs):
        self.hashes.setdefault(key, {}).update(mapping or kwargs)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def get(self, key):
        return self.values.get(key)

    async def expire(self, key, ttl):
        return key in self.values

    async def delete(self, key):
        self.values.pop(key, None)


class FakeBus:
    def __init__(self, fail_terminal=False):
        self.redis = FakeRedis()
        self.call_order = []
        self.events = []
        self.fail_terminal = fail_terminal

    async def publish(self, event, **kwargs):
        self.call_order.append(f"xadd:{event.event}")
        self.events.append(event)
        return f"{len(self.events)}-0"

    async def persist_terminal(self, event, journal_key, journal):
        if self.fail_terminal:
            raise RuntimeError("redis terminal write failed")
        await self.redis.hset(journal_key, mapping=journal)
        self.call_order.append(f"xadd:{event.event}")
        self.events.append(event)
        return f"{len(self.events)}-0"

    async def write_dlq(self, delivery, reason):
        self.call_order.append("xadd:vts.dlq")
        return "1-0"


class FakeDelivery:
    def __init__(self, event, bus):
        self.event = event
        self.message_id = "1-0"
        self.stream = "vts.commands.test-worker"
        self.raw = event.model_dump_json()
        self.redis = bus.redis
        self.group = "worker-test-worker"
        self.consumer = "consumer"
        self.acked = False
        self.touches = 0
        self.bus = bus

    async def ack(self):
        self.acked = True
        self.bus.call_order.append("xack:work.command")

    async def touch(self):
        self.touches += 1


def _command(work_id=None, attempt=1, work_type="scan.template_url"):
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
            "attempt": attempt,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": {
                "work_type": work_type,
                "input": {"url": "http://vuln-target/", "class": "page"},
                "timeout_seconds": 120,
                "max_attempts": 3,
                "dispatch_not_before": datetime.now(timezone.utc).isoformat(),
            },
        }
    )


def test_terminal_event_is_persisted_before_command_ack():
    async def handler(ctx, command):
        return WorkResult(result_count=0)

    async def scenario():
        bus = FakeBus()
        runner = WorkerRunner(
            "test-worker", bus, {WorkType.SCAN_TEMPLATE_URL: handler}, 1
        )
        delivery = FakeDelivery(_command(), bus)
        await runner.handle_delivery(delivery)
        return bus, delivery

    bus, delivery = asyncio.run(scenario())
    assert delivery.acked
    assert bus.call_order[-2:] == ["xadd:work.completed", "xack:work.command"]
    assert bus.events[-1].data["result_count"] == 0


def test_worker_updates_shared_lifecycle_metrics(monkeypatch):
    from vts_common import service as service_module
    from vts_common.service import MetricsRegistry

    async def handler(ctx, command):
        return WorkResult(0)

    async def scenario():
        metrics = MetricsRegistry()
        monkeypatch.setattr(service_module, "DEFAULT_METRICS", metrics)
        bus = FakeBus()
        runner = WorkerRunner(
            "test-worker", bus, {WorkType.SCAN_TEMPLATE_URL: handler}, 1
        )
        await runner.handle_delivery(FakeDelivery(_command(), bus))
        return metrics.render_prometheus()

    rendered = asyncio.run(scenario())
    assert 'vts_work_queued_total{service="test-worker",work_type="scan.template_url"} 1.0' in rendered
    assert 'vts_work_started_total{service="test-worker",work_type="scan.template_url"} 1.0' in rendered
    assert 'vts_work_completed_total{service="test-worker",work_type="scan.template_url"} 1.0' in rendered
    assert 'vts_work_duration_seconds_count{service="test-worker",work_type="scan.template_url"} 1' in rendered


def test_terminal_xadd_failure_leaves_command_pending():
    async def handler(ctx, command):
        return WorkResult(0)

    async def scenario():
        bus = FakeBus(fail_terminal=True)
        runner = WorkerRunner(
            "test-worker", bus, {WorkType.SCAN_TEMPLATE_URL: handler}, 1
        )
        delivery = FakeDelivery(_command(), bus)
        with pytest.raises(RuntimeError, match="terminal write"):
            await runner.handle_delivery(delivery)
        return delivery

    assert asyncio.run(scenario()).acked is False


def test_stale_fencing_token_cannot_publish_terminal():
    async def handler(ctx, command):
        await ctx.runner.bus.redis.set(ctx.lease_key, "new-owner")
        return WorkResult(1)

    async def scenario():
        bus = FakeBus()
        runner = WorkerRunner(
            "test-worker", bus, {WorkType.SCAN_TEMPLATE_URL: handler}, 1
        )
        delivery = FakeDelivery(_command(), bus)
        await runner.handle_delivery(delivery)
        return bus, delivery

    bus, delivery = asyncio.run(scenario())
    assert not delivery.acked
    assert "work.completed" not in [event.event for event in bus.events]


def test_duplicate_terminal_journal_does_not_execute_again():
    calls = 0

    async def handler(ctx, command):
        nonlocal calls
        calls += 1
        return WorkResult(0)

    async def scenario():
        bus = FakeBus()
        command = _command()
        key = f"vts:worker:test-worker:{command.work_id}:{command.attempt}"
        await bus.redis.hset(key, mapping={"terminal_event_id": str(uuid4())})
        runner = WorkerRunner(
            "test-worker", bus, {WorkType.SCAN_TEMPLATE_URL: handler}, 1
        )
        delivery = FakeDelivery(command, bus)
        await runner.handle_delivery(delivery)
        return delivery

    delivery = asyncio.run(scenario())
    assert delivery.acked
    assert calls == 0


def test_invalid_command_dlq_before_ack():
    async def scenario():
        bus = FakeBus()
        command = _command()
        command.producer = "scan-engine"
        runner = WorkerRunner("test-worker", bus, {}, 1)
        delivery = FakeDelivery(command, bus)
        await runner.handle_delivery(delivery)
        return bus, delivery

    bus, delivery = asyncio.run(scenario())
    assert delivery.acked
    assert bus.call_order[-2:] == ["xadd:vts.dlq", "xack:work.command"]


def test_progress_sequence_is_monotonic():
    async def scenario():
        bus = FakeBus()
        runner = WorkerRunner("test-worker", bus, {}, 1)
        command = _command()
        context = WorkContext(runner, command, "lease")
        await bus.redis.set(context.lease_key, "lease")
        await context.progress(1, 20, "started", {})
        with pytest.raises(ValueError, match="sequence"):
            await context.progress(1, 30, "duplicate", {})
        return bus

    bus = asyncio.run(scenario())
    assert [event.event for event in bus.events] == ["work.progress"]


def test_heartbeat_touches_pending_every_five_seconds():
    async def handler(ctx, command):
        await asyncio.sleep(0.08)
        return WorkResult(0)

    async def scenario():
        bus = FakeBus()
        runner = WorkerRunner(
            "test-worker",
            bus,
            {WorkType.SCAN_TEMPLATE_URL: handler},
            1,
            heartbeat_seconds=0.01,
        )
        delivery = FakeDelivery(_command(), bus)
        await runner.handle_delivery(delivery)
        return delivery, runner

    delivery, runner = asyncio.run(scenario())
    assert runner.default_heartbeat_seconds == 5
    assert delivery.touches >= 2
