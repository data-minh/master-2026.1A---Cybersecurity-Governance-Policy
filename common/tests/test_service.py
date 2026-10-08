import asyncio
import json
from contextlib import asynccontextmanager

from fastapi.testclient import TestClient

from vts_common.service import (
    MetricsRegistry,
    ReadinessCheck,
    ReadinessState,
    log_event,
    make_app,
    redis_readiness_check,
    supervise,
)


def test_health_ready_and_metrics_routes_reflect_runtime_state():
    readiness = ReadinessState(("redis", "consumer"))
    metrics = MetricsRegistry()
    metrics.counter("vts_work_completed_total", {"service": "worker"})
    app = make_app("test", readiness=readiness, metrics=metrics)

    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code == 503
        readiness.set("redis", True)
        readiness.set("consumer", True)
        assert client.get("/readyz").status_code == 200
        assert "vts_work_completed_total" in client.get("/metrics").text


def test_readiness_response_does_not_expose_dependency_secret():
    readiness = ReadinessState(("redis",))
    readiness.set("redis", False, "redis unavailable")
    status, payload = readiness.response()

    assert status == 503
    assert payload["status"] == "not_ready"
    assert "redis unavailable" in payload["reasons"]
    assert "redis://" not in json.dumps(payload)


def test_supervisor_marks_failure_unready_and_restarts():
    async def scenario():
        readiness = ReadinessState(("consumer",))
        attempts = 0
        restarted = asyncio.Event()

        async def factory():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("boom")
            restarted.set()
            await asyncio.Event().wait()

        task = asyncio.create_task(
            supervise("consumer", factory, readiness, backoff=(0,))
        )
        await asyncio.wait_for(restarted.wait(), timeout=1)
        healthy = readiness.checks["consumer"].healthy
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return attempts, healthy

    attempts, healthy = asyncio.run(scenario())
    assert attempts == 2
    assert healthy is True


def test_metrics_registry_renders_counter_gauge_and_histogram():
    metrics = MetricsRegistry()
    metrics.counter("vts_work_completed_total", {"service": "scan-engine"}, 2)
    metrics.gauge("vts_work_in_flight", {"service": "scan-engine"}, 3)
    metrics.observe("vts_work_duration_seconds", {"service": "scan-engine"}, 0.5)
    rendered = metrics.render_prometheus()

    assert 'vts_work_completed_total{service="scan-engine"} 2.0' in rendered
    assert 'vts_work_in_flight{service="scan-engine"} 3.0' in rendered
    assert 'vts_work_duration_seconds_count{service="scan-engine"} 1' in rendered
    assert 'vts_work_duration_seconds_sum{service="scan-engine"} 0.5' in rendered


def test_json_log_always_contains_correlation_keys(capsys):
    log_event("info", "transition committed", scan_id="scan")
    record = json.loads(capsys.readouterr().out)

    assert record["level"] == "info"
    assert record["message"] == "transition committed"
    assert record["scan_id"] == "scan"
    for key in (
        "event_id",
        "stage_run_id",
        "work_id",
        "parent_work_id",
        "attempt",
        "revision",
        "ingested_at",
    ):
        assert key in record


def test_redis_probe_fails_closed_when_aof_is_disabled():
    class RedisWithoutAof:
        async def ping(self):
            return True

        async def set(self, *args, **kwargs):
            return True

        async def get(self, *args, **kwargs):
            return "ok"

        async def delete(self, *args, **kwargs):
            return 1

        async def info(self, section):
            return {"aof_enabled": 0, "aof_last_write_status": "ok"}

    check = asyncio.run(redis_readiness_check(RedisWithoutAof()))
    assert check == ReadinessCheck("redis", False, "Redis AOF is not enabled")
