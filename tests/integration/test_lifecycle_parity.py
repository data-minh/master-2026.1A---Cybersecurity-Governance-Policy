"""Runtime ledger and pure reference FSM must agree on the same event sequence."""

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import redis.asyncio as redis_async

from services.orchestrator.app.fanout import WorkSpec, make_stage_run_id, make_work_id
from services.orchestrator.app.ledger import RedisLifecycleLedger, StartScanSpec
from services.orchestrator.app.state_machine import apply_lifecycle_event
from vts_common.lifecycle import LifecycleEnvelopeV1, WorkType

NOW = datetime.now(timezone.utc)
PRODUCER = {"recon": "recon-subdomain", "scan": "scan-engine"}


def _scan_work(scan_id, path):
    resource = f"http://vuln-target/{path}"
    return WorkSpec(
        work_type=WorkType.SCAN_TEMPLATE_URL,
        service="scan-engine",
        stage="scan",
        scan_id=scan_id,
        stage_run_id=make_stage_run_id(scan_id, "scan"),
        work_id=make_work_id(scan_id, WorkType.SCAN_TEMPLATE_URL, resource, "default"),
        parent_work_id=None,
        input={"url": resource, "class": "page"},
        variant="default",
        timeout_seconds=120,
    )


def _event(scan_id, stage, work_id, topic, data):
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": topic,
            "scan_id": scan_id,
            "stage_run_id": make_stage_run_id(scan_id, stage),
            "work_id": work_id,
            "parent_work_id": None,
            "producer": PRODUCER[stage],
            "attempt": 1,
            "occurred_at": NOW.isoformat(),
            "data": data,
        }
    )


def _completed(count=0):
    return "work.completed", {"result_count": count, "duration_ms": 1, "lease_token": "t"}


def _failed():
    return "work.failed", {"error_code": "BROKEN", "retryable": False, "message": "", "duration_ms": 1, "lease_token": "t"}


SCENARIOS = {
    "sibling_failure_fails_scan_and_closes_open_work": [("root", _completed()), ("a", _completed()), ("b", _failed())],
    "all_work_completes_scan_succeeds": [("root", _completed()), ("a", _completed()), ("b", _completed())],
    "failure_while_recon_still_open": [("a", _failed())],
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_ledger_matches_reference_fsm(redis_test_url, name):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        scan_id = str(uuid4())
        try:
            snapshot = await ledger.create_scan(
                StartScanSpec("vuln-target", "full", "parallel", scan_id, NOW), "tester", f"parity-{name}"
            )
            ids = {"root": next(iter(await redis.smembers(f"{ledger.namespace}:scan:{scan_id}:works")))}
            for label in ("a", "b"):
                registered = await ledger.register_work(
                    _scan_work(scan_id, label), expected_revision=snapshot.revision, cause_work_id=None
                )
                snapshot = registered.snapshot
                ids[label] = registered.work_id
            stage_of = {"root": "recon", "a": "scan", "b": "scan"}

            state = (await ledger.recover_active())[0]
            for offset, (label, (topic, data)) in enumerate(
                [(label, ("work.started", {"lease_token": "t"})) for label in ("root", "a", "b")]
                + SCENARIOS[name]
            ):
                event = _event(scan_id, stage_of[label], ids[label], topic, data)
                at = NOW + timedelta(milliseconds=offset)
                state = apply_lifecycle_event(state, event, at).state
                await ledger.ingest(event, at)

            snapshot = await ledger.get_scan(scan_id)
            works = (await ledger.list_work(scan_id, None, None, None, 100)).items
            ledger_view = (
                snapshot.status,
                {n: s.status for n, s in snapshot.stages.items()},
                {w.work_id: w.status for w in works},
            )
            fsm_view = (
                state.scan.status,
                {n: s.status for n, s in state.stages.items()},
                {w.work_id: w.status for w in state.works.values()},
            )
            assert ledger_view == fsm_view
        finally:
            keys = [key async for key in redis.scan_iter(match=f"{ledger.namespace}:*")]
            if keys:
                await redis.delete(*keys)
            await redis.aclose()

    asyncio.run(scenario())
