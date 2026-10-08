import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from services.orchestrator.app.fanout import make_stage_run_id
from services.orchestrator.app.ledger import IngestResult, RegistrationResult
from services.orchestrator.app.main import (
    handle_bus_delivery,
    recover_startup,
    retry_delay,
    timeout_reaper_once,
)
from services.orchestrator.app.state_machine import LifecycleState, ScanRecord, StageRecord
from vts_common.lifecycle import (
    ApprovalSummary,
    LifecycleEnvelopeV1,
    ResultSummary,
    ScanSnapshot,
    ScanStatus,
    StageSnapshot,
    StageStatus,
)
from vts_common.service import ReadinessState

NOW = datetime.now(timezone.utc)


def _snapshot():
    scan_id = str(uuid4())
    return ScanSnapshot(
        scan_id=scan_id,
        revision=2,
        status=ScanStatus.RUNNING,
        target="vuln-target",
        mode="full",
        exec_mode="parallel",
        created_at=NOW,
        queued_at=NOW,
        started_at=NOW,
        updated_at=NOW,
        stages={
            "recon": StageSnapshot(stage_run_id=make_stage_run_id(scan_id, "recon"), name="recon", status=StageStatus.RUNNING, sealed=False, total_work=1, open_work=1),
            "scan": StageSnapshot(stage_run_id=make_stage_run_id(scan_id, "scan"), name="scan", status=StageStatus.PENDING, sealed=False),
            "verification": StageSnapshot(stage_run_id=make_stage_run_id(scan_id, "verification"), name="verification", status=StageStatus.PENDING, sealed=False),
        },
        approval_summary=ApprovalSummary(),
        result_summary=ResultSummary(),
    )


def _result(snapshot):
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": "asset.endpoint.alive",
            "scan_id": snapshot.scan_id,
            "stage_run_id": snapshot.stages["recon"].stage_run_id,
            "work_id": str(uuid4()),
            "parent_work_id": None,
            "producer": "recon-httpprobe",
            "attempt": 1,
            "occurred_at": NOW.isoformat(),
            "data": {"result_id": "sha256:" + "a" * 64, "url": "http://vuln-target/"},
        }
    )


class Delivery:
    def __init__(self, event):
        self.event = event
        self.stream = "vts.bus"
        self.acked = False

    async def ack(self):
        self.acked = True


class RuntimeLedger:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.registered = []

    async def ingest(self, event, now):
        return IngestResult(self.snapshot)

    async def register_work(self, spec, expected_revision, cause_work_id):
        self.registered.append((spec, cause_work_id))
        self.snapshot = self.snapshot.model_copy(update={"revision": self.snapshot.revision + 1})
        return RegistrationResult(self.snapshot, spec.work_id, True, "1-0")

    async def recover_active(self):
        return ["active"]


class RuntimeBus:
    def __init__(self, fail=False):
        self.fail = fail
        self.dlq = []

    async def write_dlq(self, delivery, reason):
        if self.fail:
            raise RuntimeError("dlq unavailable")
        self.dlq.append(reason)


def test_result_registers_all_children_before_parent_delivery_ack():
    async def scenario():
        snapshot = _snapshot()
        ledger = RuntimeLedger(snapshot)
        delivery = Delivery(_result(snapshot))
        await handle_bus_delivery(delivery, ledger, RuntimeBus())
        return delivery, ledger

    delivery, ledger = asyncio.run(scenario())
    assert delivery.acked
    assert len(ledger.registered) == 2
    assert {item[0].stage for item in ledger.registered} == {"recon", "scan"}


def test_dlq_failure_leaves_bus_message_pending():
    async def scenario():
        snapshot = _snapshot()
        event = _result(snapshot)
        event.producer = "dashboard"
        delivery = Delivery(event)
        with pytest.raises(RuntimeError, match="dlq unavailable"):
            await handle_bus_delivery(delivery, RuntimeLedger(snapshot), RuntimeBus(True))
        return delivery

    assert asyncio.run(scenario()).acked is False


def test_parallel_work_running_25_seconds_never_succeeds():
    snapshot = _snapshot()
    state = LifecycleState(
        scan=ScanRecord(
            snapshot.scan_id,
            ScanStatus.RUNNING,
            snapshot.revision,
            snapshot.target,
            snapshot.mode,
            snapshot.exec_mode,
            snapshot.created_at,
            snapshot.queued_at,
            snapshot.updated_at,
            started_at=snapshot.started_at,
        ),
        stages={
            name: StageRecord(
                stage.stage_run_id,
                name,
                stage.status,
                open_work=stage.open_work,
                total_work=stage.total_work,
            )
            for name, stage in snapshot.stages.items()
        },
    )
    result = timeout_reaper_once(state, NOW + timedelta(seconds=25))
    assert result.scan.status == ScanStatus.RUNNING
    assert result.stages["recon"].status == StageStatus.RUNNING


def test_retry_attempts_use_1_5_15_backoff_and_stop_at_three():
    assert [retry_delay(attempt) for attempt in (1, 2, 3)] == [1, 5, 15]
    with pytest.raises(ValueError):
        retry_delay(4)


def test_active_recovery_sets_readiness_only_after_load():
    async def scenario():
        readiness = ReadinessState(("recovery",))
        active = await recover_startup(RuntimeLedger(_snapshot()), readiness)
        return active, readiness.response()

    active, response = asyncio.run(scenario())
    assert active == ["active"]
    assert response[0] == 200
