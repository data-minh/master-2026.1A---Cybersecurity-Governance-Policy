import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import redis.asyncio as redis_async

from services.orchestrator.app.fanout import WorkSpec, make_stage_run_id, make_work_id
from services.orchestrator.app.ledger import (
    IdempotencyConflict,
    RedisLifecycleLedger,
    ReplayWindowExpired,
    RevisionConflict,
    StartScanSpec,
)
from vts_common.lifecycle import LifecycleEnvelopeV1, ScanStatus, WorkType

NOW = datetime.now(timezone.utc)


def _spec(scan_id):
    return StartScanSpec(
        scan_id=scan_id,
        target="vuln-target",
        mode="full",
        exec_mode="parallel",
        created_at=NOW,
    )


def _child(scan_id, resource="http://vuln-target/"):
    return WorkSpec(
        work_type=WorkType.SCAN_TEMPLATE_URL,
        service="scan-engine",
        stage="scan",
        scan_id=scan_id,
        stage_run_id=make_stage_run_id(scan_id, "scan"),
        work_id=make_work_id(scan_id, WorkType.SCAN_TEMPLATE_URL, resource, "default"),
        parent_work_id=str(uuid4()),
        input={"url": resource, "class": "page"},
        variant="default",
        timeout_seconds=120,
    )


def _result(snapshot, work_id, attempt=1, result_id=None):
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": "vuln.detected",
            "scan_id": snapshot.scan_id,
            "stage_run_id": snapshot.stages["scan"].stage_run_id,
            "work_id": work_id,
            "parent_work_id": None,
            "producer": "scan-engine",
            "attempt": attempt,
            "occurred_at": NOW.isoformat(),
            "data": {
                "result_id": result_id or "sha256:" + uuid4().hex * 2,
                "finding_id": "sha256:" + uuid4().hex * 2,
                "url": "http://vuln-target/",
                "severity": "high",
            },
        }
    )


async def _cleanup(redis, ledger, scan_id, command_ids=()):
    keys = []
    async for key in redis.scan_iter(match=f"{ledger.namespace}:*"):
        keys.append(key)
    if keys:
        await redis.delete(*keys)
    for message_id in command_ids:
        await redis.xdel("vts.commands.recon-subdomain", message_id)
        await redis.xdel("vts.commands.scan-engine", message_id)
    await redis.aclose()


def test_create_scan_registers_root_and_command_atomically(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace = f"vts-test-{uuid4().hex}"
        ledger = RedisLifecycleLedger(redis, namespace)
        scan_id = str(uuid4())
        before = await redis.xlen("vts.commands.recon-subdomain")
        try:
            snapshot = await ledger.create_scan(_spec(scan_id), "tester", "key-create-1")
            after = await redis.xlen("vts.commands.recon-subdomain")
            assert snapshot.revision == 2
            assert snapshot.status == ScanStatus.RUNNING
            assert await redis.scard(f"{namespace}:scan:{scan_id}:works") == 1
            assert after == before + 1
            update = await redis.xrevrange(f"{namespace}:scan:{scan_id}:updates", count=1)
            assert int(update[0][1]["revision"]) == snapshot.revision
            command_id = (await redis.xrevrange("vts.commands.recon-subdomain", count=1))[0][0]
        finally:
            await _cleanup(redis, ledger, scan_id, [command_id] if 'command_id' in locals() else [])

    asyncio.run(scenario())


def test_register_work_is_idempotent_and_adds_second_cause(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        scan_id = str(uuid4())
        command_ids = []
        try:
            snapshot = await ledger.create_scan(_spec(scan_id), "tester", "key-register")
            spec = _child(scan_id)
            first = await ledger.register_work(spec, expected_revision=snapshot.revision, cause_work_id="cause-a")
            second = await ledger.register_work(spec, expected_revision=first.snapshot.revision, cause_work_id="cause-b")
            assert first.created is True
            assert second.created is False
            assert second.snapshot.revision == first.snapshot.revision
            assert await redis.scard(f"{ledger.namespace}:work:{spec.work_id}:causes") == 2
            assert second.snapshot.stages["scan"].total_work == 1
            command_ids = [first.command_message_id]
        finally:
            await _cleanup(redis, ledger, scan_id, [value for value in command_ids if value])

    asyncio.run(scenario())


def test_expected_revision_conflict_has_no_partial_write(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        scan_id = str(uuid4())
        try:
            snapshot = await ledger.create_scan(_spec(scan_id), "tester", "key-revision")
            spec = _child(scan_id)
            with pytest.raises(RevisionConflict):
                await ledger.register_work(spec, expected_revision=0, cause_work_id="cause")
            assert not await redis.exists(f"{ledger.namespace}:work:{spec.work_id}")
            assert (await ledger.get_scan(scan_id)).revision == snapshot.revision
        finally:
            await _cleanup(redis, ledger, scan_id)

    asyncio.run(scenario())


def test_duplicate_event_and_result_are_noops_and_stale_goes_late(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        scan_id = str(uuid4())
        command_ids = []
        try:
            snapshot = await ledger.create_scan(_spec(scan_id), "tester", "key-ingest")
            registered = await ledger.register_work(_child(scan_id), expected_revision=snapshot.revision, cause_work_id="cause")
            command_ids.append(registered.command_message_id)
            event = _result(registered.snapshot, _child(scan_id).work_id)
            first = await ledger.ingest(event, NOW)
            duplicate = await ledger.ingest(event, NOW + timedelta(seconds=1))
            same_result = await ledger.ingest(event.model_copy(update={"event_id": str(uuid4())}), NOW + timedelta(seconds=2))
            stale = await ledger.ingest(_result(first.snapshot, _child(scan_id).work_id, attempt=2), NOW)
            assert duplicate.snapshot.revision == first.snapshot.revision
            assert same_result.snapshot.revision == first.snapshot.revision
            assert stale.late is True
            assert await redis.xlen(f"{ledger.namespace}:late") == 1
        finally:
            await _cleanup(redis, ledger, scan_id, [value for value in command_ids if value])

    asyncio.run(scenario())


def test_terminal_late_event_does_not_change_snapshot_and_ttls_are_applied(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        scan_id = str(uuid4())
        try:
            snapshot = await ledger.create_scan(_spec(scan_id), "tester", "key-terminal")
            terminal = await ledger.cancel_scan(scan_id, "test complete", "cancel-key")
            root_id = next(iter(await redis.smembers(f"{ledger.namespace}:scan:{scan_id}:works")))
            late = await ledger.ingest(_result(snapshot, root_id), NOW)
            assert late.late is True
            assert late.snapshot.model_dump() == terminal.model_dump()
            snapshot_ttl = await redis.ttl(f"{ledger.namespace}:scan:{scan_id}:snapshot")
            dedupe_ttl = await redis.ttl(f"{ledger.namespace}:scan:{scan_id}:event_ids")
            assert 604790 <= snapshot_ttl <= 604800
            assert dedupe_ttl > snapshot_ttl
        finally:
            await _cleanup(redis, ledger, scan_id)

    asyncio.run(scenario())


def test_retry_and_lists_recover_after_repository_restart(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace = f"vts-test-{uuid4().hex}"
        ledger = RedisLifecycleLedger(redis, namespace)
        scan_id = str(uuid4())
        command_ids = []
        try:
            snapshot = await ledger.create_scan(_spec(scan_id), "tester", "key-recover")
            first = await ledger.register_work(_child(scan_id, "http://vuln-target/a"), expected_revision=snapshot.revision, cause_work_id="a")
            second = await ledger.register_work(_child(scan_id, "http://vuln-target/b"), expected_revision=first.snapshot.revision, cause_work_id="b")
            command_ids.extend([first.command_message_id, second.command_message_id])
            await ledger.schedule_retry(first.work_id, 2, NOW + timedelta(seconds=5))
            restarted = RedisLifecycleLedger(redis, namespace)
            active = await restarted.recover_active()
            page1 = await restarted.list_work(scan_id, None, None, None, 1)
            page2 = await restarted.list_work(scan_id, None, None, page1.next_cursor, 10)
            assert [state.scan.scan_id for state in active] == [scan_id]
            assert len(page1.items) == 1 and len(page2.items) >= 1
            assert await redis.zscore(f"{namespace}:retry", first.work_id) is not None
            before_retry_commands = await redis.xlen("vts.commands.scan-engine")
            assert await restarted.dispatch_due_retries(NOW + timedelta(seconds=6)) == 1
            assert await redis.zscore(f"{namespace}:retry", first.work_id) is None
            assert await redis.xlen("vts.commands.scan-engine") == before_retry_commands + 1
            retry_command_id = (await redis.xrevrange("vts.commands.scan-engine", count=1))[0][0]
            command_ids.append(retry_command_id)
        finally:
            await _cleanup(redis, ledger, scan_id, [value for value in command_ids if value])

    asyncio.run(scenario())


def test_approval_requested_updates_authoritative_summary_before_terminal(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        scan_id = str(uuid4())
        command_ids = []
        try:
            snapshot = await ledger.create_scan(_spec(scan_id), "tester", "key-approval")
            safe = WorkSpec(
                work_type=WorkType.VERIFICATION_SAFE_VERIFY,
                service="verification",
                stage="verification",
                scan_id=scan_id,
                stage_run_id=make_stage_run_id(scan_id, "verification"),
                work_id=make_work_id(scan_id, WorkType.VERIFICATION_SAFE_VERIFY, "sha256:" + "a" * 64, "default"),
                parent_work_id=str(uuid4()),
                input={"finding_id": "sha256:" + "a" * 64, "url": "http://vuln-target/", "severity": "high"},
                variant="default",
                timeout_seconds=30,
            )
            registered = await ledger.register_work(safe, expected_revision=snapshot.revision, cause_work_id="finding")
            command_ids.append(registered.command_message_id)
            approval_id = str(uuid4())
            requested = LifecycleEnvelopeV1.model_validate({
                "schema_version": 1,
                "event_id": str(uuid4()),
                "event": "approval.requested",
                "scan_id": scan_id,
                "stage_run_id": safe.stage_run_id,
                "work_id": safe.work_id,
                "parent_work_id": safe.parent_work_id,
                "producer": "verification",
                "attempt": 1,
                "occurred_at": NOW.isoformat(),
                "data": {"approval_id": approval_id, "finding_id": "sha256:" + "a" * 64, "execution_work_id": str(uuid4()), "decision_deadline": (NOW + timedelta(days=1)).isoformat()},
            })
            result = await ledger.ingest(requested, NOW)
            assert result.snapshot.status == ScanStatus.AWAITING_APPROVAL
            assert result.snapshot.approval_summary.total == 1
            assert result.snapshot.approval_summary.pending == 1
            timed_out = requested.model_copy(update={
                "event_id": str(uuid4()),
                "event": "approval.execution_failed",
                "data": {"approval_id": approval_id, "execution_work_id": requested.data["execution_work_id"], "error_code": "APPROVAL_DEADLINE", "retryable": False},
            })
            timeout_result = await ledger.ingest(timed_out, NOW + timedelta(days=1))
            assert timeout_result.snapshot.status == ScanStatus.TIMED_OUT
            assert timeout_result.snapshot.stages["verification"].status.value == "timed_out"
        finally:
            await _cleanup(redis, ledger, scan_id, [value for value in command_ids if value])

    asyncio.run(scenario())


def test_technical_watchdog_times_out_without_success_branch(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        scan_id = str(uuid4())
        try:
            await ledger.create_scan(_spec(scan_id), "tester", "watchdog-key")
            assert await ledger.expire_due(NOW + timedelta(seconds=7201)) == 1
            snapshot = await ledger.get_scan(scan_id)
            assert snapshot.status == ScanStatus.TIMED_OUT
            assert snapshot.outcome["code"] == "TECHNICAL_WATCHDOG"
            assert all(stage.status.value != "succeeded" for stage in snapshot.stages.values())
        finally:
            await _cleanup(redis, ledger, scan_id)

    asyncio.run(scenario())


def test_recovery_loads_all_work_pages_beyond_one_hundred(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        scan_id = str(uuid4())
        command_ids = []
        try:
            snapshot = await ledger.create_scan(_spec(scan_id), "tester", "many-work-key")
            for index in range(101):
                registered = await ledger.register_work(
                    _child(scan_id, f"http://vuln-target/{index}"),
                    expected_revision=snapshot.revision,
                    cause_work_id=f"cause-{index}",
                )
                snapshot = registered.snapshot
                command_ids.append(registered.command_message_id)
            recovered = await RedisLifecycleLedger(redis, ledger.namespace).recover_active()
            assert len(recovered[0].works) == 102
        finally:
            await _cleanup(redis, ledger, scan_id, [value for value in command_ids if value])

    asyncio.run(scenario())


def _work_failed(snapshot, work_id):
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": "work.failed",
            "scan_id": snapshot.scan_id,
            "stage_run_id": snapshot.stages["scan"].stage_run_id,
            "work_id": work_id,
            "parent_work_id": None,
            "producer": "scan-engine",
            "attempt": 1,
            "occurred_at": NOW.isoformat(),
            "data": {"error_code": "BROKEN", "retryable": False, "message": "", "duration_ms": 1, "lease_token": "t"},
        }
    )


def test_terminal_failure_and_cancel_close_every_open_work(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        try:
            failing_scan = str(uuid4())
            snapshot = await ledger.create_scan(_spec(failing_scan), "tester", "close-open-fail")
            a = await ledger.register_work(_child(failing_scan, "http://vuln-target/a"), expected_revision=snapshot.revision, cause_work_id="a")
            b = await ledger.register_work(_child(failing_scan, "http://vuln-target/b"), expected_revision=a.snapshot.revision, cause_work_id="b")
            await ledger.schedule_retry(b.work_id, 1, NOW + timedelta(seconds=30))
            failed = await ledger.ingest(_work_failed(b.snapshot, a.work_id), NOW)
            assert failed.snapshot.status == ScanStatus.FAILED
            works = {w.work_id: w for w in (await ledger.list_work(failing_scan, None, None, None, 100)).items}
            assert works[a.work_id].status.value == "failed"
            assert works[b.work_id].status.value == "canceled"
            assert all(w.status.value in {"failed", "canceled"} for w in works.values())
            assert await redis.zscore(f"{ledger.namespace}:retry", b.work_id) is None

            canceled_scan = str(uuid4())
            await ledger.create_scan(_spec(canceled_scan), "tester", "close-open-cancel")
            await ledger.cancel_scan(canceled_scan, "operator stop", "cancel-close-open")
            remaining = (await ledger.list_work(canceled_scan, None, None, None, 100)).items
            assert [w.status.value for w in remaining] == ["canceled"]
        finally:
            await _cleanup(redis, ledger, None)

    asyncio.run(scenario())


def test_api_style_replay_without_scan_id_returns_same_scan(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        spec = StartScanSpec(target="vuln-target", mode="full", exec_mode="parallel")
        try:
            first = await ledger.create_scan(spec, "tester", "api-replay-key")
            replay = await ledger.create_scan(spec, "tester", "api-replay-key")
            assert replay.scan_id == first.scan_id
            with pytest.raises(IdempotencyConflict):
                await ledger.create_scan(
                    StartScanSpec(target="vuln-target", mode="recon", exec_mode="parallel"),
                    "tester",
                    "api-replay-key",
                )
        finally:
            await _cleanup(redis, ledger, None)

    asyncio.run(scenario())


def test_idempotency_mismatch_and_expired_replay_are_rejected(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        scan_id = str(uuid4())
        try:
            first = await ledger.create_scan(_spec(scan_id), "tester", "same-key")
            replay = await ledger.create_scan(_spec(scan_id), "tester", "same-key")
            assert replay.scan_id == first.scan_id
            with pytest.raises(IdempotencyConflict):
                await ledger.create_scan(_spec(str(uuid4())), "tester", "same-key")
            with pytest.raises(ReplayWindowExpired):
                ledger.ensure_replayable(NOW - timedelta(days=8), NOW)
        finally:
            await _cleanup(redis, ledger, scan_id)

    asyncio.run(scenario())


def test_stage_result_count_is_not_double_counted_on_completion(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        scan_id = str(uuid4())
        command_ids = []
        try:
            snapshot = await ledger.create_scan(_spec(scan_id), "tester", "key-count")
            spec = _child(scan_id)
            registered = await ledger.register_work(spec, expected_revision=snapshot.revision, cause_work_id="c")
            command_ids.append(registered.command_message_id)
            await ledger.ingest(_result(registered.snapshot, spec.work_id), NOW)
            completed = LifecycleEnvelopeV1.model_validate(
                {
                    "schema_version": 1,
                    "event_id": str(uuid4()),
                    "event": "work.completed",
                    "scan_id": scan_id,
                    "stage_run_id": spec.stage_run_id,
                    "work_id": spec.work_id,
                    "parent_work_id": None,
                    "producer": "scan-engine",
                    "attempt": 1,
                    "occurred_at": NOW.isoformat(),
                    "data": {"result_count": 1, "duration_ms": 1, "lease_token": "t"},
                }
            )
            after = await ledger.ingest(completed, NOW + timedelta(seconds=1))
            assert after.snapshot.stages["scan"].result_count == 1
            assert after.snapshot.result_summary.findings == 1
        finally:
            await _cleanup(redis, ledger, scan_id, [value for value in command_ids if value])

    asyncio.run(scenario())


def test_create_scan_records_the_actor_and_terminal_ttl_covers_it(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        ledger = RedisLifecycleLedger(redis, f"vts-test-{uuid4().hex}")
        scan_id = str(uuid4())
        try:
            await ledger.create_scan(_spec(scan_id), "approver", "key-actor")
            meta_key = f"{ledger.namespace}:scan:{scan_id}:meta"
            assert await redis.hget(meta_key, "actor") == "approver"
            await ledger.cancel_scan(scan_id, "done", "cancel-actor")
            assert 604790 <= await redis.ttl(meta_key) <= 604800
        finally:
            await _cleanup(redis, ledger, scan_id)

    asyncio.run(scenario())
