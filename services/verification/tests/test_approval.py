import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import redis.asyncio as redis_async

from services.verification.app.main import (
    ApprovalConflict,
    ApprovalStore,
    IdempotencyKeyReused,
)
from vts_common.lifecycle import LifecycleEnvelopeV1

NOW = datetime.now(timezone.utc)


@pytest.fixture
def redis_test_url():
    return os.getenv("VTS_TEST_REDIS_URL", "redis://localhost:16379/15")


def _source(finding=None, attempt=1):
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": "vuln.verified",
            "scan_id": str(uuid4()),
            "stage_run_id": str(uuid4()),
            "work_id": str(uuid4()),
            "parent_work_id": None,
            "producer": "verification",
            "attempt": attempt,
            "occurred_at": NOW.isoformat(),
            "data": {
                "result_id": "sha256:" + "a" * 64,
                "finding_id": finding or "sha256:" + "b" * 64,
                "url": "http://vuln-target/",
                "severity": "high",
            },
        }
    )


async def _cleanup(redis, namespace):
    keys = [key async for key in redis.scan_iter(match=f"{namespace}:*")]
    if keys:
        await redis.delete(*keys)
    await redis.aclose()


def test_unique_finding_creates_one_pending_approval(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace = f"vts-test-{uuid4().hex}"
        store = ApprovalStore(redis, namespace, f"{namespace}:bus")
        try:
            source = _source()
            first = await store.create_requested(source, str(uuid4()))
            second = await store.create_requested(source, first.execution_work_id)
            assert first.approval_id == second.approval_id
            assert first.status == "pending"
            assert await redis.scard(f"{namespace}:scan:{source.scan_id}:approvals") == 1
            assert await redis.xlen(f"{namespace}:bus") == 1
        finally:
            await _cleanup(redis, namespace)

    asyncio.run(scenario())


def test_approve_does_not_execute_and_explicit_execute_is_accepted(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace = f"vts-test-{uuid4().hex}"
        store = ApprovalStore(redis, namespace, f"{namespace}:bus")
        try:
            approval = await store.create_requested(_source(), str(uuid4()))
            with pytest.raises(ApprovalConflict):
                await store.request_execution(approval.approval_id, "actor", True, "execute-before")
            approved = await store.approve(approval.approval_id, "actor", "ok", "approve-key")
            assert approved.status == "approved"
            accepted = await store.request_execution(approval.approval_id, "actor", True, "execute-key")
            assert accepted.status == "executing"
            assert accepted.execution_work_id == approval.execution_work_id
        finally:
            await _cleanup(redis, namespace)

    asyncio.run(scenario())


def test_idempotency_replay_and_payload_mismatch(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace = f"vts-test-{uuid4().hex}"
        store = ApprovalStore(redis, namespace, f"{namespace}:bus")
        try:
            approval = await store.create_requested(_source(), str(uuid4()))
            first = await store.approve(approval.approval_id, "actor", "ok", "same-action")
            replay = await store.approve(approval.approval_id, "actor", "ok", "same-action")
            assert replay == first
            with pytest.raises(IdempotencyKeyReused):
                await store.approve(approval.approval_id, "actor", "different", "same-action")
        finally:
            await _cleanup(redis, namespace)

    asyncio.run(scenario())


def test_actions_preserve_source_stage_and_retry_attempt(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace = f"vts-test-{uuid4().hex}"
        store = ApprovalStore(redis, namespace, f"{namespace}:bus")
        try:
            source = _source(attempt=2)
            approval = await store.create_requested(source, str(uuid4()))
            await store.approve(approval.approval_id, "actor", "ok", "retry-action")
            latest = await redis.xrevrange(f"{namespace}:bus", count=1)
            action = json.loads(latest[0][1]["payload"])
            assert action["stage_run_id"] == source.stage_run_id
            assert action["attempt"] == 2
        finally:
            await _cleanup(redis, namespace)

    asyncio.run(scenario())


def test_concurrent_decisions_have_exactly_one_cas_winner(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace = f"vts-test-{uuid4().hex}"
        store = ApprovalStore(redis, namespace, f"{namespace}:bus")
        try:
            approval = await store.create_requested(_source(), str(uuid4()))
            results = await asyncio.gather(
                store.approve(approval.approval_id, "a", "yes", "approve-concurrent"),
                store.reject(approval.approval_id, "b", "no", "reject-concurrent"),
                return_exceptions=True,
            )
            assert sum(not isinstance(result, Exception) for result in results) == 1
            assert sum(isinstance(result, ApprovalConflict) for result in results) == 1
        finally:
            await _cleanup(redis, namespace)

    asyncio.run(scenario())


def test_reject_after_execution_dispatch_conflicts_and_deadline_expires(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace = f"vts-test-{uuid4().hex}"
        store = ApprovalStore(redis, namespace, f"{namespace}:bus")
        try:
            approval = await store.create_requested(_source(), str(uuid4()), decision_deadline=NOW - timedelta(seconds=1))
            expired = await store.expire_due(NOW)
            assert expired[0].status == "timed_out"
            entries = await redis.xrevrange(f"{namespace}:bus", count=1)
            assert json.loads(entries[0][1]["payload"])["event"] == "approval.execution_failed"
            other = await store.create_requested(_source("sha256:" + "c" * 64), str(uuid4()))
            await store.approve(other.approval_id, "a", "ok", "approve-other")
            await store.request_execution(other.approval_id, "a", True, "execute-other")
            with pytest.raises(ApprovalConflict):
                await store.reject(other.approval_id, "a", "late", "reject-late")
        finally:
            await _cleanup(redis, namespace)

    asyncio.run(scenario())
