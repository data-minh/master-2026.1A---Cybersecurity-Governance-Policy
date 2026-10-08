import asyncio
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import redis.asyncio as redis_async

from scripts.migrate_legacy_events import LegacyMigration
from services.orchestrator.app.ledger import RedisLifecycleLedger, StartScanSpec


def _v0(event, scan_id, timestamp=None, data=None):
    return json.dumps({"event": event, "scan_id": scan_id, "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(), "data": data or {}})


def _v1(scan_id):
    return json.dumps({"schema_version": 1, "event_id": str(uuid4()), "event": "scan.running", "scan_id": scan_id, "stage_run_id": None, "work_id": None, "parent_work_id": None, "producer": "orchestrator", "attempt": 0, "occurred_at": datetime.now(timezone.utc).isoformat(), "data": {"revision": 1}})


def test_terminal_and_active_v0_import_without_inferred_success(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace, stream = f"vts-test-{uuid4().hex}", f"vts-test-{uuid4().hex}:bus"
        terminal_id, active_id = str(uuid4()), str(uuid4())
        try:
            await redis.xadd(stream, {"payload": _v0("scan.started", terminal_id, data={"target": "vuln-target"})})
            await redis.xadd(stream, {"payload": _v0("scan.finished", terminal_id)})
            await redis.xadd(stream, {"payload": _v0("scan.started", active_id, data={"target": "vuln-target"})})
            report = await LegacyMigration(redis, namespace, stream).scan("0-0", "+", False)
            terminal = json.loads(await redis.get(f"{namespace}:legacy:scan:{terminal_id}:snapshot"))
            active = json.loads(await redis.get(f"{namespace}:legacy:scan:{active_id}:snapshot"))
            assert terminal["lifecycle_version"] == 0 and terminal["authoritative"] is False
            assert active["status"] == "canceled"
            assert active["outcome"]["code"] == "migration_cutover"
            assert report.imported == 2
        finally:
            keys = [key async for key in redis.scan_iter(match=f"{namespace}:*")]
            if keys:
                await redis.delete(*keys)
            await redis.delete(stream)
            await redis.aclose()

    asyncio.run(scenario())


def test_orchestrator_reads_still_work_after_migration_apply(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace, stream = f"vts-test-{uuid4().hex}", f"vts-test-{uuid4().hex}:bus"
        legacy_id = str(uuid4())
        ledger = RedisLifecycleLedger(redis, namespace)
        try:
            await redis.xadd(stream, {"payload": _v0("scan.started", legacy_id, data={"target": "vuln-target"})})
            await redis.xadd(stream, {"payload": _v0("scan.finished", legacy_id)})
            await LegacyMigration(redis, namespace, stream).scan("0-0", "+", False)
            v1 = await ledger.create_scan(StartScanSpec("vuln-target", "full", "parallel"), "tester", "post-migration-key")
            listing = await ledger.list_scans(None, None, 20)
            assert [item.scan_id for item in listing.items] == [v1.scan_id]
            assert [state.scan.scan_id for state in await ledger.recover_active()] == [v1.scan_id]
            assert await ledger.expire_due(datetime.now(timezone.utc)) == 0
            legacy = json.loads(await redis.get(f"{namespace}:legacy:scan:{legacy_id}:snapshot"))
            assert legacy["authoritative"] is False
        finally:
            keys = [key async for key in redis.scan_iter(match=f"{namespace}:*")]
            if keys:
                await redis.delete(*keys)
            await redis.delete(stream)
            await redis.aclose()

    asyncio.run(scenario())


def test_v1_ignored_dry_run_and_repeat_apply_are_idempotent(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace, stream = f"vts-test-{uuid4().hex}", f"vts-test-{uuid4().hex}:bus"
        scan_id = str(uuid4())
        try:
            await redis.xadd(stream, {"payload": _v1(str(uuid4()))})
            await redis.xadd(stream, {"payload": _v0("scan.started", scan_id, data={"target": "vuln-target"})})
            migration = LegacyMigration(redis, namespace, stream)
            dry = await migration.scan("0-0", "+", True)
            assert dry.would_import == 1
            assert not await redis.exists(f"{namespace}:legacy:scan:{scan_id}:snapshot")
            first = await migration.scan("0-0", "+", False)
            second = await migration.scan("0-0", "+", False)
            assert first.imported == 1
            assert second.imported == 0 and second.already_migrated == 1
            assert first.v1_ignored == 1
        finally:
            keys = [key async for key in redis.scan_iter(match=f"{namespace}:*")]
            if keys:
                await redis.delete(*keys)
            await redis.delete(stream)
            await redis.aclose()

    asyncio.run(scenario())


def test_expired_legacy_event_and_existing_v1_snapshot_are_fenced(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace, stream = f"vts-test-{uuid4().hex}", f"vts-test-{uuid4().hex}:bus"
        old_id, v1_id = str(uuid4()), str(uuid4())
        v1_snapshot = {"lifecycle_version": 1, "scan_id": v1_id, "revision": 9, "status": "running"}
        try:
            await redis.xadd(stream, {"payload": _v0("scan.started", old_id, datetime.now(timezone.utc) - timedelta(days=8))})
            await redis.xadd(stream, {"payload": _v0("scan.started", v1_id)})
            await redis.set(f"{namespace}:scan:{v1_id}:snapshot", json.dumps(v1_snapshot))
            report = await LegacyMigration(redis, namespace, stream).scan("0-0", "+", False)
            assert report.expired == 1
            assert report.v1_conflicts == 1
            assert json.loads(await redis.get(f"{namespace}:scan:{v1_id}:snapshot"))["revision"] == 9
        finally:
            keys = [key async for key in redis.scan_iter(match=f"{namespace}:*")]
            if keys:
                await redis.delete(*keys)
            await redis.delete(stream)
            await redis.aclose()

    asyncio.run(scenario())
