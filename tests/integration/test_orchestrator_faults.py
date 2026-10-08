import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import redis.asyncio as redis_async

from services.orchestrator.app.ledger import RedisLifecycleLedger, StartScanSpec


def test_recovery_preserves_active_snapshot_revision(redis_test_url):
    async def scenario():
        redis = redis_async.from_url(redis_test_url, decode_responses=True)
        namespace = f"vts-test-{uuid4().hex}"
        ledger = RedisLifecycleLedger(redis, namespace)
        scan_id = str(uuid4())
        try:
            before = await ledger.create_scan(StartScanSpec("vuln-target", "full", "parallel", scan_id, datetime.now(timezone.utc)), "tester", "fault-key")
            recovered = await RedisLifecycleLedger(redis, namespace).recover_active()
            assert recovered[0].scan.revision == before.revision
            assert recovered[0].scan.status == before.status
        finally:
            keys = [key async for key in redis.scan_iter(match=f"{namespace}:*")]
            if keys:
                await redis.delete(*keys)
            await redis.aclose()

    asyncio.run(scenario())
