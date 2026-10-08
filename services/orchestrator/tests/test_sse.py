import asyncio
import json
from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from services.orchestrator.app.ledger import SnapshotUpdate
from services.orchestrator.app.main import create_api_app, scan_update_events
from vts_common.auth import create_token
from vts_common.lifecycle import ApprovalSummary, ResultSummary, ScanSnapshot, ScanStatus, StageSnapshot, StageStatus
from vts_common.service import ReadinessState

NOW = datetime.now(timezone.utc)
AUTH = {"Authorization": f"Bearer {create_token('tester')}"}


def _snapshot(revision=3):
    scan_id = str(uuid4())
    return ScanSnapshot(
        scan_id=scan_id,
        revision=revision,
        status=ScanStatus.RUNNING,
        target="vuln-target",
        mode="full",
        exec_mode="parallel",
        created_at=NOW,
        queued_at=NOW,
        started_at=NOW,
        updated_at=NOW,
        stages={name: StageSnapshot(stage_run_id=str(uuid4()), name=name, status=StageStatus.RUNNING, sealed=False) for name in ("recon", "scan", "verification")},
        approval_summary=ApprovalSummary(),
        result_summary=ResultSummary(),
    )


class FakeRedis:
    def __init__(self, entries):
        self.entries = entries

    async def xrange(self, key, min="-", max="+", count=None):
        values = [(entry.stream_id, {"revision": str(entry.revision), "snapshot": entry.snapshot.model_dump_json()}) for entry in self.entries]
        return values[:count] if count else values

    async def xrevrange(self, key, max="+", min="-", count=None):
        values = list(reversed(await self.xrange(key)))
        return values[:count] if count else values

    async def ping(self):
        return True


class FakeLedger:
    def __init__(self, snapshot, entries=()):
        self.snapshot = snapshot
        self.entries = list(entries)
        self.redis = FakeRedis(self.entries)
        self.namespace = "vts"

    def key(self, suffix):
        return f"vts:{suffix}"

    async def get_scan(self, scan_id):
        return self.snapshot

    async def read_updates(self, scan_id, after_id, block_ms):
        for entry in self.entries:
            if tuple(map(int, entry.stream_id.split("-"))) > tuple(map(int, after_id.split("-"))):
                yield entry


def test_no_id_initial_snapshot_and_valid_id_replay_full_snapshots():
    async def scenario():
        snapshot = _snapshot(3)
        older = snapshot.model_copy(update={"revision": 2})
        entries = [SnapshotUpdate("100-0", 2, older), SnapshotUpdate("101-0", 3, snapshot)]
        ledger = FakeLedger(snapshot, entries)
        initial = scan_update_events(ledger, snapshot.scan_id, None, once=True)
        replay = scan_update_events(ledger, snapshot.scan_id, "100-0", once=True)
        return await anext(initial), await anext(replay)

    initial, replay = asyncio.run(scenario())
    assert "event: snapshot" in initial and '"revision":3' in initial
    assert "id: 101-0" in replay and '"revision":3' in replay


def test_trimmed_id_emits_reset_with_current_revision():
    async def scenario():
        snapshot = _snapshot(7)
        ledger = FakeLedger(snapshot, [SnapshotUpdate("500-0", 7, snapshot)])
        events = scan_update_events(ledger, snapshot.scan_id, "100-0", once=True)
        return await anext(events)

    event = asyncio.run(scenario())
    assert "event: reset" in event
    assert '"revision":7' in event


def test_malformed_or_too_long_last_event_id_returns_400():
    snapshot = _snapshot()
    ledger = FakeLedger(snapshot)
    readiness = ReadinessState()
    app = create_api_app(ledger, object(), readiness)
    with TestClient(app) as client:
        malformed = client.get(f"/scans/{snapshot.scan_id}/stream", headers={**AUTH, "Last-Event-ID": "bad"})
        too_long = client.get(f"/scans/{snapshot.scan_id}/stream", headers={**AUTH, "Last-Event-ID": "1" * 65})
    assert malformed.status_code == 400
    assert too_long.status_code == 400


def test_sse_delivery_records_histogram_observation(monkeypatch):
    from services.orchestrator.app import main as orchestrator_main
    from vts_common.service import MetricsRegistry

    async def scenario():
        snapshot = _snapshot(9)
        ledger = FakeLedger(snapshot)
        metrics = MetricsRegistry()
        monkeypatch.setattr(orchestrator_main, "DEFAULT_METRICS", metrics)
        await anext(scan_update_events(ledger, snapshot.scan_id, None, once=True))
        return metrics.render_prometheus()

    rendered = asyncio.run(scenario())
    assert "vts_snapshot_sse_delivery_seconds_count 1" in rendered


def test_sse_framing_carries_retry_and_full_snapshot():
    async def scenario():
        snapshot = _snapshot(4)
        ledger = FakeLedger(snapshot)
        return await anext(scan_update_events(ledger, snapshot.scan_id, None, once=True))

    event = asyncio.run(scenario())
    data_line = next(line for line in event.splitlines() if line.startswith("data: "))
    assert "retry: 1500" in event
    assert json.loads(data_line[6:])["stages"]["scan"]["status"] == "running"
