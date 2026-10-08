import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from services.orchestrator.app.history import HistoryStore, archive_terminal_scans, history_record
from services.orchestrator.app.ledger import Page, ResultRecord
from services.orchestrator.app.main import build_report, create_api_app
from vts_common.auth import create_token
from vts_common.lifecycle import (
    ApprovalSummary,
    ResultSummary,
    ScanSnapshot,
    ScanStatus,
    StageSnapshot,
    StageStatus,
)
from vts_common.service import ReadinessState

NOW = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
AUTH = {"Authorization": f"Bearer {create_token('tester')}"}
TERMINAL = {ScanStatus.SUCCEEDED, ScanStatus.FAILED, ScanStatus.TIMED_OUT, ScanStatus.CANCELED}


def _snapshot(target="vuln-target", status=ScanStatus.SUCCEEDED, minutes=0, findings=2):
    created = NOW + timedelta(minutes=minutes)
    done = status in TERMINAL
    if status is ScanStatus.SUCCEEDED:
        outcome = {"type": "success", "code": "SCAN_SUCCEEDED"}
    elif done:
        outcome = {"type": "canceled", "code": "operator stop"}
    else:
        outcome = None
    return ScanSnapshot(
        scan_id=str(uuid4()),
        revision=58,
        status=status,
        outcome=outcome,
        target=target,
        mode="full",
        exec_mode="parallel",
        created_at=created,
        queued_at=created,
        started_at=created,
        updated_at=created + timedelta(seconds=20),
        completed_at=created + timedelta(seconds=20) if done else None,
        stages={
            name: StageSnapshot(
                stage_run_id=str(uuid4()), name=name, status=StageStatus.SUCCEEDED,
                sealed=True, total_work=2, result_count=3,
            )
            for name in ("recon", "scan", "verification")
        },
        approval_summary=ApprovalSummary(total=1, executed=1),
        result_summary=ResultSummary(assets=10, findings=findings, verified=1),
    )


def _finding(severity, template_id, url="http://vuln-target/x"):
    return ResultRecord(
        result_id="sha256:" + uuid4().hex * 2, scan_id="s", kind="findings", event="vuln.detected",
        work_id="w", ingested_at=NOW,
        data={"template_id": template_id, "name": template_id.upper(), "severity": severity,
              "url": url, "evidence": {"body_snippet": "DB_PASSWORD=supersecret123"}},
    )


def _record(snapshot, findings=None, actor="operator"):
    return history_record(snapshot, build_report(snapshot, findings or []), actor)


# ------------------------------------------------------------------- store
def test_store_saves_and_reads_back_a_scan_with_findings_and_no_evidence(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    snap = _snapshot()
    store.save(_record(snap, [_finding("high", "env-file-exposure"), _finding("medium", "phpinfo")], actor="approver"))

    detail = store.get(snap.scan_id)
    assert detail["target"] == "vuln-target" and detail["actor"] == "approver"
    assert detail["status"] == "succeeded" and detail["duration_seconds"] == 20
    assert detail["summary"] == {"assets": 10, "findings": 2, "verified": 1, "execution": 0}
    assert detail["findings_by_severity"]["high"] == 1 and detail["findings_by_severity"]["medium"] == 1
    assert [f["template_id"] for f in detail["findings"]] == ["env-file-exposure", "phpinfo"]
    assert detail["approvals"]["executed"] == 1
    assert set(detail["stages"]) == {"recon", "scan", "verification"}
    assert "supersecret123" not in str(detail)
    assert store.get("missing") is None
    assert store.has(snap.scan_id) and not store.has("missing")


def test_store_is_a_real_sql_database_with_two_related_tables(tmp_path):
    path = tmp_path / "h.db"
    store = HistoryStore(path)
    snap = _snapshot()
    store.save(_record(snap, [_finding("high", "a")]))
    with sqlite3.connect(path) as db:
        tables = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
        assert {"scan_history", "scan_finding"} <= tables
        assert db.execute("select count(*) from scan_finding where scan_id=?", (snap.scan_id,)).fetchone()[0] == 1


def test_saving_the_same_scan_twice_replaces_instead_of_duplicating(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    snap = _snapshot()
    store.save(_record(snap, [_finding("high", "a"), _finding("low", "b")]))
    store.save(_record(snap, [_finding("high", "a")]))
    assert store.list()[1] == 1
    assert [f["template_id"] for f in store.get(snap.scan_id)["findings"]] == ["a"]


def test_list_filters_by_status_and_target_orders_newest_first_and_paginates(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    old = _snapshot("vuln-target", minutes=0)
    mid = _snapshot("scanme.nmap.org", ScanStatus.CANCELED, minutes=10)
    new = _snapshot("vuln-target", ScanStatus.FAILED, minutes=20)
    for snap in (old, new, mid):
        store.save(_record(snap))

    items, total = store.list()
    assert total == 3 and [i["scan_id"] for i in items] == [new.scan_id, mid.scan_id, old.scan_id]
    assert "findings" not in items[0]  # list rows are summaries
    assert store.list(status="canceled")[1] == 1
    assert [i["target"] for i in store.list(target="scanme")[0]] == ["scanme.nmap.org"]
    page, total = store.list(limit=2, offset=2)
    assert total == 3 and [i["scan_id"] for i in page] == [old.scan_id]


def test_store_survives_reopening_the_database_file(tmp_path):
    snap = _snapshot()
    HistoryStore(tmp_path / "h.db").save(_record(snap))
    assert HistoryStore(tmp_path / "h.db").get(snap.scan_id)["scan_id"] == snap.scan_id


# ---------------------------------------------------------------- archiver
class FakeRedis:
    def __init__(self, actors):
        self.actors = actors

    async def hget(self, key, field):
        return self.actors.get(key.split(":")[2])


class ArchiveLedger:
    def __init__(self, snapshots, findings=None):
        self.snapshots = snapshots
        self.findings = findings or {}
        self.redis = FakeRedis({s.scan_id: "operator" for s in snapshots})
        self.result_calls = 0

    def key(self, suffix):
        return f"vts:{suffix}"

    async def list_scans(self, status, cursor, limit):
        start = int(cursor or 0)
        chunk = self.snapshots[start:start + 2]
        nxt = str(start + 2) if start + 2 < len(self.snapshots) else None
        return Page(chunk, nxt)

    async def list_results(self, scan_id, kind, cursor, limit):
        self.result_calls += 1
        return Page(self.findings.get(scan_id, []), None)


def test_archiver_stores_every_terminal_scan_once_and_skips_running_ones(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    done_a = _snapshot(minutes=0)
    done_b = _snapshot(status=ScanStatus.CANCELED, minutes=1)
    done_c = _snapshot(status=ScanStatus.TIMED_OUT, minutes=2)
    running = _snapshot(status=ScanStatus.RUNNING, minutes=3)
    ledger = ArchiveLedger([done_a, done_b, done_c, running], {done_a.scan_id: [_finding("high", "env")]})

    assert asyncio.run(archive_terminal_scans(ledger, store)) == 3
    assert store.list()[1] == 3 and not store.has(running.scan_id)
    assert store.get(done_a.scan_id)["actor"] == "operator"
    assert store.get(done_b.scan_id)["status"] == "canceled"
    assert store.get(done_c.scan_id)["status"] == "timed_out"

    calls = ledger.result_calls
    assert asyncio.run(archive_terminal_scans(ledger, store)) == 0  # idempotent, no refetch
    assert ledger.result_calls == calls


# --------------------------------------------------------------------- API
class ApiLedger:
    async def get_scan(self, scan_id):
        raise AssertionError("history endpoints must not touch the live ledger")


def _client(store):
    readiness = ReadinessState(("redis", "recovery"))
    readiness.set("redis", True)
    readiness.set("recovery", True)
    return TestClient(create_api_app(ApiLedger(), object(), readiness, history=store))


def test_history_endpoints_require_auth_filter_and_return_details(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    a = _snapshot("vuln-target", minutes=0)
    b = _snapshot("scanme.nmap.org", ScanStatus.CANCELED, minutes=5)
    store.save(_record(a, [_finding("high", "env-file-exposure")]))
    store.save(_record(b))
    with _client(store) as client:
        assert client.get("/history").status_code == 401
        listing = client.get("/history", headers=AUTH).json()
        canceled = client.get("/history?status=canceled", headers=AUTH).json()
        bad_status = client.get("/history?status=nope", headers=AUTH)
        by_target = client.get("/history?target=scanme", headers=AUTH).json()
        detail = client.get(f"/history/{a.scan_id}", headers=AUTH)
        missing = client.get(f"/history/{uuid4()}", headers=AUTH)
        invalid = client.get("/history/not-a-uuid", headers=AUTH)
        too_big = client.get("/history?limit=101", headers=AUTH)

    assert listing["total"] == 2 and listing["items"][0]["scan_id"] == b.scan_id
    assert canceled["total"] == 1 and by_target["items"][0]["target"] == "scanme.nmap.org"
    assert bad_status.status_code == 422
    assert detail.status_code == 200 and detail.json()["findings"][0]["template_id"] == "env-file-exposure"
    assert missing.status_code == 404 and invalid.status_code == 422 and too_big.status_code == 422
