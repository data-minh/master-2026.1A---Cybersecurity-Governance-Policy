import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
from fastapi.testclient import TestClient

from services.orchestrator.app import notify
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

NOW = datetime.now(timezone.utc)
AUTH = {"Authorization": f"Bearer {create_token('tester')}"}


def _snapshot(status=ScanStatus.SUCCEEDED, completed=True):
    return ScanSnapshot(
        scan_id=str(uuid4()),
        revision=58,
        status=status,
        outcome={"type": "success", "code": "SCAN_SUCCEEDED"} if completed else None,
        target="vuln-target",
        mode="full",
        exec_mode="parallel",
        created_at=NOW,
        queued_at=NOW,
        started_at=NOW,
        updated_at=NOW + timedelta(seconds=12),
        completed_at=NOW + timedelta(seconds=12) if completed else None,
        stages={
            name: StageSnapshot(
                stage_run_id=str(uuid4()),
                name=name,
                status=StageStatus.SUCCEEDED,
                sealed=True,
                total_work=2,
                result_count=3,
            )
            for name in ("recon", "scan", "verification")
        },
        approval_summary=ApprovalSummary(total=2, rejected=1, executed=1),
        result_summary=ResultSummary(assets=10, findings=3, verified=2),
    )


def _finding(severity, template_id, url="http://vuln-target/x"):
    return ResultRecord(
        result_id="sha256:" + uuid4().hex * 2,
        scan_id="s",
        kind="findings",
        event="vuln.detected",
        work_id="w",
        ingested_at=NOW,
        data={
            "template_id": template_id,
            "name": template_id.upper(),
            "severity": severity,
            "url": url,
            "evidence": {"body_snippet": "DB_PASSWORD=supersecret123"},
            "extracted": ["DB_PASSWORD"],
        },
    )


def test_report_groups_findings_by_severity_and_drops_evidence():
    snapshot = _snapshot()
    findings = [
        _finding("high", "env-file-exposure"),
        _finding("medium", "phpinfo-disclosure"),
        _finding("medium", "git-config-exposure"),
    ]
    report = build_report(snapshot, findings)

    assert report["scan_id"] == snapshot.scan_id
    assert report["status"] == "succeeded"
    assert report["duration_seconds"] == 12
    assert report["summary"] == {"assets": 10, "findings": 3, "verified": 2, "execution": 0}
    assert report["findings_by_severity"] == {
        "critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0,
    }
    assert [f["severity"] for f in report["findings"]] == ["high", "medium", "medium"]
    assert report["approvals"]["rejected"] == 1 and report["approvals"]["executed"] == 1
    assert set(report["stages"]) == {"recon", "scan", "verification"}
    flat = str(report)
    assert "supersecret123" not in flat and "evidence" not in flat


def test_report_for_unfinished_scan_has_no_duration():
    report = build_report(_snapshot(ScanStatus.RUNNING, completed=False), [])
    assert report["duration_seconds"] is None
    assert report["findings"] == []


class ReportLedger:
    def __init__(self):
        self.snapshot = _snapshot()
        self.pages = {}

    async def get_scan(self, scan_id):
        if scan_id != self.snapshot.scan_id:
            from services.orchestrator.app.ledger import LedgerError
            raise LedgerError("scan not found")
        return self.snapshot

    async def list_results(self, scan_id, kind, cursor, limit):
        assert kind == "findings"
        if cursor is None:
            return Page([_finding("critical", "a"), _finding("low", "b")], "next")
        return Page([_finding("info", "c")], None)


def _client():
    readiness = ReadinessState(("redis", "recovery"))
    readiness.set("redis", True)
    readiness.set("recovery", True)
    ledger = ReportLedger()
    app = create_api_app(ledger, object(), readiness)
    return TestClient(app), ledger


def test_report_endpoint_requires_auth_pages_through_findings_and_404s():
    client, ledger = _client()
    sid = ledger.snapshot.scan_id
    with client:
        assert client.get(f"/scans/{sid}/report").status_code == 401
        ok = client.get(f"/scans/{sid}/report", headers=AUTH)
        missing = client.get(f"/scans/{uuid4()}/report", headers=AUTH)
        invalid = client.get("/scans/not-a-uuid/report", headers=AUTH)
    assert ok.status_code == 200
    body = ok.json()
    assert [f["template_id"] for f in body["findings"]] == ["a", "b", "c"]
    assert body["findings_by_severity"]["critical"] == 1
    assert missing.status_code == 404
    assert invalid.status_code == 422


# ----------------------------------------------------------------- webhook
def test_webhook_is_off_by_default_and_never_calls_network(monkeypatch):
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    calls = []
    sent = asyncio.run(notify.send_scan_finished(_snapshot(), client_factory=lambda **k: calls.append(k)))
    assert sent is False and calls == []


def test_webhook_refuses_host_outside_allowlist(monkeypatch):
    monkeypatch.setenv("WEBHOOK_URL", "https://hooks.example.org/vts")
    monkeypatch.setenv("WEBHOOK_ALLOWED_HOSTS", "other.example.net")
    calls = []
    sent = asyncio.run(notify.send_scan_finished(_snapshot(), client_factory=lambda **k: calls.append(k)))
    assert sent is False and calls == []


def test_webhook_sends_summary_only_to_allowlisted_host(monkeypatch):
    monkeypatch.setenv("WEBHOOK_URL", "https://hooks.example.org/vts")
    monkeypatch.setenv("WEBHOOK_ALLOWED_HOSTS", "hooks.example.org")
    captured = []

    def handler(request):
        captured.append((str(request.url), request.read().decode()))
        return httpx.Response(204)

    real = httpx.AsyncClient
    snapshot = _snapshot()
    sent = asyncio.run(
        notify.send_scan_finished(snapshot, client_factory=lambda **k: real(transport=httpx.MockTransport(handler)))
    )
    assert sent is True and len(captured) == 1
    url, body = captured[0]
    assert url == "https://hooks.example.org/vts"
    for forbidden in ("evidence", "http://vuln-target", "body_snippet", "token"):
        assert forbidden not in body
    assert snapshot.scan_id in body and '"status":"succeeded"' in body.replace(" ", "")


def test_webhook_failure_is_swallowed(monkeypatch):
    monkeypatch.setenv("WEBHOOK_URL", "https://hooks.example.org/vts")
    monkeypatch.setenv("WEBHOOK_ALLOWED_HOSTS", "hooks.example.org")

    def boom(request):
        raise httpx.ConnectError("down", request=request)

    real = httpx.AsyncClient
    sent = asyncio.run(
        notify.send_scan_finished(_snapshot(), client_factory=lambda **k: real(transport=httpx.MockTransport(boom)))
    )
    assert sent is False


def test_cancel_notifies_once_not_on_idempotent_replay(monkeypatch):
    from services.orchestrator.app import main as orchestrator_main

    class CancelLedger(ReportLedger):
        def __init__(self):
            super().__init__()
            self.snapshot = _snapshot(ScanStatus.RUNNING, completed=False)

        async def cancel_scan(self, scan_id, reason, key):
            self.snapshot = self.snapshot.model_copy(
                update={"status": ScanStatus.CANCELED, "completed_at": NOW}
            )
            return self.snapshot

    sent = []

    async def fake_send(snapshot, **kwargs):
        sent.append(snapshot.scan_id)
        return True

    monkeypatch.setattr(orchestrator_main.notify, "send_scan_finished", fake_send)
    readiness = ReadinessState(("redis", "recovery"))
    readiness.set("redis", True)
    readiness.set("recovery", True)
    ledger = CancelLedger()
    app = create_api_app(ledger, object(), readiness)
    headers = {**AUTH, "Idempotency-Key": "cancel-key-123"}
    with TestClient(app) as client:
        first = client.post(f"/scans/{ledger.snapshot.scan_id}/cancel", json={"reason": "stop"}, headers=headers)
        replay = client.post(f"/scans/{ledger.snapshot.scan_id}/cancel", json={"reason": "stop"}, headers=headers)
    assert first.status_code == replay.status_code == 200
    assert sent == [ledger.snapshot.scan_id]
