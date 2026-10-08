from datetime import datetime, timezone
from uuid import uuid4

import httpx
from fastapi.testclient import TestClient

from services.orchestrator.app.ledger import IdempotencyConflict, Page
from services.orchestrator.app.main import create_api_app
from vts_common.auth import create_token
from vts_common.lifecycle import (
    ApprovalSummary,
    ResultSummary,
    ScanSnapshot,
    ScanStatus,
    StageSnapshot,
    StageStatus,
)
from vts_common.scope import ScopeDenied
from vts_common.service import ReadinessState

NOW = datetime.now(timezone.utc)
AUTH = {"Authorization": f"Bearer {create_token('tester')}"}


def _snapshot(scan_id=None):
    scan_id = scan_id or str(uuid4())
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
            name: StageSnapshot(
                stage_run_id=str(uuid4()),
                name=name,
                status=StageStatus.RUNNING if name == "recon" else StageStatus.PENDING,
                sealed=False,
            )
            for name in ("recon", "scan", "verification")
        },
        approval_summary=ApprovalSummary(),
        result_summary=ResultSummary(),
    )


class FakeScope:
    def __init__(self, error=None):
        self.error = error
        self.checked = []

    async def check(self, target):
        self.checked.append(target)
        if self.error:
            raise self.error
        return {"allowed": True}


class FakeLedger:
    def __init__(self):
        self.snapshot = _snapshot()
        self.calls = []
        self.keys = {}

    async def create_scan(self, spec, actor, idempotency_key):
        self.calls.append((spec, actor, idempotency_key))
        payload = (spec.target, spec.mode, spec.exec_mode)
        if idempotency_key in self.keys and self.keys[idempotency_key] != payload:
            raise IdempotencyConflict("IDEMPOTENCY_KEY_REUSED")
        self.keys[idempotency_key] = payload
        self.snapshot = self.snapshot.model_copy(
            update={
                "scan_id": spec.scan_id or self.snapshot.scan_id,
                "target": spec.target,
                "mode": spec.mode,
                "exec_mode": spec.exec_mode,
            }
        )
        return self.snapshot

    async def list_scans(self, status, cursor, limit):
        return Page([self.snapshot], None)

    async def get_scan(self, scan_id):
        if scan_id != self.snapshot.scan_id:
            from services.orchestrator.app.ledger import LedgerError
            raise LedgerError("scan not found")
        return self.snapshot

    async def list_work(self, *args):
        return Page([], None)

    async def list_results(self, *args):
        return Page([], None)

    async def cancel_scan(self, scan_id, reason, key):
        self.snapshot = self.snapshot.model_copy(
            update={"status": ScanStatus.CANCELED, "revision": 3}
        )
        return self.snapshot


def _client(ledger=None, scope=None, ready=True):
    readiness = ReadinessState(("redis", "recovery"))
    readiness.set("redis", ready)
    readiness.set("recovery", ready)
    app = create_api_app(ledger or FakeLedger(), scope or FakeScope(), readiness)
    return TestClient(app), app


def test_start_scan_rejects_invalid_mode_and_oversized_yaml_with_error_shape():
    client, _ = _client()
    with client:
        invalid = client.post("/scans", json={"target": "vuln-target", "mode": "typo"}, headers=AUTH)
        oversized = client.post("/scans", json={"config_yaml": "x" * 65537}, headers=AUTH)
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "VALIDATION_ERROR"
    assert oversized.status_code == 422


def test_start_scan_normalizes_target_checks_scope_then_returns_201():
    ledger, scope = FakeLedger(), FakeScope()
    client, _ = _client(ledger, scope)
    with client:
        response = client.post(
            "/scans",
            json={"target": "HTTP://VULN-TARGET:80", "mode": "full", "exec_mode": "parallel"},
            headers={**AUTH, "Idempotency-Key": "scan-key-123"},
        )
    assert response.status_code == 201
    assert scope.checked == ["vuln-target"]
    assert ledger.calls[0][2] == "scan-key-123"
    assert response.json()["revision"] == 2


def test_start_scan_scope_denied_timeout_and_unready_do_not_call_ledger():
    denied_ledger = FakeLedger()
    denied, _ = _client(denied_ledger, FakeScope(ScopeDenied("denied")))
    timeout_ledger = FakeLedger()
    timeout, _ = _client(timeout_ledger, FakeScope(httpx.TimeoutException("timeout")))
    unready_ledger = FakeLedger()
    unready, _ = _client(unready_ledger, ready=False)
    with denied, timeout, unready:
        denied_response = denied.post("/scans", json={"target": "vuln-target"}, headers=AUTH)
        timeout_response = timeout.post("/scans", json={"target": "vuln-target"}, headers=AUTH)
        unready_response = unready.post("/scans", json={"target": "vuln-target"}, headers=AUTH)
    assert denied_response.status_code == 403
    assert timeout_response.status_code == 503
    assert unready_response.status_code == 503
    assert denied_ledger.calls == timeout_ledger.calls == unready_ledger.calls == []


def test_idempotency_replay_and_mismatch_map_to_contract():
    ledger = FakeLedger()
    client, _ = _client(ledger)
    headers = {**AUTH, "Idempotency-Key": "same-key-123"}
    with client:
        first = client.post("/scans", json={"target": "vuln-target"}, headers=headers)
        replay = client.post("/scans", json={"target": "vuln-target"}, headers=headers)
        reused = client.post("/scans", json={"target": "other-target"}, headers=headers)
    assert first.status_code == replay.status_code == 201
    assert replay.json()["scan_id"] == first.json()["scan_id"]
    assert reused.status_code == 422
    assert reused.json()["error"]["code"] == "IDEMPOTENCY_KEY_REUSED"


def test_list_detail_validation_pagination_and_manual_complete_removed():
    ledger = FakeLedger()
    client, _ = _client(ledger)
    sid = ledger.snapshot.scan_id
    with client:
        listing = client.get("/scans?limit=1", headers=AUTH)
        detail = client.get(f"/scans/{sid}", headers=AUTH)
        bad_uuid = client.get("/scans/not-a-uuid", headers=AUTH)
        bad_limit = client.get("/scans?limit=101", headers=AUTH)
        removed = client.post(f"/scans/{sid}/stage/recon/complete", headers=AUTH)
    assert listing.json()["items"][0]["scan_id"] == sid
    assert detail.json()["revision"] == 2
    assert bad_uuid.status_code == 422
    assert bad_limit.status_code == 422
    assert removed.status_code == 410
    assert removed.json()["error"]["code"] == "STAGE_MANUAL_COMPLETION_REMOVED"


def test_cancel_requires_reason_and_readiness():
    ledger = FakeLedger()
    client, _ = _client(ledger)
    sid = ledger.snapshot.scan_id
    with client:
        bad = client.post(f"/scans/{sid}/cancel", json={"reason": ""}, headers=AUTH)
        accepted = client.post(
            f"/scans/{sid}/cancel",
            json={"reason": "operator canceled"},
            headers={**AUTH, "Idempotency-Key": "cancel-key-123"},
        )
    assert bad.status_code == 422
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "canceled"
