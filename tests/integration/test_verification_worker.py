import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from services.verification.app import main as verification
from vts_common.lifecycle import LifecycleEnvelopeV1


class Context:
    def __init__(self):
        self.results = []

    async def publish_result(self, topic, data):
        self.results.append((topic, data))
        return "1-0"


class Store:
    def __init__(self):
        self.topics = []
        self.status = "pending"

    async def create_requested(self, source, execution_work_id, decision_deadline=None):
        self.topics.append("approval.requested")
        return type("Approval", (), {"approval_id": verification.approval_identity(source.data["finding_id"]), "execution_work_id": execution_work_id, "status": "pending"})()

    async def get(self, approval_id):
        return type("Approval", (), {"approval_id": approval_id, "status": self.status})()

    async def mark_executed(self, event):
        if self.status == "broken":
            raise RuntimeError("execution exploded")
        self.topics.append("approval.executed")

    async def mark_execution_failed(self, event):
        self.topics.append(event.event)
        self.failure = event.data


class AllowedScope:
    async def permits(self, host):
        return True


def _command(work_type, input_data):
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": "work.command",
            "scan_id": str(uuid4()),
            "stage_run_id": str(uuid4()),
            "work_id": str(uuid4()),
            "parent_work_id": None,
            "producer": "orchestrator",
            "attempt": 1,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": {"work_type": work_type, "input": input_data, "timeout_seconds": 30, "max_attempts": 3, "dispatch_not_before": datetime.now(timezone.utc).isoformat()},
        }
    )


def test_safe_verify_emits_verified_then_approval_requested(monkeypatch):
    finding_id = "sha256:" + "d" * 64
    command = _command("verification.safe_verify", {"finding_id": finding_id, "url": "http://vuln-target/", "severity": "high"})
    context, store = Context(), Store()
    monkeypatch.setattr(verification, "APPROVAL_STORE", store)
    monkeypatch.setattr(verification, "ScopeClient", lambda: AllowedScope())
    monkeypatch.setattr(verification, "_safe_verify", lambda url: asyncio.sleep(0, result={"reachable": True, "status": 200}))
    result = asyncio.run(verification.handle_safe_verify(context, command))
    assert result.result_count == 1
    assert [topic for topic, _ in context.results] + store.topics == ["vuln.verified", "approval.requested"]


def test_execute_worker_marks_approval_before_terminal_return(monkeypatch):
    approval_id = str(uuid4())
    command = _command("verification.execute", {"approval_id": approval_id, "dry_run": True})
    context, store = Context(), Store()
    store.status = "executing"
    monkeypatch.setattr(verification, "APPROVAL_STORE", store)
    result = asyncio.run(verification.handle_execute(context, command))
    assert result.result_count == 1
    assert store.topics == ["approval.executed"]


def test_final_execute_failure_marks_approval_execution_failed(monkeypatch):
    approval_id = str(uuid4())
    command = _command("verification.execute", {"approval_id": approval_id, "dry_run": True})
    context, store = Context(), Store()
    store.status = "executing"
    monkeypatch.setattr(verification, "APPROVAL_STORE", store)
    original = store.get

    async def get(approval_id):
        approval = await original(approval_id)
        store.status = "broken"
        approval.status = "executing"
        return approval

    store.get = get
    with pytest.raises(RuntimeError, match="exploded"):
        asyncio.run(verification.handle_execute(context, command))
    assert store.topics == ["approval.execution_failed"]
    assert store.failure["approval_id"] == approval_id
    assert store.failure["error_code"] == "RUNTIMEERROR"
