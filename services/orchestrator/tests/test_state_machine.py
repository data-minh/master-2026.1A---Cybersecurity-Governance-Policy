from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from services.orchestrator.app.state_machine import (
    ApprovalRecord,
    LifecycleState,
    ScanRecord,
    StageRecord,
    WorkRecord,
    apply_lifecycle_event,
    build_snapshot,
    expire_due,
    reconcile,
)
from vts_common.lifecycle import (
    ApprovalStatus,
    LifecycleEnvelopeV1,
    ScanStatus,
    StageStatus,
    WorkStatus,
    WorkType,
)

NOW = datetime(2026, 10, 4, 7, 18, 27, tzinfo=timezone.utc)


def _stage(name, status=StageStatus.PENDING, enabled=True, **values):
    return StageRecord(
        stage_run_id=str(uuid4()),
        name=name,
        status=status,
        enabled=enabled,
        sealed=status in {StageStatus.SUCCEEDED, StageStatus.SKIPPED},
        **values,
    )


def _state(stages=None, works=None, approvals=None, status=ScanStatus.RUNNING):
    scan_id = str(uuid4())
    return LifecycleState(
        scan=ScanRecord(
            scan_id=scan_id,
            status=status,
            revision=1,
            target="vuln-target",
            mode="full",
            exec_mode="parallel",
            created_at=NOW,
            queued_at=NOW,
            started_at=NOW,
            updated_at=NOW,
        ),
        stages=stages
        or {
            "recon": _stage("recon", StageStatus.RUNNING, open_work=1, total_work=1),
            "scan": _stage("scan"),
            "verification": _stage("verification"),
        },
        works=works or {},
        approvals=approvals or {},
    )


def _work(state, stage, status=WorkStatus.QUEUED, attempt=1, **values):
    return WorkRecord(
        work_id=str(uuid4()),
        scan_id=state.scan.scan_id,
        stage_run_id=state.stages[stage].stage_run_id,
        stage=stage,
        work_type=values.pop("work_type", WorkType.SCAN_TEMPLATE_URL),
        service=values.pop("service", "scan-engine"),
        status=status,
        attempt=attempt,
        **values,
    )


def _event(state, work, topic, data, producer="scan-engine", attempt=None):
    return LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": topic,
            "scan_id": state.scan.scan_id,
            "stage_run_id": work.stage_run_id,
            "work_id": work.work_id,
            "parent_work_id": work.parent_work_id,
            "producer": producer,
            "attempt": work.attempt if attempt is None else attempt,
            "occurred_at": NOW.isoformat(),
            "data": data,
        }
    )


def test_stage_start_does_not_close_previous_stage():
    state = _state()
    scan_work = _work(state, "scan")
    state = replace(
        state,
        works={scan_work.work_id: scan_work},
        stages={
            **state.stages,
            "scan": replace(state.stages["scan"], total_work=1, open_work=1),
        },
    )
    result = apply_lifecycle_event(
        state,
        _event(state, scan_work, "work.started", {"lease_token": "token"}),
        NOW,
    )

    assert result.state.stages["recon"].status == StageStatus.RUNNING
    assert result.state.stages["scan"].status == StageStatus.RUNNING


def test_completed_zero_result_succeeds_not_skipped():
    state = _state(
        stages={
            "recon": _stage("recon", StageStatus.SUCCEEDED),
            "scan": _stage("scan", StageStatus.RUNNING, total_work=1, open_work=1),
            "verification": _stage("verification", StageStatus.SKIPPED, enabled=False),
        }
    )
    work = _work(state, "scan", WorkStatus.RUNNING)
    state = replace(state, works={work.work_id: work})
    result = apply_lifecycle_event(
        state,
        _event(
            state,
            work,
            "work.completed",
            {"result_count": 0, "duration_ms": 5, "lease_token": "token"},
        ),
        NOW,
    )

    assert result.state.stages["scan"].status == StageStatus.SUCCEEDED
    assert result.state.stages["scan"].result_count == 0
    assert result.state.scan.status == ScanStatus.SUCCEEDED


def test_enabled_zero_work_succeeds_after_upstream_seal():
    state = _state(
        stages={
            "recon": _stage("recon", StageStatus.SUCCEEDED),
            "scan": _stage("scan", total_work=0, open_work=0),
            "verification": _stage("verification", StageStatus.SKIPPED, enabled=False),
        }
    )
    result = reconcile(state, NOW)
    assert result.state.stages["scan"].status == StageStatus.SUCCEEDED
    assert result.state.stages["scan"].status != StageStatus.SKIPPED


def test_approval_requested_sets_awaiting_immediately():
    state = _state()
    source = _work(state, "verification", WorkStatus.RUNNING, service="verification")
    state = replace(state, works={source.work_id: source})
    approval_id = str(uuid4())
    result = apply_lifecycle_event(
        state,
        _event(
            state,
            source,
            "approval.requested",
            {
                "approval_id": approval_id,
                "finding_id": "sha256:" + "a" * 64,
                "execution_work_id": str(uuid4()),
                "decision_deadline": (NOW + timedelta(days=1)).isoformat(),
            },
            producer="verification",
        ),
        NOW,
    )
    assert result.state.scan.status == ScanStatus.AWAITING_APPROVAL
    assert result.state.approvals[approval_id].status == ApprovalStatus.PENDING


def test_approved_is_unresolved_until_executed():
    approval_id = str(uuid4())
    execution_id = str(uuid4())
    state = _state(
        stages={
            "recon": _stage("recon", StageStatus.SUCCEEDED),
            "scan": _stage("scan", StageStatus.SUCCEEDED),
            "verification": _stage("verification", StageStatus.RUNNING, total_work=1, open_work=0),
        },
        status=ScanStatus.AWAITING_APPROVAL,
    )
    source = _work(state, "verification", WorkStatus.COMPLETED, service="verification")
    state = replace(
        state,
        works={source.work_id: source},
        approvals={
            approval_id: ApprovalRecord(
                approval_id,
                ApprovalStatus.PENDING,
                execution_id,
                NOW + timedelta(days=1),
            )
        },
    )
    approved = apply_lifecycle_event(
        state,
        _event(
            state,
            source,
            "approval.approved",
            {"approval_id": approval_id, "actor": "approver", "reason": "ok"},
            producer="verification",
        ),
        NOW,
    )
    assert approved.state.scan.status == ScanStatus.AWAITING_APPROVAL

    executed = apply_lifecycle_event(
        approved.state,
        _event(
            approved.state,
            source,
            "approval.executed",
            {"approval_id": approval_id, "execution_work_id": execution_id, "outcome": {}},
            producer="verification",
        ),
        NOW,
    )
    assert executed.state.approvals[approval_id].status == ApprovalStatus.EXECUTED
    assert executed.state.scan.status == ScanStatus.SUCCEEDED


def test_reject_cancels_blocked_execute_and_allows_success():
    approval_id = str(uuid4())
    state = _state(
        stages={
            "recon": _stage("recon", StageStatus.SUCCEEDED),
            "scan": _stage("scan", StageStatus.SUCCEEDED),
            "verification": _stage("verification", StageStatus.RUNNING, total_work=1, open_work=1),
        },
        status=ScanStatus.AWAITING_APPROVAL,
    )
    execute = _work(
        state,
        "verification",
        dispatch_state="blocked_approval",
        work_type=WorkType.VERIFICATION_EXECUTE,
        service="verification",
    )
    state = replace(
        state,
        works={execute.work_id: execute},
        approvals={
            approval_id: ApprovalRecord(
                approval_id,
                ApprovalStatus.PENDING,
                execute.work_id,
                NOW + timedelta(days=1),
            )
        },
    )
    result = apply_lifecycle_event(
        state,
        _event(
            state,
            execute,
            "approval.rejected",
            {"approval_id": approval_id, "actor": "approver", "reason": "no"},
            producer="verification",
        ),
        NOW,
    )
    assert result.state.works[execute.work_id].status == WorkStatus.CANCELED
    assert result.state.scan.status == ScanStatus.SUCCEEDED


def test_execution_final_failure_dominates_success():
    state = _state(
        stages={
            "recon": _stage("recon", StageStatus.SUCCEEDED),
            "scan": _stage("scan", StageStatus.SUCCEEDED),
            "verification": _stage("verification", StageStatus.RUNNING, total_work=1, open_work=1),
        }
    )
    work = _work(state, "verification", WorkStatus.RUNNING, attempt=3, service="verification")
    state = replace(state, works={work.work_id: work})
    result = apply_lifecycle_event(
        state,
        _event(
            state,
            work,
            "work.failed",
            {
                "error_code": "EXECUTION_FAILED",
                "retryable": False,
                "message": "failed",
                "duration_ms": 1,
                "lease_token": "token",
            },
            producer="verification",
        ),
        NOW,
    )
    assert result.state.stages["verification"].status == StageStatus.FAILED
    assert result.state.scan.status == ScanStatus.FAILED


def test_policy_deadline_times_out_scan():
    approval_id = str(uuid4())
    state = _state(
        approvals={
            approval_id: ApprovalRecord(
                approval_id,
                ApprovalStatus.PENDING,
                str(uuid4()),
                NOW - timedelta(seconds=1),
            )
        },
        status=ScanStatus.AWAITING_APPROVAL,
    )
    result = expire_due(state, NOW)
    assert result.state.scan.status == ScanStatus.TIMED_OUT
    assert result.state.approvals[approval_id].status == ApprovalStatus.TIMED_OUT


def test_retryable_attempt_returns_work_to_queued():
    state = _state()
    work = _work(state, "recon", WorkStatus.RUNNING)
    state = replace(state, works={work.work_id: work})
    result = apply_lifecycle_event(
        state,
        _event(
            state,
            work,
            "work.failed",
            {
                "error_code": "TEMPORARY",
                "retryable": True,
                "message": "retry",
                "duration_ms": 1,
                "lease_token": "token",
            },
        ),
        NOW,
    )
    assert result.state.works[work.work_id].status == WorkStatus.QUEUED
    assert result.state.works[work.work_id].attempt == 2


def test_terminal_snapshot_is_immutable():
    state = _state(status=ScanStatus.SUCCEEDED)
    state = replace(state, terminal_snapshot=build_snapshot(state))
    work = _work(state, "recon", WorkStatus.COMPLETED)
    late = apply_lifecycle_event(
        state,
        _event(state, work, "work.started", {"lease_token": "late"}),
        NOW + timedelta(seconds=5),
    )
    assert late.changed is False
    assert late.state.scan.revision == state.scan.revision
    assert build_snapshot(late.state) == state.terminal_snapshot


def test_stale_attempt_is_rejected():
    state = _state()
    work = _work(state, "recon", WorkStatus.RUNNING, attempt=2)
    state = replace(state, works={work.work_id: work})
    result = apply_lifecycle_event(
        state,
        _event(
            state,
            work,
            "work.completed",
            {"result_count": 1, "duration_ms": 1, "lease_token": "old"},
            attempt=1,
        ),
        NOW,
    )
    assert result.changed is False
    assert result.rejection_reason == "stale_attempt"


def test_revision_only_increases_on_real_mutation():
    state = _state()
    unchanged = reconcile(state, NOW)
    assert unchanged.state.scan.revision == state.scan.revision
    work = _work(state, "recon")
    state = replace(state, works={work.work_id: work})
    changed = apply_lifecycle_event(
        state,
        _event(state, work, "work.started", {"lease_token": "token"}),
        NOW,
    )
    assert changed.state.scan.revision == state.scan.revision + 1
