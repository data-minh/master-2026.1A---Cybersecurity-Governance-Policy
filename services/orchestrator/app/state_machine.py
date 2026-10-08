"""Pure reference model of the orchestrator lifecycle rules.

The runtime path is ``ledger.RedisLifecycleLedger``, which applies the same
rules incrementally on Redis snapshots (it cannot load whole-scan state inside
each CAS transaction). This module is the executable specification those rules
are checked against; ``tests/integration/test_lifecycle_parity.py`` replays the
same scenarios through both, so a change to one must be mirrored in the other.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from vts_common.lifecycle import (
    ApprovalStatus,
    ApprovalSummary,
    LifecycleEnvelopeV1,
    ResultSummary,
    ScanSnapshot,
    ScanStatus,
    StageSnapshot,
    StageStatus,
    WorkStatus,
    WorkType,
)

TERMINAL_SCANS = {
    ScanStatus.SUCCEEDED,
    ScanStatus.FAILED,
    ScanStatus.TIMED_OUT,
    ScanStatus.CANCELED,
}
TERMINAL_STAGES = {
    StageStatus.SUCCEEDED,
    StageStatus.FAILED,
    StageStatus.TIMED_OUT,
    StageStatus.SKIPPED,
}
TERMINAL_WORK = {
    WorkStatus.COMPLETED,
    WorkStatus.FAILED,
    WorkStatus.TIMED_OUT,
    WorkStatus.CANCELED,
}
RESOLVED_APPROVALS = {ApprovalStatus.REJECTED, ApprovalStatus.EXECUTED}


@dataclass(frozen=True, slots=True)
class WorkRecord:
    work_id: str
    scan_id: str
    stage_run_id: str
    stage: str
    work_type: WorkType
    service: str
    status: WorkStatus = WorkStatus.QUEUED
    attempt: int = 1
    max_attempts: int = 3
    parent_work_id: str | None = None
    dispatch_state: str = "ready"
    result_count: int = 0
    queued_at: datetime | None = None
    started_at: datetime | None = None
    last_progress_at: datetime | None = None
    completed_at: datetime | None = None
    outcome: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class StageRecord:
    stage_run_id: str
    name: str
    status: StageStatus = StageStatus.PENDING
    enabled: bool = True
    sealed: bool = False
    total_work: int = 0
    open_work: int = 0
    completed_work: int = 0
    failed_work: int = 0
    timed_out_work: int = 0
    result_count: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    outcome: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approval_id: str
    status: ApprovalStatus
    execution_work_id: str
    decision_deadline: datetime
    finding_id: str | None = None


@dataclass(frozen=True, slots=True)
class ScanRecord:
    scan_id: str
    status: ScanStatus
    revision: int
    target: str
    mode: str
    exec_mode: str
    created_at: datetime
    queued_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    awaiting_approval_at: datetime | None = None
    last_progress_at: datetime | None = None
    completed_at: datetime | None = None
    outcome: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class LifecycleState:
    scan: ScanRecord
    stages: dict[str, StageRecord]
    works: dict[str, WorkRecord] = field(default_factory=dict)
    approvals: dict[str, ApprovalRecord] = field(default_factory=dict)
    terminal_snapshot: ScanSnapshot | None = None


@dataclass(frozen=True, slots=True)
class TransitionResult:
    state: LifecycleState
    changed: bool
    emitted_topics: tuple[str, ...] = ()
    rejection_reason: str | None = None


def apply_lifecycle_event(
    state: LifecycleState,
    event: LifecycleEnvelopeV1,
    ingested_at: datetime,
) -> TransitionResult:
    if state.scan.status in TERMINAL_SCANS:
        return TransitionResult(state, False, rejection_reason="scan_terminal")
    if event.scan_id != state.scan.scan_id:
        return TransitionResult(state, False, rejection_reason="scan_mismatch")

    if event.event.startswith("approval."):
        return _apply_approval(state, event, ingested_at)

    work = state.works.get(event.work_id or "")
    if work is None:
        return TransitionResult(state, False, rejection_reason="unknown_work")
    if event.attempt != work.attempt:
        return TransitionResult(state, False, rejection_reason="stale_attempt")
    if work.status in TERMINAL_WORK:
        return TransitionResult(state, False, rejection_reason="work_terminal")

    works = dict(state.works)
    stages = dict(state.stages)
    stage = stages[work.stage]
    changed = False

    if event.event == "work.started" and work.status is WorkStatus.QUEUED:
        works[work.work_id] = replace(
            work, status=WorkStatus.RUNNING, started_at=ingested_at
        )
        if stage.status is StageStatus.PENDING:
            stages[work.stage] = replace(
                stage, status=StageStatus.RUNNING, started_at=ingested_at
            )
        changed = True
    elif event.event == "work.progress":
        works[work.work_id] = replace(work, last_progress_at=ingested_at)
        changed = True
    elif event.event == "work.completed":
        result_count = int(event.data.get("result_count", 0))
        works[work.work_id] = replace(
            work,
            status=WorkStatus.COMPLETED,
            result_count=result_count,
            completed_at=ingested_at,
            outcome={"type": "success"},
        )
        stages[work.stage] = replace(
            stage,
            open_work=max(0, stage.open_work - 1),
            completed_work=stage.completed_work + 1,
            result_count=stage.result_count + result_count,
        )
        changed = True
    elif event.event == "work.failed":
        retryable = bool(event.data.get("retryable"))
        if retryable and work.attempt < work.max_attempts:
            works[work.work_id] = replace(
                work,
                status=WorkStatus.QUEUED,
                attempt=work.attempt + 1,
                started_at=None,
                last_progress_at=ingested_at,
            )
        else:
            error_code = str(event.data.get("error_code", "WORK_FAILED"))
            works[work.work_id] = replace(
                work,
                status=WorkStatus.FAILED,
                completed_at=ingested_at,
                outcome={"type": "failure", "code": error_code},
            )
            stages[work.stage] = replace(
                stage,
                status=StageStatus.FAILED,
                open_work=max(0, stage.open_work - 1),
                failed_work=stage.failed_work + 1,
                completed_at=ingested_at,
                outcome={"type": "failure", "code": error_code},
            )
        changed = True
    elif event.event == "work.timed_out":
        works[work.work_id] = replace(
            work,
            status=WorkStatus.TIMED_OUT,
            completed_at=ingested_at,
            outcome={"type": "timeout", "code": "WORK_TIMED_OUT"},
        )
        stages[work.stage] = replace(
            stage,
            status=StageStatus.TIMED_OUT,
            open_work=max(0, stage.open_work - 1),
            timed_out_work=stage.timed_out_work + 1,
            completed_at=ingested_at,
            outcome={"type": "timeout", "code": "WORK_TIMED_OUT"},
        )
        changed = True

    if not changed:
        return TransitionResult(state, False, rejection_reason="invalid_transition")
    candidate = replace(state, works=works, stages=stages)
    reconciled, topics, _ = _reconcile_raw(candidate, ingested_at)
    return _commit(state, reconciled, ingested_at, topics)


def _apply_approval(
    state: LifecycleState,
    event: LifecycleEnvelopeV1,
    ingested_at: datetime,
) -> TransitionResult:
    approval_id = event.data.get("approval_id")
    if not approval_id:
        return TransitionResult(state, False, rejection_reason="approval_id_required")
    approvals = dict(state.approvals)
    works = dict(state.works)
    stages = dict(state.stages)

    if event.event == "approval.requested":
        if approval_id in approvals:
            return TransitionResult(state, False, rejection_reason="duplicate_approval")
        deadline_raw = event.data.get("decision_deadline")
        deadline = datetime.fromisoformat(str(deadline_raw).replace("Z", "+00:00"))
        approvals[approval_id] = ApprovalRecord(
            approval_id=approval_id,
            status=ApprovalStatus.PENDING,
            execution_work_id=str(event.data.get("execution_work_id")),
            decision_deadline=deadline,
            finding_id=event.data.get("finding_id"),
        )
    else:
        current = approvals.get(approval_id)
        if current is None:
            return TransitionResult(state, False, rejection_reason="unknown_approval")
        if event.event == "approval.approved" and current.status is ApprovalStatus.PENDING:
            approvals[approval_id] = replace(current, status=ApprovalStatus.APPROVED)
        elif event.event == "approval.rejected" and current.status in {
            ApprovalStatus.PENDING,
            ApprovalStatus.APPROVED,
        }:
            execute = works.get(current.execution_work_id)
            if execute and execute.dispatch_state == "blocked_approval" and execute.status is WorkStatus.QUEUED:
                works[execute.work_id] = replace(
                    execute,
                    status=WorkStatus.CANCELED,
                    completed_at=ingested_at,
                    outcome={"type": "canceled", "code": "approval_rejected"},
                )
                stage = stages[execute.stage]
                stages[execute.stage] = replace(
                    stage, open_work=max(0, stage.open_work - 1)
                )
            approvals[approval_id] = replace(current, status=ApprovalStatus.REJECTED)
        elif event.event == "approval.executed" and current.status in {
            ApprovalStatus.APPROVED,
            ApprovalStatus.EXECUTING,
        }:
            approvals[approval_id] = replace(current, status=ApprovalStatus.EXECUTED)
        elif event.event == "approval.execution_failed":
            approvals[approval_id] = replace(
                current, status=ApprovalStatus.EXECUTION_FAILED
            )
        else:
            return TransitionResult(state, False, rejection_reason="invalid_approval_transition")

    candidate = replace(state, approvals=approvals, works=works, stages=stages)
    reconciled, topics, _ = _reconcile_raw(candidate, ingested_at)
    return _commit(state, reconciled, ingested_at, topics)


def reconcile(state: LifecycleState, ingested_at: datetime) -> TransitionResult:
    if state.scan.status in TERMINAL_SCANS:
        return TransitionResult(state, False, rejection_reason="scan_terminal")
    candidate, topics, changed = _reconcile_raw(state, ingested_at)
    if not changed:
        return TransitionResult(state, False)
    return _commit(state, candidate, ingested_at, topics)


def _reconcile_raw(
    state: LifecycleState, now: datetime
) -> tuple[LifecycleState, tuple[str, ...], bool]:
    stages = dict(state.stages)
    works = dict(state.works)
    topics: list[str] = []
    changed = False

    failed_stage = next(
        (stage for stage in stages.values() if stage.status is StageStatus.FAILED),
        None,
    )
    timed_stage = next(
        (stage for stage in stages.values() if stage.status is StageStatus.TIMED_OUT),
        None,
    )
    if failed_stage or timed_stage:
        terminal = ScanStatus.FAILED if failed_stage else ScanStatus.TIMED_OUT
        reason = "STAGE_FAILED" if failed_stage else "STAGE_TIMED_OUT"
        for name, stage in tuple(stages.items()):
            if stage.status is StageStatus.PENDING:
                stages[name] = replace(
                    stage,
                    status=StageStatus.SKIPPED,
                    sealed=True,
                    completed_at=now,
                    outcome={"type": "skipped", "code": reason},
                )
            elif stage.status is StageStatus.RUNNING and stage is not failed_stage and stage is not timed_stage:
                stages[name] = replace(
                    stage,
                    status=StageStatus.FAILED,
                    completed_at=now,
                    outcome={
                        "type": "failure",
                        "code": "scan_aborted_due_to_stage_failure",
                    },
                )
        for work_id, work in tuple(works.items()):
            if work.status in {WorkStatus.QUEUED, WorkStatus.RUNNING}:
                works[work_id] = replace(
                    work,
                    status=WorkStatus.CANCELED,
                    completed_at=now,
                    outcome={"type": "canceled", "code": reason},
                )
        scan = replace(
            state.scan,
            status=terminal,
            completed_at=now,
            outcome={"type": "failure" if failed_stage else "timeout", "code": reason},
        )
        topics.append(f"scan.{terminal.value}")
        return replace(state, scan=scan, stages=stages, works=works), tuple(topics), True

    for name in ("recon", "scan", "verification"):
        stage = stages.get(name)
        if stage is None or not stage.enabled or stage.status in TERMINAL_STAGES:
            continue
        upstream_ready = (
            name == "recon"
            or (name == "scan" and stages["recon"].status in {StageStatus.SUCCEEDED, StageStatus.SKIPPED})
            or (
                name == "verification"
                and stages["scan"].status in {StageStatus.SUCCEEDED, StageStatus.SKIPPED}
            )
        )
        approvals_resolved = name != "verification" or all(
            approval.status in RESOLVED_APPROVALS
            for approval in state.approvals.values()
        )
        if upstream_ready and stage.open_work == 0 and approvals_resolved:
            stages[name] = replace(
                stage,
                status=StageStatus.SUCCEEDED,
                sealed=True,
                completed_at=now,
                outcome={"type": "success"},
            )
            topics.append("stage.succeeded")
            changed = True

    unresolved = any(
        approval.status not in RESOLVED_APPROVALS
        for approval in state.approvals.values()
    )
    scan = state.scan
    if unresolved and scan.status is not ScanStatus.AWAITING_APPROVAL:
        scan = replace(
            scan,
            status=ScanStatus.AWAITING_APPROVAL,
            awaiting_approval_at=scan.awaiting_approval_at or now,
        )
        topics.append("scan.awaiting_approval")
        changed = True
    elif not unresolved and scan.status is ScanStatus.AWAITING_APPROVAL:
        scan = replace(scan, status=ScanStatus.RUNNING)
        changed = True

    enabled = [stage for stage in stages.values() if stage.enabled]
    if not unresolved and enabled and all(
        stage.status in {StageStatus.SUCCEEDED, StageStatus.SKIPPED}
        for stage in enabled
    ):
        if scan.status is not ScanStatus.SUCCEEDED:
            scan = replace(
                scan,
                status=ScanStatus.SUCCEEDED,
                completed_at=now,
                outcome={"type": "success", "code": "SCAN_SUCCEEDED"},
            )
            topics.append("scan.succeeded")
            changed = True

    return replace(state, scan=scan, stages=stages, works=works), tuple(topics), changed


def expire_due(state: LifecycleState, now: datetime) -> TransitionResult:
    if state.scan.status in TERMINAL_SCANS:
        return TransitionResult(state, False, rejection_reason="scan_terminal")
    due = [
        approval_id
        for approval_id, approval in state.approvals.items()
        if approval.status not in RESOLVED_APPROVALS
        and approval.status not in {ApprovalStatus.EXECUTION_FAILED, ApprovalStatus.TIMED_OUT}
        and approval.decision_deadline <= now
    ]
    if not due:
        return TransitionResult(state, False)
    approvals = dict(state.approvals)
    works = dict(state.works)
    stages = dict(state.stages)
    for approval_id in due:
        approval = approvals[approval_id]
        approvals[approval_id] = replace(approval, status=ApprovalStatus.TIMED_OUT)
        work = works.get(approval.execution_work_id)
        if work and work.status not in TERMINAL_WORK:
            works[work.work_id] = replace(
                work,
                status=WorkStatus.TIMED_OUT,
                completed_at=now,
                outcome={"type": "timeout", "code": "APPROVAL_DEADLINE"},
            )
    verification = stages.get("verification")
    if verification and verification.status not in TERMINAL_STAGES:
        stages["verification"] = replace(
            verification,
            status=StageStatus.TIMED_OUT,
            completed_at=now,
            outcome={"type": "timeout", "code": "APPROVAL_DEADLINE"},
        )
    scan = replace(
        state.scan,
        status=ScanStatus.TIMED_OUT,
        completed_at=now,
        outcome={"type": "timeout", "code": "APPROVAL_DEADLINE"},
    )
    return _commit(
        state,
        replace(state, scan=scan, stages=stages, works=works, approvals=approvals),
        now,
        ("stage.timed_out", "scan.timed_out"),
    )


def _commit(
    previous: LifecycleState,
    candidate: LifecycleState,
    now: datetime,
    topics: tuple[str, ...],
) -> TransitionResult:
    scan = replace(
        candidate.scan,
        revision=previous.scan.revision + 1,
        updated_at=now,
        last_progress_at=now,
    )
    committed = replace(candidate, scan=scan)
    if scan.status in TERMINAL_SCANS:
        committed = replace(committed, terminal_snapshot=build_snapshot(committed))
    return TransitionResult(committed, True, topics)


def build_snapshot(state: LifecycleState) -> ScanSnapshot:
    if state.terminal_snapshot is not None:
        return state.terminal_snapshot
    approval_counts = {status: 0 for status in ApprovalStatus}
    for approval in state.approvals.values():
        approval_counts[approval.status] += 1
    summary = ApprovalSummary(
        total=len(state.approvals),
        pending=approval_counts[ApprovalStatus.PENDING],
        approved_awaiting_execution=approval_counts[ApprovalStatus.APPROVED],
        executing=approval_counts[ApprovalStatus.EXECUTING],
        rejected=approval_counts[ApprovalStatus.REJECTED],
        executed=approval_counts[ApprovalStatus.EXECUTED],
        failed=approval_counts[ApprovalStatus.EXECUTION_FAILED]
        + approval_counts[ApprovalStatus.TIMED_OUT],
    )
    stages = {
        name: StageSnapshot(
            stage_run_id=stage.stage_run_id,
            name=name,
            status=stage.status,
            sealed=stage.sealed,
            total_work=stage.total_work,
            open_work=stage.open_work,
            completed_work=stage.completed_work,
            failed_work=stage.failed_work,
            timed_out_work=stage.timed_out_work,
            result_count=stage.result_count,
            started_at=stage.started_at,
            completed_at=stage.completed_at,
            outcome=stage.outcome,
        )
        for name, stage in state.stages.items()
    }
    return ScanSnapshot(
        scan_id=state.scan.scan_id,
        revision=state.scan.revision,
        status=state.scan.status,
        outcome=state.scan.outcome,
        target=state.scan.target,
        mode=state.scan.mode,
        exec_mode=state.scan.exec_mode,
        created_at=state.scan.created_at,
        queued_at=state.scan.queued_at,
        started_at=state.scan.started_at,
        awaiting_approval_at=state.scan.awaiting_approval_at,
        last_progress_at=state.scan.last_progress_at,
        updated_at=state.scan.updated_at,
        completed_at=state.scan.completed_at,
        stages=stages,
        approval_summary=summary,
        result_summary=ResultSummary(
            assets=stages.get("recon").result_count if "recon" in stages else 0,
            findings=stages.get("scan").result_count if "scan" in stages else 0,
            verified=stages.get("verification").result_count if "verification" in stages else 0,
        ),
    )
