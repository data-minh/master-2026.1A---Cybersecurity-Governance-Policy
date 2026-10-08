import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from vts_common.lifecycle import (
    ApprovalStatus,
    ApprovalSummary,
    EventValidationError,
    LegacyEventV0,
    LifecycleEnvelopeV1,
    MAX_EVENT_BYTES,
    ResultSummary,
    ScanSnapshot,
    ScanStatus,
    StageSnapshot,
    StageStatus,
    WorkCommandData,
    WorkSnapshot,
    WorkStatus,
    WorkType,
    parse_event,
    serialize_event,
    validate_event,
    validate_work_input,
)


def _ids():
    return str(uuid4()), str(uuid4()), str(uuid4())


def _event(topic="work.started", producer="scan-engine", attempt=1, data=None):
    scan_id, stage_run_id, work_id = _ids()
    return {
        "schema_version": 1,
        "event_id": str(uuid4()),
        "event": topic,
        "scan_id": scan_id,
        "stage_run_id": stage_run_id,
        "work_id": work_id,
        "parent_work_id": None,
        "producer": producer,
        "attempt": attempt,
        "occurred_at": "2026-10-04T07:18:27.204000Z",
        "data": data
        or {
            "lease_token": "a" * 32,
            "started_at": "2026-10-04T07:18:27.204000Z",
        },
    }


def test_v1_round_trip_uses_canonical_ids_and_utc():
    raw = json.dumps(_event())
    parsed = parse_event(raw)

    assert parsed.schema_version == 1
    assert parsed.event_id == str(parsed.event_id).lower()
    assert parsed.occurred_at.tzinfo == timezone.utc
    assert parse_event(serialize_event(parsed)) == parsed


def test_v0_is_parsed_only_as_legacy():
    parsed = parse_event(
        json.dumps(
            {
                "event": "scan.started",
                "scan_id": str(uuid4()),
                "timestamp": "2026-10-04T07:18:16.896Z",
                "data": {"target": "vuln-target"},
            }
        )
    )

    assert isinstance(parsed, LegacyEventV0)
    assert parsed.schema_version == 0


def test_unknown_schema_version_is_rejected():
    value = _event()
    value["schema_version"] = 2

    with pytest.raises(EventValidationError, match="unsupported_schema_version"):
        parse_event(json.dumps(value))


def test_payload_over_256_kib_is_rejected():
    value = _event()
    value["data"]["padding"] = "x" * MAX_EVENT_BYTES

    with pytest.raises(EventValidationError, match="payload_too_large"):
        parse_event(json.dumps(value))


def test_topic_requires_registered_producer_and_ids():
    valid = LifecycleEnvelopeV1.model_validate(_event())
    assert validate_event(valid, stream="vts.bus").attempt == 1

    wrong_producer = LifecycleEnvelopeV1.model_validate(_event(producer="dashboard"))
    with pytest.raises(EventValidationError, match="producer_not_allowed"):
        validate_event(wrong_producer, stream="vts.bus")

    missing_work = _event()
    missing_work["work_id"] = None
    with pytest.raises(EventValidationError, match="work_id_required"):
        validate_event(LifecycleEnvelopeV1.model_validate(missing_work), stream="vts.bus")


def test_attempt_bounds_depend_on_topic():
    with pytest.raises(ValidationError):
        LifecycleEnvelopeV1.model_validate(_event(attempt=4))

    scan_id = str(uuid4())
    scan_event = LifecycleEnvelopeV1.model_validate(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "event": "scan.succeeded",
            "scan_id": scan_id,
            "stage_run_id": None,
            "work_id": None,
            "parent_work_id": None,
            "producer": "orchestrator",
            "attempt": 0,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "data": {"revision": 4},
        }
    )
    assert validate_event(scan_event, stream="vts.bus").attempt == 0

    work_zero = LifecycleEnvelopeV1.model_validate(_event(attempt=0))
    with pytest.raises(EventValidationError, match="attempt_invalid"):
        validate_event(work_zero, stream="vts.bus")


def test_work_input_models_reject_invalid_host_ip_url_finding_and_approval():
    invalid = {
        WorkType.RECON_BOOTSTRAP: {"target": "https://bad/path", "mode": "full"},
        WorkType.RECON_HTTP_PROBE_AND_HARVEST: {"host": "https://bad"},
        WorkType.RECON_PORT_SCAN: {"ip": "999.2.3.4"},
        WorkType.RECON_CONTENT_FUZZ: {"base_url": "ftp://vuln-target/path"},
        WorkType.SCAN_TEMPLATE_URL: {"url": "http://user@vuln-target/path"},
        WorkType.SCAN_SPECIALIZED_URL: {"url": "http://vuln-target/#fragment"},
        WorkType.VERIFICATION_SAFE_VERIFY: {
            "finding_id": "bad",
            "url": "http://vuln-target/",
            "severity": "medium",
        },
        WorkType.VERIFICATION_EXECUTE: {
            "approval_id": "not-a-uuid",
            "dry_run": "yes",
        },
    }

    for work_type, value in invalid.items():
        with pytest.raises(EventValidationError, match="invalid_work_input"):
            validate_work_input(work_type, value)

    valid = validate_work_input(
        WorkType.RECON_BOOTSTRAP,
        {"target": "vuln-target", "mode": "recon-passive"},
    )
    assert valid.target == "vuln-target"


def test_work_command_data_validates_registered_input():
    data = WorkCommandData.model_validate(
        {
            "work_type": "scan.template_url",
            "input": {"url": "http://vuln-target/", "class": "page"},
            "timeout_seconds": 120,
            "max_attempts": 3,
            "dispatch_not_before": "2026-10-04T07:18:27.204000Z",
        }
    )
    assert data.work_type == WorkType.SCAN_TEMPLATE_URL


def test_scan_snapshot_requires_revision_stage_approval_and_result_summaries():
    scan_id, stage_id, work_id = _ids()
    now = datetime.now(timezone.utc)
    stage = StageSnapshot(
        stage_run_id=stage_id,
        name="recon",
        status=StageStatus.RUNNING,
        sealed=False,
        total_work=1,
        open_work=1,
        completed_work=0,
        failed_work=0,
        timed_out_work=0,
        result_count=0,
        started_at=now,
    )
    snapshot = ScanSnapshot(
        scan_id=scan_id,
        revision=2,
        status=ScanStatus.RUNNING,
        target="vuln-target",
        mode="full",
        exec_mode="parallel",
        created_at=now,
        queued_at=now,
        started_at=now,
        updated_at=now,
        stages={"recon": stage},
        approval_summary=ApprovalSummary(total=0),
        result_summary=ResultSummary(),
    )
    work = WorkSnapshot(
        work_id=work_id,
        scan_id=scan_id,
        stage_run_id=stage_id,
        work_type=WorkType.RECON_BOOTSTRAP,
        service="recon-subdomain",
        status=WorkStatus.QUEUED,
        attempt=1,
        max_attempts=3,
        result_count=0,
    )

    assert snapshot.lifecycle_version == 1
    assert snapshot.revision == 2
    assert snapshot.approval_summary.pending == 0
    assert work.status == WorkStatus.QUEUED
    assert ApprovalStatus.PENDING.value == "pending"

    with pytest.raises(ValidationError):
        ScanSnapshot.model_validate(
            {
                "scan_id": scan_id,
                "revision": 1,
                "status": "running",
                "target": "vuln-target",
                "mode": "full",
                "exec_mode": "parallel",
                "created_at": now,
                "queued_at": now,
                "updated_at": now,
            }
        )


def test_unknown_fields_never_drive_transition():
    value = _event(data={"lease_token": "b" * 32, "status": "completed"})
    value["status"] = "succeeded"
    envelope = validate_event(LifecycleEnvelopeV1.model_validate(value), stream="vts.bus")

    assert envelope.status == "succeeded"
    assert envelope.validated_data.model_dump().get("status") is None
    assert envelope.event == "work.started"
