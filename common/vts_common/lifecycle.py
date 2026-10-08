"""Versioned lifecycle contracts shared by VTS services."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    field_validator,
    model_validator,
)

MAX_EVENT_BYTES = 262_144
LEGACY_COMPATIBILITY_ALIASES = frozenset({"scan.finished", "scan.stage.completed"})
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
PRODUCER_PATTERN = re.compile(r"^[a-z0-9-]{1,64}$")
FINDING_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class EventValidationError(ValueError):
    """A stable event-boundary validation error."""


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELED = "canceled"


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


class WorkStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELED = "canceled"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    EXECUTED = "executed"
    EXECUTION_FAILED = "execution_failed"
    TIMED_OUT = "timed_out"


class WorkType(str, Enum):
    RECON_BOOTSTRAP = "recon.bootstrap"
    RECON_HTTP_PROBE_AND_HARVEST = "recon.http_probe_and_harvest"
    RECON_PORT_SCAN = "recon.port_scan"
    RECON_CONTENT_FUZZ = "recon.content_fuzz"
    SCAN_TEMPLATE_URL = "scan.template_url"
    SCAN_SPECIALIZED_URL = "scan.specialized_url"
    VERIFICATION_SAFE_VERIFY = "verification.safe_verify"
    VERIFICATION_EXECUTE = "verification.execute"


class _Payload(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ReconBootstrapInput(_Payload):
    target: str
    mode: Literal["full", "recon", "recon-passive"] = "full"

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return _validate_hostname(value, "target")


class ReconHttpProbeInput(_Payload):
    host: str

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        return _validate_hostname(value, "host")


class ReconPortScanInput(_Payload):
    ip: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        parsed = ipaddress.ip_address(value)
        if str(parsed) != value.lower():
            raise ValueError("ip must be canonical")
        return str(parsed)


class _UrlInput(_Payload):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return _validate_url(value)


class ReconContentFuzzInput(_Payload):
    base_url: str

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        return _validate_url(value)


class ScanUrlInput(_UrlInput):
    resource_class: Literal["page"] | None = Field(default=None, alias="class")
    variant: str | None = Field(default=None, max_length=128)


class SafeVerifyInput(_UrlInput):
    finding_id: str
    severity: Literal["high", "critical"]

    @field_validator("finding_id")
    @classmethod
    def validate_finding_id(cls, value: str) -> str:
        if not FINDING_PATTERN.fullmatch(value):
            raise ValueError("invalid finding_id")
        return value


class ExecuteInput(_Payload):
    approval_id: str
    dry_run: StrictBool

    @field_validator("approval_id")
    @classmethod
    def validate_approval_id(cls, value: str) -> str:
        return _canonical_uuid(value, "approval_id")


WORK_INPUT_MODELS: dict[WorkType, type[BaseModel]] = {
    WorkType.RECON_BOOTSTRAP: ReconBootstrapInput,
    WorkType.RECON_HTTP_PROBE_AND_HARVEST: ReconHttpProbeInput,
    WorkType.RECON_PORT_SCAN: ReconPortScanInput,
    WorkType.RECON_CONTENT_FUZZ: ReconContentFuzzInput,
    WorkType.SCAN_TEMPLATE_URL: ScanUrlInput,
    WorkType.SCAN_SPECIALIZED_URL: ScanUrlInput,
    WorkType.VERIFICATION_SAFE_VERIFY: SafeVerifyInput,
    WorkType.VERIFICATION_EXECUTE: ExecuteInput,
}


def validate_work_input(work_type: WorkType | str, value: dict[str, Any]) -> BaseModel:
    try:
        typed_work = WorkType(work_type)
        return WORK_INPUT_MODELS[typed_work].model_validate(value)
    except (KeyError, ValueError, ValidationError, TypeError) as exc:
        raise EventValidationError(f"invalid_work_input: {exc}") from exc


class WorkCommandData(_Payload):
    work_type: WorkType
    input: dict[str, Any]
    timeout_seconds: int = Field(ge=1, le=86_400)
    max_attempts: int = Field(default=3, ge=1, le=3)
    dispatch_not_before: datetime

    @field_validator("dispatch_not_before")
    @classmethod
    def validate_dispatch_time(cls, value: datetime) -> datetime:
        return _utc_datetime(value)

    @model_validator(mode="after")
    def validate_input_for_work_type(self) -> WorkCommandData:
        validate_work_input(self.work_type, self.input)
        return self


class WorkQueuedData(_Payload):
    command_event_id: str
    command_message_id: str
    lease_token: str = Field(min_length=1, max_length=256)


class WorkStartedData(_Payload):
    lease_token: str = Field(min_length=1, max_length=256)
    started_at: datetime | None = None


class WorkProgressData(_Payload):
    sequence: int = Field(ge=0)
    percent: float | None = Field(default=None, ge=0, le=100)
    message: str = Field(default="", max_length=500)
    counters: dict[str, int | float] = Field(default_factory=dict)


class WorkCompletedData(_Payload):
    result_count: int = Field(ge=0)
    duration_ms: int = Field(ge=0)
    lease_token: str = Field(min_length=1, max_length=256)


class WorkFailedData(_Payload):
    error_code: str = Field(min_length=1, max_length=128)
    retryable: StrictBool
    message: str = Field(default="", max_length=1000)
    duration_ms: int = Field(ge=0)
    lease_token: str = Field(min_length=1, max_length=256)


class WorkTimedOutData(_Payload):
    deadline: datetime
    last_progress_at: datetime | None = None
    attempts: int = Field(ge=1, le=3)


class WorkCanceledData(_Payload):
    reason: str = Field(min_length=1, max_length=500)


class ResultData(_Payload):
    result_id: str

    @field_validator("result_id")
    @classmethod
    def validate_result_id(cls, value: str) -> str:
        if not FINDING_PATTERN.fullmatch(value):
            raise ValueError("invalid result_id")
        return value


class ApprovalEventData(_Payload):
    approval_id: str

    @field_validator("approval_id")
    @classmethod
    def validate_approval_id(cls, value: str) -> str:
        return _canonical_uuid(value, "approval_id")


class RevisionData(_Payload):
    revision: int = Field(ge=1)


WORKER_PRODUCERS = frozenset(
    {
        "recon-subdomain",
        "recon-httpprobe",
        "recon-portfuzz",
        "scan-engine",
        "scan-specialized",
        "verification",
    }
)

TOPIC_PRODUCERS: dict[str, frozenset[str]] = {
    "work.command": frozenset({"orchestrator"}),
    "work.queued": WORKER_PRODUCERS,
    "work.started": WORKER_PRODUCERS,
    "work.progress": WORKER_PRODUCERS,
    "work.completed": WORKER_PRODUCERS,
    "work.failed": WORKER_PRODUCERS,
    "work.timed_out": frozenset({"orchestrator"}),
    "work.canceled": frozenset({"orchestrator"}),
    "asset.subdomain.discovered": frozenset({"recon-subdomain"}),
    "asset.osint.collected": frozenset({"recon-subdomain"}),
    "asset.endpoint.alive": frozenset({"recon-httpprobe"}),
    "asset.url.collected": frozenset({"recon-httpprobe"}),
    "asset.port.open": frozenset({"recon-portfuzz"}),
    "asset.path.found": frozenset({"recon-portfuzz"}),
    "vuln.detected": frozenset({"scan-engine", "scan-specialized"}),
    "vuln.verified": frozenset({"verification"}),
    "approval.requested": frozenset({"verification"}),
    "approval.approved": frozenset({"verification"}),
    "approval.rejected": frozenset({"verification"}),
    "approval.execution.requested": frozenset({"verification"}),
    "approval.executed": frozenset({"verification"}),
    "approval.execution_failed": frozenset({"verification", "orchestrator"}),
    "scan.queued": frozenset({"orchestrator"}),
    "scan.running": frozenset({"orchestrator"}),
    "scan.awaiting_approval": frozenset({"orchestrator"}),
    "scan.succeeded": frozenset({"orchestrator"}),
    "scan.failed": frozenset({"orchestrator"}),
    "scan.timed_out": frozenset({"orchestrator"}),
    "scan.canceled": frozenset({"orchestrator"}),
    "stage.succeeded": frozenset({"orchestrator"}),
    "stage.failed": frozenset({"orchestrator"}),
    "stage.timed_out": frozenset({"orchestrator"}),
    "stage.skipped": frozenset({"orchestrator"}),
    "scan.finished": frozenset({"orchestrator"}),
    "scan.stage.completed": frozenset({"orchestrator"}),
}

TOPIC_DATA_MODELS: dict[str, type[BaseModel]] = {
    "work.command": WorkCommandData,
    "work.queued": WorkQueuedData,
    "work.started": WorkStartedData,
    "work.progress": WorkProgressData,
    "work.completed": WorkCompletedData,
    "work.failed": WorkFailedData,
    "work.timed_out": WorkTimedOutData,
    "work.canceled": WorkCanceledData,
}
for _topic in TOPIC_PRODUCERS:
    if _topic.startswith(("asset.", "vuln.")):
        TOPIC_DATA_MODELS[_topic] = ResultData
    elif _topic.startswith("approval."):
        TOPIC_DATA_MODELS[_topic] = ApprovalEventData
    elif _topic.startswith(("scan.", "stage.")):
        TOPIC_DATA_MODELS[_topic] = RevisionData


class LegacyEventV0(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: Literal[0] = 0
    event: str = Field(min_length=1, max_length=96)
    scan_id: str = ""
    timestamp: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class LifecycleEnvelopeV1(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: Literal[1]
    event_id: str
    event: str = Field(min_length=1, max_length=96)
    scan_id: str
    stage_run_id: str | None = None
    work_id: str | None = None
    parent_work_id: str | None = None
    producer: str
    attempt: int = Field(ge=0, le=3)
    occurred_at: datetime
    data: dict[str, Any]

    _uuid_fields: ClassVar[tuple[str, ...]] = (
        "event_id",
        "scan_id",
        "stage_run_id",
        "work_id",
        "parent_work_id",
    )

    @field_validator("event_id", "scan_id")
    @classmethod
    def validate_required_uuid(cls, value: str, info) -> str:
        return _canonical_uuid(value, info.field_name)

    @field_validator("stage_run_id", "work_id", "parent_work_id")
    @classmethod
    def validate_optional_uuid(cls, value: str | None, info) -> str | None:
        return None if value is None else _canonical_uuid(value, info.field_name)

    @field_validator("producer")
    @classmethod
    def validate_producer(cls, value: str) -> str:
        if not PRODUCER_PATTERN.fullmatch(value):
            raise ValueError("invalid producer")
        return value

    @field_validator("occurred_at")
    @classmethod
    def validate_occurred_at(cls, value: datetime) -> datetime:
        return _utc_datetime(value)

    @property
    def validated_data(self) -> BaseModel:
        model = TOPIC_DATA_MODELS.get(self.event, _Payload)
        return model.model_validate(self.data)


def validate_event(
    envelope: LifecycleEnvelopeV1, *, stream: str
) -> LifecycleEnvelopeV1:
    allowed = TOPIC_PRODUCERS.get(envelope.event)
    if allowed is None:
        raise EventValidationError("unknown_topic")
    if envelope.producer not in allowed:
        raise EventValidationError("producer_not_allowed")

    is_scan = envelope.event.startswith("scan.")
    is_stage = envelope.event.startswith("stage.") or envelope.event == "scan.stage.completed"
    attached_to_work = not is_scan and not is_stage
    if is_scan:
        if envelope.stage_run_id is not None or envelope.work_id is not None:
            raise EventValidationError("scan_event_ids_invalid")
        if envelope.attempt != 0:
            raise EventValidationError("attempt_invalid")
    elif is_stage:
        if envelope.stage_run_id is None:
            raise EventValidationError("stage_run_id_required")
        if envelope.work_id is not None or envelope.attempt != 0:
            raise EventValidationError("stage_event_ids_invalid")
    elif attached_to_work:
        if envelope.stage_run_id is None:
            raise EventValidationError("stage_run_id_required")
        if envelope.work_id is None:
            raise EventValidationError("work_id_required")
        if not 1 <= envelope.attempt <= 3:
            raise EventValidationError("attempt_invalid")

    if envelope.event == "work.command":
        if not stream.startswith("vts.commands."):
            raise EventValidationError("command_stream_invalid")
    elif stream != "vts.bus":
        raise EventValidationError("bus_stream_invalid")

    try:
        envelope.validated_data
    except ValidationError as exc:
        raise EventValidationError(f"invalid_topic_data: {exc}") from exc
    return envelope


def parse_event(raw: str | bytes) -> LifecycleEnvelopeV1 | LegacyEventV0:
    encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(encoded) > MAX_EVENT_BYTES:
        raise EventValidationError("payload_too_large")
    try:
        value = json.loads(encoded)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
        raise EventValidationError("malformed_json") from exc
    if not isinstance(value, dict):
        raise EventValidationError("event_must_be_object")

    version = value.get("schema_version")
    try:
        if version is None:
            return LegacyEventV0.model_validate(value)
        if version != 1:
            raise EventValidationError("unsupported_schema_version")
        return LifecycleEnvelopeV1.model_validate(value)
    except ValidationError as exc:
        raise EventValidationError(f"invalid_event: {exc}") from exc


def serialize_event(event: LifecycleEnvelopeV1 | LegacyEventV0) -> str:
    raw = event.model_dump_json(exclude_none=False)
    if len(raw.encode("utf-8")) > MAX_EVENT_BYTES:
        raise EventValidationError("payload_too_large")
    return raw


class WorkSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    work_id: str
    scan_id: str
    stage_run_id: str
    parent_work_id: str | None = None
    work_type: WorkType
    service: str
    status: WorkStatus
    attempt: int = Field(ge=1, le=3)
    max_attempts: int = Field(default=3, ge=1, le=3)
    dispatch_state: str = "ready"
    result_count: int = Field(default=0, ge=0)
    queued_at: datetime | None = None
    started_at: datetime | None = None
    last_progress_at: datetime | None = None
    completed_at: datetime | None = None
    outcome: dict[str, Any] | None = None


class StageSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage_run_id: str
    name: Literal["recon", "scan", "verification"]
    status: StageStatus
    sealed: bool
    total_work: int = Field(default=0, ge=0)
    open_work: int = Field(default=0, ge=0)
    completed_work: int = Field(default=0, ge=0)
    failed_work: int = Field(default=0, ge=0)
    timed_out_work: int = Field(default=0, ge=0)
    result_count: int = Field(default=0, ge=0)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    outcome: dict[str, Any] | None = None


class ApprovalSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(default=0, ge=0)
    pending: int = Field(default=0, ge=0)
    approved_awaiting_execution: int = Field(default=0, ge=0)
    executing: int = Field(default=0, ge=0)
    rejected: int = Field(default=0, ge=0)
    executed: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)


class ResultSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assets: int = Field(default=0, ge=0)
    findings: int = Field(default=0, ge=0)
    verified: int = Field(default=0, ge=0)
    execution: int = Field(default=0, ge=0)


class ScanSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lifecycle_version: Literal[1] = 1
    scan_id: str
    revision: int = Field(ge=1)
    status: ScanStatus
    outcome: dict[str, Any] | None = None
    target: str
    mode: Literal["full", "recon", "recon-passive"]
    exec_mode: Literal["sequential", "parallel"]
    created_at: datetime
    queued_at: datetime
    started_at: datetime | None = None
    awaiting_approval_at: datetime | None = None
    last_progress_at: datetime | None = None
    updated_at: datetime
    completed_at: datetime | None = None
    stages: dict[str, StageSnapshot]
    approval_summary: ApprovalSummary
    result_summary: ResultSummary


def _canonical_uuid(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not UUID_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be canonical lowercase UUID")
    parsed = UUID(value)
    if str(parsed) != value:
        raise ValueError(f"{field_name} must be canonical lowercase UUID")
    return value


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include UTC timezone")
    if value.utcoffset().total_seconds() != 0:
        raise ValueError("timestamp must be UTC")
    return value.astimezone(timezone.utc)


def _validate_hostname(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        raise ValueError(f"{field_name} length invalid")
    if "://" in value or any(character in value for character in "/?#@"):
        raise ValueError(f"{field_name} must be a hostname")
    labels = value.rstrip(".").split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise ValueError(f"{field_name} must be a hostname")
    return value.lower().rstrip(".")


def _validate_url(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("url length invalid")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("url must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("url userinfo is forbidden")
    if parsed.fragment:
        raise ValueError("url fragment is forbidden")
    _validate_hostname(parsed.hostname, "url host")
    return value
