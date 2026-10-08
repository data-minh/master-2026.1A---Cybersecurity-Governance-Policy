"""vts_common - shared library for the Vulnerability Testing System (Đề 7).

Provides a unified event schema {event, scan_id, timestamp, data}, a Redis
pub/sub event bus client, JWT auth helpers and a scope-check client that every
service must call before acting on a target.
"""

from .events import Event, EventBus, Topics
from .auth import create_token, decode_token, AuthError
from .scope import ScopeClient, ScopeDenied
from .config import settings
from .util import host_from_url
from .execmode import ScanExecutor, SEQUENTIAL, PARALLEL, VALID_MODES
from .lifecycle import (
    ApprovalStatus,
    ApprovalSummary,
    EventValidationError,
    LegacyEventV0,
    LifecycleEnvelopeV1,
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
from .worker import WorkContext, WorkResult, WorkerRunner

__all__ = [
    "Event",
    "EventBus",
    "Topics",
    "create_token",
    "decode_token",
    "AuthError",
    "ScopeClient",
    "ScopeDenied",
    "settings",
    "host_from_url",
    "ScanExecutor",
    "SEQUENTIAL",
    "PARALLEL",
    "VALID_MODES",
    "ApprovalStatus",
    "ApprovalSummary",
    "EventValidationError",
    "LegacyEventV0",
    "LifecycleEnvelopeV1",
    "ResultSummary",
    "ScanSnapshot",
    "ScanStatus",
    "StageSnapshot",
    "StageStatus",
    "WorkCommandData",
    "WorkSnapshot",
    "WorkStatus",
    "WorkType",
    "parse_event",
    "serialize_event",
    "validate_event",
    "validate_work_input",
    "WorkContext",
    "WorkResult",
    "WorkerRunner",
]
