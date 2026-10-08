"""Typed, fail-closed configuration shared by all VTS services."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping


class SettingsError(ValueError):
    """Raised when a service environment value is invalid."""


def parse_bounded_int(
    name: str,
    raw: str,
    minimum: int = 1,
    maximum: int = 86_400,
) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise SettingsError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise SettingsError(f"{name} must be between {minimum} and {maximum}")
    return value


def _parse_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise SettingsError(f"{name} must be true or false")


def _read(environ: Mapping[str, str], name: str, default: str) -> str:
    return environ.get(name, default)


@dataclass(frozen=True, slots=True)
class Settings:
    REDIS_URL: str
    JWT_SECRET: str
    JWT_ALG: str
    JWT_TTL_SECONDS: int
    SCOPE_SERVICE_URL: str
    ORCHESTRATOR_URL: str
    DASHBOARD_URL: str
    SERVICE_NAME: str
    DRY_RUN: bool
    RECON_EXTERNAL_SOURCES_ENABLED: bool
    MAX_CONCURRENCY: int
    TOP_PORTS: int
    SCAN_MAX_PARALLEL: int
    WORK_BOOTSTRAP_TIMEOUT_SECONDS: int
    WORK_HTTP_PROBE_TIMEOUT_SECONDS: int
    WORK_PORT_TIMEOUT_SECONDS: int
    WORK_FUZZ_TIMEOUT_SECONDS: int
    WORK_TEMPLATE_TIMEOUT_SECONDS: int
    WORK_SPECIALIZED_TIMEOUT_SECONDS: int
    WORK_SAFE_VERIFY_TIMEOUT_SECONDS: int
    WORK_EXECUTE_TIMEOUT_SECONDS: int
    WORK_HEARTBEAT_SECONDS: int
    WORK_LEASE_TTL_SECONDS: int
    WORK_RECLAIM_IDLE_SECONDS: int
    WORK_MAX_ATTEMPTS: int
    WORK_RETRY_BACKOFF_SECONDS: tuple[int, ...]
    TECHNICAL_WATCHDOG_SECONDS: int
    APPROVAL_DEADLINE_SECONDS: int
    TERMINAL_RETENTION_SECONDS: int
    DEDUPE_RETENTION_SECONDS: int
    UPDATE_STREAM_MAXLEN: int

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        source = os.environ if environ is None else environ

        retry_raw = _read(source, "WORK_RETRY_BACKOFF_SECONDS", "1,5,15")
        try:
            retry_backoff = tuple(
                parse_bounded_int(
                    "WORK_RETRY_BACKOFF_SECONDS", part.strip(), 1, 86_400
                )
                for part in retry_raw.split(",")
            )
        except SettingsError:
            raise
        if retry_backoff != (1, 5, 15):
            raise SettingsError(
                "WORK_RETRY_BACKOFF_SECONDS must be the fixed sequence 1,5,15"
            )

        return cls(
            REDIS_URL=_read(source, "REDIS_URL", "redis://localhost:6379/0"),
            JWT_SECRET=_read(
                source, "JWT_SECRET", "change-me-in-prod-vts-secret"
            ),
            JWT_ALG=_read(source, "JWT_ALG", "HS256"),
            JWT_TTL_SECONDS=parse_bounded_int(
                "JWT_TTL_SECONDS", _read(source, "JWT_TTL_SECONDS", "3600")
            ),
            SCOPE_SERVICE_URL=_read(
                source, "SCOPE_SERVICE_URL", "http://scope-auth:8000"
            ),
            ORCHESTRATOR_URL=_read(
                source, "ORCHESTRATOR_URL", "http://orchestrator:8000"
            ),
            DASHBOARD_URL=_read(
                source, "DASHBOARD_URL", "http://dashboard:8000"
            ),
            SERVICE_NAME=_read(source, "SERVICE_NAME", "unknown-service"),
            DRY_RUN=_parse_bool("DRY_RUN", _read(source, "DRY_RUN", "true")),
            RECON_EXTERNAL_SOURCES_ENABLED=_parse_bool(
                "RECON_EXTERNAL_SOURCES_ENABLED",
                _read(source, "RECON_EXTERNAL_SOURCES_ENABLED", "true"),
            ),
            MAX_CONCURRENCY=parse_bounded_int(
                "MAX_CONCURRENCY", _read(source, "MAX_CONCURRENCY", "20")
            ),
            TOP_PORTS=parse_bounded_int(
                "TOP_PORTS", _read(source, "TOP_PORTS", "100")
            ),
            SCAN_MAX_PARALLEL=parse_bounded_int(
                "SCAN_MAX_PARALLEL", _read(source, "SCAN_MAX_PARALLEL", "4")
            ),
            WORK_BOOTSTRAP_TIMEOUT_SECONDS=_timeout(
                source, "WORK_BOOTSTRAP_TIMEOUT_SECONDS", 90
            ),
            WORK_HTTP_PROBE_TIMEOUT_SECONDS=_timeout(
                source, "WORK_HTTP_PROBE_TIMEOUT_SECONDS", 60
            ),
            WORK_PORT_TIMEOUT_SECONDS=_timeout(
                source, "WORK_PORT_TIMEOUT_SECONDS", 30
            ),
            WORK_FUZZ_TIMEOUT_SECONDS=_timeout(
                source, "WORK_FUZZ_TIMEOUT_SECONDS", 45
            ),
            WORK_TEMPLATE_TIMEOUT_SECONDS=_timeout(
                source, "WORK_TEMPLATE_TIMEOUT_SECONDS", 120
            ),
            WORK_SPECIALIZED_TIMEOUT_SECONDS=_timeout(
                source, "WORK_SPECIALIZED_TIMEOUT_SECONDS", 60
            ),
            WORK_SAFE_VERIFY_TIMEOUT_SECONDS=_timeout(
                source, "WORK_SAFE_VERIFY_TIMEOUT_SECONDS", 30
            ),
            WORK_EXECUTE_TIMEOUT_SECONDS=_timeout(
                source, "WORK_EXECUTE_TIMEOUT_SECONDS", 30
            ),
            WORK_HEARTBEAT_SECONDS=_timeout(
                source, "WORK_HEARTBEAT_SECONDS", 5
            ),
            WORK_LEASE_TTL_SECONDS=_timeout(
                source, "WORK_LEASE_TTL_SECONDS", 15
            ),
            WORK_RECLAIM_IDLE_SECONDS=_timeout(
                source, "WORK_RECLAIM_IDLE_SECONDS", 20
            ),
            WORK_MAX_ATTEMPTS=parse_bounded_int(
                "WORK_MAX_ATTEMPTS",
                _read(source, "WORK_MAX_ATTEMPTS", "3"),
                1,
                3,
            ),
            WORK_RETRY_BACKOFF_SECONDS=retry_backoff,
            TECHNICAL_WATCHDOG_SECONDS=_timeout(
                source, "TECHNICAL_WATCHDOG_SECONDS", 7200
            ),
            APPROVAL_DEADLINE_SECONDS=_timeout(
                source, "APPROVAL_DEADLINE_SECONDS", 86_400
            ),
            TERMINAL_RETENTION_SECONDS=parse_bounded_int(
                "TERMINAL_RETENTION_SECONDS",
                _read(source, "TERMINAL_RETENTION_SECONDS", "604800"),
                1,
                31_536_000,
            ),
            DEDUPE_RETENTION_SECONDS=parse_bounded_int(
                "DEDUPE_RETENTION_SECONDS",
                _read(source, "DEDUPE_RETENTION_SECONDS", "691200"),
                1,
                31_536_000,
            ),
            UPDATE_STREAM_MAXLEN=parse_bounded_int(
                "UPDATE_STREAM_MAXLEN",
                _read(source, "UPDATE_STREAM_MAXLEN", "1000"),
                1,
                100_000,
            ),
        )


def _timeout(source: Mapping[str, str], name: str, default: int) -> int:
    return parse_bounded_int(name, _read(source, name, str(default)))


settings = Settings.from_env()
