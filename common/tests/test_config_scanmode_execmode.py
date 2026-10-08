import asyncio
import time

import pytest

from vts_common.config import Settings, SettingsError, parse_bounded_int
from vts_common.execmode import ExecMode, ScanExecutor
from vts_common.scanmode import ScanMode, stages_for_mode


def test_settings_reject_zero_out_of_range_and_invalid_boolean():
    with pytest.raises(SettingsError, match="WORK_HEARTBEAT_SECONDS"):
        Settings.from_env({"WORK_HEARTBEAT_SECONDS": "0"})
    with pytest.raises(SettingsError, match="APPROVAL_DEADLINE_SECONDS"):
        Settings.from_env({"APPROVAL_DEADLINE_SECONDS": "86401"})
    with pytest.raises(SettingsError, match="DRY_RUN"):
        Settings.from_env({"DRY_RUN": "sometimes"})


def test_parse_bounded_int_accepts_exact_limits():
    assert parse_bounded_int("VALUE", "1") == 1
    assert parse_bounded_int("VALUE", "86400") == 86400
    with pytest.raises(SettingsError, match="VALUE"):
        parse_bounded_int("VALUE", "not-an-int")


def test_settings_load_all_lifecycle_defaults_without_reading_class_time_env():
    settings = Settings.from_env({})

    assert settings.WORK_BOOTSTRAP_TIMEOUT_SECONDS == 90
    assert settings.WORK_HTTP_PROBE_TIMEOUT_SECONDS == 60
    assert settings.WORK_PORT_TIMEOUT_SECONDS == 30
    assert settings.WORK_FUZZ_TIMEOUT_SECONDS == 45
    assert settings.WORK_TEMPLATE_TIMEOUT_SECONDS == 120
    assert settings.WORK_SPECIALIZED_TIMEOUT_SECONDS == 60
    assert settings.WORK_SAFE_VERIFY_TIMEOUT_SECONDS == 30
    assert settings.WORK_EXECUTE_TIMEOUT_SECONDS == 30
    assert settings.WORK_HEARTBEAT_SECONDS == 5
    assert settings.WORK_LEASE_TTL_SECONDS == 15
    assert settings.WORK_RECLAIM_IDLE_SECONDS == 20
    assert settings.WORK_MAX_ATTEMPTS == 3
    assert settings.WORK_RETRY_BACKOFF_SECONDS == (1, 5, 15)
    assert settings.TECHNICAL_WATCHDOG_SECONDS == 7200
    assert settings.APPROVAL_DEADLINE_SECONDS == 86400
    assert settings.TERMINAL_RETENTION_SECONDS == 604800
    assert settings.DEDUPE_RETENTION_SECONDS == 691200


def test_scan_and_execution_modes_are_strict():
    assert ScanMode("recon-passive") is ScanMode.RECON_PASSIVE
    assert ExecMode("parallel") is ExecMode.PARALLEL
    assert stages_for_mode("full") == ("recon", "scan", "verification")
    assert stages_for_mode("recon-passive") == ("recon",)
    with pytest.raises(ValueError, match="mode"):
        stages_for_mode("typo")


def test_parallel_executor_awaits_factory_and_clears_in_flight():
    async def scenario():
        executor = ScanExecutor(2)

        async def factory():
            await asyncio.sleep(0.08)
            return "done"

        started = time.monotonic()
        result = await executor.run("parallel", factory)
        return result, time.monotonic() - started, executor.in_flight

    result, elapsed, in_flight = asyncio.run(scenario())
    assert result == "done"
    assert elapsed >= 0.05
    assert in_flight == 0


def test_sequential_executor_serializes_and_invalid_mode_does_not_fallback():
    async def scenario():
        executor = ScanExecutor(2)
        active = 0
        peak = 0

        async def factory():
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return peak

        results = await asyncio.gather(
            executor.run("sequential", factory),
            executor.run("sequential", factory),
        )
        with pytest.raises(ValueError, match="mode"):
            await executor.run("typo", factory)
        return results, peak

    results, peak = asyncio.run(scenario())
    assert results == [1, 1]
    assert peak == 1
