"""Strict scan-mode selection plus a legacy scan.started compatibility cache."""

from __future__ import annotations

from enum import Enum

from .events import Event, Topics


class ScanMode(str, Enum):
    FULL = "full"
    RECON = "recon"
    RECON_PASSIVE = "recon-passive"


DEFAULT_STAGES = ("recon", "scan", "verification")
DEFAULT_EXEC_MODE = "sequential"
MODE_STAGES: dict[ScanMode, tuple[str, ...]] = {
    ScanMode.FULL: DEFAULT_STAGES,
    ScanMode.RECON: ("recon",),
    ScanMode.RECON_PASSIVE: ("recon",),
}


def stages_for_mode(mode: str) -> tuple[str, ...]:
    try:
        return MODE_STAGES[ScanMode(mode)]
    except (ValueError, KeyError) as exc:
        raise ValueError(f"invalid scan mode: {mode}") from exc


def is_passive_mode(mode: str) -> bool:
    try:
        return ScanMode(mode) is ScanMode.RECON_PASSIVE
    except ValueError as exc:
        raise ValueError(f"invalid scan mode: {mode}") from exc


class ScanModes:
    """Compatibility cache used only by legacy v0 scan.started consumers."""

    def __init__(self) -> None:
        self._modes: dict[str, dict] = {}

    def record(self, evt: Event) -> None:
        if evt.event != Topics.SCAN_STARTED:
            return
        stages = evt.data.get("stages") or DEFAULT_STAGES
        if not isinstance(stages, (list, tuple)) or any(
            stage not in DEFAULT_STAGES for stage in stages
        ):
            raise ValueError("invalid scan mode stages")
        exec_mode = evt.data.get("exec_mode") or DEFAULT_EXEC_MODE
        if exec_mode not in {"sequential", "parallel"}:
            raise ValueError(f"invalid execution mode: {exec_mode}")
        self._modes[evt.scan_id] = {
            "stages": tuple(stages),
            "passive": bool(evt.data.get("passive", False)),
            "exec": exec_mode,
        }

    def stage_enabled(self, scan_id: str, stage: str) -> bool:
        mode = self._modes.get(scan_id)
        return True if mode is None else stage in mode["stages"]

    def is_passive(self, scan_id: str) -> bool:
        mode = self._modes.get(scan_id)
        return bool(mode and mode["passive"])

    def exec_mode(self, scan_id: str) -> str:
        mode = self._modes.get(scan_id)
        return DEFAULT_EXEC_MODE if mode is None else mode["exec"]
