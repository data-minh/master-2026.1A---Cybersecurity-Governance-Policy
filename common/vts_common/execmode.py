"""Awaited per-operation execution gates for sequential and parallel modes."""

from __future__ import annotations

import asyncio
from enum import Enum
from typing import Awaitable, Callable, Optional, TypeVar

from .config import settings

T = TypeVar("T")
SEQUENTIAL = "sequential"
PARALLEL = "parallel"
VALID_MODES = (SEQUENTIAL, PARALLEL)


class ExecMode(str, Enum):
    SEQUENTIAL = SEQUENTIAL
    PARALLEL = PARALLEL


class ScanExecutor:
    """Limit concurrency without detaching work from delivery acknowledgement."""

    def __init__(self, max_parallel: Optional[int] = None):
        self.max_parallel = max_parallel or settings.SCAN_MAX_PARALLEL
        self._lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(self.max_parallel)
        self._in_flight = 0

    async def run(self, mode: str, factory: Callable[[], Awaitable[T]]) -> T:
        try:
            selected = ExecMode(mode)
        except ValueError as exc:
            raise ValueError(f"invalid execution mode: {mode}") from exc

        if selected is ExecMode.SEQUENTIAL:
            async with self._lock:
                return await factory()

        async with self._sem:
            self._in_flight += 1
            try:
                return await factory()
            finally:
                self._in_flight -= 1

    @property
    def in_flight(self) -> int:
        return self._in_flight
