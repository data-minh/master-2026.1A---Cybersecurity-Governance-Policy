"""Optional scan-finished webhook (off by default).

Enabled only when WEBHOOK_URL is set *and* its host is listed in
WEBHOOK_ALLOWED_HOSTS. The payload is a summary: IDs, status and counters. It
never carries finding URLs, evidence, tokens or response bodies.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

import httpx

from vts_common.lifecycle import ScanSnapshot
from vts_common.service import log_event

WEBHOOK_TIMEOUT_SECONDS = 5.0


def _allowed_hosts() -> set[str]:
    raw = os.environ.get("WEBHOOK_ALLOWED_HOSTS", "")
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def webhook_target() -> str | None:
    """Return the configured webhook URL, or None when disabled or not allowed."""
    url = os.environ.get("WEBHOOK_URL", "").strip()
    if not url:
        return None
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or host not in _allowed_hosts()
    ):
        log_event("warning", "webhook ignored: URL invalid or host not in WEBHOOK_ALLOWED_HOSTS")
        return None
    return url


def build_payload(snapshot: ScanSnapshot) -> dict:
    return {
        "event": "scan.finished",
        "scan_id": snapshot.scan_id,
        "target": snapshot.target,
        "status": snapshot.status.value,
        "outcome_code": (snapshot.outcome or {}).get("code"),
        "revision": snapshot.revision,
        "completed_at": snapshot.completed_at.isoformat() if snapshot.completed_at else None,
        "summary": snapshot.result_summary.model_dump(),
        "approvals": snapshot.approval_summary.model_dump(),
    }


async def send_scan_finished(snapshot: ScanSnapshot, client_factory=httpx.AsyncClient) -> bool:
    """Best-effort POST of the summary. Never raises; returns True if delivered."""
    url = webhook_target()
    if url is None:
        return False
    try:
        async with client_factory(timeout=WEBHOOK_TIMEOUT_SECONDS) as client:
            response = await client.post(url, json=build_payload(snapshot))
        return response.status_code < 400
    except Exception as exc:  # delivery must never affect scan lifecycle
        log_event("warning", f"webhook delivery failed: {type(exc).__name__}", scan_id=snapshot.scan_id)
        return False
