"""Measure authoritative lifecycle and dashboard fallback freshness."""

from __future__ import annotations

import os
import statistics
import sys
import time

import httpx

SCOPE = os.getenv("VTS_SCOPE_URL", "http://127.0.0.1:8001").rstrip("/")
ORCH = os.getenv("VTS_ORCHESTRATOR_URL", "http://127.0.0.1:8002").rstrip("/")
DASH = os.getenv("VTS_DASHBOARD_URL", "http://127.0.0.1:8080").rstrip("/")
TARGET = os.getenv("VTS_TARGET", "vuln-target")
TERMINAL = {"succeeded", "failed", "timed_out", "canceled"}


def percentile(values, fraction):
    if not values:
        return float("inf")
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def main() -> int:
    if TARGET != "vuln-target" or os.getenv("RECON_EXTERNAL_SOURCES_ENABLED", "").lower() not in {"false", "0", "no"}:
        print("[measure] unsafe environment: internal vuln-target/external=false required", file=sys.stderr)
        return 2
    try:
        with httpx.Client(timeout=10) as client:
            login = client.post(f"{SCOPE}/auth/login", json={"username": "approver", "password": "approver123"})
            login.raise_for_status()
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            client.post(f"{DASH}/dashboard/login", json={"username": "approver", "password": "approver123"}).raise_for_status()
            listing = client.get(f"{ORCH}/scans?limit=1", headers=headers)
            listing.raise_for_status()
            items = listing.json().get("items", [])
            if not items:
                raise AssertionError("no E2E scan available")
            scan = items[0]
            if scan["status"] not in TERMINAL:
                raise AssertionError(f"scan is not terminal: {scan['status']}")
            if scan["status"] != "succeeded":
                raise AssertionError(f"happy-path scan did not succeed: {scan['status']}")

            detail_latencies = []
            revisions = []
            for _ in range(20):
                started = time.perf_counter()
                response = client.get(f"{DASH}/dashboard/scans/{scan['scan_id']}")
                response.raise_for_status()
                detail_latencies.append(time.perf_counter() - started)
                revisions.append(response.json()["revision"])
            fallback_p95 = percentile(detail_latencies, 0.95)
            if fallback_p95 > 2:
                raise AssertionError(f"fallback p95 exceeds 2s: {fallback_p95:.3f}")
            if any(revision < revisions[0] for revision in revisions):
                raise AssertionError("dashboard revision regressed")

            sse_latencies = []
            for _ in range(10):
                started = time.perf_counter()
                with client.stream(
                    "GET",
                    f"{DASH}/dashboard/scans/{scan['scan_id']}/stream",
                ) as stream:
                    stream.raise_for_status()
                    for line in stream.iter_lines():
                        if line.startswith("data: "):
                            sse_latencies.append(time.perf_counter() - started)
                            break
            sse_p95 = percentile(sse_latencies, 0.95)
            if sse_p95 > 1:
                raise AssertionError(f"SSE initial delivery p95 exceeds 1s: {sse_p95:.3f}")

            work = client.get(f"{ORCH}/scans/{scan['scan_id']}/work?limit=100", headers=headers)
            work.raise_for_status()
            durations = []
            queue_waits = []
            for item in work.json().get("items", []):
                if item.get("started_at") and item.get("queued_at"):
                    queue_waits.append(max(0, _seconds(item["started_at"]) - _seconds(item["queued_at"])))
                if item.get("completed_at") and item.get("started_at"):
                    durations.append(max(0, _seconds(item["completed_at"]) - _seconds(item["started_at"])))
            metrics = client.get(f"{ORCH}/metrics")
            metrics.raise_for_status()
            for name in ("vts_work_completed_total", "vts_event_late_total", "vts_snapshot_sse_delivery_seconds"):
                if name not in metrics.text:
                    raise AssertionError(f"missing metric {name}")
            print(f"[measure] scan_id={scan['scan_id']} terminal={scan['status']} revision={scan['revision']}")
            print(f"[measure] fallback_detail_p95_s={fallback_p95:.4f}")
            print(f"[measure] sse_initial_delivery_p95_s={sse_p95:.4f}")
            print(f"[measure] queue_wait_p95_s={percentile(queue_waits, .95) if queue_waits else 0:.4f}")
            print(f"[measure] work_duration_p95_s={percentile(durations, .95) if durations else 0:.4f}")
            return 0
    except Exception as exc:
        print(f"[measure] FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


def _seconds(value):
    from datetime import datetime
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


if __name__ == "__main__":
    raise SystemExit(main())
