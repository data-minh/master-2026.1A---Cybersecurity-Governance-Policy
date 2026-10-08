"""Internal-only lifecycle E2E and restart-state verifier."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
import redis

SCOPE = os.getenv("VTS_SCOPE_URL", "http://127.0.0.1:8001").rstrip("/")
ORCH = os.getenv("VTS_ORCHESTRATOR_URL", "http://127.0.0.1:8002").rstrip("/")
DASH = os.getenv("VTS_DASHBOARD_URL", "http://127.0.0.1:8080").rstrip("/")
VERIFY = os.getenv("VTS_VERIFICATION_URL", "http://127.0.0.1:8023").rstrip("/")
REDIS_URL = os.getenv("VTS_REDIS_URL", "redis://127.0.0.1:6379/0")
TARGET = os.getenv("VTS_TARGET", "vuln-target")
TERMINAL = {"succeeded", "failed", "timed_out", "canceled"}


def require_safe_environment():
    if TARGET != "vuln-target":
        raise RuntimeError("E2E refuses every target except canonical vuln-target")
    if os.getenv("RECON_EXTERNAL_SOURCES_ENABLED", "").lower() not in {"false", "0", "no"}:
        raise RuntimeError("E2E requires RECON_EXTERNAL_SOURCES_ENABLED=false")


def login(client, username="approver", password="approver123"):
    response = client.post(f"{SCOPE}/auth/login", json={"username": username, "password": password})
    response.raise_for_status()
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def dashboard_login(client):
    """The dashboard keeps the user JWT in an HttpOnly session cookie."""
    response = client.post(f"{DASH}/dashboard/login", json={"username": "approver", "password": "approver123"})
    response.raise_for_status()


def isolate_scope(client, headers):
    response = client.get(f"{SCOPE}/scope", headers=headers)
    response.raise_for_status()
    for item in response.json().get("items", []):
        if item.get("target") != TARGET:
            deleted = client.delete(f"{SCOPE}/scope/{item['id']}", headers=headers)
            deleted.raise_for_status()
    remaining = client.get(f"{SCOPE}/scope", headers=headers).json().get("items", [])
    if not any(item.get("target") == TARGET for item in remaining):
        client.post(f"{SCOPE}/scope", headers=headers, json={"target": TARGET, "type": "domain", "note": "isolated lifecycle E2E"}).raise_for_status()
        remaining = client.get(f"{SCOPE}/scope", headers=headers).json().get("items", [])
    if [item.get("target") for item in remaining] != [TARGET]:
        raise AssertionError("scope isolation failed")


def snapshot_bundle(client, headers, scan_id):
    orchestrator = client.get(f"{ORCH}/scans/{scan_id}", headers=headers)
    dashboard = client.get(f"{DASH}/dashboard/scans/{scan_id}")
    work = client.get(f"{ORCH}/scans/{scan_id}/work?limit=100", headers=headers)
    approvals = client.get(f"{VERIFY}/approvals", headers=headers, params={"scan_id": scan_id, "limit": 100})
    for response in (orchestrator, dashboard, work, approvals):
        response.raise_for_status()
    return {"scan_id": scan_id, "orchestrator": orchestrator.json(), "dashboard": dashboard.json(), "work": work.json(), "approvals": approvals.json()}


def capture_state(path):
    with httpx.Client(timeout=30) as client:
        headers = login(client)
        dashboard_login(client)
        listing = client.get(f"{ORCH}/scans?limit=1", headers=headers)
        listing.raise_for_status()
        items = listing.json().get("items", [])
        if not items:
            raise AssertionError("no scan available to capture")
        bundle = snapshot_bundle(client, headers, items[0]["scan_id"])
        Path(path).write_text(json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[capture] scan_id={bundle['scan_id']} revision={bundle['orchestrator']['revision']}")


def verify_state(path):
    expected = json.loads(Path(path).read_text(encoding="utf-8"))
    deadline = time.monotonic() + 5
    last_error = None
    while time.monotonic() < deadline:
        try:
            with httpx.Client(timeout=5) as client:
                headers = login(client)
                dashboard_login(client)
                actual = snapshot_bundle(client, headers, expected["scan_id"])
            if actual["orchestrator"]["revision"] < expected["orchestrator"]["revision"]:
                raise AssertionError("revision regressed")
            for key in ("status", "stages", "approval_summary", "result_summary"):
                if actual["orchestrator"].get(key) != expected["orchestrator"].get(key):
                    raise AssertionError(f"restart changed {key}")
            print(f"[restart] recovered revision={actual['orchestrator']['revision']} within 5s")
            return
        except Exception as exc:
            last_error = exc
            time.sleep(0.25)
    raise AssertionError(f"restart recovery failed: {last_error}")


def historical_overlap(scan_id):
    client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        for _stream_id, fields in client.xrange(f"vts:scan:{scan_id}:updates"):
            try:
                snapshot = json.loads(fields["snapshot"])
            except (KeyError, ValueError):
                continue
            stages = snapshot.get("stages", {})
            if (
                stages.get("recon", {}).get("status") == "running"
                and stages.get("scan", {}).get("status") == "running"
            ):
                return True
        return False
    finally:
        client.close()


def audit_commands(scan_id):
    client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    try:
        for stream in client.scan_iter(match="vts.commands.*"):
            for _message_id, fields in client.xrange(stream):
                try:
                    event = json.loads(fields.get("payload", "{}"))
                except ValueError:
                    continue
                if event.get("scan_id") != scan_id:
                    continue
                value = event.get("data", {}).get("input", {})
                for field in ("target", "host"):
                    if field in value and value[field] != TARGET:
                        raise AssertionError(f"unsafe command {field}={value[field]}")
                for field in ("url", "base_url"):
                    if field in value and urlsplit(value[field]).hostname != TARGET:
                        raise AssertionError(f"unsafe command URL={value[field]}")
        if client.config_get("appendonly").get("appendonly") != "yes":
            raise AssertionError("Redis AOF is disabled")
    finally:
        client.close()


def run_e2e():
    require_safe_environment()
    with httpx.Client(timeout=30) as client:
        headers = login(client)
        dashboard_login(client)
        # Scope changes are restricted to the admin role.
        isolate_scope(client, login(client, "admin", "admin123"))
        key = str(uuid4())
        response = client.post(f"{ORCH}/scans", headers={**headers, "Idempotency-Key": key}, json={"target": TARGET, "mode": "full", "exec_mode": "parallel"})
        response.raise_for_status()
        scan_id = response.json()["scan_id"]
        print(f"[e2e] target={TARGET} scan_id={scan_id}")
        last_revision = -1
        acted = set()
        saw_awaiting = False
        saw_overlap = False
        checked_preapprove = False
        deadline = time.monotonic() + 180
        terminal = None
        while time.monotonic() < deadline:
            snapshot_response = client.get(f"{ORCH}/scans/{scan_id}", headers=headers)
            snapshot_response.raise_for_status()
            snapshot = snapshot_response.json()
            revision = snapshot["revision"]
            if revision < last_revision:
                raise AssertionError("revision regressed")
            if revision != last_revision:
                stages = snapshot["stages"]
                print(f"[rev {revision}] scan={snapshot['status']} recon={stages['recon']['status']} scan-stage={stages['scan']['status']} verification={stages['verification']['status']}")
                last_revision = revision
            stages = snapshot["stages"]
            saw_overlap |= stages["recon"]["status"] == "running" and stages["scan"]["status"] == "running"
            saw_awaiting |= snapshot["status"] == "awaiting_approval"

            approvals_response = client.get(f"{VERIFY}/approvals", headers=headers, params={"scan_id": scan_id, "limit": 100})
            approvals_response.raise_for_status()
            approvals = approvals_response.json().get("items", [])
            for index, approval in enumerate(approvals):
                approval_id = approval["approval_id"]
                if approval["status"] != "pending" or approval_id in acted:
                    continue
                if not checked_preapprove:
                    blocked = client.post(f"{VERIFY}/approvals/{approval_id}/execute", headers={**headers, "Idempotency-Key": str(uuid4())}, json={"dry_run": True})
                    if blocked.status_code != 409:
                        raise AssertionError("execute-before-approve was not blocked")
                    checked_preapprove = True
                if index % 2 == 0 and len(approvals) > 1:
                    action = client.post(f"{VERIFY}/approvals/{approval_id}/reject", headers={**headers, "Idempotency-Key": str(uuid4())}, json={"reason": "E2E reject path"})
                    action.raise_for_status()
                    print(f"[policy] rejected {approval_id}")
                else:
                    approved = client.post(f"{VERIFY}/approvals/{approval_id}/approve", headers={**headers, "Idempotency-Key": str(uuid4())}, json={"reason": "E2E approve path"})
                    approved.raise_for_status()
                    execute = client.post(f"{VERIFY}/approvals/{approval_id}/execute", headers={**headers, "Idempotency-Key": str(uuid4())}, json={"dry_run": True})
                    if execute.status_code != 202:
                        raise AssertionError(f"execute did not return 202: {execute.text}")
                    print(f"[policy] approved+execute {approval_id}")
                acted.add(approval_id)
            if snapshot["status"] in TERMINAL:
                terminal = snapshot
                break
            time.sleep(0.25)
        if terminal is None:
            raise AssertionError("scan did not reach a terminal state")
        if terminal["status"] != "succeeded":
            raise AssertionError(f"happy path ended as {terminal['status']}: {terminal.get('outcome')}")
        if not (saw_overlap or historical_overlap(scan_id)):
            raise AssertionError("streaming Recon/Scan overlap was not observed")
        if acted and not saw_awaiting:
            raise AssertionError("approval never moved scan to awaiting_approval")
        work = client.get(f"{ORCH}/scans/{scan_id}/work?limit=100", headers=headers).json().get("items", [])
        identities = [item["work_id"] for item in work]
        if len(identities) != len(set(identities)):
            raise AssertionError("duplicate logical work IDs")
        audit_commands(scan_id)
        print(f"[PASS] terminal={terminal['status']} revision={terminal['revision']} work={len(work)} approvals={len(acted)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-restart-state")
    parser.add_argument("--verify-restart-state")
    args = parser.parse_args()
    try:
        require_safe_environment()
        if args.capture_restart_state:
            capture_state(args.capture_restart_state)
        elif args.verify_restart_state:
            verify_state(args.verify_restart_state)
        else:
            run_e2e()
        return 0
    except Exception as exc:
        print(f"[FAIL] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
