from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

import httpx
from fastapi.testclient import TestClient

from services.dashboard.app.main import create_dashboard_app
from vts_common.auth import create_token

CSRF = {"X-VTS-CSRF": "1"}
USERS = {"operator": ("operator123", "operator"), "approver": ("approver123", "approver"), "admin": ("admin123", "admin")}


def _login(client, username="approver"):
    response = client.post("/dashboard/login", json={"username": username, "password": USERS[username][0]})
    assert response.status_code == 200
    return response

NOW = datetime.now(timezone.utc).isoformat()


def _snapshot():
    return {
        "lifecycle_version": 1,
        "scan_id": str(uuid4()),
        "revision": 12,
        "status": "running",
        "outcome": None,
        "target": "vuln-target",
        "mode": "full",
        "exec_mode": "parallel",
        "created_at": NOW,
        "queued_at": NOW,
        "started_at": NOW,
        "updated_at": NOW,
        "completed_at": None,
        "stages": {
            "recon": {"stage_run_id": str(uuid4()), "name": "recon", "status": "running", "sealed": False, "total_work": 2, "open_work": 1, "completed_work": 1, "failed_work": 0, "timed_out_work": 0, "result_count": 1},
            "scan": {"stage_run_id": str(uuid4()), "name": "scan", "status": "running", "sealed": False, "total_work": 1, "open_work": 1, "completed_work": 0, "failed_work": 0, "timed_out_work": 0, "result_count": 0},
            "verification": {"stage_run_id": str(uuid4()), "name": "verification", "status": "pending", "sealed": False, "total_work": 0, "open_work": 0, "completed_work": 0, "failed_work": 0, "timed_out_work": 0, "result_count": 0},
        },
        "approval_summary": {"total": 0, "pending": 0, "approved_awaiting_execution": 0, "executing": 0, "rejected": 0, "executed": 0, "failed": 0},
        "result_summary": {"assets": 1, "findings": 0, "verified": 0, "execution": 0},
    }


class Backend:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.calls = []

    async def login(self, username, password):
        record = USERS.get(username)
        if not record or record[0] != password:
            return httpx.Response(401, json={"detail": "Invalid credentials"})
        return httpx.Response(200, json={"access_token": create_token(username, record[1]), "role": record[1]})

    async def request(self, service, method, path, token=None, **kwargs):
        self.calls.append((service, method, path, {**kwargs, "token": token, "service": service}))
        if path == "/readyz":
            return httpx.Response(200, json={"status": "ready"})
        if path == "/scope":
            if method == "POST":
                return httpx.Response(201, json={"id": 6, "target": "lab.example.com", "type": "domain"})
            return httpx.Response(200, json={"items": [{"id": 5, "target": "vuln-target", "type": "domain"}]})
        if service == "scope" and method == "DELETE":
            return httpx.Response(200, json={"deleted": 5})
        if path == "/preview":
            return httpx.Response(200, json={"url": "http://vuln-target/.env", "status": 200, "content_type": "text/plain", "bytes": 12, "truncated": False, "body": "DB_PASSWORD="})
        if path == "/scans":
            if method == "POST":
                return httpx.Response(201, json=self.snapshot)
            return httpx.Response(200, json={"items": [self.snapshot], "next_cursor": None})
        if path.startswith("/scans/"):
            if path.endswith("/work") or path.endswith("/results"):
                return httpx.Response(200, json={"items": [], "next_cursor": None})
            return httpx.Response(200, json=self.snapshot)
        if path == "/approvals":
            return httpx.Response(200, json={"items": [], "next_cursor": None})
        if path.endswith("/approve"):
            return httpx.Response(409, json={"error": {"code": "APPROVAL_CONFLICT", "message": "conflict"}})
        return httpx.Response(404, json={"error": {"code": "NOT_FOUND", "message": "missing"}})

    async def stream(self, path, last_event_id, token):
        self.calls.append(("orchestrator", "STREAM", path, {"last_event_id": last_event_id}))
        yield b"id: 100-0\nevent: snapshot\ndata: {}\n\n"


def test_list_and_detail_are_unmodified_authoritative_snapshots():
    snapshot = _snapshot()
    backend = Backend(snapshot)
    app = create_dashboard_app(backend)
    with TestClient(app) as client:
        _login(client)
        listing = client.get("/dashboard/scans")
        detail = client.get(f"/dashboard/scans/{snapshot['scan_id']}")
    assert listing.json()["items"][0]["revision"] == 12
    assert detail.json()["revision"] == 12
    assert detail.json()["stages"]["recon"]["status"] == "running"
    assert detail.json()["stages"]["scan"]["status"] == "running"


def test_work_results_queries_and_upstream_errors_preserve_status():
    snapshot = _snapshot()
    backend = Backend(snapshot)
    app = create_dashboard_app(backend)
    with TestClient(app) as client:
        _login(client)
        work = client.get(f"/dashboard/scans/{snapshot['scan_id']}/work?stage=scan&limit=10")
        results = client.get(f"/dashboard/scans/{snapshot['scan_id']}/results?kind=findings")
        conflict = client.post(f"/dashboard/approvals/{uuid4()}/approve", json={"reason": "ok", "idempotency_key": "approval-key"}, headers=CSRF)
    assert work.status_code == results.status_code == 200
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "APPROVAL_CONFLICT"


def test_sse_proxy_preserves_framing_last_event_id_and_headers():
    snapshot = _snapshot()
    backend = Backend(snapshot)
    app = create_dashboard_app(backend)
    with TestClient(app) as client:
        _login(client)
        with client.stream("GET", f"/dashboard/scans/{snapshot['scan_id']}/stream", headers={"Last-Event-ID": "99-0"}) as response:
            body = b"".join(response.iter_bytes())
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-cache"
    assert b"event: snapshot" in body
    assert backend.calls[-1][3]["last_event_id"] == "99-0"


def test_launcher_forwards_stable_idempotency_key_and_exact_modes():
    snapshot = _snapshot()
    backend = Backend(snapshot)
    app = create_dashboard_app(backend)
    key = str(uuid4())
    with TestClient(app) as client:
        _login(client)
        first = client.post("/dashboard/scan", json={"target": "vuln-target", "mode": "full", "exec_mode": "parallel", "idempotency_key": key}, headers=CSRF)
        second = client.post("/dashboard/scan", json={"target": "vuln-target", "mode": "full", "exec_mode": "parallel", "idempotency_key": key}, headers=CSRF)
        invalid = client.post("/dashboard/scan", json={"target": "vuln-target", "mode": "typo"}, headers=CSRF)
    post_calls = [call for call in backend.calls if call[1] == "POST" and call[2] == "/scans"]
    assert first.status_code == second.status_code == 201
    assert post_calls[0][3]["headers"]["Idempotency-Key"] == key
    assert post_calls[1][3]["headers"]["Idempotency-Key"] == key
    assert invalid.status_code == 422


def test_scope_management_requires_affirmation_csrf_and_forwards_user_token():
    backend = Backend(_snapshot())
    app = create_dashboard_app(backend)
    with TestClient(app) as client:
        assert client.get("/dashboard/scope").status_code == 401  # no session
        _login(client, "admin")
        assert client.get("/dashboard/scope").json()["items"][0]["target"] == "vuln-target"
        # add without CSRF header is blocked
        assert client.post("/dashboard/scope", json={"target": "lab.example.com", "authorized": True}).status_code == 403
        # add without the authorization affirmation is rejected
        unaff = client.post("/dashboard/scope", json={"target": "lab.example.com", "authorized": False}, headers=CSRF)
        assert unaff.status_code == 422
        assert unaff.json()["error"]["code"] == "AUTHORIZATION_REQUIRED"
        ok = client.post("/dashboard/scope", json={"target": "lab.example.com", "authorized": True}, headers=CSRF)
        assert ok.status_code == 201
        assert client.delete("/dashboard/scope/5", headers=CSRF).status_code == 200
    posted = [c for c in backend.calls if c[2] == "/scope" and c[1] == "POST"]
    assert posted and posted[0][3]["service"] == "scope" and posted[0][3]["token"] is not None
    # the dashboard never forwards an "authorized" flag upstream; scope-auth enforces the admin role
    assert "authorized" not in posted[0][3]["json"]


def test_preview_is_proxied_to_verification_under_the_user_session():
    backend = Backend(_snapshot())
    app = create_dashboard_app(backend)
    with TestClient(app) as client:
        assert client.get("/dashboard/preview?url=http://vuln-target/.env").status_code == 401
        _login(client, "operator")
        res = client.get("/dashboard/preview?url=http://vuln-target/.env")
        assert res.status_code == 200
        assert res.json()["body"] == "DB_PASSWORD="
    call = [c for c in backend.calls if c[2] == "/preview"][0]
    assert call[3]["service"] == "verification" and call[3]["params"]["url"] == "http://vuln-target/.env"


def test_requests_without_session_or_csrf_are_rejected_and_role_comes_from_token():
    backend = Backend(_snapshot())
    app = create_dashboard_app(backend)
    with TestClient(app) as client:
        assert client.get("/dashboard/scans").status_code == 401
        assert client.get(f"/dashboard/scans/{uuid4()}/stream").status_code == 401
        bad_login = client.post("/dashboard/login", json={"username": "approver", "password": "wrong"})
        assert bad_login.status_code == 401
        login = _login(client, "operator")
        assert "httponly" in login.headers["set-cookie"].lower()
        assert "samesite=strict" in login.headers["set-cookie"].lower()
        assert client.get("/dashboard/me").json() == {"username": "operator", "role": "operator"}
        no_csrf = client.post("/dashboard/scan", json={"target": "vuln-target"})
        assert no_csrf.status_code == 403
        forged_role = client.post(
            f"/dashboard/approvals/{uuid4()}/approve",
            json={"role": "admin", "idempotency_key": "approval-key"},
            headers=CSRF,
        )
        assert forged_role.status_code == 422
        client.post(f"/dashboard/approvals/{uuid4()}/reject", json={"idempotency_key": "approval-key"}, headers=CSRF)
        assert client.post("/dashboard/logout", headers=CSRF).status_code == 200
        assert client.get("/dashboard/me").status_code == 401
    forwarded = [call for call in backend.calls if call[2].endswith("/reject")]
    assert forwarded and forwarded[0][3]["token"] is not None
    from vts_common.auth import decode_token
    assert decode_token(forwarded[0][3]["token"])["role"] == "operator"

def test_report_is_proxied_to_orchestrator_under_the_user_session():
    snapshot = _snapshot()
    backend = Backend(snapshot)
    app = create_dashboard_app(backend)
    with TestClient(app) as client:
        assert client.get(f"/dashboard/scans/{snapshot['scan_id']}/report").status_code == 401
        _login(client, "operator")
        response = client.get(f"/dashboard/scans/{snapshot['scan_id']}/report")
    assert response.status_code == 200
    call = [c for c in backend.calls if c[2].endswith("/report")][0]
    assert call[3]["service"] == "orchestrator"
    assert call[2] == f"/scans/{snapshot['scan_id']}/report"
    assert call[3]["token"] is not None


# ------------------------------------------------ scope visibility and templates
class TemplateBackend(Backend):
    async def request(self, service, method, path, token=None, **kwargs):
        if service == "templates":
            self.calls.append((service, method, path, {**kwargs, "token": token, "service": service}))
            if method == "GET" and path == "/templates":
                return httpx.Response(200, json={"items": [{"id": "user-demo", "yaml": "id: user-demo", "parsed": {"id": "user-demo", "info": {"name": "Demo", "severity": "low"}}}]})
            if method == "POST" and path == "/templates":
                return httpx.Response(201, json={"id": "user-demo", "stored": True})
            if method == "POST" and path == "/templates/validate":
                return httpx.Response(200, json={"valid": True, "errors": []})
            if method == "DELETE":
                return httpx.Response(200, json={"deleted": path.rsplit("/", 1)[1]})
        return await super().request(service, method, path, token, **kwargs)


def _calls_to(backend, service):
    return [c for c in backend.calls if c[3]["service"] == service]


def test_scope_list_is_hidden_from_operator_and_read_only_for_approver():
    backend = Backend(_snapshot())
    app = create_dashboard_app(backend)
    with TestClient(app) as client:
        _login(client, "operator")
        assert client.get("/dashboard/scope").status_code == 403
        assert client.post("/dashboard/scope", json={"target": "a.lab", "authorized": True}, headers=CSRF).status_code == 403
        assert _calls_to(backend, "scope") == []  # refused before any upstream call
        client.post("/dashboard/logout", headers=CSRF)

        _login(client, "approver")
        assert client.get("/dashboard/scope").status_code == 200
        assert client.post("/dashboard/scope", json={"target": "a.lab", "authorized": True}, headers=CSRF).status_code == 403
        assert client.delete("/dashboard/scope/5", headers=CSRF).status_code == 403
        assert [c[1] for c in _calls_to(backend, "scope")] == ["GET"]  # only the read went upstream
        client.post("/dashboard/logout", headers=CSRF)

        _login(client, "admin")
        assert client.get("/dashboard/scope").status_code == 200
        assert client.post("/dashboard/scope", json={"target": "a.lab", "authorized": True}, headers=CSRF).status_code == 201


def test_template_management_is_admin_only_and_forwards_the_user_token():
    backend = TemplateBackend(_snapshot())
    app = create_dashboard_app(backend)
    body = {"yaml_body": "id: user-demo\ninfo: {severity: low}\nrequests: []\n"}
    with TestClient(app) as client:
        assert client.get("/dashboard/templates").status_code == 401
        for role in ("operator", "approver"):
            _login(client, role)
            assert client.get("/dashboard/templates").status_code == 403
            assert client.post("/dashboard/templates", json=body, headers=CSRF).status_code == 403
            assert client.post("/dashboard/templates/validate", json=body, headers=CSRF).status_code == 403
            assert client.delete("/dashboard/templates/user-demo", headers=CSRF).status_code == 403
            client.post("/dashboard/logout", headers=CSRF)
        assert _calls_to(backend, "templates") == []

        _login(client, "admin")
        listing = client.get("/dashboard/templates")
        assert listing.status_code == 200 and listing.json()["items"][0]["id"] == "user-demo"
        assert client.post("/dashboard/templates", json=body).status_code == 403  # CSRF header required
        created = client.post("/dashboard/templates", json=body, headers=CSRF)
        validated = client.post("/dashboard/templates/validate", json=body, headers=CSRF)
        deleted = client.delete("/dashboard/templates/user-demo", headers=CSRF)
    assert (created.status_code, validated.status_code, deleted.status_code) == (201, 200, 200)
    calls = _calls_to(backend, "templates")
    assert [(c[1], c[2]) for c in calls] == [
        ("GET", "/templates"), ("POST", "/templates"), ("POST", "/templates/validate"), ("DELETE", "/templates/user-demo"),
    ]
    assert all(c[3]["token"] for c in calls)
    assert calls[1][3]["json"] == body


class HistoryBackend(Backend):
    async def request(self, service, method, path, token=None, **kwargs):
        if path.startswith("/history"):
            self.calls.append((service, method, path, {**kwargs, "token": token, "service": service}))
            if path == "/history":
                return httpx.Response(200, json={"items": [], "total": 0, "limit": 20, "offset": 0})
            return httpx.Response(200, json={"scan_id": path.rsplit("/", 1)[1], "findings": []})
        return await super().request(service, method, path, token, **kwargs)


def test_history_is_proxied_for_every_role_with_filters_and_session_token():
    backend = HistoryBackend(_snapshot())
    app = create_dashboard_app(backend)
    sid = str(uuid4())
    with TestClient(app) as client:
        assert client.get("/dashboard/history").status_code == 401
        for role in ("operator", "approver", "admin"):
            _login(client, role)
            listing = client.get("/dashboard/history?status=succeeded&target=vuln&limit=10&offset=20")
            detail = client.get(f"/dashboard/history/{sid}")
            assert listing.status_code == 200 and detail.json()["scan_id"] == sid
            client.post("/dashboard/logout", headers=CSRF)
    calls = [c for c in backend.calls if c[2].startswith("/history")]
    assert len(calls) == 6 and all(c[3]["service"] == "orchestrator" and c[3]["token"] for c in calls)
    assert calls[0][3]["params"] == {"status": "succeeded", "target": "vuln", "limit": "10", "offset": "20"}
    assert calls[1][2] == f"/history/{sid}"
