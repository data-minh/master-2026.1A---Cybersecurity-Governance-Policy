import importlib.util
import sys
from pathlib import Path
from uuid import uuid4

import redis
import redis.asyncio as redis_async
from fastapi.testclient import TestClient

from vts_common.auth import create_token

ROOT = Path(__file__).parents[2]
_spec = importlib.util.spec_from_file_location("test_scope_auth_main", ROOT / "services/scope-auth/app/main.py")
scope_auth = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = scope_auth
_spec.loader.exec_module(scope_auth)


def _auth(role):
    return {"Authorization": f"Bearer {create_token(role, role)}"}


def _client(redis_test_url, namespace):
    store = scope_auth.ScopeStore(redis_async.from_url(redis_test_url, decode_responses=True), namespace)
    return TestClient(scope_auth.create_scope_app(store))


def _cleanup(redis_test_url, namespace):
    sync = redis.Redis.from_url(redis_test_url, decode_responses=True)
    keys = list(sync.scan_iter(match=f"{namespace}:*"))
    if keys:
        sync.delete(*keys)
    sync.close()


def test_only_admin_can_change_scope_and_check_reflects_changes(redis_test_url):
    namespace = f"vts-test-{uuid4().hex}"
    try:
        with _client(redis_test_url, namespace) as client:
            assert client.get("/scope/check", params={"target": "vuln-target"}).json()["allowed"] is True
            for role in ("operator", "approver"):
                assert client.post("/scope", json={"target": "new.lab"}, headers=_auth(role)).status_code == 403
                assert client.delete("/scope/5", headers=_auth(role)).status_code == 403
            created = client.post("/scope", json={"target": "new.lab"}, headers=_auth("admin"))
            assert created.status_code == 201 and created.json()["id"] == 6
            assert client.get("/scope/check", params={"target": "new.lab"}).json()["allowed"] is True
            assert client.delete("/scope/5", headers=_auth("admin")).status_code == 200
            assert client.get("/scope/check", params={"target": "vuln-target"}).json()["allowed"] is False
            assert client.post("/scope", json={"target": "x", "type": "bogus"}, headers=_auth("admin")).status_code == 422
    finally:
        _cleanup(redis_test_url, namespace)


def test_scope_survives_service_restart(redis_test_url):
    namespace = f"vts-test-{uuid4().hex}"
    try:
        with _client(redis_test_url, namespace) as client:
            client.post("/scope", json={"target": "persisted.lab"}, headers=_auth("admin"))
            client.delete("/scope/1", headers=_auth("admin"))
        with _client(redis_test_url, namespace) as restarted:
            targets = [item["target"] for item in restarted.get("/scope", headers=_auth("approver")).json()["items"]]
            assert "persisted.lab" in targets
            assert "*.example.com" not in targets
    finally:
        _cleanup(redis_test_url, namespace)


def test_scope_list_is_visible_to_admin_and_approver_but_not_operator(redis_test_url):
    namespace = f"vts-test-{uuid4().hex}"
    try:
        with _client(redis_test_url, namespace) as client:
            assert client.get("/scope").status_code == 401
            assert client.get("/scope", headers=_auth("operator")).status_code == 403
            for role in ("approver", "admin"):
                response = client.get("/scope", headers=_auth(role))
                assert response.status_code == 200
                assert any(item["target"] == "vuln-target" for item in response.json()["items"])
            # the internal safety probe stays reachable without a token
            assert client.get("/scope/check", params={"target": "vuln-target"}).json()["allowed"] is True
            # only admin may write; approver is read-only
            assert client.post("/scope", json={"target": "x.lab"}, headers=_auth("approver")).status_code == 403
            assert client.delete("/scope/5", headers=_auth("approver")).status_code == 403
    finally:
        _cleanup(redis_test_url, namespace)
