"""The verification /preview endpoint only reads in-scope resources (GET)."""
import httpx
from fastapi.testclient import TestClient

from services.verification.app import main as verification
from vts_common.auth import create_token

AUTH = {"Authorization": f"Bearer {create_token('operator', 'operator')}"}


class Scope:
    def __init__(self, allowed):
        self.allowed = allowed
        self.asked = []

    async def permits(self, host):
        self.asked.append(host)
        return self.allowed


class FakeResponse:
    def __init__(self, url, status, content, ct="text/html", encoding="utf-8"):
        self.url = url
        self.status_code = status
        self.content = content
        self.headers = {"content-type": ct}
        self.encoding = encoding


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.requested = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url):
        self.requested.append(url)
        if self.response is None:
            raise httpx.ConnectError("refused", request=httpx.Request("GET", url))
        return self.response


def _app():
    return verification.create_verification_app(object(), verification.EventBus(), None)


def _client():
    # No context manager: the app's lifespan (which needs Redis) does not run.
    return TestClient(_app())


def test_in_scope_url_is_fetched_and_returned(monkeypatch):
    scope = Scope(True)
    client = FakeClient(FakeResponse("http://vuln-target/.env", 200, b"DB_PASSWORD=secret"))
    monkeypatch.setattr(verification, "ScopeClient", lambda: scope)
    monkeypatch.setattr(verification, "scoped_http_client", lambda **k: client)
    res = _client().get("/preview", params={"url": "http://vuln-target/.env"}, headers=AUTH)
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == 200 and body["body"] == "DB_PASSWORD=secret"
    assert scope.asked == ["vuln-target"] and client.requested == ["http://vuln-target/.env"]


def test_out_of_scope_url_is_refused_without_fetching(monkeypatch):
    scope = Scope(False)
    client = FakeClient(FakeResponse("http://evil.example/", 200, b"x"))
    monkeypatch.setattr(verification, "ScopeClient", lambda: scope)
    monkeypatch.setattr(verification, "scoped_http_client", lambda **k: client)
    res = _client().get("/preview", params={"url": "http://evil.example/"}, headers=AUTH)
    assert res.status_code == 403
    assert client.requested == []  # never fetched


def test_bad_url_and_missing_auth_are_rejected(monkeypatch):
    monkeypatch.setattr(verification, "ScopeClient", lambda: Scope(True))
    app_client = _client()
    assert app_client.get("/preview", params={"url": "ftp://vuln-target/x"}, headers=AUTH).status_code == 400
    assert app_client.get("/preview", params={"url": "http://vuln-target/"}).status_code == 401


def test_oversized_body_is_truncated(monkeypatch):
    big = b"A" * (verification.MAX_EVIDENCE_BYTES + 500)
    client = FakeClient(FakeResponse("http://vuln-target/big", 200, big, ct="text/plain"))
    monkeypatch.setattr(verification, "ScopeClient", lambda: Scope(True))
    monkeypatch.setattr(verification, "scoped_http_client", lambda **k: client)
    body = _client().get("/preview", params={"url": "http://vuln-target/big"}, headers=AUTH).json()
    assert body["truncated"] is True
    assert len(body["body"]) == verification.MAX_EVIDENCE_BYTES
    assert body["bytes"] == len(big)
