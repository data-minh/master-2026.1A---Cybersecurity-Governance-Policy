import httpx
from fastapi.testclient import TestClient

from services.gateway.app import main as gateway


def _client(monkeypatch, handler):
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        gateway.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler)),
    )
    return TestClient(gateway.app)


def test_readyz_is_ready_when_scope_auth_is_ready(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(200, json={"status": "ready", "reasons": []})

    response = _client(monkeypatch, handler).get("/readyz")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert seen == ["/readyz"]


def test_readyz_fails_closed_when_scope_auth_not_ready_or_down(monkeypatch):
    not_ready = _client(monkeypatch, lambda r: httpx.Response(503, json={"status": "not_ready"}))
    assert not_ready.get("/readyz").status_code == 503

    def down(request):
        raise httpx.ConnectError("refused", request=request)

    unreachable = _client(monkeypatch, down).get("/readyz")
    assert unreachable.status_code == 503
    assert unreachable.json()["status"] == "not_ready"
    assert "scope-auth" in " ".join(unreachable.json()["reasons"])


def test_readyz_does_not_require_a_token_and_healthz_still_works(monkeypatch):
    client = _client(monkeypatch, lambda r: httpx.Response(200, json={}))
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code in (200, 503)  # never 401
