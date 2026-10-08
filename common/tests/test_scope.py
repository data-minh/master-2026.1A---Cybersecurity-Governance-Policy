import asyncio

import httpx
import pytest

from vts_common import scope as scope_module
from vts_common.scope import (
    OutOfScopeRequest,
    ScopeClient,
    ScopeUnavailable,
    scoped_http_client,
)


class OnlyHost:
    def __init__(self, host):
        self.host = host
        self.asked = []

    async def permits(self, host):
        self.asked.append(host)
        return host == self.host


def test_scoped_client_blocks_redirect_hop_leaving_scope():
    sent = []

    def handler(request):
        sent.append(str(request.url))
        if request.url.host == "vuln-target":
            return httpx.Response(302, headers={"Location": "https://outside.example/"})
        return httpx.Response(200, text="should never be reached")

    async def scenario():
        checker = OnlyHost("vuln-target")
        async with scoped_http_client(
            checker, transport=httpx.MockTransport(handler), follow_redirects=True
        ) as client:
            with pytest.raises(OutOfScopeRequest):
                await client.get("http://vuln-target/")
            # Decisions are cached per host within one client.
            await client.get("http://vuln-target/", follow_redirects=False)
        return checker.asked

    asked = asyncio.run(scenario())
    assert sent == ["http://vuln-target/", "http://vuln-target/"]
    assert asked == ["vuln-target", "outside.example"]


def test_out_of_scope_request_is_an_httpx_error():
    assert issubclass(OutOfScopeRequest, httpx.HTTPError)


def test_scope_client_separates_denial_from_outage(monkeypatch):
    responses = {
        "allowed": httpx.Response(200, json={"allowed": True}),
        "denied": httpx.Response(200, json={"allowed": False}),
        "broken": httpx.Response(503, text="down"),
    }

    def handler(request):
        target = request.url.params["target"]
        if target == "offline":
            raise httpx.ConnectError("refused", request=request)
        return responses[target]

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        scope_module.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler)),
    )

    async def scenario():
        client = ScopeClient("http://scope")
        assert await client.permits("allowed") is True
        assert await client.permits("denied") is False
        for target in ("broken", "offline"):
            with pytest.raises(ScopeUnavailable):
                await client.permits(target)
            assert await client.is_allowed(target) is False

    asyncio.run(scenario())
    assert issubclass(ScopeUnavailable, ConnectionError)
