"""Subdomain discovery and OSINT command worker."""

from __future__ import annotations

import asyncio
import hashlib
import re
import socket

import httpx
from fastapi import Depends, HTTPException
from pydantic import BaseModel

from vts_common.auth import require_auth
from vts_common.config import settings
from vts_common.events import Event, EventBus, Topics
from vts_common.lifecycle import WorkCommandData, WorkType, validate_work_input
from vts_common.scope import ScopeClient, ScopeDenied, scoped_http_client
from vts_common.service import make_app
from vts_common.worker import WorkContext, WorkerRunner, WorkResult

RECON_EXTERNAL_SOURCES_ENABLED = settings.RECON_EXTERNAL_SOURCES_ENABLED
COMMON_SUBS = [
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "portal",
    "vpn", "ns1", "ns2", "blog", "shop", "app", "cdn", "static", "secure",
    "beta", "demo", "gateway", "git", "docs",
]


def _result_id(scan_id: str, topic: str, resource: str) -> str:
    raw = f"result|{scan_id}|{topic}|{resource.lower()}".encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


async def _resolve(host: str) -> list[str]:
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return sorted({item[4][0] for item in infos})
    except (socket.gaierror, OSError):
        return []


async def _crtsh(domain: str) -> set[str]:
    out: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}
            )
            if response.status_code == 200:
                for row in response.json():
                    for name in str(row.get("name_value", "")).splitlines():
                        name = name.strip().lstrip("*.").lower()
                        if name.endswith(domain):
                            out.add(name)
    except (httpx.HTTPError, ValueError):
        pass
    return out


async def _osint(domain: str) -> dict:
    emails: set[str] = set()
    title = ""
    try:
        async with scoped_http_client(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(f"http://{domain}")
            emails = set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", response.text))
            match = re.search(r"<title[^>]*>(.*?)</title>", response.text, re.I | re.S)
            if match:
                title = match.group(1).strip()[:200]
    except httpx.HTTPError:
        pass
    return {"domain": domain, "emails": sorted(emails), "title": title}


async def handle_recon_bootstrap(
    ctx: WorkContext, command
) -> WorkResult:
    command_data = WorkCommandData.model_validate(command.data)
    work_input = validate_work_input(WorkType.RECON_BOOTSTRAP, command_data.input)
    target = work_input.target
    scope = ScopeClient()
    try:
        await scope.check(target)
    except ScopeDenied as exc:
        raise ValueError("scope denied") from exc

    candidates = {target, *(f"{name}.{target}" for name in COMMON_SUBS)}
    if RECON_EXTERNAL_SOURCES_ENABLED:
        candidates.update(await _crtsh(target))
    found_count = 0
    sem = asyncio.Semaphore(settings.MAX_CONCURRENCY)

    async def check(host: str):
        nonlocal found_count
        async with sem:
            if not await scope.permits(host):
                return
            ips = await _resolve(host)
            if not ips:
                return
            await ctx.publish_result(
                Topics.SUBDOMAIN_DISCOVERED,
                {
                    "result_id": _result_id(command.scan_id, Topics.SUBDOMAIN_DISCOVERED, host),
                    "subdomain": host,
                    "host": host,
                    "ip": ips[0],
                    "ips": ips,
                    "root": target,
                },
            )
            found_count += 1

    await asyncio.gather(*(check(candidate) for candidate in sorted(candidates)))
    osint = await _osint(target)
    await ctx.publish_result(
        Topics.OSINT_COLLECTED,
        {
            "result_id": _result_id(command.scan_id, Topics.OSINT_COLLECTED, target),
            **osint,
        },
    )
    return WorkResult(found_count + 1)


BUS = EventBus()
RUNNER = WorkerRunner(
    "recon-subdomain",
    BUS,
    {WorkType.RECON_BOOTSTRAP: handle_recon_bootstrap},
    settings.MAX_CONCURRENCY,
)


async def discover(target: str, scan_id: str, token: str | None = None) -> dict:
    scope = ScopeClient(token=token)
    try:
        await scope.check(target)
    except ScopeDenied as exc:
        raise HTTPException(status_code=403, detail=f"out of scope: {exc}")
    candidates = {target, *(f"{name}.{target}" for name in COMMON_SUBS)}
    if RECON_EXTERNAL_SOURCES_ENABLED:
        candidates.update(await _crtsh(target))
    found = {}
    for host in sorted(candidates):
        if await scope.is_allowed(host):
            ips = await _resolve(host)
            if ips:
                found[host] = ips
                await BUS.publish(Event(event=Topics.SUBDOMAIN_DISCOVERED, scan_id=scan_id, data={"subdomain": host, "ips": ips, "root": target}))
    osint = await _osint(target)
    await BUS.publish(Event(event=Topics.OSINT_COLLECTED, scan_id=scan_id, data=osint))
    return {"target": target, "scan_id": scan_id, "subdomains": found, "osint": osint}


app = make_app(
    title="VTS Recon - Subdomain & OSINT",
    description="Người 1 - A1/A6: subdomain discovery + OSINT.",
    command_runner=RUNNER,
)


class DiscoverReq(BaseModel):
    target: str
    scan_id: str = "manual"


@app.post("/discover", tags=["recon"])
async def discover_endpoint(req: DiscoverReq, _claims: dict = Depends(require_auth)):
    return await discover(req.target, req.scan_id)
