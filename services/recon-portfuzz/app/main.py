"""Rate-limited port scan and content fuzz command worker."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress

import httpx
from fastapi import Depends
from pydantic import BaseModel

from vts_common.auth import require_auth
from vts_common.config import settings
from vts_common.events import Event, EventBus, Topics
from vts_common.lifecycle import WorkCommandData, WorkType, validate_work_input
from vts_common.scope import ScopeClient, scoped_http_client
from vts_common.service import make_app
from vts_common.util import host_from_url
from vts_common.worker import WorkContext, WorkerRunner, WorkResult

PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 6379: "redis", 8000: "http-alt",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}
PATH_WORDLIST = ["admin", "login", "robots.txt", ".git/config", ".env", "backup", "config.php", "wp-admin", "api", "api/v1", "health", "status", "server-status", "phpinfo.php", "test", "debug", ".well-known/security.txt", "swagger", "swagger.json", "openapi.json", "actuator"]


def _result_id(scan_id, topic, resource):
    return "sha256:" + hashlib.sha256(f"result|{scan_id}|{topic}|{resource.lower()}".encode()).hexdigest()


async def _scan_port(ip: str, port: int, sem: asyncio.Semaphore) -> int | None:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1.5)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port
        except (asyncio.TimeoutError, OSError):
            return None


async def scan_ports_operation(ip: str) -> list[dict]:
    sem = asyncio.Semaphore(settings.MAX_CONCURRENCY)
    ports = list(PORT_SERVICES)[: settings.TOP_PORTS]
    results = await asyncio.gather(*(_scan_port(ip, port, sem) for port in ports))
    return [{"ip": ip, "port": port, "service": PORT_SERVICES.get(port, "unknown")} for port in results if port]


async def fuzz_content_operation(base_url: str) -> list[dict]:
    base = base_url.rstrip("/")
    sem = asyncio.Semaphore(settings.MAX_CONCURRENCY)

    async def attempt(client, path):
        async with sem:
            url = f"{base}/{path}"
            try:
                response = await client.get(url)
            except httpx.HTTPError:
                return None
            if response.status_code in (200, 201, 204, 301, 302, 401, 403):
                return {"url": url, "path": path, "status": response.status_code, "length": len(response.content)}
            return None

    async with scoped_http_client(timeout=6.0, follow_redirects=False, verify=False) as client:
        records = await asyncio.gather(*(attempt(client, path) for path in PATH_WORDLIST))
    return [record for record in records if record]


async def _ip_permitted(ip: str) -> bool:
    """The resolved IP must be private/loopback (lab network) or itself in scope.

    The hostname scope check alone is not enough: an in-scope name may resolve
    to a third-party public address (CDN, shared hosting).
    """
    address = ipaddress.ip_address(ip)
    if address.is_private or address.is_loopback or address.is_link_local:
        return True
    return await ScopeClient().permits(ip)


async def handle_port_scan(ctx: WorkContext, command) -> WorkResult:
    data = WorkCommandData.model_validate(command.data)
    work_input = validate_work_input(WorkType.RECON_PORT_SCAN, data.input)
    scope_target = data.input.get("scope_host") or work_input.ip
    if not await ScopeClient().permits(scope_target):
        return WorkResult(0, {"skipped": "out_of_scope"})
    if not await _ip_permitted(work_input.ip):
        return WorkResult(0, {"skipped": "ip_not_in_scope"})
    records = await scan_ports_operation(work_input.ip)
    for record in records:
        await ctx.publish_result(Topics.PORT_OPEN, {"result_id": _result_id(command.scan_id, Topics.PORT_OPEN, f"{record['ip']}:{record['port']}"), **record})
    return WorkResult(len(records))


async def handle_content_fuzz(ctx: WorkContext, command) -> WorkResult:
    data = WorkCommandData.model_validate(command.data)
    work_input = validate_work_input(WorkType.RECON_CONTENT_FUZZ, data.input)
    if not await ScopeClient().permits(host_from_url(work_input.base_url)):
        return WorkResult(0, {"skipped": "out_of_scope"})
    records = await fuzz_content_operation(work_input.base_url)
    for record in records:
        await ctx.publish_result(Topics.PATH_FOUND, {"result_id": _result_id(command.scan_id, Topics.PATH_FOUND, record["url"]), **record})
    return WorkResult(len(records))


BUS = EventBus()
RUNNER = WorkerRunner("recon-portfuzz", BUS, {WorkType.RECON_PORT_SCAN: handle_port_scan, WorkType.RECON_CONTENT_FUZZ: handle_content_fuzz}, settings.MAX_CONCURRENCY)


async def scan_ports(ip: str, scan_id: str) -> list[dict]:
    if not await ScopeClient().is_allowed(ip):
        return []
    records = await scan_ports_operation(ip)
    for record in records:
        await BUS.publish(Event(event=Topics.PORT_OPEN, scan_id=scan_id, data=record))
    return records


async def fuzz_content(base_url: str, scan_id: str) -> list[dict]:
    if not await ScopeClient().is_allowed(host_from_url(base_url)):
        return []
    records = await fuzz_content_operation(base_url)
    for record in records:
        await BUS.publish(Event(event=Topics.PATH_FOUND, scan_id=scan_id, data=record))
    return records


app = make_app(title="VTS Recon - Port Scan & Content Fuzz", description="Người 1 - A3/A4: top-N port scan + content fuzzing.", command_runner=RUNNER)


class PortReq(BaseModel):
    ip: str
    scan_id: str = "manual"


class FuzzReq(BaseModel):
    base_url: str
    scan_id: str = "manual"


@app.post("/portscan", tags=["recon"])
async def portscan_endpoint(req: PortReq, _claims: dict = Depends(require_auth)):
    return {"open_ports": await scan_ports(req.ip, req.scan_id)}


@app.post("/fuzz", tags=["recon"])
async def fuzz_endpoint(req: FuzzReq, _claims: dict = Depends(require_auth)):
    return {"found": await fuzz_content(req.base_url, req.scan_id)}
