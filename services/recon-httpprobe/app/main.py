"""HTTP probe and URL harvesting command worker."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import Depends
from pydantic import BaseModel

from vts_common.auth import require_auth
from vts_common.config import settings
from vts_common.events import Event, EventBus, Topics
from vts_common.lifecycle import WorkCommandData, WorkType, validate_work_input
from vts_common.scope import ScopeClient, scoped_http_client
from vts_common.service import make_app
from vts_common.worker import WorkContext, WorkerRunner, WorkResult

RECON_EXTERNAL_SOURCES_ENABLED = settings.RECON_EXTERNAL_SOURCES_ENABLED
TECH_HINTS = {"server": "Server", "x-powered-by": "X-Powered-By"}
LINK_RE = re.compile(r"""(?:href|src)=["']([^"'#]+)["']""", re.I)
EXT_CLASSES = {
    "js": ["js"], "style": ["css"], "doc": ["pdf", "doc", "docx", "xls", "xlsx"],
    "image": ["png", "jpg", "jpeg", "gif", "svg", "webp"],
    "data": ["json", "xml", "yaml", "yml", "csv"], "archive": ["zip", "tar", "gz", "rar"],
}


def _result_id(scan_id, topic, resource):
    return "sha256:" + hashlib.sha256(f"result|{scan_id}|{topic}|{resource.lower()}".encode()).hexdigest()


def classify(url: str) -> str:
    path = urlparse(url).path.lower()
    ext = path.rsplit(".", 1)[-1] if "." in path.rsplit("/", 1)[-1] else ""
    for name, extensions in EXT_CLASSES.items():
        if ext in extensions:
            return name
    return "page"


async def _probe(host: str) -> dict | None:
    for scheme in ("https", "http"):
        try:
            async with scoped_http_client(timeout=8.0, follow_redirects=True, verify=False) as client:
                response = await client.get(f"{scheme}://{host}")
        except httpx.HTTPError:
            continue
        title = ""
        match = re.search(r"<title[^>]*>(.*?)</title>", response.text, re.I | re.S)
        if match:
            title = match.group(1).strip()[:200]
        return {
            "host": host,
            "url": str(response.url),
            "scheme": scheme,
            "status": response.status_code,
            "title": title,
            "tech": {label: response.headers[key] for key, label in TECH_HINTS.items() if key in response.headers},
            "final_url": str(response.url),
        }
    return None


async def _wayback(host: str) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get("http://web.archive.org/cdx/search/cdx", params={"url": f"{host}/*", "output": "json", "fl": "original", "collapse": "urlkey", "limit": "200"})
            if response.status_code == 200:
                rows = response.json()
                return [row[0] for row in rows[1:]] if len(rows) > 1 else []
    except (httpx.HTTPError, ValueError):
        pass
    return []


async def _crawl_links(base_url: str) -> list[str]:
    links = set()
    try:
        async with scoped_http_client(timeout=8.0, follow_redirects=True, verify=False) as client:
            response = await client.get(base_url)
            for raw in LINK_RE.findall(response.text):
                absolute = urljoin(base_url, raw)
                if absolute.startswith("http"):
                    links.add(absolute)
    except httpx.HTTPError:
        pass
    return sorted(links)


async def _scope_filter(scope: ScopeClient):
    """Return a per-work URL predicate that caches one scope decision per host."""
    decisions: dict[str, bool] = {}

    async def in_scope(url: str) -> bool:
        host = urlparse(url).hostname or ""
        if host not in decisions:
            decisions[host] = bool(host) and await scope.permits(host)
        return decisions[host]

    return in_scope


async def handle_http_probe_and_harvest(ctx: WorkContext, command) -> WorkResult:
    command_data = WorkCommandData.model_validate(command.data)
    work_input = validate_work_input(WorkType.RECON_HTTP_PROBE_AND_HARVEST, command_data.input)
    host = work_input.host
    scope = ScopeClient()
    if not await scope.permits(host):
        return WorkResult(0, {"skipped": "out_of_scope"})
    probe = await _probe(host)
    if probe is None:
        return WorkResult(0)
    in_scope = await _scope_filter(scope)
    # The final URL after redirects becomes the base for further work, so it
    # must itself be in scope before anything downstream is fanned out.
    if not await in_scope(probe["url"]):
        return WorkResult(0, {"skipped": "redirected_out_of_scope"})
    await ctx.publish_result(Topics.ENDPOINT_ALIVE, {"result_id": _result_id(command.scan_id, Topics.ENDPOINT_ALIVE, probe["url"]), **probe})
    harvested = set(await _crawl_links(probe["url"]))
    if RECON_EXTERNAL_SOURCES_ENABLED:
        harvested.update(await _wayback(host))
    count = 1
    for url in sorted(harvested):
        if not await in_scope(url):
            continue
        await ctx.publish_result(Topics.URL_COLLECTED, {"result_id": _result_id(command.scan_id, Topics.URL_COLLECTED, url), "url": url, "class": classify(url), "source_host": host})
        count += 1
    return WorkResult(count)


BUS = EventBus()
RUNNER = WorkerRunner("recon-httpprobe", BUS, {WorkType.RECON_HTTP_PROBE_AND_HARVEST: handle_http_probe_and_harvest}, settings.MAX_CONCURRENCY)


async def process_host(host: str, scan_id: str) -> None:
    if not await ScopeClient().is_allowed(host):
        return
    probe = await _probe(host)
    if not probe:
        return
    await BUS.publish(Event(event=Topics.ENDPOINT_ALIVE, scan_id=scan_id, data=probe))
    harvested = set(await _crawl_links(probe["url"]))
    if RECON_EXTERNAL_SOURCES_ENABLED:
        harvested.update(await _wayback(host))
    for url in sorted(harvested):
        await BUS.publish(Event(event=Topics.URL_COLLECTED, scan_id=scan_id, data={"url": url, "class": classify(url), "source_host": host}))


app = make_app(title="VTS Recon - HTTP Probe & URL Harvest", description="Người 1 - A2/A5: probe alive hosts + harvest URLs.", command_runner=RUNNER)


class ProbeReq(BaseModel):
    host: str
    scan_id: str = "manual"


@app.post("/probe", tags=["recon"])
async def probe_endpoint(req: ProbeReq, _claims: dict = Depends(require_auth)):
    await process_host(req.host, req.scan_id)
    return {"status": "processed", "host": req.host}
