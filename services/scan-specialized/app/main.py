"""Awaited specialized scan command worker and template management API."""

from __future__ import annotations

import asyncio
import hashlib
import os
import sys
import uuid
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx
import redis.asyncio as redis_async
import yaml
from fastapi import Depends, HTTPException
from pydantic import BaseModel

from vts_common.auth import require_auth, require_role
from vts_common.config import settings
from vts_common.events import Event, EventBus, Topics
from vts_common.execmode import ScanExecutor
from vts_common.lifecycle import WorkCommandData, WorkType, validate_work_input
from vts_common.scope import ScopeClient, scoped_http_client
from vts_common.service import make_app
from vts_common.util import host_from_url
from vts_common.worker import WorkContext, WorkerRunner, WorkResult

_SEM = asyncio.Semaphore(settings.MAX_CONCURRENCY)
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scan-engine", "app"))
try:
    from engine import validate_template  # type: ignore
except ImportError:
    def validate_template(template):
        return [] if isinstance(template, dict) and template.get("id") else ["missing 'id'"]

XSS_MARKER = "vtsx" + uuid.uuid4().hex[:8]
CRLF_PAYLOAD = "%0d%0aVts-Injected: 1"
TEMPLATE_KEY = "vts:templates:user"  # scan-engine reads the same hash
TEMPLATE_ADMIN_ROLES = ("admin",)


class TemplateStore:
    """User templates persisted in Redis so they survive restarts and replicas."""

    def __init__(self, redis) -> None:
        self.redis = redis

    async def save(self, template_id: str, body: str) -> None:
        await self.redis.hset(TEMPLATE_KEY, template_id, body)

    async def delete(self, template_id: str) -> bool:
        return bool(await self.redis.hdel(TEMPLATE_KEY, template_id))

    async def all(self) -> dict[str, str]:
        return await self.redis.hgetall(TEMPLATE_KEY)


TEMPLATE_STORE = TemplateStore(redis_async.from_url(settings.REDIS_URL, decode_responses=True))


def _template_view(template_id: str, body: str) -> dict:
    return {"id": template_id, "yaml": body, "parsed": yaml.safe_load(body)}
EXECUTOR = ScanExecutor()


def _canonical_url(url):
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    return urlunparse((scheme, host, parsed.path or "/", "", urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True))), ""))


def _identity(scan_id, url, template_id):
    finding = "sha256:" + hashlib.sha256(f"finding|{scan_id}|{_canonical_url(url)}|{template_id}|default".encode()).hexdigest()
    result = "sha256:" + hashlib.sha256(f"result|{finding}".encode()).hexdigest()
    return result, finding


async def xss_probe(url: str, scan_id: str, publish_legacy: bool = True) -> list[dict]:
    if not await ScopeClient().is_allowed(host_from_url(url)):
        return []
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query)) or {"q": ""}
    findings = []
    for key in params:
        test = dict(params)
        test[key] = f"<{XSS_MARKER}>"
        new_url = urlunparse(parsed._replace(query=urlencode(test)))
        try:
            async with _SEM:
                async with scoped_http_client(timeout=8.0, verify=False, follow_redirects=True) as client:
                    response = await client.get(new_url)
        except httpx.HTTPError:
            continue
        if f"<{XSS_MARKER}>" in response.text:
            record = {"url": new_url, "template_id": "specialized-xss-reflected", "name": "Reflected XSS (parameter reflection)", "severity": "high", "param": key, "evidence": {"reflected_marker": XSS_MARKER}}
            findings.append(record)
            if publish_legacy:
                await BUS.publish(Event(event=Topics.VULN_DETECTED, scan_id=scan_id, data=record))
    return findings


async def crlf_probe(url: str, scan_id: str, publish_legacy: bool = True) -> list[dict]:
    if not await ScopeClient().is_allowed(host_from_url(url)):
        return []
    test_url = url.rstrip("/") + "/" + CRLF_PAYLOAD
    try:
        async with _SEM:
            async with scoped_http_client(timeout=8.0, verify=False, follow_redirects=False) as client:
                response = await client.get(test_url)
    except httpx.HTTPError:
        return []
    if "vts-injected" not in {key.lower() for key in response.headers}:
        return []
    record = {"url": test_url, "template_id": "specialized-crlf", "name": "CRLF Header Injection", "severity": "medium", "evidence": {"injected_header": "Vts-Injected"}}
    if publish_legacy:
        await BUS.publish(Event(event=Topics.VULN_DETECTED, scan_id=scan_id, data=record))
    return [record]


async def s3_probe(url: str, scan_id: str, publish_legacy: bool = True) -> list[dict]:
    host = host_from_url(url)
    if not await ScopeClient().is_allowed(host):
        return []
    try:
        async with _SEM:
            async with scoped_http_client(timeout=8.0, verify=False) as client:
                response = await client.get(url)
    except httpx.HTTPError:
        return []
    if "<ListBucketResult" not in response.text or "s3" not in host:
        return []
    record = {"url": url, "template_id": "specialized-s3-public", "name": "Public S3 Bucket Listing", "severity": "high", "evidence": {"body_snippet": response.text[:160]}}
    if publish_legacy:
        await BUS.publish(Event(event=Topics.VULN_DETECTED, scan_id=scan_id, data=record))
    return [record]


async def specialized_scan_operation(url: str) -> list[dict]:
    findings = []
    findings.extend(await xss_probe(url, "", False))
    findings.extend(await crlf_probe(url, "", False))
    if "s3" in url:
        findings.extend(await s3_probe(url, "", False))
    return findings


async def handle_specialized_url(ctx: WorkContext, command) -> WorkResult:
    command_data = WorkCommandData.model_validate(command.data)
    work_input = validate_work_input(WorkType.SCAN_SPECIALIZED_URL, command_data.input)
    if not await ScopeClient().permits(host_from_url(work_input.url)):
        return WorkResult(0, {"skipped": "out_of_scope"})
    findings = await EXECUTOR.run("parallel", lambda: specialized_scan_operation(work_input.url))
    for finding in findings:
        result_id, finding_id = _identity(command.scan_id, finding["url"], finding["template_id"])
        await ctx.publish_result(Topics.VULN_DETECTED, {"result_id": result_id, "finding_id": finding_id, **finding})
    return WorkResult(len(findings))


BUS = EventBus()
RUNNER = WorkerRunner("scan-specialized", BUS, {WorkType.SCAN_SPECIALIZED_URL: handle_specialized_url}, settings.SCAN_MAX_PARALLEL)


app = make_app(title="VTS Specialized Scanners & Template Mgmt", description="Người 2 - B2/B3: specialized scans and template CRUD.", command_runner=RUNNER)


class TemplateReq(BaseModel):
    yaml_body: str


@app.get("/templates", tags=["template-mgmt"])
async def list_templates(_claims: dict = Depends(require_auth)):
    stored = await TEMPLATE_STORE.all()
    return {"items": [_template_view(tid, body) for tid, body in sorted(stored.items())]}


@app.post("/templates", tags=["template-mgmt"], status_code=201)
async def create_template(req: TemplateReq, claims: dict = Depends(require_auth)):
    require_role(claims, TEMPLATE_ADMIN_ROLES)
    try:
        template = yaml.safe_load(req.yaml_body)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"invalid YAML: {exc}")
    errors = validate_template(template)
    if errors:
        raise HTTPException(status_code=422, detail={"validation_errors": errors})
    template_id = template["id"]
    await TEMPLATE_STORE.save(template_id, req.yaml_body)
    await BUS.publish(Event(event=Topics.TEMPLATE_REGISTERED, data={"id": template_id, "template": template}))
    return {"id": template_id, "stored": True}


@app.get("/templates/{tid}", tags=["template-mgmt"])
async def get_template(tid: str, _claims: dict = Depends(require_auth)):
    stored = await TEMPLATE_STORE.all()
    if tid not in stored:
        raise HTTPException(status_code=404, detail="template not found")
    return _template_view(tid, stored[tid])


@app.delete("/templates/{tid}", tags=["template-mgmt"])
async def delete_template(tid: str, claims: dict = Depends(require_auth)):
    require_role(claims, TEMPLATE_ADMIN_ROLES)
    if not await TEMPLATE_STORE.delete(tid):
        raise HTTPException(status_code=404, detail="template not found")
    await BUS.publish(Event(event=Topics.TEMPLATE_DELETED, data={"id": tid}))
    return {"deleted": tid}


@app.post("/templates/validate", tags=["template-mgmt"])
async def validate_only(req: TemplateReq, _claims: dict = Depends(require_auth)):
    try:
        template = yaml.safe_load(req.yaml_body)
    except yaml.YAMLError as exc:
        return {"valid": False, "errors": [f"invalid YAML: {exc}"]}
    errors = validate_template(template)
    return {"valid": not errors, "errors": errors}


class ScanReq(BaseModel):
    url: str
    scan_id: str = "manual"


@app.post("/scan/xss", tags=["specialized"])
async def scan_xss(req: ScanReq, _claims: dict = Depends(require_auth)):
    return {"findings": await xss_probe(req.url, req.scan_id)}


@app.post("/scan/crlf", tags=["specialized"])
async def scan_crlf(req: ScanReq, _claims: dict = Depends(require_auth)):
    return {"findings": await crlf_probe(req.url, req.scan_id)}


@app.post("/scan/s3", tags=["specialized"])
async def scan_s3(req: ScanReq, _claims: dict = Depends(require_auth)):
    return {"findings": await s3_probe(req.url, req.scan_id)}
