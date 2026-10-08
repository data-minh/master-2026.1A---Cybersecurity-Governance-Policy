"""Awaited YAML-template scan command worker."""

from __future__ import annotations

import asyncio
import glob
import hashlib
import os
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
import redis.asyncio as redis_async
import yaml
from fastapi import Depends, HTTPException
from pydantic import BaseModel

from vts_common.auth import require_auth
from vts_common.config import settings
from vts_common.events import Event, EventBus, Topics
from vts_common.execmode import ScanExecutor
from vts_common.lifecycle import WorkCommandData, WorkType, validate_work_input
from vts_common.scope import ScopeClient, scoped_http_client
from vts_common.service import make_app
from vts_common.util import host_from_url
from vts_common.worker import WorkContext, WorkerRunner, WorkResult

from .engine import SAFE_METHODS, HttpResponse, evaluate_request, validate_template

TEMPLATE_DIR = os.getenv("TEMPLATE_DIR", "/app/templates")
TEMPLATES: dict[str, dict] = {}
EXECUTOR = ScanExecutor()


def _canonical_url(value: str) -> str:
    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    return urlunsplit((scheme, host, parsed.path or "/", urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True))), ""))


def finding_identity(scan_id: str, url: str, template_id: str, variant: str) -> str:
    raw = f"finding|{scan_id}|{_canonical_url(url)}|{template_id}|{variant}".encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


USER_TEMPLATE_KEY = "vts:templates:user"  # written by scan-specialized (admin only)
USER_TEMPLATE_SYNC_SECONDS = 5
_USER_TEMPLATE_IDS: set[str] = set()


def reconcile_user_templates(stored: dict[str, str]) -> None:
    """Make the user-supplied templates in TEMPLATES match the persisted set.

    Built-in file templates are never touched; invalid stored templates are ignored.
    """
    wanted: dict[str, dict] = {}
    for template_id, body in stored.items():
        try:
            template = yaml.safe_load(body)
        except yaml.YAMLError:
            continue
        if isinstance(template, dict) and template.get("id") == template_id and not validate_template(template):
            wanted[template_id] = template
    for template_id in list(_USER_TEMPLATE_IDS - set(wanted)):
        TEMPLATES.pop(template_id, None)
        _USER_TEMPLATE_IDS.discard(template_id)
    for template_id, template in wanted.items():
        TEMPLATES[template_id] = template
        _USER_TEMPLATE_IDS.add(template_id)


_template_redis = redis_async.from_url(settings.REDIS_URL, decode_responses=True)


async def _sync_user_templates() -> None:
    while True:
        try:
            reconcile_user_templates(await _template_redis.hgetall(USER_TEMPLATE_KEY))
        except Exception as exc:  # Redis hiccup: keep current templates, retry
            print(f"[scan-engine] user template sync failed: {type(exc).__name__}", flush=True)
        await asyncio.sleep(USER_TEMPLATE_SYNC_SECONDS)


def _upsert_template(tpl: dict, source: str) -> bool:
    errors = validate_template(tpl)
    if errors:
        print(f"[scan-engine] reject template from {source}: {errors}", flush=True)
        return False
    TEMPLATES[tpl["id"]] = tpl
    return True


def load_templates() -> int:
    TEMPLATES.clear()
    for path in sorted(glob.glob(os.path.join(TEMPLATE_DIR, "*.y*ml"))):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                template = yaml.safe_load(handle)
            _upsert_template(template, os.path.basename(path))
        except (yaml.YAMLError, OSError) as exc:
            print(f"[scan-engine] failed to load {path}: {exc}", flush=True)
    return len(TEMPLATES)


def _render_path(path_template: str, base_url: str) -> str:
    return path_template.replace("{{BaseURL}}", base_url.rstrip("/")).replace("{{RootURL}}", base_url.rstrip("/"))


async def _do_request(client: httpx.AsyncClient, method: str, url: str, headers: dict) -> HttpResponse | None:
    try:
        response = await client.request(method, url, headers=headers)
    except httpx.HTTPError:
        return None
    return HttpResponse(status=response.status_code, body=response.text, headers=dict(response.headers))


async def template_scan_operation(base_url: str) -> list[dict]:
    detected = []
    async with scoped_http_client(timeout=8.0, follow_redirects=True, verify=False) as client:
        for template in list(TEMPLATES.values()):
            for request in template.get("requests") or template.get("http") or []:
                method = request.get("method", "GET").upper()
                if method not in SAFE_METHODS:
                    continue
                headers = request.get("headers", {}) or {}
                for raw_path in request.get("path", ["{{BaseURL}}"]):
                    url = _render_path(raw_path, base_url)
                    response = await _do_request(client, method, url, headers)
                    if response is None:
                        continue
                    result = evaluate_request(template, request, response)
                    if result.matched:
                        detected.append({"url": url, "template_id": result.template_id, "name": result.name, "severity": result.severity, "extracted": result.extracted, "evidence": result.evidence})
    return detected


async def handle_template_url(ctx: WorkContext, command) -> WorkResult:
    command_data = WorkCommandData.model_validate(command.data)
    work_input = validate_work_input(WorkType.SCAN_TEMPLATE_URL, command_data.input)
    if not await ScopeClient().permits(host_from_url(work_input.url)):
        return WorkResult(0, {"skipped": "out_of_scope"})
    findings = await EXECUTOR.run("parallel", lambda: template_scan_operation(work_input.url))
    for finding in findings:
        finding_id = finding_identity(command.scan_id, finding["url"], finding["template_id"], work_input.variant or "default")
        result_id = "sha256:" + hashlib.sha256(f"result|{finding_id}".encode()).hexdigest()
        await ctx.publish_result(Topics.VULN_DETECTED, {"result_id": result_id, "finding_id": finding_id, **finding})
    return WorkResult(len(findings))


BUS = EventBus()
RUNNER = WorkerRunner("scan-engine", BUS, {WorkType.SCAN_TEMPLATE_URL: handle_template_url}, settings.SCAN_MAX_PARALLEL)


async def scan_url(base_url: str, scan_id: str) -> list[dict]:
    if not await ScopeClient().is_allowed(host_from_url(base_url)):
        return []
    findings = await template_scan_operation(base_url)
    for finding in findings:
        await BUS.publish(Event(event=Topics.VULN_DETECTED, scan_id=scan_id, data=finding))
    return findings


async def _on_template_event(evt) -> None:
    """Keep the in-memory template set in sync with scan-specialized CRUD."""
    if evt.event == Topics.TEMPLATE_REGISTERED:
        template = evt.data.get("template")
        if isinstance(template, dict):
            _upsert_template(template, "event:scan-specialized")
    elif evt.event == Topics.TEMPLATE_DELETED:
        TEMPLATES.pop(evt.data.get("id"), None)


app = make_app(title="VTS Scan Engine (YAML Template Engine)", description="Người 2 - B1: self-written YAML template engine.", consumer=([Topics.TEMPLATE_REGISTERED, Topics.TEMPLATE_DELETED], _on_template_event), command_runner=RUNNER, workers=[_sync_user_templates])
load_templates()


class ScanReq(BaseModel):
    url: str
    scan_id: str = "manual"


@app.get("/templates", tags=["engine"])
async def list_loaded_templates():
    return {"count": len(TEMPLATES), "templates": [{"id": value.get("id"), "severity": value.get("info", {}).get("severity")} for value in TEMPLATES.values()]}


@app.post("/templates/reload", tags=["engine"])
async def reload_templates(_claims: dict = Depends(require_auth)):
    return {"loaded": load_templates()}


@app.post("/scan", tags=["engine"])
async def scan_endpoint(req: ScanReq, _claims: dict = Depends(require_auth)):
    if not TEMPLATES:
        raise HTTPException(status_code=400, detail="no templates loaded")
    return {"detected": await scan_url(req.url, req.scan_id)}
