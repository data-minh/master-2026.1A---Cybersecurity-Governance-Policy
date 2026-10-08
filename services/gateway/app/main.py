"""API Gateway (Người 3 - D1: "định tuyến request qua gateway").

A single front door for the whole system. It:
  * routes `/<service>/<path>` to the matching upstream service, and
  * enforces JWT auth centrally (one place instead of per-service), so the
    backend services can stay on the internal network.

Public (no token) routes:
  * POST /scope-auth/auth/login     - obtain a token
  * GET  /scope-auth/scope/check    - the internal safety probe services call
  * GET  /healthz                   - gateway health

Everything else requires a valid `Authorization: Bearer <jwt>`; the header is
forwarded unchanged so upstreams can still apply their own role checks
(defense in depth, e.g. the verification approval gate).

Example:
    curl -s localhost:8000/scope-auth/auth/login -d '{...}'      # login
    curl -s localhost:8000/orchestrator/scans -H "Authorization: Bearer <t>"
"""
from __future__ import annotations

import os

import httpx
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse

from vts_common.auth import decode_token, AuthError

# Logical service name -> upstream base URL (in-cluster DNS names).
ROUTES: dict[str, str] = {
    "scope-auth": os.getenv("SCOPE_SERVICE_URL", "http://scope-auth:8000"),
    "orchestrator": os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8000"),
    "dashboard": os.getenv("DASHBOARD_URL", "http://dashboard:8000"),
    "verification": os.getenv("VERIFICATION_URL", "http://verification:8000"),
    "scan-engine": os.getenv("SCAN_ENGINE_URL", "http://scan-engine:8000"),
    "scan-specialized": os.getenv("SCAN_SPECIALIZED_URL", "http://scan-specialized:8000"),
    "recon-subdomain": os.getenv("RECON_SUBDOMAIN_URL", "http://recon-subdomain:8000"),
    "recon-httpprobe": os.getenv("RECON_HTTPPROBE_URL", "http://recon-httpprobe:8000"),
    "recon-portfuzz": os.getenv("RECON_PORTFUZZ_URL", "http://recon-portfuzz:8000"),
}

# (service, path) pairs reachable without a token.
PUBLIC = {
    ("scope-auth", "auth/login"),
    ("scope-auth", "scope/check"),
}

# Hop-by-hop headers we must not forward.
_STRIP = {"host", "content-length", "connection", "keep-alive",
          "transfer-encoding", "upgrade"}

app = FastAPI(title="VTS API Gateway",
              description="Người 3 - D1: central routing + JWT enforcement.")


@app.get("/healthz", tags=["meta"])
async def healthz():
    return {"status": "ok", "service": "gateway", "routes": sorted(ROUTES)}


@app.get("/readyz", tags=["meta"])
async def readyz():
    """Ready only when scope-auth (login + scope-check) answers /readyz with 200."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{ROUTES['scope-auth']}/readyz")
        ready = resp.status_code == 200
    except httpx.HTTPError:
        ready = False
    if not ready:
        return JSONResponse(
            {"status": "not_ready", "reasons": ["scope-auth unavailable"]},
            status_code=503,
        )
    return {"status": "ready", "reasons": []}


def _authorize(service: str, path: str, request: Request) -> None:
    if (service, path) in PUBLIC:
        return
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    try:
        decode_token(auth.split(" ", 1)[1].strip())
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")


@app.api_route("/{service}/{path:path}",
               methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
               tags=["gateway"])
async def proxy(service: str, path: str, request: Request):
    upstream = ROUTES.get(service)
    if not upstream:
        raise HTTPException(status_code=404, detail=f"unknown service '{service}'")
    _authorize(service, path, request)

    url = f"{upstream}/{path}"
    fwd_headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in _STRIP}
    body = await request.body()
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.request(
                request.method, url, params=request.query_params,
                headers=fwd_headers, content=body,
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"upstream error: {exc}")

    out_headers = {k: v for k, v in resp.headers.items()
                   if k.lower() not in _STRIP}
    return Response(content=resp.content, status_code=resp.status_code,
                    headers=out_headers,
                    media_type=resp.headers.get("content-type"))
