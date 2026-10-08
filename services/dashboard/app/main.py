"""Authoritative dashboard BFF; lifecycle state remains owned by orchestrator.

Every /dashboard/* route acts as the signed-in user: the JWT issued by
scope-auth is kept in an HttpOnly, SameSite=Strict cookie and forwarded as the
bearer token, so upstream role checks (e.g. the approval gate) apply to the
real user instead of a privileged built-in account.
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Literal
from urllib.parse import quote
from uuid import uuid4

import httpx
from fastapi import Depends, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from vts_common.auth import AuthError, decode_token
from vts_common.config import settings
from vts_common.service import ReadinessCheck, make_app

VERIFICATION_URL = os.getenv("VERIFICATION_URL", "http://verification:8000")
SCAN_SPECIALIZED_URL = os.getenv("SCAN_SPECIALIZED_URL", "http://scan-specialized:8000")
SCOPE_VIEW_ROLES = ("admin", "approver")
ADMIN_ROLES = ("admin",)
ID_PATTERN = re.compile(r"^\d+-\d+$")
SESSION_COOKIE = "vts_session"
CSRF_HEADER = "X-VTS-CSRF"


class Session(BaseModel):
    token: str
    subject: str
    role: str


def current_session(request: Request) -> Session:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Chưa đăng nhập")
    try:
        claims = decode_token(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail="Phiên đăng nhập không hợp lệ") from exc
    return Session(token=token, subject=claims["sub"], role=claims.get("role", ""))


def require_roles(*roles: str):
    """Dependency: the signed-in user must hold one of `roles` (checked again upstream)."""

    def dependency(session: Session = Depends(current_session)) -> Session:
        if session.role not in roles:
            raise HTTPException(status_code=403, detail="Vai trò của bạn không có quyền thực hiện thao tác này")
        return session

    return dependency


def require_csrf(x_vts_csrf: str | None = Header(default=None, alias=CSRF_HEADER)) -> None:
    # A custom header cannot be sent cross-site without a CORS preflight, which
    # this app never approves; together with SameSite=Strict it blocks CSRF.
    if x_vts_csrf != "1":
        raise HTTPException(status_code=403, detail="Thiếu header chống CSRF")


class DashboardBackend:
    def __init__(self):
        self.urls = {
            "orchestrator": settings.ORCHESTRATOR_URL.rstrip("/"),
            "verification": VERIFICATION_URL.rstrip("/"),
            "scope": settings.SCOPE_SERVICE_URL.rstrip("/"),
            "templates": SCAN_SPECIALIZED_URL.rstrip("/"),
        }

    async def login(self, username: str, password: str) -> httpx.Response:
        async with httpx.AsyncClient(timeout=10) as client:
            return await client.post(
                f"{settings.SCOPE_SERVICE_URL}/auth/login",
                json={"username": username, "password": password},
            )

    async def request(self, service: str, method: str, path: str, token: str | None = None, **kwargs):
        headers = dict(kwargs.pop("headers", {}))
        if token:
            headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.request(
                method,
                self.urls[service] + path,
                headers=headers,
                **kwargs,
            )
        return response

    async def stream(self, path: str, last_event_id: str | None, token: str):
        headers = {"Authorization": f"Bearer {token}"}
        if last_event_id:
            headers["Last-Event-ID"] = last_event_id
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream(
                "GET", self.urls["orchestrator"] + path, headers=headers
            ) as response:
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    yield chunk


class LaunchReq(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=2048)
    authorize: bool = False
    mode: Literal["full", "recon", "recon-passive"] = "full"
    exec_mode: Literal["sequential", "parallel"] = "sequential"
    idempotency_key: str | None = None

    @field_validator("idempotency_key")
    @classmethod
    def validate_key(cls, value):
        if value is None:
            return value
        if not 8 <= len(value) <= 128:
            raise ValueError("invalid idempotency key")
        return value


class LoginReq(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class ApprovalActionReq(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="", max_length=500)
    dry_run: bool = True
    idempotency_key: str = Field(min_length=8, max_length=128)


class TemplateReq(BaseModel):
    model_config = ConfigDict(extra="forbid")

    yaml_body: str = Field(min_length=1, max_length=65_536)


class ScopeAddReq(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=253)
    type: Literal["domain", "cidr"] = "domain"
    note: str = Field(default="", max_length=500)
    # An explicit affirmation that the operator is authorized to test this
    # target. Registering scope *is* the authorization record, so it must be a
    # deliberate act, never an implicit side effect.
    authorized: bool = False


def _response(upstream: httpx.Response) -> Response:
    try:
        payload = upstream.json()
        return JSONResponse(payload, status_code=upstream.status_code)
    except ValueError:
        return Response(
            upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "text/plain"),
        )


def create_dashboard_app(backend):
    async def orchestrator_ready():
        try:
            response = await backend.request("orchestrator", "GET", "/readyz")
            if response.status_code == 200:
                return ReadinessCheck("orchestrator", True)
        except Exception:
            pass
        return ReadinessCheck("orchestrator", False, "orchestrator unavailable")

    app = make_app(
        title="VTS Dashboard BFF",
        description="Authoritative lifecycle proxy.",
        readiness_checks=[orchestrator_ready],
    )
    app.state.backend = backend

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError):
        return JSONResponse(
            {
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Dữ liệu yêu cầu không hợp lệ",
                    "details": exc.errors(),
                }
            },
            status_code=422,
        )

    @app.post("/dashboard/login")
    async def login(req: LoginReq):
        upstream = await backend.login(req.username, req.password)
        if upstream.status_code != 200:
            return JSONResponse(
                {"error": {"code": "INVALID_CREDENTIALS", "message": "Sai tên đăng nhập hoặc mật khẩu"}},
                status_code=401,
            )
        body = upstream.json()
        response = JSONResponse({"username": req.username, "role": body.get("role")})
        response.set_cookie(
            SESSION_COOKIE,
            body["access_token"],
            max_age=settings.JWT_TTL_SECONDS,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return response

    @app.post("/dashboard/logout", dependencies=[Depends(require_csrf)])
    async def logout():
        response = JSONResponse({"logged_out": True})
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.get("/dashboard/me")
    async def me(session: Session = Depends(current_session)):
        return {"username": session.subject, "role": session.role}

    @app.get("/dashboard/scans")
    async def scans(request: Request, session: Session = Depends(current_session)):
        response = await backend.request(
            "orchestrator",
            "GET",
            "/scans",
            token=session.token,
            params=dict(request.query_params),
        )
        return _response(response)

    @app.get("/dashboard/scans/{scan_id}")
    async def scan(scan_id: str, session: Session = Depends(current_session)):
        return _response(
            await backend.request("orchestrator", "GET", f"/scans/{scan_id}", token=session.token)
        )

    @app.get("/dashboard/scans/{scan_id}/report")
    async def report(scan_id: str, session: Session = Depends(current_session)):
        return _response(
            await backend.request(
                "orchestrator", "GET", f"/scans/{scan_id}/report", token=session.token
            )
        )

    @app.get("/dashboard/history")
    async def history(request: Request, session: Session = Depends(current_session)):
        return _response(
            await backend.request(
                "orchestrator", "GET", "/history", token=session.token,
                params=dict(request.query_params),
            )
        )

    @app.get("/dashboard/history/{scan_id}")
    async def history_detail(scan_id: str, session: Session = Depends(current_session)):
        return _response(
            await backend.request(
                "orchestrator", "GET", f"/history/{quote(scan_id, safe='')}", token=session.token
            )
        )

    @app.get("/dashboard/scans/{scan_id}/work")
    async def work(scan_id: str, request: Request, session: Session = Depends(current_session)):
        return _response(
            await backend.request(
                "orchestrator",
                "GET",
                f"/scans/{scan_id}/work",
                token=session.token,
                params=dict(request.query_params),
            )
        )

    @app.get("/dashboard/scans/{scan_id}/results")
    async def results(scan_id: str, request: Request, session: Session = Depends(current_session)):
        return _response(
            await backend.request(
                "orchestrator",
                "GET",
                f"/scans/{scan_id}/results",
                token=session.token,
                params=dict(request.query_params),
            )
        )

    @app.get("/dashboard/scans/{scan_id}/stream")
    async def stream(
        scan_id: str,
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
        session: Session = Depends(current_session),
    ):
        if last_event_id and (
            len(last_event_id) > 64 or ID_PATTERN.fullmatch(last_event_id) is None
        ):
            return JSONResponse(
                {"error": {"code": "INVALID_LAST_EVENT_ID", "message": "Last-Event-ID không hợp lệ"}},
                status_code=400,
            )

        async def relay():
            try:
                async for chunk in backend.stream(
                    f"/scans/{scan_id}/stream", last_event_id, session.token
                ):
                    yield chunk
            except asyncio.CancelledError:
                raise
            except Exception:
                yield b"event: error\ndata: {\"error\":\"stream_unavailable\"}\n\n"

        return StreamingResponse(
            relay(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.post("/dashboard/scan", dependencies=[Depends(require_csrf)])
    async def launch(req: LaunchReq, session: Session = Depends(current_session)):
        key = req.idempotency_key or str(uuid4())
        response = await backend.request(
            "orchestrator",
            "POST",
            "/scans",
            token=session.token,
            json={
                "target": req.target,
                "mode": req.mode,
                "exec_mode": req.exec_mode,
            },
            headers={"Idempotency-Key": key},
        )
        return _response(response)

    @app.get("/dashboard/approvals")
    async def approvals(request: Request, session: Session = Depends(current_session)):
        return _response(
            await backend.request(
                "verification",
                "GET",
                "/approvals",
                token=session.token,
                params=dict(request.query_params),
            )
        )

    @app.post("/dashboard/approvals/{approval_id}/{action}", dependencies=[Depends(require_csrf)])
    async def approval_action(
        approval_id: str,
        action: Literal["approve", "reject", "execute"],
        req: ApprovalActionReq,
        session: Session = Depends(current_session),
    ):
        body = (
            {"dry_run": req.dry_run}
            if action == "execute"
            else {"reason": req.reason}
        )
        response = await backend.request(
            "verification",
            "POST",
            f"/approvals/{approval_id}/{action}",
            token=session.token,
            json=body,
            headers={"Idempotency-Key": req.idempotency_key},
        )
        return _response(response)

    @app.get("/dashboard/approvals/{approval_id}/evidence")
    async def evidence(approval_id: str, session: Session = Depends(current_session)):
        response = await backend.request(
            "verification", "GET", f"/approvals/{approval_id}/evidence", token=session.token
        )
        return Response(
            response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type", "text/plain"),
            headers={
                "Content-Disposition": response.headers.get(
                    "content-disposition",
                    f'attachment; filename="evidence_{approval_id}.txt"',
                )
            },
        )

    @app.get("/dashboard/scope")
    async def scope_list(session: Session = Depends(require_roles(*SCOPE_VIEW_ROLES))):
        return _response(
            await backend.request("scope", "GET", "/scope", token=session.token)
        )

    @app.post("/dashboard/scope", status_code=201, dependencies=[Depends(require_csrf)])
    async def scope_add(req: ScopeAddReq, session: Session = Depends(require_roles(*ADMIN_ROLES))):
        if not req.authorized:
            return JSONResponse(
                {"error": {"code": "AUTHORIZATION_REQUIRED",
                           "message": "Cần xác nhận bạn được phép kiểm thử mục tiêu này"}},
                status_code=422,
            )
        # scope-auth enforces the admin role; the dashboard never elevates it.
        return _response(
            await backend.request(
                "scope", "POST", "/scope", token=session.token,
                json={"target": req.target, "type": req.type, "note": req.note},
            )
        )

    @app.delete("/dashboard/scope/{item_id}", dependencies=[Depends(require_csrf)])
    async def scope_delete(item_id: int, session: Session = Depends(require_roles(*ADMIN_ROLES))):
        return _response(
            await backend.request(
                "scope", "DELETE", f"/scope/{item_id}", token=session.token
            )
        )

    @app.get("/dashboard/templates")
    async def templates_list(session: Session = Depends(require_roles(*ADMIN_ROLES))):
        return _response(
            await backend.request("templates", "GET", "/templates", token=session.token)
        )

    @app.post("/dashboard/templates", status_code=201, dependencies=[Depends(require_csrf)])
    async def templates_create(req: TemplateReq, session: Session = Depends(require_roles(*ADMIN_ROLES))):
        return _response(
            await backend.request(
                "templates", "POST", "/templates", token=session.token,
                json={"yaml_body": req.yaml_body},
            )
        )

    @app.post("/dashboard/templates/validate", dependencies=[Depends(require_csrf)])
    async def templates_validate(req: TemplateReq, session: Session = Depends(require_roles(*ADMIN_ROLES))):
        return _response(
            await backend.request(
                "templates", "POST", "/templates/validate", token=session.token,
                json={"yaml_body": req.yaml_body},
            )
        )

    @app.delete("/dashboard/templates/{template_id}", dependencies=[Depends(require_csrf)])
    async def templates_delete(template_id: str, session: Session = Depends(require_roles(*ADMIN_ROLES))):
        return _response(
            await backend.request(
                "templates", "DELETE", f"/templates/{quote(template_id, safe='')}", token=session.token
            )
        )

    @app.get("/dashboard/preview")
    async def preview(url: str, session: Session = Depends(current_session)):
        # Read-only GET of an in-scope resource. The verification service
        # scope-checks the host (and every redirect hop) before fetching, so an
        # out-of-scope URL is refused there, never fetched.
        return _response(
            await backend.request(
                "verification", "GET", "/preview", token=session.token,
                params={"url": url},
            )
        )

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return INDEX_HTML

    return app


INDEX_HTML = (Path(__file__).with_name("index.html")).read_text(encoding="utf-8")


app = create_dashboard_app(DashboardBackend())
