from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import __version__
from app.actions import ActionError, ban_ip, disconnect_ssh_session, unban_ip
from app.collectors.fail2ban import collect_fail2ban
from app.collectors.network import collect_connections
from app.collectors.processes import collect_processes
from app.collectors.ssh import collect_auth_events, collect_sessions
from app.collectors.system import collect_system
from app.collectors.traffic import collect_traffic
from app.collectors.users import collect_users
from app.config import settings
from app.security import (
    Session,
    clear_failures,
    client_ip,
    create_session,
    delete_session,
    ip_allowed,
    is_rate_limited,
    record_failure,
    require_session,
    verify_credentials,
)

logger = logging.getLogger("scout-easy")
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title=settings.app_name, version=__version__, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if request.headers.get("x-forwarded-proto") == "https" or request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)
    totp: str = Field(pattern=r"^\d{6}$")


class DisconnectRequest(BaseModel):
    tty: str = Field(pattern=r"^[A-Za-z0-9_./-]{1,32}$")


class Fail2banRequest(BaseModel):
    jail: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    ip: str = Field(min_length=3, max_length=45)


def _safe_section(name: str, collector: Callable[[], Any], fallback: Any) -> tuple[Any, dict[str, str] | None]:
    try:
        return collector(), None
    except Exception as exc:
        logger.exception("collector_failed section=%s", name)
        return fallback, {"section": name, "message": str(exc) or exc.__class__.__name__}


def _csrf(request: Request, session: Session) -> None:
    csrf = request.headers.get("x-csrf-token")
    if not csrf or not __import__("secrets").compare_digest(csrf, session.csrf):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    origin = request.headers.get("origin")
    if origin:
        expected_scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        expected = f"{expected_scheme}://{request.headers.get('host')}"
        if origin != expected:
            raise HTTPException(status_code=403, detail="Invalid origin")


def _action_response(result) -> dict[str, Any]:
    if not result.ok:
        raise HTTPException(status_code=409, detail=result.stderr or result.stdout or "Command failed")
    return {"ok": True, "output": result.stdout}


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request) -> Response:
    ip = client_ip(request)
    if not ip_allowed(ip):
        raise HTTPException(status_code=403, detail="IP is not allowed")
    if is_rate_limited(ip):
        raise HTTPException(status_code=429, detail="Слишком много попыток входа")
    if not verify_credentials(payload.username, payload.password, payload.totp):
        record_failure(ip)
        raise HTTPException(status_code=401, detail="Неверные данные входа или код 2FA")
    clear_failures(ip)
    session_id, session = create_session(payload.username, ip)
    response = JSONResponse({"ok": True, "csrf": session.csrf, "expires_in": settings.session_minutes * 60})
    response.set_cookie(
        "scout_session",
        session_id,
        max_age=settings.session_minutes * 60,
        httponly=True,
        secure=settings.secure_cookie,
        samesite="strict",
        path="/",
    )
    return response


@app.post("/api/auth/logout")
def logout(request: Request, session: Session = Depends(require_session)) -> Response:
    _csrf(request, session)
    delete_session(request.cookies.get("scout_session"))
    response = JSONResponse({"ok": True})
    response.delete_cookie("scout_session", path="/")
    return response


@app.get("/api/auth/session")
def auth_session(session: Session = Depends(require_session)) -> dict[str, Any]:
    return {"authenticated": True, "username": session.username, "csrf": session.csrf, "expires_at": session.expires_at}


@app.get("/api/dashboard")
def dashboard(session: Session = Depends(require_session)) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    system, error = _safe_section("system", collect_system, {})
    if error: errors.append(error)
    sessions, error = _safe_section("ssh_sessions", collect_sessions, [])
    if error: errors.append(error)
    auth_events, error = _safe_section("ssh_events", lambda: collect_auth_events(settings.max_events), [])
    if error: errors.append(error)
    fail2ban, error = _safe_section("fail2ban", collect_fail2ban, {"running": False, "jails": [], "error": "Данные недоступны"})
    if error: errors.append(error)
    network, error = _safe_section("network", lambda: collect_connections(settings.max_connections), {"summary": {"total": 0, "with_traffic": 0}, "connections": [], "process_traffic": []})
    if error: errors.append(error)
    processes, error = _safe_section("processes", collect_processes, {"top": [], "suspicious": []})
    if error: errors.append(error)
    traffic, error = _safe_section("traffic", collect_traffic, {"total": {"bytes_sent": 0, "bytes_recv": 0, "bytes_all": 0}, "current": {"sent_per_second": 0, "recv_per_second": 0, "all_per_second": 0}, "interfaces": []})
    if error: errors.append(error)
    users, error = _safe_section("users", collect_users, {"users": [], "groups": []})
    if error: errors.append(error)

    failed = sum(1 for event in auth_events if event.get("type") == "failure")
    succeeded = sum(1 for event in auth_events if event.get("type") == "success")
    banned = sum(int(jail.get("currently_banned", 0) or 0) for jail in fail2ban.get("jails", []))
    warnings = [{"level": "warning", "title": f"Секция {item['section']} недоступна", "message": item["message"]} for item in errors]
    if not fail2ban.get("running"):
        warnings.append({"level": "info", "title": "Fail2ban неактивен", "message": fail2ban.get("error") or "Fail2ban не запущен."})

    return {
        "meta": {"name": settings.app_name, "version": __version__, "refresh_seconds": settings.refresh_seconds, "actions_enabled": settings.actions_enabled, "actor": session.username, "partial": bool(errors), "two_factor": True},
        "overview": {"ssh_sessions": len(sessions), "auth_failures": failed, "auth_successes": succeeded, "banned_ips": banned, "network_connections": network.get("summary", {}).get("total", 0), "linux_users": len(users.get("users", []))},
        "errors": errors, "warnings": warnings, "system": system,
        "ssh": {"sessions": sessions, "events": auth_events}, "fail2ban": fail2ban,
        "network": network, "traffic": traffic, "processes": processes, "users": users,
    }


@app.post("/api/actions/ssh/disconnect")
def api_disconnect(payload: DisconnectRequest, request: Request, session: Session = Depends(require_session)) -> dict[str, Any]:
    if not settings.actions_enabled: raise HTTPException(status_code=403, detail="Administrative actions are disabled")
    _csrf(request, session)
    try: return _action_response(disconnect_ssh_session(payload.tty, session.username))
    except ActionError as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/actions/fail2ban/ban")
def api_ban(payload: Fail2banRequest, request: Request, session: Session = Depends(require_session)) -> dict[str, Any]:
    if not settings.actions_enabled: raise HTTPException(status_code=403, detail="Administrative actions are disabled")
    _csrf(request, session)
    try: return _action_response(ban_ip(payload.jail, payload.ip, session.username))
    except ActionError as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/actions/fail2ban/unban")
def api_unban(payload: Fail2banRequest, request: Request, session: Session = Depends(require_session)) -> dict[str, Any]:
    if not settings.actions_enabled: raise HTTPException(status_code=403, detail="Administrative actions are disabled")
    _csrf(request, session)
    try: return _action_response(unban_ip(payload.jail, payload.ip, session.username))
    except ActionError as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/login")
def login_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/")
def index(request: Request) -> Response:
    try:
        require_session(request, request.cookies.get("scout_session"))
    except HTTPException:
        return RedirectResponse("/login", status_code=302)
    return FileResponse(STATIC_DIR / "index.html")
