from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
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
from app.config import settings
from app.security import require_action_token, require_auth

logger = logging.getLogger("scout-easy")
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title=settings.app_name, version=__version__, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def no_cache_dynamic_responses(request, call_next):
    response: Response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/api/") or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return response


class DisconnectRequest(BaseModel):
    tty: str = Field(min_length=3, max_length=32)


class Fail2banRequest(BaseModel):
    jail: str = Field(min_length=1, max_length=64)
    ip: str = Field(min_length=3, max_length=45)


def _action_response(result) -> dict[str, Any]:
    if not result.ok:
        raise HTTPException(status_code=409, detail=result.stderr or result.stdout or "Command failed")
    return {"ok": True, "output": result.stdout}


def _safe_section(name: str, collector: Callable[[], Any], fallback: Any) -> tuple[Any, dict[str, str] | None]:
    try:
        return collector(), None
    except Exception as exc:  # a broken collector must not break the whole dashboard
        logger.exception("collector_failed section=%s", name)
        return fallback, {"section": name, "message": str(exc) or exc.__class__.__name__}


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/api/dashboard")
def dashboard(actor: str = Depends(require_auth)) -> dict[str, Any]:
    errors: list[dict[str, str]] = []

    system, error = _safe_section("system", collect_system, {})
    if error:
        errors.append(error)
    sessions, error = _safe_section("ssh_sessions", collect_sessions, [])
    if error:
        errors.append(error)
    auth_events, error = _safe_section("ssh_events", lambda: collect_auth_events(settings.max_events), [])
    if error:
        errors.append(error)
    fail2ban, error = _safe_section("fail2ban", collect_fail2ban, {"running": False, "jails": [], "error": "Данные недоступны"})
    if error:
        errors.append(error)
    network, error = _safe_section("network", lambda: collect_connections(settings.max_connections), {"summary": {"total": 0, "with_traffic": 0}, "connections": [], "process_traffic": []})
    if error:
        errors.append(error)
    processes, error = _safe_section("processes", collect_processes, {"top": [], "suspicious": []})
    if error:
        errors.append(error)
    traffic, error = _safe_section(
        "traffic",
        collect_traffic,
        {
            "total": {"bytes_sent": 0, "bytes_recv": 0, "bytes_all": 0},
            "current": {"sent_per_second": 0, "recv_per_second": 0, "all_per_second": 0},
            "interfaces": [],
        },
    )
    if error:
        errors.append(error)

    failed = sum(1 for event in auth_events if event.get("type") == "failure")
    succeeded = sum(1 for event in auth_events if event.get("type") == "success")
    banned = sum(int(jail.get("currently_banned", 0) or 0) for jail in fail2ban.get("jails", []))

    warnings: list[dict[str, str]] = []
    for item in errors:
        warnings.append({
            "level": "warning",
            "title": f"Секция {item['section']} недоступна",
            "message": item["message"],
        })
    if network.get("summary", {}).get("total", 0) >= settings.max_connections:
        warnings.append({"level": "warning", "title": "Много сетевых соединений", "message": f"Обнаружено не менее {settings.max_connections} соединений."})
    if processes.get("suspicious"):
        warnings.append({"level": "critical", "title": "Подозрительный процесс", "message": f"Обнаружено процессов для проверки: {len(processes['suspicious'])}."})
    if not fail2ban.get("running"):
        warnings.append({"level": "info", "title": "Fail2ban неактивен", "message": fail2ban.get("error") or "Fail2ban не запущен."})
    if settings.actions_enabled:
        warnings.append({"level": "warning", "title": "Управляющие действия включены", "message": "Для выполнения действий требуется отдельный токен, который не передаётся в dashboard API."})

    return {
        "meta": {
            "name": settings.app_name,
            "version": __version__,
            "refresh_seconds": settings.refresh_seconds,
            "read_only": not settings.actions_enabled,
            "actions_enabled": settings.actions_enabled,
            "actor": actor,
            "partial": bool(errors),
        },
        "overview": {
            "ssh_sessions": len(sessions),
            "auth_failures": failed,
            "auth_successes": succeeded,
            "banned_ips": banned,
            "network_connections": network.get("summary", {}).get("total", 0),
        },
        "errors": errors,
        "warnings": warnings,
        "system": system,
        "ssh": {"sessions": sessions, "events": auth_events},
        "fail2ban": fail2ban,
        "network": network,
        "traffic": traffic,
        "processes": processes,
    }


@app.post("/api/actions/ssh/disconnect")
def api_disconnect(payload: DisconnectRequest, actor: str = Depends(require_auth), _: None = Depends(require_action_token)) -> dict[str, Any]:
    try:
        return _action_response(disconnect_ssh_session(payload.tty, actor))
    except ActionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/actions/fail2ban/ban")
def api_ban(payload: Fail2banRequest, actor: str = Depends(require_auth), _: None = Depends(require_action_token)) -> dict[str, Any]:
    try:
        return _action_response(ban_ip(payload.jail, payload.ip, actor))
    except ActionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/actions/fail2ban/unban")
def api_unban(payload: Fail2banRequest, actor: str = Depends(require_auth), _: None = Depends(require_action_token)) -> dict[str, Any]:
    try:
        return _action_response(unban_ip(payload.jail, payload.ip, actor))
    except ActionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/")
def index(_: str = Depends(require_auth)) -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
