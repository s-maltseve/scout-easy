from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
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

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title=settings.app_name, version=__version__, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class DisconnectRequest(BaseModel):
    tty: str = Field(min_length=3, max_length=32)


class Fail2banRequest(BaseModel):
    jail: str = Field(min_length=1, max_length=64)
    ip: str = Field(min_length=3, max_length=45)


def _action_response(result) -> dict:
    if not result.ok:
        raise HTTPException(status_code=409, detail=result.stderr or result.stdout or "Command failed")
    return {"ok": True, "output": result.stdout}


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/dashboard")
def dashboard(actor: str = Depends(require_auth)) -> dict:
    system = collect_system()
    sessions = collect_sessions()
    auth_events = collect_auth_events(settings.max_events)
    fail2ban = collect_fail2ban()
    network = collect_connections(settings.max_connections)
    processes = collect_processes()
    traffic = collect_traffic()

    failed = sum(1 for event in auth_events if event["type"] == "failure")
    succeeded = sum(1 for event in auth_events if event["type"] == "success")
    banned = sum(jail.get("currently_banned", 0) for jail in fail2ban.get("jails", []))

    warnings: list[dict] = []
    if network.get("summary", {}).get("total", 0) > settings.max_connections:
        warnings.append({"level": "warning", "title": "Много сетевых соединений", "message": f"Обнаружено более {settings.max_connections} соединений."})
    if processes["suspicious"]:
        warnings.append({"level": "critical", "title": "Подозрительный процесс", "message": f"Обнаружено процессов для проверки: {len(processes['suspicious'])}."})
    if not fail2ban.get("running"):
        warnings.append({"level": "info", "title": "Fail2ban неактивен", "message": fail2ban.get("error") or "Fail2ban не запущен."})
    if settings.actions_enabled:
        warnings.append({"level": "warning", "title": "Управляющие действия включены", "message": "Панель может завершать SSH-сессии и управлять банами Fail2ban."})

    return {
        "meta": {
            "name": settings.app_name,
            "version": __version__,
            "refresh_seconds": settings.refresh_seconds,
            "read_only": not settings.actions_enabled,
            "actions_enabled": settings.actions_enabled,
            "action_token": settings.action_token if settings.actions_enabled else "",
            "actor": actor,
        },
        "overview": {
            "ssh_sessions": len(sessions),
            "auth_failures": failed,
            "auth_successes": succeeded,
            "banned_ips": banned,
            "network_connections": network.get("summary", {}).get("total", 0),
        },
        "warnings": warnings,
        "system": system,
        "ssh": {"sessions": sessions, "events": auth_events},
        "fail2ban": fail2ban,
        "network": network,
        "traffic": traffic,
        "processes": processes,
    }


@app.post("/api/actions/ssh/disconnect")
def api_disconnect(
    payload: DisconnectRequest,
    actor: str = Depends(require_auth),
    _: None = Depends(require_action_token),
) -> dict:
    try:
        return _action_response(disconnect_ssh_session(payload.tty, actor))
    except ActionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/actions/fail2ban/ban")
def api_ban(
    payload: Fail2banRequest,
    actor: str = Depends(require_auth),
    _: None = Depends(require_action_token),
) -> dict:
    try:
        return _action_response(ban_ip(payload.jail, payload.ip, actor))
    except ActionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/actions/fail2ban/unban")
def api_unban(
    payload: Fail2banRequest,
    actor: str = Depends(require_auth),
    _: None = Depends(require_action_token),
) -> dict:
    try:
        return _action_response(unban_ip(payload.jail, payload.ip, actor))
    except ActionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/")
def index(_: str = Depends(require_auth)) -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
