from __future__ import annotations

import logging
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import __version__
from app.actions import ActionError, ban_ip, disconnect_ssh_session, unban_ip, service_action
from app.collectors.fail2ban import collect_fail2ban
from app.collectors.network import collect_connections
from app.collectors.processes import collect_processes
from app.collectors.ssh import collect_auth_events, collect_sessions
from app.collectors.system import collect_system
from app.collectors.traffic import collect_traffic
from app.collectors.users import collect_users
from app.collectors.services import collect_services
from app.alerts_engine import evaluate as evaluate_alerts
from app.storage import init_db, add_traffic, traffic_history, audit, list_audit, list_alerts, resolve_alert, record_auth_activity, activity_heatmap, get_integrations, set_integration
from app.config import settings
from app.security import (
    Session,
    clear_failures,
    client_ip,
    create_session,
    delete_session,
    ip_allowed,
    is_rate_limited,
    blocked_seconds,
    record_failure,
    require_session,
    verify_credentials,
    hash_password,
    verify_password,
    generate_totp_secret,
    provisioning_uri,
    update_password_hash,
    update_totp_secret,
    delete_all_sessions_except,
)

logger = logging.getLogger("scout-easy")
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

PROFILE_DIR = Path(os.getenv("SCOUT_PROFILE_DIR", "/var/lib/scout-easy"))
PROFILE_FILE = PROFILE_DIR / "profile.json"
AVATAR_FILE = PROFILE_DIR / "avatar.png"
ENV_FILE = Path("/etc/scout-easy/scout-easy.env")


def _load_profile() -> dict[str, Any]:
    try:
        return json.loads(PROFILE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"display_name": settings.username}


def _save_profile(data: dict[str, Any]) -> None:
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    PROFILE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(PROFILE_FILE, 0o600)


def _replace_env_value(key: str, value: str) -> None:
    if not re.fullmatch(r"[A-Z0-9_]+", key):
        raise ValueError("invalid key")
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
    replacement = f"{key}='{value.replace(chr(39), '')}'"
    found = False
    output = []
    for line in lines:
        if line.startswith(f"{key}="):
            output.append(replacement); found = True
        else:
            output.append(line)
    if not found: output.append(replacement)
    ENV_FILE.write_text("\n".join(output) + "\n", encoding="utf-8")
    os.chmod(ENV_FILE, 0o600)

init_db()

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




class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=14, max_length=256)
    totp: str = Field(pattern=r"^\d{6}$")


class ProfileRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)


class TotpResetRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    totp: str = Field(pattern=r"^\d{6}$")


class DisconnectRequest(BaseModel):
    tty: str = Field(pattern=r"^[A-Za-z0-9_./-]{1,32}$")


class Fail2banRequest(BaseModel):
    jail: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")
    ip: str = Field(min_length=3, max_length=45)

class ServiceActionRequest(BaseModel):
    unit: str = Field(pattern=r"^[A-Za-z0-9_.@:-]{1,128}\.service$")
    operation: str = Field(pattern=r"^(start|stop|restart|enable|disable)$")

class AlertResolveRequest(BaseModel):
    note: str = Field(default='', max_length=500)

class IntegrationRequest(BaseModel):
    kind: str = Field(pattern=r"^(telegram|smtp|webhook|zabbix|prometheus|syslog)$")
    enabled: bool = False
    config: dict[str, Any] = Field(default_factory=dict)


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
        remaining = blocked_seconds(ip)
        detail = f"IP заблокирован. Повторите через {max(1, remaining // 3600)} ч." if remaining else "Слишком много попыток входа"
        raise HTTPException(status_code=429, detail=detail)
    if not verify_credentials(payload.username, payload.password, payload.totp):
        blocked = record_failure(ip)
        audit(payload.username, ip, "auth.login", result="blocked" if blocked else "failure", details={"blocked_seconds": settings.login_block_seconds if blocked else 0})
        raise HTTPException(status_code=401, detail="Неверные данные входа или код 2FA")
    clear_failures(ip)
    audit(payload.username, ip, "auth.login", result="success")
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
    audit(session.username, client_ip(request), "auth.logout")
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
    services, error = _safe_section("services", collect_services, {"services": []})
    if error: errors.append(error)

    failed = sum(1 for event in auth_events if event.get("type") == "failure")
    succeeded = sum(1 for event in auth_events if event.get("type") == "success")
    banned = sum(int(jail.get("currently_banned", 0) or 0) for jail in fail2ban.get("jails", []))
    record_auth_activity(succeeded, failed)
    add_traffic(float(traffic.get("current", {}).get("recv_per_second", 0) or 0), float(traffic.get("current", {}).get("sent_per_second", 0) or 0), int(network.get("summary", {}).get("total", 0) or 0))
    warnings = [{"level": "warning", "title": f"Секция {item['section']} недоступна", "message": item["message"]} for item in errors]
    if not fail2ban.get("running"):
        warnings.append({"level": "info", "title": "Fail2ban неактивен", "message": fail2ban.get("error") or "Fail2ban не запущен."})

    payload = {
        "meta": {"name": settings.app_name, "version": __version__, "refresh_seconds": settings.refresh_seconds, "actions_enabled": settings.actions_enabled, "actor": session.username, "partial": bool(errors), "two_factor": True},
        "overview": {"ssh_sessions": len(sessions), "auth_failures": failed, "auth_successes": succeeded, "banned_ips": banned, "network_connections": network.get("summary", {}).get("total", 0), "linux_users": len(users.get("users", []))},
        "errors": errors, "warnings": warnings, "system": system,
        "ssh": {"sessions": sessions, "events": auth_events}, "fail2ban": fail2ban,
        "network": network, "traffic": traffic, "processes": processes, "users": users, "services": services,
    }
    evaluate_alerts(payload)
    payload["alerts_state"] = list_alerts(active_only=True, limit=50)
    return payload


@app.post("/api/actions/ssh/disconnect")
def api_disconnect(payload: DisconnectRequest, request: Request, session: Session = Depends(require_session)) -> dict[str, Any]:
    if not settings.actions_enabled: raise HTTPException(status_code=403, detail="Administrative actions are disabled")
    _csrf(request, session)
    try:
        result=_action_response(disconnect_ssh_session(payload.tty, session.username)); audit(session.username,client_ip(request),"ssh.disconnect",payload.tty); return result
    except ActionError as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/actions/fail2ban/ban")
def api_ban(payload: Fail2banRequest, request: Request, session: Session = Depends(require_session)) -> dict[str, Any]:
    if not settings.actions_enabled: raise HTTPException(status_code=403, detail="Administrative actions are disabled")
    _csrf(request, session)
    try:
        result=_action_response(ban_ip(payload.jail, payload.ip, session.username)); audit(session.username,client_ip(request),"fail2ban.ban",f"{payload.jail}:{payload.ip}"); return result
    except ActionError as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/actions/fail2ban/unban")
def api_unban(payload: Fail2banRequest, request: Request, session: Session = Depends(require_session)) -> dict[str, Any]:
    if not settings.actions_enabled: raise HTTPException(status_code=403, detail="Administrative actions are disabled")
    _csrf(request, session)
    try:
        result=_action_response(unban_ip(payload.jail, payload.ip, session.username)); audit(session.username,client_ip(request),"fail2ban.unban",f"{payload.jail}:{payload.ip}"); return result
    except ActionError as exc: raise HTTPException(status_code=400, detail=str(exc)) from exc



@app.get("/api/history/traffic")
def api_traffic_history(range_seconds: int = 3600, session: Session = Depends(require_session)) -> dict[str, Any]:
    return {"samples": traffic_history(range_seconds)}

@app.get("/api/activity")
def api_activity(days: int = 120, session: Session = Depends(require_session)) -> dict[str, Any]:
    return {"days": activity_heatmap(max(30,min(days,365)))}

@app.get("/api/audit")
def api_audit(limit: int = 300, session: Session = Depends(require_session)) -> dict[str, Any]:
    return {"events": list_audit(limit)}

@app.get("/api/alerts")
def api_alerts(active_only: bool = False, session: Session = Depends(require_session)) -> dict[str, Any]:
    return {"alerts": list_alerts(active_only=active_only)}

@app.post("/api/alerts/{alert_id}/resolve")
def api_resolve_alert(alert_id: int, payload: AlertResolveRequest, request: Request, session: Session = Depends(require_session)) -> dict[str, Any]:
    _csrf(request, session)
    if not resolve_alert(alert_id, session.username, payload.note):
        raise HTTPException(status_code=404, detail="Тревога не найдена")
    audit(session.username,client_ip(request),"alert.resolve",str(alert_id),details={"note":payload.note})
    return {"ok": True}

@app.get("/api/integrations")
def api_integrations(session: Session = Depends(require_session)) -> dict[str, Any]:
    return {"integrations": get_integrations()}

@app.put("/api/integrations")
def api_update_integration(payload: IntegrationRequest, request: Request, session: Session = Depends(require_session)) -> dict[str, Any]:
    _csrf(request, session)
    safe_config={k:v for k,v in payload.config.items() if len(str(k))<80 and len(str(v))<2000}
    set_integration(payload.kind,payload.enabled,safe_config)
    audit(session.username,client_ip(request),"integration.update",payload.kind,details={"enabled":payload.enabled})
    return {"ok":True}

@app.post("/api/actions/services")
def api_service_action(payload: ServiceActionRequest, request: Request, session: Session = Depends(require_session)) -> dict[str, Any]:
    if not settings.actions_enabled: raise HTTPException(status_code=403, detail="Administrative actions are disabled")
    _csrf(request, session)
    try:
        result=_action_response(service_action(payload.unit,payload.operation,session.username))
        audit(session.username,client_ip(request),f"service.{payload.operation}",payload.unit)
        return result
    except ActionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics() -> str:
    alerts=list_alerts(active_only=True,limit=1000)
    by={"critical":0,"high":0,"warning":0,"info":0}
    for item in alerts: by[item.get("severity","info")]=by.get(item.get("severity","info"),0)+1
    latest=traffic_history(900,limit=1)
    sample=latest[-1] if latest else {"rx_bps":0,"tx_bps":0,"connections":0}
    lines=[
      "# HELP scout_alerts_active Active SCOUT-EASY alerts",
      "# TYPE scout_alerts_active gauge",
      f"scout_alerts_active {len(alerts)}",
      *[f'scout_alerts_severity{{severity="{k}"}} {v}' for k,v in by.items()],
      f"scout_network_rx_bytes_per_second {float(sample.get('rx_bps',0) or 0)}",
      f"scout_network_tx_bytes_per_second {float(sample.get('tx_bps',0) or 0)}",
      f"scout_network_connections {int(sample.get('connections',0) or 0)}",
    ]
    return "\n".join(lines)+"\n"

@app.get("/api/v1/servers")
def api_v1_servers(session: Session = Depends(require_session)) -> dict[str,Any]:
    system=collect_system()
    return {"servers":[{"id":"local","name":system.get("hostname","local"),"status":"online","mode":"embedded"}],"agent_enrollment":"planned"}

@app.get("/api/v1/alerts")
def api_v1_alerts(session: Session = Depends(require_session)) -> dict[str,Any]:
    return {"alerts":list_alerts(active_only=False)}


@app.get("/api/profile")
def get_profile(session: Session = Depends(require_session)) -> dict[str, Any]:
    profile = _load_profile()
    return {"username": session.username, "display_name": profile.get("display_name", session.username), "avatar": "/api/profile/avatar", "two_factor": bool(settings.totp_secret), "session_minutes": settings.session_minutes}


@app.put("/api/profile")
def update_profile(payload: ProfileRequest, request: Request, session: Session = Depends(require_session)) -> dict[str, Any]:
    _csrf(request, session)
    profile = _load_profile(); profile["display_name"] = payload.display_name.strip(); _save_profile(profile)
    return {"ok": True}


@app.get("/api/profile/avatar")
def profile_avatar(session: Session = Depends(require_session)) -> Response:
    path = AVATAR_FILE if AVATAR_FILE.exists() else STATIC_DIR / "default-avatar.png"
    return FileResponse(path, media_type="image/png", headers={"Cache-Control": "no-store"})


@app.post("/api/profile/avatar")
async def upload_avatar(request: Request, avatar: UploadFile = File(...), session: Session = Depends(require_session)) -> dict[str, Any]:
    _csrf(request, session)
    if avatar.content_type not in {"image/png", "image/jpeg", "image/webp"}:
        raise HTTPException(status_code=400, detail="Поддерживаются PNG, JPEG и WEBP")
    data = await avatar.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024: raise HTTPException(status_code=400, detail="Файл больше 2 МБ")
    try:
        from PIL import Image
        with Image.open(__import__("io").BytesIO(data)) as image:
            image = image.convert("RGBA"); image.thumbnail((512, 512))
            PROFILE_DIR.mkdir(parents=True, exist_ok=True); image.save(AVATAR_FILE, "PNG")
            os.chmod(AVATAR_FILE, 0o600)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Некорректное изображение") from exc
    return {"ok": True}


@app.post("/api/profile/password")
def change_password(payload: PasswordChangeRequest, request: Request, session: Session = Depends(require_session)) -> dict[str, Any]:
    _csrf(request, session)
    from app.security import verify_totp
    if not verify_password(settings.password_hash, payload.current_password) or not verify_totp(settings.totp_secret, payload.totp):
        raise HTTPException(status_code=401, detail="Текущий пароль или код 2FA неверен")
    if not (re.search(r"[a-z]", payload.new_password) and re.search(r"[A-Z]", payload.new_password) and re.search(r"\d", payload.new_password) and re.search(r"[^A-Za-z0-9]", payload.new_password)):
        raise HTTPException(status_code=400, detail="Пароль должен содержать строчные и прописные буквы, цифру и спецсимвол")
    new_hash = hash_password(payload.new_password); _replace_env_value("SCOUT_PASSWORD_HASH", new_hash); update_password_hash(new_hash)
    delete_all_sessions_except(request.cookies.get("scout_session"))
    return {"ok": True}


@app.post("/api/profile/2fa/reset")
def reset_2fa(payload: TotpResetRequest, request: Request, session: Session = Depends(require_session)) -> dict[str, Any]:
    _csrf(request, session)
    from app.security import verify_totp
    if not verify_password(settings.password_hash, payload.password) or not verify_totp(settings.totp_secret, payload.totp):
        raise HTTPException(status_code=401, detail="Пароль или текущий код 2FA неверен")
    secret = generate_totp_secret(); _replace_env_value("SCOUT_TOTP_SECRET", secret); update_totp_secret(secret)
    delete_all_sessions_except(request.cookies.get("scout_session"))
    return {"ok": True, "secret": secret, "uri": provisioning_uri(secret, settings.username, settings.totp_issuer)}


@app.get("/api/profile/logs")
def download_logs(session: Session = Depends(require_session)) -> StreamingResponse:
    result = subprocess.run(["journalctl", "-u", "scout-easy", "--since", "-24 hours", "--no-pager", "-o", "short-iso"], text=True, capture_output=True, timeout=15, check=False)
    content = result.stdout or result.stderr or "Журнал пуст\n"
    filename = f"scout-easy-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.log"
    return StreamingResponse(iter([content.encode("utf-8")]), media_type="text/plain; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


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
