from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.collectors.fail2ban import collect_fail2ban
from app.collectors.network import collect_connections
from app.collectors.processes import collect_processes
from app.collectors.ssh import collect_auth_events, collect_sessions
from app.collectors.system import collect_system
from app.config import settings
from app.security import require_auth

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title=settings.app_name, version=__version__, docs_url="/api/docs")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/dashboard")
def dashboard(_: str = Depends(require_auth)) -> dict:
    system = collect_system()
    sessions = collect_sessions()
    auth_events = collect_auth_events(settings.max_events)
    fail2ban = collect_fail2ban()
    network = collect_connections(settings.max_connections)
    processes = collect_processes()

    failed = sum(1 for event in auth_events if event["type"] == "failure")
    succeeded = sum(1 for event in auth_events if event["type"] == "success")
    banned = sum(jail.get("currently_banned", 0) for jail in fail2ban.get("jails", []))

    warnings: list[dict] = []
    if network.get("summary", {}).get("total", 0) > settings.max_connections:
        warnings.append(
            {
                "level": "warning",
                "title": "High connection count",
                "message": f"More than {settings.max_connections} network connections detected.",
            }
        )
    if processes["suspicious"]:
        warnings.append(
            {
                "level": "critical",
                "title": "Suspicious process name",
                "message": f"Found {len(processes['suspicious'])} process(es) requiring review.",
            }
        )
    if not fail2ban.get("running"):
        warnings.append(
            {
                "level": "info",
                "title": "Fail2ban inactive",
                "message": fail2ban.get("error") or "Fail2ban is not running.",
            }
        )

    return {
        "meta": {
            "name": settings.app_name,
            "version": __version__,
            "refresh_seconds": settings.refresh_seconds,
            "read_only": True,
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
        "processes": processes,
    }


@app.get("/")
def index(_: str = Depends(require_auth)) -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
