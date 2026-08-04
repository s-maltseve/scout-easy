from __future__ import annotations

import ipaddress
import secrets
import threading
import time
from collections import defaultdict, deque

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from app.config import settings

basic = HTTPBasic(auto_error=False)
_attempts: dict[str, deque[float]] = defaultdict(deque)
_attempt_lock = threading.Lock()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _ip_allowed(client_ip: str) -> bool:
    if not settings.allowed_ips:
        return True
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for item in settings.allowed_ips:
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if address in network:
            return True
    return False


def _is_rate_limited(client_ip: str) -> bool:
    now = time.monotonic()
    with _attempt_lock:
        attempts = _attempts[client_ip]
        while attempts and attempts[0] < now - settings.login_window_seconds:
            attempts.popleft()
        return len(attempts) >= settings.login_attempts


def _record_failure(client_ip: str) -> None:
    with _attempt_lock:
        _attempts[client_ip].append(time.monotonic())


def _clear_failures(client_ip: str) -> None:
    with _attempt_lock:
        _attempts.pop(client_ip, None)


def require_auth(
    request: Request,
    credentials: HTTPBasicCredentials | None = Depends(basic),
) -> str:
    client_ip = _client_ip(request)
    if not _ip_allowed(client_ip):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="IP is not allowed")
    if not settings.auth_enabled:
        if settings.bind_host not in {"127.0.0.1", "::1", "localhost"}:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication cannot be disabled on a public bind address",
            )
        return "auth-disabled"
    if not settings.password:
        raise HTTPException(status_code=503, detail="SCOUT_PASSWORD is not configured")
    if _is_rate_limited(client_ip):
        raise HTTPException(status_code=429, detail="Too many authentication attempts")
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Basic"})

    valid_user = secrets.compare_digest(credentials.username, settings.username)
    valid_password = secrets.compare_digest(credentials.password, settings.password)
    if not (valid_user and valid_password):
        _record_failure(client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Basic"})
    _clear_failures(client_ip)
    return credentials.username


def require_action_token(
    token: str | None = Header(default=None, alias="X-SCOUT-ACTION-TOKEN"),
) -> None:
    if not settings.actions_enabled:
        raise HTTPException(status_code=403, detail="Administrative actions are disabled")
    if not settings.action_token:
        raise HTTPException(status_code=503, detail="SCOUT_ACTION_TOKEN is not configured")
    if token is None or not secrets.compare_digest(token, settings.action_token):
        raise HTTPException(status_code=403, detail="Invalid action token")
