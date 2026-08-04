from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
import struct
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from urllib.parse import quote

from fastapi import Cookie, HTTPException, Request

from app.config import settings

_attempts: dict[str, deque[float]] = defaultdict(deque)
_attempt_lock = threading.Lock()
_sessions_lock = threading.Lock()


@dataclass
class Session:
    username: str
    csrf: str
    expires_at: float
    client_ip: str


_sessions: dict[str, Session] = {}


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def verify_password(stored: str, password: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = stored.split("$", 2)
        if scheme != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        expected = base64.urlsafe_b64decode(digest_b64.encode())
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_code(secret: str, timestamp: int | None = None, interval: int = 30) -> str:
    timestamp = int(time.time() if timestamp is None else timestamp)
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = timestamp // interval
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{value:06d}"


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    now = int(time.time())
    return any(hmac.compare_digest(totp_code(secret, now + step * 30), code) for step in range(-window, window + 1))


def provisioning_uri(secret: str, username: str, issuer: str = "SCOUT-EASY") -> str:
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else "unknown")


def ip_allowed(value: str) -> bool:
    if not settings.allowed_ips:
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    for item in settings.allowed_ips:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


def is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    with _attempt_lock:
        attempts = _attempts[ip]
        while attempts and attempts[0] < now - settings.login_window_seconds:
            attempts.popleft()
        return len(attempts) >= settings.login_attempts


def record_failure(ip: str) -> None:
    with _attempt_lock:
        _attempts[ip].append(time.monotonic())


def clear_failures(ip: str) -> None:
    with _attempt_lock:
        _attempts.pop(ip, None)


def verify_credentials(username: str, password: str, code: str) -> bool:
    return bool(
        settings.password_hash
        and settings.totp_secret
        and secrets.compare_digest(username, settings.username)
        and verify_password(settings.password_hash, password)
        and verify_totp(settings.totp_secret, code)
    )


def create_session(username: str, ip: str) -> tuple[str, Session]:
    session_id = secrets.token_urlsafe(48)
    session = Session(username=username, csrf=secrets.token_urlsafe(32), expires_at=time.time() + settings.session_minutes * 60, client_ip=ip)
    with _sessions_lock:
        _sessions[session_id] = session
    return session_id, session


def delete_session(session_id: str | None) -> None:
    if session_id:
        with _sessions_lock:
            _sessions.pop(session_id, None)


def require_session(request: Request, scout_session: str | None = Cookie(default=None)) -> Session:
    ip = client_ip(request)
    if not ip_allowed(ip):
        raise HTTPException(status_code=403, detail="IP is not allowed")
    if not scout_session:
        raise HTTPException(status_code=401, detail="Authentication required")
    with _sessions_lock:
        session = _sessions.get(scout_session)
        if not session or session.expires_at < time.time():
            _sessions.pop(scout_session, None)
            raise HTTPException(status_code=401, detail="Session expired")
        if session.client_ip != ip:
            _sessions.pop(scout_session, None)
            raise HTTPException(status_code=401, detail="Session address changed")
        session.expires_at = time.time() + settings.session_minutes * 60
        return session
