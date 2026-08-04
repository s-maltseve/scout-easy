from __future__ import annotations

import os
from dataclasses import dataclass


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _csv_env(name: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.getenv(name, "").split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("SCOUT_APP_NAME", "SCOUT-EASY")
    bind_host: str = os.getenv("SCOUT_BIND_HOST", "127.0.0.1")
    bind_port: int = int(os.getenv("SCOUT_BIND_PORT", "8765"))
    username: str = os.getenv("SCOUT_USERNAME", "admin")
    password_hash: str = os.getenv("SCOUT_PASSWORD_HASH", "")
    totp_secret: str = os.getenv("SCOUT_TOTP_SECRET", "")
    totp_issuer: str = os.getenv("SCOUT_TOTP_ISSUER", "SCOUT-EASY")
    actions_enabled: bool = _bool_env("SCOUT_ACTIONS_ENABLED", True)
    allowed_ips: tuple[str, ...] = _csv_env("SCOUT_ALLOWED_IPS")
    refresh_seconds: int = int(os.getenv("SCOUT_REFRESH_SECONDS", "5"))
    max_connections: int = int(os.getenv("SCOUT_MAX_CONNECTIONS", "250"))
    max_events: int = int(os.getenv("SCOUT_MAX_EVENTS", "100"))
    login_attempts: int = int(os.getenv("SCOUT_LOGIN_ATTEMPTS", "3"))
    login_window_seconds: int = int(os.getenv("SCOUT_LOGIN_WINDOW_SECONDS", "600"))
    login_block_seconds: int = int(os.getenv("SCOUT_LOGIN_BLOCK_SECONDS", "21600"))
    session_minutes: int = int(os.getenv("SCOUT_SESSION_MINUTES", "480"))
    secure_cookie: bool = _bool_env("SCOUT_SECURE_COOKIE", True)


settings = Settings()
