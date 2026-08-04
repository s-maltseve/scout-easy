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
    password: str = os.getenv("SCOUT_PASSWORD", "")
    auth_enabled: bool = _bool_env("SCOUT_AUTH_ENABLED", True)
    actions_enabled: bool = _bool_env("SCOUT_ACTIONS_ENABLED", False)
    action_token: str = os.getenv("SCOUT_ACTION_TOKEN", "")
    allowed_ips: tuple[str, ...] = _csv_env("SCOUT_ALLOWED_IPS")
    refresh_seconds: int = int(os.getenv("SCOUT_REFRESH_SECONDS", "5"))
    max_connections: int = int(os.getenv("SCOUT_MAX_CONNECTIONS", "250"))
    max_events: int = int(os.getenv("SCOUT_MAX_EVENTS", "100"))
    login_attempts: int = int(os.getenv("SCOUT_LOGIN_ATTEMPTS", "8"))
    login_window_seconds: int = int(os.getenv("SCOUT_LOGIN_WINDOW_SECONDS", "300"))


settings = Settings()
