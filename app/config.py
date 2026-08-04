from __future__ import annotations

import os
from dataclasses import dataclass


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("SCOUT_APP_NAME", "Scout-Easy")
    bind_host: str = os.getenv("SCOUT_BIND_HOST", "127.0.0.1")
    bind_port: int = int(os.getenv("SCOUT_BIND_PORT", "8765"))
    username: str = os.getenv("SCOUT_USERNAME", "admin")
    password: str = os.getenv("SCOUT_PASSWORD", "")
    auth_enabled: bool = _bool_env("SCOUT_AUTH_ENABLED", True)
    refresh_seconds: int = int(os.getenv("SCOUT_REFRESH_SECONDS", "5"))
    max_connections: int = int(os.getenv("SCOUT_MAX_CONNECTIONS", "250"))
    max_events: int = int(os.getenv("SCOUT_MAX_EVENTS", "100"))


settings = Settings()
