from __future__ import annotations

import re

from app.utils import command_exists, run_command

JAIL_RE = re.compile(r"Jail list:\s*(?P<jails>.*)")
INT_RE = re.compile(r"(?P<key>Currently failed|Total failed|Currently banned|Total banned):\s*(?P<value>\d+)")
BAN_RE = re.compile(r"Banned IP list:\s*(?P<ips>.*)")


def _get_jail_value(jail: str, key: str, default=None):
    result = run_command(["fail2ban-client", "get", jail, key], timeout=4)
    if not result.ok:
        return default
    value = result.stdout.strip()
    if key in {"bantime", "findtime", "maxretry"}:
        try:
            return int(value.splitlines()[-1].strip())
        except (ValueError, IndexError):
            return default
    return value or default


def collect_fail2ban() -> dict:
    if not command_exists("fail2ban-client"):
        return {"available": False, "running": False, "responsive": False, "jails": [], "error": "not installed"}

    ping = run_command(["fail2ban-client", "ping"], timeout=4)
    status = run_command(["fail2ban-client", "status"], timeout=4)
    if not status.ok:
        return {
            "available": True,
            "running": False,
            "responsive": ping.ok,
            "jails": [],
            "error": status.stderr or status.stdout or "fail2ban unavailable",
        }

    jail_names: list[str] = []
    match = JAIL_RE.search(status.stdout)
    if match:
        jail_names = [j.strip() for j in match.group("jails").split(",") if j.strip()]

    jails: list[dict] = []
    for jail in jail_names:
        detail = run_command(["fail2ban-client", "status", jail], timeout=4)
        info = {
            "name": jail,
            "healthy": detail.ok,
            "currently_failed": 0,
            "total_failed": 0,
            "currently_banned": 0,
            "total_banned": 0,
            "banned_ips": [],
            "bantime": _get_jail_value(jail, "bantime", 0),
            "findtime": _get_jail_value(jail, "findtime", 0),
            "maxretry": _get_jail_value(jail, "maxretry", 0),
            "filter": _get_jail_value(jail, "failregex", "настроен"),
            "actions": _get_jail_value(jail, "actions", ""),
        }
        if detail.ok:
            for item in INT_RE.finditer(detail.stdout):
                key = item.group("key").lower().replace(" ", "_")
                info[key] = int(item.group("value"))
            ban_match = BAN_RE.search(detail.stdout)
            if ban_match and ban_match.group("ips").strip():
                info["banned_ips"] = ban_match.group("ips").split()
        else:
            info["error"] = detail.stderr or detail.stdout
        jails.append(info)

    return {
        "available": True,
        "running": True,
        "responsive": ping.ok and "pong" in ping.stdout.lower(),
        "jails": jails,
        "error": None,
    }
