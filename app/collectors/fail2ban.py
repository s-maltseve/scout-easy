from __future__ import annotations

import re

from app.utils import command_exists, run_command

JAIL_RE = re.compile(r"Jail list:\s*(?P<jails>.*)")
INT_RE = re.compile(r"(?P<key>Currently failed|Total failed|Currently banned|Total banned):\s*(?P<value>\d+)")
BAN_RE = re.compile(r"Banned IP list:\s*(?P<ips>.*)")


def collect_fail2ban() -> dict:
    if not command_exists("fail2ban-client"):
        return {"available": False, "running": False, "jails": [], "error": "not installed"}

    status = run_command(["fail2ban-client", "status"], timeout=4)
    if not status.ok:
        return {
            "available": True,
            "running": False,
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
            "currently_failed": 0,
            "total_failed": 0,
            "currently_banned": 0,
            "total_banned": 0,
            "banned_ips": [],
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

    return {"available": True, "running": True, "jails": jails, "error": None}
