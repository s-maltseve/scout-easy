from __future__ import annotations

import ipaddress
import logging
import re

from app.collectors.fail2ban import collect_fail2ban
from app.collectors.ssh import collect_sessions
from app.utils import CommandResult, run_command

logger = logging.getLogger("scout-easy.actions")
TTY_RE = re.compile(r"^(?:pts/\d+|tty\d+)$")
JAIL_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


class ActionError(ValueError):
    pass


def _validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ActionError("Некорректный IP-адрес") from exc


def _validate_jail(jail: str) -> str:
    if not JAIL_RE.fullmatch(jail):
        raise ActionError("Некорректное имя jail")
    existing = {item["name"] for item in collect_fail2ban().get("jails", [])}
    if jail not in existing:
        raise ActionError("Указанный jail не найден")
    return jail


def disconnect_ssh_session(tty: str, actor: str) -> CommandResult:
    if not TTY_RE.fullmatch(tty):
        raise ActionError("Некорректный SSH-терминал")
    active_ttys = {item["terminal"] for item in collect_sessions()}
    if tty not in active_ttys:
        raise ActionError("SSH-сессия уже завершена или не найдена")

    result = run_command(["pkill", "-HUP", "-t", tty], timeout=5)
    logger.warning("actor=%s action=disconnect_ssh tty=%s result=%s", actor, tty, result.ok)
    return result


def ban_ip(jail: str, ip: str, actor: str) -> CommandResult:
    jail = _validate_jail(jail)
    ip = _validate_ip(ip)
    result = run_command(["fail2ban-client", "set", jail, "banip", ip], timeout=8)
    logger.warning("actor=%s action=ban_ip jail=%s ip=%s result=%s", actor, jail, ip, result.ok)
    return result


def unban_ip(jail: str, ip: str, actor: str) -> CommandResult:
    jail = _validate_jail(jail)
    ip = _validate_ip(ip)
    result = run_command(["fail2ban-client", "set", jail, "unbanip", ip], timeout=8)
    logger.warning("actor=%s action=unban_ip jail=%s ip=%s result=%s", actor, jail, ip, result.ok)
    return result
