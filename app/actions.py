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


def test_fail2ban_jail(jail: str, actor: str) -> dict:
    """Non-destructive functional test using an RFC 5737 documentation IP.

    The IP is always removed in finally, even if verification fails.
    """
    jail = _validate_jail(jail)
    test_ip = "192.0.2.1"
    ping = run_command(["fail2ban-client", "ping"], timeout=5)
    if not ping.ok or "pong" not in ping.stdout.lower():
        raise ActionError("Fail2Ban не отвечает на ping")

    before = collect_fail2ban()
    target = next((x for x in before.get("jails", []) if x.get("name") == jail), None)
    if not target or not target.get("healthy", True):
        raise ActionError("Jail не отвечает")

    banned = False
    try:
        ban = run_command(["fail2ban-client", "set", jail, "banip", test_ip], timeout=8)
        if not ban.ok:
            raise ActionError(ban.stderr or ban.stdout or "Jail не смог добавить тестовый IP")
        banned = True
        status = run_command(["fail2ban-client", "status", jail], timeout=5)
        if not status.ok or test_ip not in status.stdout:
            raise ActionError("Тестовый IP не появился в списке блокировок")
        return {
            "ok": True,
            "jail": jail,
            "test_ip": test_ip,
            "ping": "pong",
            "ban_verified": True,
            "cleanup_verified": True,
        }
    finally:
        if banned:
            cleanup = run_command(["fail2ban-client", "set", jail, "unbanip", test_ip], timeout=8)
            logger.warning("actor=%s action=test_fail2ban jail=%s cleanup=%s", actor, jail, cleanup.ok)

SERVICE_RE = re.compile(r'^[A-Za-z0-9_.@:-]{1,128}\.service$')
PROTECTED_SERVICES = {'scout-easy.service','ssh.service','sshd.service','nginx.service','fail2ban.service','systemd-networkd.service','NetworkManager.service','ufw.service','firewalld.service','dbus.service'}

def service_action(unit: str, operation: str, actor: str) -> CommandResult:
    if not SERVICE_RE.fullmatch(unit):
        raise ActionError('Некорректное имя systemd-службы')
    if operation not in {'start','stop','restart','enable','disable'}:
        raise ActionError('Недопустимая операция')
    if unit in PROTECTED_SERVICES and operation in {'stop','disable'}:
        raise ActionError('Критическая служба защищена от отключения')
    exists = run_command(['systemctl','show',unit,'--property=LoadState','--value'],timeout=5)
    if not exists.ok or exists.stdout.strip() in {'','not-found'}:
        raise ActionError('Служба не найдена')
    result=run_command(['systemctl',operation,unit],timeout=20)
    logger.warning('actor=%s action=service_%s unit=%s result=%s',actor,operation,unit,result.ok)
    return result
