from __future__ import annotations

import re
from datetime import datetime

import psutil

from app.utils import command_exists, run_command

SSH_ACCEPT_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
SSH_FAIL_RE = re.compile(
    r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")


def collect_sessions() -> list[dict]:
    sessions: list[dict] = []
    for user in psutil.users():
        sessions.append(
            {
                "username": user.name,
                "terminal": user.terminal or "",
                "source_ip": user.host or "local",
                "started_at": datetime.fromtimestamp(user.started).astimezone().isoformat(),
                "pid": user.pid,
            }
        )
    return sessions


def _journal_lines(limit: int) -> list[str]:
    if not command_exists("journalctl"):
        return []
    for unit in ("ssh.service", "sshd.service"):
        result = run_command(
            ["journalctl", "-u", unit, "--no-pager", "-n", str(limit), "-o", "short-iso"],
            timeout=5,
        )
        if result.ok and result.stdout:
            return result.stdout.splitlines()
    return []


def collect_auth_events(limit: int = 100) -> list[dict]:
    events: list[dict] = []
    for line in reversed(_journal_lines(max(limit * 4, 200))):
        accepted = SSH_ACCEPT_RE.search(line)
        failed = SSH_FAIL_RE.search(line)
        invalid = INVALID_USER_RE.search(line)
        if accepted:
            events.append({"type": "success", **accepted.groupdict(), "raw": line})
        elif failed:
            events.append({"type": "failure", **failed.groupdict(), "raw": line})
        elif invalid:
            events.append(
                {
                    "type": "failure",
                    "method": "unknown",
                    "port": "",
                    **invalid.groupdict(),
                    "raw": line,
                }
            )
        if len(events) >= limit:
            break
    return events
