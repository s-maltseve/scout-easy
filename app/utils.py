from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence


@dataclass
class CommandResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(args: Sequence[str], timeout: float = 3.0) -> CommandResult:
    try:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
        )
        return CommandResult(
            ok=completed.returncode == 0,
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip(),
            returncode=completed.returncode,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return CommandResult(False, "", str(exc), 1)
