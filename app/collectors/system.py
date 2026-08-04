from __future__ import annotations

import os
import platform
import socket
import time
from datetime import datetime, timezone

import psutil


def collect_system() -> dict:
    boot_time = psutil.boot_time()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    load1, load5, load15 = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)

    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "time": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": max(0, int(time.time() - boot_time)),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "cpu_count": psutil.cpu_count(),
        "load": [round(load1, 2), round(load5, 2), round(load15, 2)],
        "memory": {
            "total": memory.total,
            "used": memory.used,
            "available": memory.available,
            "percent": memory.percent,
        },
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent,
        },
    }
