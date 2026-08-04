from __future__ import annotations

import socket
from collections import Counter

import psutil


def _addr(value) -> dict | None:
    if not value:
        return None
    if hasattr(value, "ip"):
        return {"ip": value.ip, "port": value.port}
    if isinstance(value, tuple) and len(value) >= 2:
        return {"ip": value[0], "port": value[1]}
    return None


def collect_connections(limit: int = 250) -> dict:
    rows: list[dict] = []
    remote_counter: Counter[str] = Counter()
    process_counter: Counter[str] = Counter()

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return {"connections": [], "summary": {}, "error": "permission denied"}

    for conn in connections[:limit]:
        process_name = "unknown"
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        remote = _addr(conn.raddr)
        local = _addr(conn.laddr)
        if remote:
            remote_counter[remote["ip"]] += 1
        process_counter[process_name] += 1

        rows.append(
            {
                "family": "ipv6" if conn.family == socket.AF_INET6 else "ipv4",
                "type": "udp" if conn.type == socket.SOCK_DGRAM else "tcp",
                "status": conn.status,
                "local": local,
                "remote": remote,
                "pid": conn.pid,
                "process": process_name,
            }
        )

    return {
        "connections": rows,
        "summary": {
            "total": len(connections),
            "returned": len(rows),
            "remote_ips": remote_counter.most_common(10),
            "processes": process_counter.most_common(10),
        },
        "error": None,
    }
