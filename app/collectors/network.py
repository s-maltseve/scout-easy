from __future__ import annotations

import re
import socket
import threading
import time
from collections import Counter, defaultdict
from typing import Any

import psutil

from app.utils import command_exists, run_command

_BYTES_ACKED_RE = re.compile(r"\bbytes_acked:(\d+)")
_BYTES_RECEIVED_RE = re.compile(r"\bbytes_received:(\d+)")
_USERS_RE = re.compile(r'users:\(\("(?P<name>[^"]+)"(?:,pid=(?P<pid>\d+))?')
_ENDPOINT_RE = re.compile(r"^(?P<host>.*):(?P<port>\*|\d+)$")

_SAMPLE_LOCK = threading.Lock()
_PREVIOUS: dict[str, tuple[float, int, int]] = {}


def _addr(value: Any) -> dict | None:
    if not value:
        return None
    if hasattr(value, "ip"):
        return {"ip": value.ip, "port": value.port}
    if isinstance(value, tuple) and len(value) >= 2:
        return {"ip": value[0], "port": value[1]}
    return None


def _endpoint_key(local: dict | None, remote: dict | None, pid: int | None) -> str:
    def fmt(item: dict | None) -> str:
        if not item:
            return "-"
        return f"{item.get('ip', '-')}/{item.get('port', '-')}"

    return f"{fmt(local)}>{fmt(remote)}@{pid or 0}"


def _split_endpoint(raw: str) -> dict | None:
    raw = raw.strip()
    if not raw or raw == "*":
        return None
    match = _ENDPOINT_RE.match(raw)
    if not match:
        return None
    host = match.group("host")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    port_raw = match.group("port")
    return {"ip": host, "port": int(port_raw) if port_raw.isdigit() else port_raw}


def _collect_tcp_counters() -> dict[str, dict[str, int | str | None]]:
    """Read cumulative counters from `ss -tinpH`.

    Linux exposes bytes_received and bytes_acked for established TCP sockets.
    These are transport counters, not full interface packet counters.
    """
    if not command_exists("ss"):
        return {}
    result = run_command(["ss", "-tinpH"], timeout=6)
    if not result.ok:
        return {}

    rows: dict[str, dict[str, int | str | None]] = {}
    current: dict[str, Any] | None = None
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            parts = line.split()
            if len(parts) < 5:
                current = None
                continue
            # Typical: ESTAB 0 0 local remote users:((...))
            state = parts[0]
            local = _split_endpoint(parts[3])
            remote = _split_endpoint(parts[4])
            users_match = _USERS_RE.search(line)
            process = users_match.group("name") if users_match else None
            pid = int(users_match.group("pid")) if users_match and users_match.group("pid") else None
            current = {
                "state": state,
                "local": local,
                "remote": remote,
                "pid": pid,
                "process": process,
                "bytes_sent": 0,
                "bytes_received": 0,
            }
            rows[_endpoint_key(local, remote, pid)] = current
        elif current is not None:
            sent = _BYTES_ACKED_RE.search(line)
            received = _BYTES_RECEIVED_RE.search(line)
            if sent:
                current["bytes_sent"] = int(sent.group(1))
            if received:
                current["bytes_received"] = int(received.group(1))
    return rows


def _rates(key: str, sent: int, received: int, now: float) -> tuple[float, float]:
    with _SAMPLE_LOCK:
        previous = _PREVIOUS.get(key)
        _PREVIOUS[key] = (now, sent, received)
        # Remove old sockets from the in-memory cache.
        stale_before = now - 1800
        for old_key, sample in list(_PREVIOUS.items()):
            if sample[0] < stale_before:
                _PREVIOUS.pop(old_key, None)
    if not previous:
        return 0.0, 0.0
    elapsed = max(now - previous[0], 0.001)
    sent_rate = max(sent - previous[1], 0) / elapsed
    received_rate = max(received - previous[2], 0) / elapsed
    return sent_rate, received_rate


def collect_connections(limit: int = 250) -> dict:
    rows: list[dict] = []
    remote_counter: Counter[str] = Counter()
    process_counter: Counter[str] = Counter()
    process_traffic: dict[str, dict[str, float | int | str]] = defaultdict(
        lambda: {
            "process": "unknown",
            "connections": 0,
            "sent_per_second": 0.0,
            "recv_per_second": 0.0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "bytes_all": 0,
        }
    )

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return {"connections": [], "summary": {}, "process_traffic": [], "error": "permission denied"}

    tcp_counters = _collect_tcp_counters()
    now = time.monotonic()

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

        key = _endpoint_key(local, remote, conn.pid)
        counter = tcp_counters.get(key, {})
        # `ss` can omit pid for sockets that disappear during collection. Try a tuple-only match.
        if not counter and conn.type == socket.SOCK_STREAM:
            tuple_prefix = _endpoint_key(local, remote, None).split("@")[0]
            for candidate_key, candidate in tcp_counters.items():
                if candidate_key.split("@")[0] == tuple_prefix:
                    counter = candidate
                    break

        bytes_sent = int(counter.get("bytes_sent", 0) or 0)
        bytes_received = int(counter.get("bytes_received", 0) or 0)
        sent_rate, recv_rate = _rates(key, bytes_sent, bytes_received, now) if counter else (0.0, 0.0)
        traffic_available = bool(counter) and conn.type == socket.SOCK_STREAM and conn.status not in {"LISTEN", "TIME_WAIT", "NONE"}

        row = {
            "family": "ipv6" if conn.family == socket.AF_INET6 else "ipv4",
            "type": "udp" if conn.type == socket.SOCK_DGRAM else "tcp",
            "status": conn.status,
            "local": local,
            "remote": remote,
            "pid": conn.pid,
            "process": process_name,
            "loopback": bool(local and str(local.get("ip", "")).startswith(("127.", "::1"))) and bool(remote and str(remote.get("ip", "")).startswith(("127.", "::1"))),
            "traffic_available": traffic_available,
            "sent_per_second": sent_rate if traffic_available else None,
            "recv_per_second": recv_rate if traffic_available else None,
            "bytes_sent": bytes_sent if traffic_available else None,
            "bytes_received": bytes_received if traffic_available else None,
            "bytes_all": (bytes_sent + bytes_received) if traffic_available else None,
        }
        rows.append(row)

        if traffic_available:
            bucket = process_traffic[process_name]
            bucket["process"] = process_name
            bucket["connections"] = int(bucket["connections"]) + 1
            bucket["sent_per_second"] = float(bucket["sent_per_second"]) + sent_rate
            bucket["recv_per_second"] = float(bucket["recv_per_second"]) + recv_rate
            bucket["bytes_sent"] = int(bucket["bytes_sent"]) + bytes_sent
            bucket["bytes_received"] = int(bucket["bytes_received"]) + bytes_received
            bucket["bytes_all"] = int(bucket["bytes_all"]) + bytes_sent + bytes_received

    process_traffic_rows = sorted(
        process_traffic.values(),
        key=lambda item: float(item["sent_per_second"]) + float(item["recv_per_second"]),
        reverse=True,
    )

    return {
        "connections": rows,
        "process_traffic": process_traffic_rows,
        "summary": {
            "total": len(connections),
            "returned": len(rows),
            "with_traffic": sum(1 for row in rows if row["traffic_available"]),
            "remote_ips": remote_counter.most_common(10),
            "processes": process_counter.most_common(10),
        },
        "error": None,
    }
