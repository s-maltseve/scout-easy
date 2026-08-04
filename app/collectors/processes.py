from __future__ import annotations

import time
from typing import Any

import psutil

SUSPICIOUS_NAMES = {"xmrig", "minerd", "kinsing", "kdevtmpfsi", "masscan", "zmap", "hydra", "nmap"}
_SAMPLE_CACHE: dict[int, tuple[float, float, int, int]] = {}


def _safe_parent(proc: psutil.Process) -> tuple[int, str]:
    try:
        parent = proc.parent()
        return (parent.pid, parent.name()) if parent else (0, "—")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return 0, "—"


def collect_processes(limit: int = 300) -> dict[str, Any]:
    now = time.time()
    cpu_count = max(psutil.cpu_count() or 1, 1)
    rows: list[dict[str, Any]] = []
    suspicious: list[dict[str, Any]] = []
    next_cache: dict[int, tuple[float, float, int, int]] = {}

    attrs = ["pid", "name", "username", "memory_percent", "memory_info", "cmdline", "create_time", "status", "num_threads", "cpu_times", "io_counters"]
    for proc in psutil.process_iter(attrs):
        try:
            info = proc.info
            pid = int(info["pid"])
            cpu_times = info.get("cpu_times")
            cpu_total = float((cpu_times.user + cpu_times.system) if cpu_times else 0.0)
            io = info.get("io_counters")
            read_bytes = int(getattr(io, "read_bytes", 0) or 0)
            write_bytes = int(getattr(io, "write_bytes", 0) or 0)
            previous = _SAMPLE_CACHE.get(pid)
            cpu_percent = read_rate = write_rate = 0.0
            if previous:
                prev_time, prev_cpu, prev_read, prev_write = previous
                elapsed = max(now - prev_time, 0.001)
                cpu_percent = max(0.0, (cpu_total - prev_cpu) / elapsed * 100.0 / cpu_count)
                read_rate = max(0.0, (read_bytes - prev_read) / elapsed)
                write_rate = max(0.0, (write_bytes - prev_write) / elapsed)
            next_cache[pid] = (now, cpu_total, read_bytes, write_bytes)

            memory_info = info.get("memory_info")
            parent_pid, parent_name = _safe_parent(proc)
            created = float(info.get("create_time") or now)
            row = {
                "pid": pid,
                "name": info.get("name") or "unknown",
                "username": info.get("username") or "unknown",
                "cpu_percent": round(cpu_percent, 1),
                "memory_percent": round(float(info.get("memory_percent") or 0.0), 2),
                "memory_mb": round(float(getattr(memory_info, "rss", 0) or 0) / 1024 / 1024, 1),
                "read_bytes": read_bytes,
                "write_bytes": write_bytes,
                "read_per_second": round(read_rate, 1),
                "write_per_second": round(write_rate, 1),
                "uptime_seconds": max(0, int(now - created)),
                "created_at": created,
                "status": info.get("status") or "unknown",
                "threads": int(info.get("num_threads") or 0),
                "parent_pid": parent_pid,
                "parent_name": parent_name,
                "cmdline": " ".join(info.get("cmdline") or [])[:1000],
            }
            rows.append(row)
            if row["name"].lower() in SUSPICIOUS_NAMES:
                suspicious.append({**row, "reason": "known suspicious process name"})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    _SAMPLE_CACHE.clear()
    _SAMPLE_CACHE.update(next_cache)
    rows.sort(key=lambda item: (item["cpu_percent"], item["memory_mb"]), reverse=True)
    return {"top": rows[:limit], "suspicious": suspicious, "sampled_at": now}
