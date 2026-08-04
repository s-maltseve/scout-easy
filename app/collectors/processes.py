from __future__ import annotations

import psutil

SUSPICIOUS_NAMES = {
    "xmrig",
    "minerd",
    "kinsing",
    "kdevtmpfsi",
    "masscan",
    "zmap",
    "hydra",
    "nmap",
}


def collect_processes(limit: int = 50) -> dict:
    rows: list[dict] = []
    suspicious: list[dict] = []
    for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "cmdline"]):
        try:
            info = proc.info
            row = {
                "pid": info["pid"],
                "name": info.get("name") or "unknown",
                "username": info.get("username") or "unknown",
                "cpu_percent": round(info.get("cpu_percent") or 0.0, 1),
                "memory_percent": round(info.get("memory_percent") or 0.0, 2),
                "cmdline": " ".join(info.get("cmdline") or [])[:400],
            }
            rows.append(row)
            if row["name"].lower() in SUSPICIOUS_NAMES:
                suspicious.append({**row, "reason": "known suspicious process name"})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    rows.sort(key=lambda item: (item["cpu_percent"], item["memory_percent"]), reverse=True)
    return {"top": rows[:limit], "suspicious": suspicious}
