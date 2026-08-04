from __future__ import annotations

import threading
import time

import psutil

_lock = threading.Lock()
_previous: tuple[float, int, int] | None = None


def collect_traffic() -> dict:
    """Return aggregate network counters and rates, excluding loopback."""
    global _previous

    pernic = psutil.net_io_counters(pernic=True)
    interfaces: list[dict] = []
    total_sent = 0
    total_recv = 0

    for name, counters in pernic.items():
        if name == "lo":
            continue
        sent = int(counters.bytes_sent)
        recv = int(counters.bytes_recv)
        total_sent += sent
        total_recv += recv
        interfaces.append(
            {
                "name": name,
                "bytes_sent": sent,
                "bytes_recv": recv,
                "packets_sent": int(counters.packets_sent),
                "packets_recv": int(counters.packets_recv),
                "errors_in": int(counters.errin),
                "errors_out": int(counters.errout),
                "drops_in": int(counters.dropin),
                "drops_out": int(counters.dropout),
            }
        )

    now = time.monotonic()
    sent_per_second = 0.0
    recv_per_second = 0.0

    with _lock:
        if _previous is not None:
            previous_time, previous_sent, previous_recv = _previous
            elapsed = max(now - previous_time, 0.001)
            sent_per_second = max(0.0, (total_sent - previous_sent) / elapsed)
            recv_per_second = max(0.0, (total_recv - previous_recv) / elapsed)
        _previous = (now, total_sent, total_recv)

    interfaces.sort(key=lambda item: item["bytes_sent"] + item["bytes_recv"], reverse=True)
    return {
        "total": {
            "bytes_sent": total_sent,
            "bytes_recv": total_recv,
            "bytes_all": total_sent + total_recv,
        },
        "current": {
            "sent_per_second": round(sent_per_second, 2),
            "recv_per_second": round(recv_per_second, 2),
            "all_per_second": round(sent_per_second + recv_per_second, 2),
        },
        "interfaces": interfaces,
    }
