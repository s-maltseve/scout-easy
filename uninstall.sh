#!/usr/bin/env bash
set -Eeuo pipefail
if [[ $EUID -ne 0 ]]; then echo "Run as root" >&2; exit 1; fi
systemctl disable --now scout-easy 2>/dev/null || true
rm -f /etc/systemd/system/scout-easy.service
systemctl daemon-reload
rm -rf /opt/scout-easy
echo "Application removed. Config remains in /etc/scout-easy."
