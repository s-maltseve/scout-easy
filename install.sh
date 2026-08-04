#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo bash install.sh" >&2; exit 1; fi
if ! command -v apt-get >/dev/null 2>&1; then echo "Only Debian/Ubuntu are supported by this installer." >&2; exit 1; fi

INSTALL_DIR=/opt/scout-easy
CONFIG_DIR=/etc/scout-easy
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

apt-get update
apt-get install -y python3 python3-venv python3-pip rsync
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
rsync -a --delete --exclude '.git' --exclude '.venv' "$SOURCE_DIR/" "$INSTALL_DIR/"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

if [[ ! -f "$CONFIG_DIR/scout-easy.env" ]]; then
  PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
  cat > "$CONFIG_DIR/scout-easy.env" <<ENV
SCOUT_USERNAME=admin
SCOUT_PASSWORD=$PASSWORD
SCOUT_AUTH_ENABLED=true
SCOUT_BIND_HOST=127.0.0.1
SCOUT_BIND_PORT=8765
SCOUT_REFRESH_SECONDS=5
SCOUT_MAX_CONNECTIONS=250
SCOUT_MAX_EVENTS=100
ENV
  chmod 600 "$CONFIG_DIR/scout-easy.env"
  echo "Generated credentials: admin / $PASSWORD"
else
  echo "Keeping existing config: $CONFIG_DIR/scout-easy.env"
fi

install -m 0644 "$INSTALL_DIR/systemd/scout-easy.service" /etc/systemd/system/scout-easy.service
systemctl daemon-reload
systemctl enable --now scout-easy

echo
echo "Scout-Easy installed."
echo "Local URL: http://127.0.0.1:8765"
echo "Recommended access: SSH tunnel: ssh -L 8765:127.0.0.1:8765 user@server"
echo "Then open: http://127.0.0.1:8765"
echo "Config: $CONFIG_DIR/scout-easy.env"
