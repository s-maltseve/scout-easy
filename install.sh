#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Запусти установщик от root: sudo bash install.sh" >&2
  exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "Автоматический установщик поддерживает Debian/Ubuntu." >&2
  exit 1
fi

INSTALL_DIR=/opt/scout-easy
CONFIG_DIR=/etc/scout-easy
SERVICE=scout-easy.service
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

apt-get update
apt-get install -y python3 python3-venv python3-pip rsync
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

# Stop the old process before replacing its source. This prevents a new frontend
# from talking to an old Python process after an update.
if systemctl is-active --quiet "$SERVICE"; then
  systemctl stop "$SERVICE"
fi

rsync -a --delete \
  --exclude '.git' \
  --exclude '.venv' \
  --exclude '.pytest_cache' \
  --exclude '__pycache__' \
  "$SOURCE_DIR/" "$INSTALL_DIR/"

if [[ ! -x "$INSTALL_DIR/.venv/bin/python3" ]]; then
  python3 -m venv "$INSTALL_DIR/.venv"
fi
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

if [[ ! -f "$CONFIG_DIR/scout-easy.env" ]]; then
  PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
  ACTION_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
  cat > "$CONFIG_DIR/scout-easy.env" <<ENV
SCOUT_USERNAME=admin
SCOUT_PASSWORD=$PASSWORD
SCOUT_AUTH_ENABLED=true
SCOUT_ACTIONS_ENABLED=false
SCOUT_ACTION_TOKEN=$ACTION_TOKEN
SCOUT_ALLOWED_IPS=
SCOUT_BIND_HOST=127.0.0.1
SCOUT_BIND_PORT=8765
SCOUT_REFRESH_SECONDS=5
SCOUT_MAX_CONNECTIONS=250
SCOUT_MAX_EVENTS=100
SCOUT_LOGIN_ATTEMPTS=8
SCOUT_LOGIN_WINDOW_SECONDS=300
ENV
  chmod 600 "$CONFIG_DIR/scout-easy.env"
  echo "Созданы данные входа: admin / $PASSWORD"
else
  echo "Существующий конфиг сохранён: $CONFIG_DIR/scout-easy.env"
fi

install -m 0644 "$INSTALL_DIR/systemd/scout-easy.service" /etc/systemd/system/scout-easy.service
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null
systemctl restart "$SERVICE"

sleep 1
if ! systemctl is-active --quiet "$SERVICE"; then
  echo "SCOUT-EASY не запустился. Последние строки журнала:" >&2
  journalctl -u "$SERVICE" -n 50 --no-pager >&2
  exit 1
fi

VERSION=$("$INSTALL_DIR/.venv/bin/python3" -c 'from app import __version__; print(__version__)' 2>/dev/null || true)
echo
echo "SCOUT-EASY ${VERSION:-unknown} установлен и перезапущен."
echo "Локальный адрес: http://127.0.0.1:8765"
echo "Конфигурация: $CONFIG_DIR/scout-easy.env"
echo "Проверка: systemctl status scout-easy --no-pager"
