#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Запусти: sudo bash install.sh'; exit 1; }
command -v apt-get >/dev/null || { echo 'Поддерживаются Debian/Ubuntu'; exit 1; }
INSTALL_DIR=/opt/scout-easy; CONFIG_DIR=/etc/scout-easy; SERVICE=scout-easy.service
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
NON_INTERACTIVE=false; [[ ${1:-} == --non-interactive ]] && NON_INTERACTIVE=true
apt-get update
apt-get install -y python3 python3-venv python3-pip rsync curl nginx
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"
systemctl stop "$SERVICE" 2>/dev/null || true
rsync -a --delete --exclude .git --exclude .venv --exclude __pycache__ --exclude .pytest_cache "$SOURCE_DIR/" "$INSTALL_DIR/"
[[ -x "$INSTALL_DIR/.venv/bin/python3" ]] || python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
ENV_FILE="$CONFIG_DIR/scout-easy.env"

generate_username() {
 python3 - <<'PYGEN'
import secrets
import string
alphabet = string.ascii_lowercase + string.digits
print("scout-" + "".join(secrets.choice(alphabet) for _ in range(12)))
PYGEN
}

generate_secret() {
 local length="${1:-48}"
 python3 - "$length" <<'PYGEN'
import secrets
import string
import sys
length = int(sys.argv[1])
special = "!@#$%^&*_-+=:"
groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits, special]
alphabet = "".join(groups)
while True:
    chars = [secrets.choice(group) for group in groups]
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    value = "".join(chars)
    if all(any(ch in group for ch in value) for group in groups):
        print(value)
        break
PYGEN
}

read_env_value() {
 local key="$1"
 [[ -f "$ENV_FILE" ]] || return 0
 python3 - "$ENV_FILE" "$key" <<'PYREAD'
from pathlib import Path
import sys
path, key = Path(sys.argv[1]), sys.argv[2]
for raw in path.read_text(errors="replace").splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    name, value = line.split("=", 1)
    if name.strip() != key:
        continue
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    print(value)
    break
PYREAD
}

SCOUT_USERNAME="$(read_env_value SCOUT_USERNAME)"
SCOUT_PASSWORD="$(read_env_value SCOUT_PASSWORD)"
SCOUT_ACTION_TOKEN="$(read_env_value SCOUT_ACTION_TOKEN)"
SCOUT_ACTIONS_ENABLED="$(read_env_value SCOUT_ACTIONS_ENABLED)"

[[ -n "$SCOUT_USERNAME" ]] || SCOUT_USERNAME="$(generate_username)"
[[ -n "$SCOUT_PASSWORD" ]] || SCOUT_PASSWORD="$(generate_secret 40)"
[[ -n "$SCOUT_ACTION_TOKEN" ]] || SCOUT_ACTION_TOKEN="$(generate_secret 64)"
[[ -n "$SCOUT_ACTIONS_ENABLED" ]] || SCOUT_ACTIONS_ENABLED=true

# Перезаписываем конфигурацию атомарно: старые секреты сохраняются,
# отсутствующие или пустые значения генерируются автоматически.
TMP_ENV="$(mktemp)"
cat > "$TMP_ENV" <<ENV
SCOUT_USERNAME='$SCOUT_USERNAME'
SCOUT_PASSWORD='$SCOUT_PASSWORD'
SCOUT_AUTH_ENABLED=true
SCOUT_ACTIONS_ENABLED=$SCOUT_ACTIONS_ENABLED
SCOUT_ACTION_TOKEN='$SCOUT_ACTION_TOKEN'
SCOUT_ALLOWED_IPS=$(read_env_value SCOUT_ALLOWED_IPS)
SCOUT_BIND_HOST=$(read_env_value SCOUT_BIND_HOST)
SCOUT_BIND_PORT=$(read_env_value SCOUT_BIND_PORT)
SCOUT_REFRESH_SECONDS=$(read_env_value SCOUT_REFRESH_SECONDS)
SCOUT_MAX_CONNECTIONS=$(read_env_value SCOUT_MAX_CONNECTIONS)
SCOUT_MAX_EVENTS=$(read_env_value SCOUT_MAX_EVENTS)
SCOUT_LOGIN_ATTEMPTS=$(read_env_value SCOUT_LOGIN_ATTEMPTS)
SCOUT_LOGIN_WINDOW_SECONDS=$(read_env_value SCOUT_LOGIN_WINDOW_SECONDS)
ENV

# Значения по умолчанию для параметров, отсутствовавших в старом конфиге.
sed -i \
 -e 's/^SCOUT_BIND_HOST=$/SCOUT_BIND_HOST=127.0.0.1/' \
 -e 's/^SCOUT_BIND_PORT=$/SCOUT_BIND_PORT=8765/' \
 -e 's/^SCOUT_REFRESH_SECONDS=$/SCOUT_REFRESH_SECONDS=5/' \
 -e 's/^SCOUT_MAX_CONNECTIONS=$/SCOUT_MAX_CONNECTIONS=250/' \
 -e 's/^SCOUT_MAX_EVENTS=$/SCOUT_MAX_EVENTS=100/' \
 -e 's/^SCOUT_LOGIN_ATTEMPTS=$/SCOUT_LOGIN_ATTEMPTS=8/' \
 -e 's/^SCOUT_LOGIN_WINDOW_SECONDS=$/SCOUT_LOGIN_WINDOW_SECONDS=300/' \
 "$TMP_ENV"
install -m 0600 "$TMP_ENV" "$ENV_FILE"
rm -f "$TMP_ENV"
install -m 0644 "$INSTALL_DIR/systemd/scout-easy.service" /etc/systemd/system/scout-easy.service
install -m 0755 "$INSTALL_DIR/scout-easy-manager.sh" /usr/local/bin/scout-easy
systemctl daemon-reload; systemctl enable "$SERVICE" nginx >/dev/null; systemctl restart "$SERVICE" nginx
configure_https(){
 local target=$1 email=$2 mode=$3 webroot=/var/www/scout-easy-acme
 mkdir -p "$webroot/.well-known/acme-challenge"
 cat > /etc/nginx/sites-available/scout-easy <<NGINX
server { listen 80; listen [::]:80; server_name $target;
 location /.well-known/acme-challenge/ { root $webroot; }
 location / { proxy_pass http://127.0.0.1:8765; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto \$scheme; }
}
NGINX
 ln -sf /etc/nginx/sites-available/scout-easy /etc/nginx/sites-enabled/scout-easy; nginx -t; systemctl reload nginx
 if [[ $mode == domain ]]; then
  apt-get install -y certbot python3-certbot-nginx
  certbot --nginx -d "$target" --non-interactive --agree-tos -m "$email" --redirect
 else
  command -v snap >/dev/null || apt-get install -y snapd
  snap install core >/dev/null 2>&1 || true; snap refresh core >/dev/null 2>&1 || true; snap install --classic certbot >/dev/null 2>&1 || snap refresh certbot >/dev/null 2>&1
  ln -sf /snap/bin/certbot /usr/local/bin/certbot
  certbot certonly --preferred-profile shortlived --webroot --webroot-path "$webroot" --ip-address "$target" --non-interactive --agree-tos -m "$email"
  cat > /etc/nginx/sites-available/scout-easy <<NGINX
server { listen 80; listen [::]:80; server_name $target; return 301 https://\$host\$request_uri; }
server { listen 443 ssl; listen [::]:443 ssl; server_name $target;
 ssl_certificate /etc/letsencrypt/live/$target/fullchain.pem; ssl_certificate_key /etc/letsencrypt/live/$target/privkey.pem;
 location / { proxy_pass http://127.0.0.1:8765; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto https; }
}
NGINX
  nginx -t; systemctl reload nginx
 fi
}
if ! $NON_INTERACTIVE && [[ -t 0 ]]; then
 read -rp 'Настроить публичный HTTPS-доступ? [y/N]: ' yn
 if [[ $yn =~ ^[Yy]$ ]]; then
  read -rp 'Домен или публичный IP: ' target
  read -rp 'Email для Let’s Encrypt: ' email
  if [[ $target =~ ^[0-9a-fA-F:.]+$ ]]; then configure_https "$target" "$email" ip; else configure_https "$target" "$email" domain; fi
 fi
fi
sleep 1; systemctl is-active --quiet "$SERVICE" || { journalctl -u "$SERVICE" -n 50 --no-pager; exit 1; }
echo
echo 'SCOUT-EASY установлен.'
echo "Логин: $SCOUT_USERNAME"
echo "Пароль: $SCOUT_PASSWORD"
echo "Admin token: $SCOUT_ACTION_TOKEN"
echo 'Менеджер: sudo scout-easy' 
