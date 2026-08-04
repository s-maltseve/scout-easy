#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Запусти: sudo bash install.sh'; exit 1; }
command -v apt-get >/dev/null || { echo 'Поддерживаются Debian/Ubuntu'; exit 1; }
INSTALL_DIR=/opt/scout-easy
CONFIG_DIR=/etc/scout-easy
ENV_FILE="$CONFIG_DIR/scout-easy.env"
SERVICE=scout-easy.service
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
NON_INTERACTIVE=false
[[ ${1:-} == --non-interactive ]] && NON_INTERACTIVE=true

apt-get update
apt-get install -y python3 python3-venv python3-pip rsync curl nginx qrencode
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" /var/lib/scout-easy
chmod 700 /var/lib/scout-easy
systemctl stop "$SERVICE" 2>/dev/null || true
rsync -a --delete --exclude .git --exclude .venv --exclude __pycache__ --exclude .pytest_cache "$SOURCE_DIR/" "$INSTALL_DIR/"
[[ -x "$INSTALL_DIR/.venv/bin/python3" ]] || python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

read_env_value() {
 local key="$1"
 [[ -f "$ENV_FILE" ]] || return 0
 "$INSTALL_DIR/.venv/bin/python3" - "$ENV_FILE" "$key" <<'PY'
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
PY
}

generate_username() { "$INSTALL_DIR/.venv/bin/python3" - <<'PY'
import secrets,string
print('scout-' + ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(12)))
PY
}
generate_password() { "$INSTALL_DIR/.venv/bin/python3" - <<'PY'
import secrets,string
special='!@#$%^&*_-+=:'
groups=[string.ascii_lowercase,string.ascii_uppercase,string.digits,special]
alphabet=''.join(groups)
while True:
 c=[secrets.choice(g) for g in groups]+[secrets.choice(alphabet) for _ in range(36)]
 secrets.SystemRandom().shuffle(c); p=''.join(c)
 if all(any(x in g for x in p) for g in groups): print(p); break
PY
}
hash_password() { "$INSTALL_DIR/.venv/bin/python3" - "$1" <<'PY'
import sys
sys.path.insert(0, '/opt/scout-easy')
from app.security import hash_password
print(hash_password(sys.argv[1]))
PY
}
generate_totp() { "$INSTALL_DIR/.venv/bin/python3" - <<'PY'
import sys
sys.path.insert(0, '/opt/scout-easy')
from app.security import generate_totp_secret
print(generate_totp_secret())
PY
}

SCOUT_USERNAME="$(read_env_value SCOUT_USERNAME)"
SCOUT_PASSWORD_HASH="$(read_env_value SCOUT_PASSWORD_HASH)"
LEGACY_PASSWORD="$(read_env_value SCOUT_PASSWORD)"
SCOUT_TOTP_SECRET="$(read_env_value SCOUT_TOTP_SECRET)"
SCOUT_ACTIONS_ENABLED="$(read_env_value SCOUT_ACTIONS_ENABLED)"
SCOUT_USERNAME=${SCOUT_USERNAME:-$(generate_username)}
SCOUT_ACTIONS_ENABLED=${SCOUT_ACTIONS_ENABLED:-true}
NEW_PASSWORD=""
if [[ -z "$SCOUT_PASSWORD_HASH" ]]; then
  NEW_PASSWORD=${LEGACY_PASSWORD:-$(generate_password)}
  SCOUT_PASSWORD_HASH="$(hash_password "$NEW_PASSWORD")"
fi
if [[ -z "$SCOUT_TOTP_SECRET" ]]; then
  SCOUT_TOTP_SECRET="$(generate_totp)"
fi

value_or_default(){ local key=$1 def=$2 value; value="$(read_env_value "$key")"; printf '%s' "${value:-$def}"; }
SESSION_MINUTES="$(value_or_default SCOUT_SESSION_MINUTES 480)"
[[ "$SESSION_MINUTES" == "30" ]] && SESSION_MINUTES=480
TMP_ENV=$(mktemp)
cat > "$TMP_ENV" <<ENV
SCOUT_USERNAME='$SCOUT_USERNAME'
SCOUT_PASSWORD_HASH='$SCOUT_PASSWORD_HASH'
SCOUT_TOTP_SECRET='$SCOUT_TOTP_SECRET'
SCOUT_TOTP_ISSUER='SCOUT-EASY'
SCOUT_ACTIONS_ENABLED=$SCOUT_ACTIONS_ENABLED
SCOUT_ALLOWED_IPS=$(value_or_default SCOUT_ALLOWED_IPS '')
SCOUT_BIND_HOST=$(value_or_default SCOUT_BIND_HOST 127.0.0.1)
SCOUT_BIND_PORT=$(value_or_default SCOUT_BIND_PORT 8765)
SCOUT_REFRESH_SECONDS=$(value_or_default SCOUT_REFRESH_SECONDS 5)
SCOUT_MAX_CONNECTIONS=$(value_or_default SCOUT_MAX_CONNECTIONS 250)
SCOUT_MAX_EVENTS=$(value_or_default SCOUT_MAX_EVENTS 100)
SCOUT_LOGIN_ATTEMPTS=$(value_or_default SCOUT_LOGIN_ATTEMPTS 3)
SCOUT_LOGIN_WINDOW_SECONDS=$(value_or_default SCOUT_LOGIN_WINDOW_SECONDS 600)
SCOUT_LOGIN_BLOCK_SECONDS=$(value_or_default SCOUT_LOGIN_BLOCK_SECONDS 21600)
SCOUT_SESSION_MINUTES=$SESSION_MINUTES
SCOUT_SECURE_COOKIE=$(value_or_default SCOUT_SECURE_COOKIE true)
ENV
install -m 0600 "$TMP_ENV" "$ENV_FILE"
rm -f "$TMP_ENV"
install -m 0644 "$INSTALL_DIR/systemd/scout-easy.service" /etc/systemd/system/scout-easy.service
install -m 0755 "$INSTALL_DIR/scout-easy-manager.sh" /usr/local/bin/scout-easy
systemctl daemon-reload
systemctl enable "$SERVICE" nginx >/dev/null
systemctl restart "$SERVICE" nginx

configure_https(){
 local target=$1 email=$2
 apt-get install -y certbot python3-certbot-nginx
 cat > /etc/nginx/sites-available/scout-easy <<NGINX
server {
 listen 80; listen [::]:80;
 server_name $target;
 location / {
  proxy_pass http://127.0.0.1:8765;
  proxy_set_header Host \$host;
  proxy_set_header X-Real-IP \$remote_addr;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto \$scheme;
 }
}
NGINX
 ln -sf /etc/nginx/sites-available/scout-easy /etc/nginx/sites-enabled/scout-easy
 nginx -t && systemctl reload nginx
 certbot --nginx -d "$target" --non-interactive --agree-tos -m "$email" --redirect
}
if ! $NON_INTERACTIVE && [[ -t 0 ]]; then
 read -rp 'Настроить публичный HTTPS-доступ для домена? [y/N]: ' yn
 if [[ $yn =~ ^[Yy]$ ]]; then
  read -rp 'Домен: ' target
  read -rp 'Email для Let’s Encrypt: ' email
  configure_https "$target" "$email"
 fi
fi
sleep 1
systemctl is-active --quiet "$SERVICE" || { journalctl -u "$SERVICE" -n 80 --no-pager; exit 1; }

URI="$($INSTALL_DIR/.venv/bin/python3 - "$SCOUT_TOTP_SECRET" "$SCOUT_USERNAME" <<'PY'
import sys
sys.path.insert(0, '/opt/scout-easy')
from app.security import provisioning_uri
print(provisioning_uri(sys.argv[1], sys.argv[2]))
PY
)"
echo
echo 'SCOUT-EASY 0.8.0 установлен.'
echo "Логин: $SCOUT_USERNAME"
if [[ -n "$NEW_PASSWORD" ]]; then echo "Пароль: $NEW_PASSWORD"; else echo 'Пароль сохранён. Для смены: sudo scout-easy'; fi
echo 'Добавь 2FA в Aegis, 2FAS, Bitwarden или Google Authenticator:'
qrencode -t ANSIUTF8 "$URI" || true
echo "Секрет 2FA: $SCOUT_TOTP_SECRET"
echo 'Менеджер: sudo scout-easy'
