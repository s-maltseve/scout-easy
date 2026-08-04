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
if [[ ! -f "$CONFIG_DIR/scout-easy.env" ]]; then
 readarray -t G < <(python3 - <<'PY'
import secrets,string
r=secrets.SystemRandom(); user='scout-'+''.join(r.choice(string.ascii_lowercase+string.digits) for _ in range(12))
def strong(n=32):
 g=[string.ascii_lowercase,string.ascii_uppercase,string.digits,'!@#$%^&*_-+=']; a=[r.choice(x) for x in g]+[r.choice(''.join(g)) for _ in range(n-len(g))]; r.shuffle(a); return ''.join(a)
print(user); print(strong()); print(strong(48))
PY
 )
 cat > "$CONFIG_DIR/scout-easy.env" <<ENV
SCOUT_USERNAME='${G[0]}'
SCOUT_PASSWORD='${G[1]}'
SCOUT_AUTH_ENABLED=true
SCOUT_ACTIONS_ENABLED=true
SCOUT_ACTION_TOKEN='${G[2]}'
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
 echo "Логин: ${G[0]}"; echo "Пароль: ${G[1]}"; echo "Admin token: ${G[2]}"
else echo "Существующий конфиг сохранён"; fi
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
source "$CONFIG_DIR/scout-easy.env"
echo; echo 'SCOUT-EASY установлен.'; echo "Логин: $SCOUT_USERNAME"; echo "Пароль: $SCOUT_PASSWORD"; echo "Admin token: $SCOUT_ACTION_TOKEN"; echo 'Менеджер: sudo scout-easy'
