#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || exec sudo "$0" "$@"
ENV_FILE=/etc/scout-easy/scout-easy.env
PY=/opt/scout-easy/.venv/bin/python3
get(){ sed -n "s/^$1=//p" "$ENV_FILE" | head -1 | sed "s/^['\"]//;s/['\"]$//"; }
setv(){ local key=$1 value=$2; sed -i "/^${key}=/d" "$ENV_FILE"; printf "%s='%s'\n" "$key" "$value" >> "$ENV_FILE"; chmod 600 "$ENV_FILE"; }
while true; do
 echo; echo 'SCOUT-EASY Manager'; echo '1) Показать логин и QR-код 2FA'; echo '2) Сбросить пароль'; echo '3) Пересоздать 2FA'; echo '4) Перезапустить сервис'; echo '5) Статус'; echo '6) Логи'; echo '0) Выход'; read -rp '> ' choice
 case $choice in
 1) u=$(get SCOUT_USERNAME); s=$(get SCOUT_TOTP_SECRET); uri=$($PY - "$s" "$u" <<'PY'
import sys
sys.path.insert(0, '/opt/scout-easy')
from app.security import provisioning_uri
print(provisioning_uri(sys.argv[1], sys.argv[2]))
PY
); echo "Логин: $u"; qrencode -t ANSIUTF8 "$uri"; echo "Секрет: $s";;
 2) read -rsp 'Новый пароль (пусто = сгенерировать): ' p; echo; [[ -n "$p" ]] || p=$($PY - <<'PY'
import secrets,string
chars=string.ascii_letters+string.digits+'!@#$%^&*_-+=:'
print(''.join(secrets.choice(chars) for _ in range(40)))
PY
); h=$($PY - "$p" <<'PY'
import sys
sys.path.insert(0, '/opt/scout-easy')
from app.security import hash_password
print(hash_password(sys.argv[1]))
PY
); setv SCOUT_PASSWORD_HASH "$h"; systemctl restart scout-easy; echo "Новый пароль: $p";;
 3) s=$($PY - <<'PY'
import sys
sys.path.insert(0, '/opt/scout-easy')
from app.security import generate_totp_secret
print(generate_totp_secret())
PY
); setv SCOUT_TOTP_SECRET "$s"; systemctl restart scout-easy; echo '2FA пересоздана. Выбери пункт 1 и отсканируй QR.';;
 4) systemctl restart scout-easy; echo OK;;
 5) systemctl status scout-easy --no-pager;;
 6) journalctl -u scout-easy -n 100 --no-pager;;
 0) exit 0;; esac
done
