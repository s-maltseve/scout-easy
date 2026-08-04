#!/usr/bin/env bash
set -Eeuo pipefail
ENV_FILE=/etc/scout-easy/scout-easy.env
SERVICE=scout-easy.service
REPO_DIR=${SCOUT_REPO_DIR:-$HOME/scout-easy}
need_root(){ [[ $EUID -eq 0 ]] || exec sudo "$0" "$@"; }
show_env(){ [[ -f "$ENV_FILE" ]] && grep -E '^(SCOUT_USERNAME|SCOUT_PASSWORD|SCOUT_ACTION_TOKEN|SCOUT_BIND_HOST|SCOUT_BIND_PORT|SCOUT_ACTIONS_ENABLED)=' "$ENV_FILE" || echo 'Конфигурация не найдена'; }
reset_secret(){
 local key=$1 length=40 value
 [[ $key == SCOUT_ACTION_TOKEN ]] && length=64
 value=$(python3 - "$length" <<'PY'
import secrets,string,sys
length=int(sys.argv[1]); special='!@#$%^&*_-+=:'
groups=[string.ascii_lowercase,string.ascii_uppercase,string.digits,special]
alphabet=''.join(groups)
chars=[secrets.choice(g) for g in groups]
chars += [secrets.choice(alphabet) for _ in range(length-len(chars))]
secrets.SystemRandom().shuffle(chars)
print(''.join(chars))
PY
 )
 if grep -q "^${key}=" "$ENV_FILE"; then
  sed -i "s|^${key}=.*|${key}='${value}'|" "$ENV_FILE"
 else
  printf "%s='%s'\n" "$key" "$value" >> "$ENV_FILE"
 fi
 chmod 600 "$ENV_FILE"
 systemctl restart "$SERVICE"
 echo "$key=$value"
}
while true; do
cat <<'MENU'

SCOUT-EASY Manager
1) Показать логин, пароль и admin token
2) Сбросить пароль
3) Сбросить admin token
4) Обновить из GitHub
5) Перезапустить сервис
6) Статус сервиса
7) Последние логи
8) Проверить/обновить сертификаты
9) Удалить SCOUT-EASY
0) Выход
MENU
read -rp 'Выбери пункт: ' n
case "$n" in
1) need_root "$@"; show_env;;
2) need_root "$@"; reset_secret SCOUT_PASSWORD;;
3) need_root "$@"; reset_secret SCOUT_ACTION_TOKEN;;
4) need_root "$@"; if [[ -d "$REPO_DIR/.git" ]]; then git -C "$REPO_DIR" pull --ff-only && bash "$REPO_DIR/install.sh" --non-interactive; else echo "Репозиторий не найден: $REPO_DIR"; fi;;
5) need_root "$@"; systemctl restart "$SERVICE";;
6) systemctl status "$SERVICE" --no-pager;;
7) journalctl -u "$SERVICE" -n 100 --no-pager;;
8) need_root "$@"; certbot renew --dry-run || true;;
9) need_root "$@"; read -rp 'Удалить SCOUT-EASY? [y/N] ' x; [[ $x =~ ^[Yy]$ ]] && bash /opt/scout-easy/uninstall.sh;;
0) exit 0;; *) echo 'Неизвестный пункт';;
esac
done
