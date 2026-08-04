# SCOUT-EASY

Лёгкая self-hosted панель безопасности Linux: SSH-сессии и события, Fail2ban, процессы, сетевые соединения и трафик.

![SCOUT-EASY](app/static/scout-easy-logo.png)

## Возможности

- активные SSH-сессии и отключение сессий;
- успешные и неудачные SSH-входы;
- просмотр jail Fail2ban, ручной бан и разбан IP;
- сетевые соединения с текущей и накопленной TCP-статистикой;
- трафик по процессам;
- CPU, RAM, диск и uptime;
- фильтры и сортировка;
- случайные логин, пароль и admin token на каждой новой установке;
- интерактивная настройка Nginx и HTTPS для домена или публичного IP;
- консольный менеджер `sudo scout-easy`.

## Поддерживаемые системы

Debian и Ubuntu с systemd. Установка выполняется от root.

## Установка

```bash
git clone https://github.com/s-maltseve/scout-easy.git
cd scout-easy
sudo bash install.sh
```

Установщик:

1. устанавливает Python, Nginx и необходимые пакеты;
2. размещает приложение в `/opt/scout-easy`;
3. создаёт `/etc/scout-easy/scout-easy.env`;
4. генерирует уникальные учётные данные;
5. запускает `scout-easy.service`;
6. предлагает настроить публичный HTTPS-доступ.

При настройке HTTPS укажи домен либо публичный IP и email. Для домена DNS-запись уже должна вести на сервер. Порты 80 и 443 должны быть доступны извне.

## Где посмотреть логин и пароль

Установщик выводит их в конце. Позже используй:

```bash
sudo scout-easy
```

Пункт 1 показывает логин, пароль и admin token. Напрямую:

```bash
sudo grep -E 'SCOUT_USERNAME|SCOUT_PASSWORD|SCOUT_ACTION_TOKEN' /etc/scout-easy/scout-easy.env
```

Файл доступен только root и имеет права `600`.

## Для чего нужен admin token

Обычный логин открывает панель. Отдельный admin token подтверждает опасные действия:

- отключение SSH-сессии;
- добавление IP в Fail2ban;
- удаление IP из Fail2ban.

Токен вводится при первом действии и хранится только в текущей вкладке браузера.

## Fail2ban

В блоке Fail2ban выбери jail, введи IPv4/IPv6 и нажми «Добавить в бан». У каждого заблокированного IP есть кнопка удаления из бана. Управляющие действия включены по умолчанию:

```env
SCOUT_ACTIONS_ENABLED=true
```

## Обновление

На сервере:

```bash
cd ~/scout-easy
git pull --ff-only origin main
sudo bash install.sh --non-interactive
```

Существующие логин, пароль, token и настройки сохраняются. Установщик останавливает старый процесс, копирует новый код и перезапускает службу.

Либо через менеджер:

```bash
sudo scout-easy
```

Выбери пункт «Обновить из GitHub».

## Управление

```bash
sudo scout-easy
```

Меню позволяет показать и сбросить учётные данные, обновить приложение, проверить статус, посмотреть логи, проверить сертификаты и удалить SCOUT-EASY.

Полезные команды:

```bash
sudo systemctl status scout-easy --no-pager
sudo systemctl restart scout-easy
sudo journalctl -u scout-easy -n 100 --no-pager
```

Проверка API:

```bash
source /etc/scout-easy/scout-easy.env
curl -u "$SCOUT_USERNAME:$SCOUT_PASSWORD" http://127.0.0.1:8765/api/health
```

## Публичный доступ и безопасность

Приложение остаётся на `127.0.0.1:8765`; наружу публикуется Nginx на 443. Не открывай 8765 в firewall.

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw delete allow 8765/tcp 2>/dev/null || true
```

Сертификаты для IP у Let’s Encrypt короткоживущие, поэтому автоматическое продление должно постоянно работать. Проверка:

```bash
sudo systemctl status certbot.timer --no-pager
sudo certbot renew --dry-run
```

## Удаление

```bash
sudo bash /opt/scout-easy/uninstall.sh
```

## Лицензия

MIT.
