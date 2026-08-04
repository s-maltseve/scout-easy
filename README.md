# SCOUT-EASY

SCOUT-EASY — лёгкая self-hosted панель мониторинга безопасности Linux-сервера.

Она показывает активные SSH-сессии, события входа, состояние Fail2ban, сетевые соединения, текущую скорость и общий объём трафика, системные показатели и процессы. При отдельном включении административного режима панель может завершать SSH-сессии, блокировать и разблокировать IP через Fail2ban.

## Что изменилось в версии 0.3.0

- исправлено обновление приложения: установщик теперь останавливает старый процесс и обязательно перезапускает службу;
- новый интерфейс больше не может работать со старым backend после обновления;
- ошибка одного сборщика не обрушает всю панель;
- добавлены безопасные значения по умолчанию для отсутствующих данных;
- frontend проверяет структуру API перед выводом значений;
- отключено кэширование HTML, JavaScript, CSS и API;
- добавлены защитные HTTP-заголовки;
- административный токен больше не передаётся внутри `/api/dashboard`;
- токен действий вводится вручную и хранится только до закрытия вкладки;
- сохранены фильтрация и сортировка процессов и соединений;
- сохранены текущая скорость и суммарный сетевой трафик.

## Возможности

- активные SSH-сессии;
- успешные и неудачные SSH-входы из systemd journal;
- состояние Fail2ban, jail и заблокированные IP;
- TCP/UDP-соединения, PID и процесс;
- фильтрация и сортировка соединений;
- процессы с сортировкой по CPU и RAM;
- фильтрация процессов;
- CPU, RAM, диск и uptime;
- входящий и исходящий трафик сейчас;
- полученный и отправленный трафик с момента запуска ОС;
- завершение SSH-сессий;
- ручной бан и разбан IP через Fail2ban;
- HTTP Basic авторизация и ограничение попыток входа;
- ограничение доступа по IP-подсетям.

## Поддерживаемые системы

- Debian 12 и новее;
- Ubuntu 22.04 и новее;
- Python 3.11 и новее;
- systemd.

## Установка

```bash
git clone https://github.com/s-maltseve/scout-easy.git
cd scout-easy
sudo bash install.sh
```

Установщик создаст конфигурацию:

```text
/etc/scout-easy/scout-easy.env
```

По умолчанию приложение слушает только:

```text
127.0.0.1:8765
```

Для безопасного доступа используй SSH-туннель:

```bash
ssh -L 8765:127.0.0.1:8765 root@IP_СЕРВЕРА
```

Затем открой:

```text
http://127.0.0.1:8765
```

## Обновление

```bash
cd ~/scout-easy
git pull --ff-only
sudo bash install.sh
```

Версия 0.3.0 корректно останавливает старый процесс, копирует файлы и запускает новый backend.

Проверка установленной версии:

```bash
curl -u admin:ПАРОЛЬ http://127.0.0.1:8765/api/health
```

Ожидаемый ответ:

```json
{"status":"ok","version":"0.3.0"}
```

## Конфигурация

```env
SCOUT_USERNAME=admin
SCOUT_PASSWORD=длинный-случайный-пароль
SCOUT_AUTH_ENABLED=true
SCOUT_ACTIONS_ENABLED=false
SCOUT_ACTION_TOKEN=отдельный-длинный-токен
SCOUT_ALLOWED_IPS=
SCOUT_BIND_HOST=127.0.0.1
SCOUT_BIND_PORT=8765
SCOUT_REFRESH_SECONDS=5
SCOUT_MAX_CONNECTIONS=250
SCOUT_MAX_EVENTS=100
SCOUT_LOGIN_ATTEMPTS=8
SCOUT_LOGIN_WINDOW_SECONDS=300
```

После изменений:

```bash
sudo systemctl restart scout-easy
```

## Включение административных действий

Открой конфигурацию:

```bash
sudo nano /etc/scout-easy/scout-easy.env
```

Измени:

```env
SCOUT_ACTIONS_ENABLED=false
```

на:

```env
SCOUT_ACTIONS_ENABLED=true
```

Перезапусти службу:

```bash
sudo systemctl restart scout-easy
```

При первом нажатии на административную кнопку интерфейс запросит `SCOUT_ACTION_TOKEN`. Он не приходит из API и сохраняется только в `sessionStorage` текущей вкладки.

Посмотреть токен на сервере:

```bash
sudo grep '^SCOUT_ACTION_TOKEN=' /etc/scout-easy/scout-easy.env
```

## Безопасная публикация

Не открывай порт `8765` напрямую в интернет по HTTP.

Рекомендуемая схема:

```text
Интернет → HTTPS/Nginx/Caddy или VPN → 127.0.0.1:8765
```

Минимальные требования:

- `SCOUT_BIND_HOST=127.0.0.1`;
- доступ через SSH-туннель, WireGuard, AmneziaWG или Tailscale;
- либо reverse proxy с HTTPS;
- длинный случайный пароль;
- отдельный токен для административных действий;
- `SCOUT_ALLOWED_IPS` при наличии постоянного адреса или VPN-подсети.

## Диагностика

```bash
sudo systemctl status scout-easy --no-pager
sudo journalctl -u scout-easy -n 100 --no-pager
sudo cat /etc/scout-easy/scout-easy.env
```

Проверка API с авторизацией:

```bash
curl -u admin:ПАРОЛЬ http://127.0.0.1:8765/api/dashboard
```

## Разработка

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
export SCOUT_AUTH_ENABLED=false
uvicorn app.main:app --reload --host 127.0.0.1 --port 8765
```

Тесты:

```bash
pytest
ruff check .
```

## Лицензия

MIT
