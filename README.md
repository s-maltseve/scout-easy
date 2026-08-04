# SCOUT-EASY

Lightweight, read-only Linux security dashboard for a single Debian/Ubuntu server.

## What it shows

- active login/SSH sessions;
- successful and failed SSH authentication events from systemd journal;
- Fail2ban status, jails and banned addresses;
- active TCP/UDP connections, PIDs and process names;
- CPU, RAM, disk, load and uptime;
- top processes and basic warnings.

SCOUT-EASY работает в режиме только чтения по умолчанию. Управляющие действия версии 0.2.0 включаются отдельно в конфигурации.

## Supported systems

- Debian 12+
- Ubuntu 22.04+
- Python 3.11+
- systemd

Other Linux distributions may work when installed manually.

## Quick installation from GitHub

```bash
git clone https://github.com/YOUR-USERNAME/scout-easy.git
cd scout-easy
sudo bash install.sh
```

The installer generates a random password and binds the service to `127.0.0.1:8765`.

Open it safely through an SSH tunnel:

```bash
ssh -L 8765:127.0.0.1:8765 your-user@your-server
```

Then visit:

```text
http://127.0.0.1:8765
```

## Configuration

Configuration is stored at:

```text
/etc/scout-easy/scout-easy.env
```

Example:

```env
SCOUT_USERNAME=admin
SCOUT_PASSWORD=use-a-long-random-password
SCOUT_AUTH_ENABLED=true
SCOUT_BIND_HOST=127.0.0.1
SCOUT_BIND_PORT=8765
SCOUT_REFRESH_SECONDS=5
SCOUT_MAX_CONNECTIONS=250
SCOUT_MAX_EVENTS=100
```

After editing:

```bash
sudo systemctl restart scout-easy
```

## Service management

```bash
sudo systemctl status scout-easy
sudo journalctl -u scout-easy -f
sudo systemctl restart scout-easy
```

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
export SCOUT_AUTH_ENABLED=false
uvicorn app.main:app --reload --host 127.0.0.1 --port 8765
```

API documentation:

```text
http://127.0.0.1:8765/api/docs
```

Run tests:

```bash
pytest
ruff check .
```

## Security notes

- Keep the default loopback binding and use an SSH tunnel, VPN, or authenticated reverse proxy.
- Do not expose port 8765 directly to the public internet.
- The service currently runs as root because process-to-connection mapping, journal access and Fail2ban inspection often require elevated permissions.
- The systemd unit applies several sandboxing restrictions and the application exposes no write actions.
- HTTP Basic credentials are only safe over an encrypted tunnel or HTTPS.

## Roadmap

- configurable alert rules;
- Telegram notifications;
- persistent event history;
- nftables/UFW module with narrowly scoped privileged helper;
- multi-server hub and agent architecture;
- GeoIP enrichment;
- package/release installation without Git.

## License

MIT

## Управляющие действия (v0.2)

По умолчанию SCOUT-EASY работает только на чтение. Чтобы включить завершение SSH-сессий и управление банами Fail2ban:

```bash
sudo nano /etc/scout-easy/scout-easy.env
```

Установите:

```env
SCOUT_ACTIONS_ENABLED=true
```

Затем перезапустите службу:

```bash
sudo systemctl restart scout-easy
```

Действия требуют HTTP Basic-аутентификацию и отдельный `SCOUT_ACTION_TOKEN`, проверяются на сервере и записываются в журнал systemd.

## Безопасный публичный доступ

Не публикуйте порт 8765 напрямую через HTTP. Рекомендуемая схема:

```text
Интернет → HTTPS (Nginx/Caddy) → 127.0.0.1:8765
```

Дополнительно можно ограничить доступ IP-адресами:

```env
SCOUT_ALLOWED_IPS=127.0.0.1/32,192.168.1.0/24
```

Для доступа из любой сети оставьте значение пустым, но обязательно используйте HTTPS, длинный случайный пароль и при возможности VPN/Tailscale/WireGuard.


## Новое в 0.4.0

- текущая входящая и исходящая скорость по активным TCP-соединениям;
- накопленный TCP-трафик по соединению;
- агрегирование трафика по процессам;
- фильтр, сортировка, скрытие loopback и пассивных сокетов;
- ручное добавление IP в выбранный Fail2ban jail;
- удаление IP из бана непосредственно из панели;
- административные действия требуют `SCOUT_ACTIONS_ENABLED=true` и отдельный `SCOUT_ACTION_TOKEN`.

> Счётчики соединений берутся из `ss -tinpH`. Для UDP, LISTEN и TIME_WAIT точные счётчики не отображаются.


Установщик сохраняет существующий `/etc/scout-easy/scout-easy.env` при обновлении. При первой установке он создаёт уникальный логин вида `scout-xxxxxxxxxxxx`, пароль длиной 32 символа с буквами в обоих регистрах, цифрами и спецсимволами, а также отдельный административный токен. Генерация использует криптографически стойкий системный источник случайности.
