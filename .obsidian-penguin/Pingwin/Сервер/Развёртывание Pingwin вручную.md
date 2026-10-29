---
type: инструкция
summary: stage.sh, rsync, certbot, keygen и запуск compose по шагам
code: servers/pingwin/docker
tags:
  - pingwin
  - сервер
  - развёртывание
---

# Развёртывание Pingwin вручную

## 1. Контекст сборки — на машине с репозиторием

```bash
bash servers/pingwin/docker/stage.sh /tmp/pingwin-ctx
rsync -a --delete --exclude target /tmp/pingwin-ctx/ root@СЕРВЕР:/opt/pingwin/
```

## 2. Сертификат и образ — на сервере

```bash
cd /opt/pingwin
printf 'PINGWIN_PORT=443\nPINGWIN_DOMAIN=vpn.example.com\n' > .env
docker compose run --rm --service-ports certbot certonly --standalone \
    -d vpn.example.com --agree-tos --register-unsafely-without-email -n
bash renew.sh                                     # раскладывает сертификат в certs/
docker compose build
```

## 3. Ключ

```bash
docker run --rm pingwin-server:latest keygen
```

Первая строка вывода — закрытый ключ → `pingwin.toml`, см.
[[Настройки сервера Pingwin]].

## 4. Запуск и продление

```bash
chown 10001:10001 pingwin.toml && chmod 600 pingwin.toml
docker compose up -d
echo '17 4 * * 1 bash /opt/pingwin/renew.sh # pingwin-renew' | crontab -
```

Дальше: [[Профиль клиента Pingwin]].
