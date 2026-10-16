# Сервер Pingwin в Docker

Один контейнер: сервер HTTP/3 на UDP. Прикрытие он отдаёт сам — каталог
`cover/html` видит тот, кто не прошёл опознание. Сертификат выписывает
Let's Encrypt (служба `certbot`, запускается только по требованию).

Нужно доменное имя, указывающее на сервер, и открытый порт 80/tcp на время
проверки имени.

---

## Одной командой

```bash
bash servers/pingwin/deploy.sh
```

Спросит адрес сервера, доступ по SSH, доменное имя и порт. Дальше сам:
поставит Docker, увезёт исходники, соберёт образ, выпишет сертификат, заведёт
ключи, поставит продление в cron, поднимет сервер и напечатает
ссылку-приглашение.

Порт по умолчанию — **443/udp**: там браузеры ищут HTTP/3.

Запускать можно сколько угодно раз: ключ и пароли не трогаются, ссылка та же.

---

## Руками

На машине с репозиторием:

```bash
bash servers/pingwin/docker/stage.sh /tmp/pingwin-ctx
rsync -a --delete --exclude target /tmp/pingwin-ctx/ root@СЕРВЕР:/opt/pingwin/
```

На сервере:

```bash
cd /opt/pingwin
printf 'PINGWIN_PORT=443\nPINGWIN_DOMAIN=vpn.example.com\n' > .env
docker compose run --rm --service-ports certbot certonly --standalone \
    -d vpn.example.com --agree-tos --register-unsafely-without-email -n
bash renew.sh                                     # раскладывает сертификат в certs/
docker compose build
docker run --rm pingwin-server:latest keygen
```

Первая строка вывода `keygen` — закрытый ключ, он идёт в `pingwin.toml`:

```toml
listen   = "0.0.0.0:8443"                        # внутри контейнера; наружу 443/udp
key      = "<закрытый ключ>"
cert     = "/etc/pingwin/certs/fullchain.pem"
cert_key = "/etc/pingwin/certs/privkey.pem"
cover    = "/srv/cover"

[[users]]
name     = "petya"
password = "<длинный случайный пароль>"
```

Права обязательны: в файле закрытый ключ, а номер владельца — тот, под которым
работает сервер внутри контейнера (`Dockerfile`, `--uid 10001`).

```bash
chown 10001:10001 pingwin.toml && chmod 600 pingwin.toml
docker compose up -d
echo '17 4 * * 1 bash /opt/pingwin/renew.sh # pingwin-renew' | crontab -
```

---

## Профиль клиента

```bash
docker compose run --rm --no-deps --entrypoint pingwin-server pingwin \
    link --config /etc/pingwin/pingwin.toml --host vpn.example.com:443
```

Полученную ссылку вставляют в клиент: «Добавить сервер» → «Ссылка».

---

## Обновить

```bash
bash servers/pingwin/deploy.sh
```

Или руками:

```bash
bash servers/pingwin/docker/stage.sh /tmp/pingwin-ctx
rsync -a --delete --exclude target --exclude pingwin.toml --exclude .env \
    --exclude certs --exclude letsencrypt /tmp/pingwin-ctx/ root@СЕРВЕР:/opt/pingwin/
ssh root@СЕРВЕР 'cd /opt/pingwin && docker compose up -d --build --force-recreate'
```

`--exclude` обязательны: ключ, пароли и сертификат живут только на сервере.
`--force-recreate` — тоже: примонтированные файлы Docker держит по inode, и
контейнер без пересоздания читал бы прежние.

---

## Что где лежит

| Файл | Что это |
|---|---|
| `../deploy.sh` | развёртывание одной командой |
| `Dockerfile` | сборка сервера из исходников, образ на `debian-slim` |
| `workspace.toml` | корень workspace на пять крейтов; `stage.sh` кладёт его в контекст как `Cargo.toml` |
| `stage.sh` | вырезает из репозитория контекст сборки |
| `dockerignore` | ложится в контекст как `.dockerignore`: держит `target/`, ключ и сертификат подальше от образа |
| `compose.yml` | сервер и `certbot` |
| `renew.sh` | продление сертификата и перезапуск сервера, если он сменился |
| `cover/html` | сайт прикрытия |
| `pingwin.toml` | ключ и пользователи; создаётся на сервере, в репозиторий не входит |
