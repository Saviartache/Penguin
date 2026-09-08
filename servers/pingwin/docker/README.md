# Сервер Pingwin в Docker

Два контейнера: сервер и прикрытие — настоящий сайт, к которому уходят
соединения, не прошедшие опознание. Без прикрытия сервер закрывает чужую
пробу, а обычный сайт так себя не ведёт — по этому его и находят.

---

## Одной командой

```bash
bash servers/pingwin/deploy.sh
```

Спросит адрес сервера, доступ по SSH, порт и имя прикрытия. Дальше сам:
поставит Docker, увезёт исходники, соберёт образ, заведёт ключи, поднимет всё
и напечатает ссылку-приглашение.

Запускать можно сколько угодно раз: ключ и пароли не трогаются, ссылка та же.
На сервере нужен только доступ по SSH и выход в интернет.

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
docker run --rm pingwin-server:latest keygen   # если образ уже собран
```

Первая строка вывода — закрытый ключ, он идёт в `pingwin.toml` рядом с
`compose.yml`:

```toml
listen   = "0.0.0.0:8443"   # внутри контейнера; наружу это 443
key      = "<закрытый ключ>"
fallback = "cover:80"       # имя службы прикрытия из compose.yml

[[users]]
name     = "petya"
password = "<длинный случайный пароль>"
```

Права обязательны: в файле закрытый ключ, а номер владельца — тот, под которым
работает сервер внутри контейнера (`Dockerfile`, `--uid 10001`).

```bash
chown 10001:10001 pingwin.toml && chmod 600 pingwin.toml
docker compose up -d --build
docker compose logs -f pingwin
```

Первая сборка занимает минуты: сервер собирается из исходников на месте — он
обязан быть из того же дерева, что и клиент.

---

## Профиль клиента

```bash
docker compose run --rm --no-deps --entrypoint pingwin-server pingwin \
    link --config /etc/pingwin/pingwin.toml --host СЕРВЕР:443
```

Полученную ссылку вставляют в клиент: «Добавить сервер» → «Ссылка». Руками то
же самое: протокол `pingwin`, адрес `СЕРВЕР:443`, публичный ключ из `keygen`,
пароль из `[[users]]`, имя прикрытия — любое существующее доменное имя.

---

## Обновить

```bash
bash servers/pingwin/deploy.sh
```

Или руками:

```bash
bash servers/pingwin/docker/stage.sh /tmp/pingwin-ctx
rsync -a --delete --exclude target --exclude pingwin.toml /tmp/pingwin-ctx/ root@СЕРВЕР:/opt/pingwin/
ssh root@СЕРВЕР 'cd /opt/pingwin && docker compose up -d --build --force-recreate'
```

`--exclude pingwin.toml` обязателен: ключ и пароли живут только на сервере.

`--force-recreate` — тоже. `up -d` пересоздаёт только то, у чего изменился
образ, а `pingwin.toml` и папка прикрытия примонтированы. Docker держит
**inode**, а не путь: папка, снесённая и созданная заново, до контейнера не
доедет — nginx останется с прежней и ответит `403`. Поэтому и настройки после
правки требуют пересоздания контейнера, а не перезапуска.

---

## Что где лежит

| Файл | Что это |
|---|---|
| `../deploy.sh` | развёртывание одной командой |
| `Dockerfile` | сборка сервера из исходников, образ на `debian-slim` |
| `workspace.toml` | корень workspace на шесть крейтов; `stage.sh` кладёт его в контекст как `Cargo.toml` |
| `stage.sh` | вырезает из репозитория контекст сборки |
| `dockerignore` | ложится в контекст как `.dockerignore`: держит `target/` и ключ подальше от образа |
| `compose.yml` | сервер и прикрытие |
| `cover/` | сайт прикрытия |
| `pingwin.toml` | ключ и пользователи; создаётся на сервере, в репозиторий не входит |
