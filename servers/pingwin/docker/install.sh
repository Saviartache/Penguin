#!/usr/bin/env bash
#
# Ставит сервер Pingwin на этой машине: Docker, исходники, образ, сертификат,
# ключи, запуск. Выполняется на сервере под `root`, текст приходит на stdin:
#
#   ssh root@сервер 'PINGWIN_DOMAIN=vpn.example.com … bash -s' < install.sh
#
# Его зовут `deploy.sh` (из терминала) и `penguin deploy pingwin` (из окна).
# Ключ и пароли не трогаются, если уже есть: иначе разосланные ссылки
# перестали бы работать. Запускать можно сколько угодно раз.
#
# Окружение:
#   PINGWIN_DOMAIN   имя сервера; уже указывает сюда (обязательно)
#   PINGWIN_PORT     порт клиентов, udp и tcp              [443]
#   PINGWIN_EMAIL    почта для Let's Encrypt                [пусто]
#   PINGWIN_USER     пользователь, для которого ссылка      [client]
#   PINGWIN_PROFILE  имя профиля в клиенте                  [Pingwin <имя>]
#   PINGWIN_SOURCE   `uploaded` — исходники уже в /opt/pingwin, иначе адрес
#                    архива исходников (GitHub, тег версии клиента)
#   PINGWIN_MODE     `full` — весь путь, `user` — только пользователь и ссылка
#
# Ход — строками на stdout: `::step <шаг>`, `::ok <текст>`, `::info <текст>`,
# `::link <ссылка>`, `::fail <причина>`. Шаги: inspect docker memory source
# build cert keys start firewall check link. Остальной вывод — шум.

set -euo pipefail

# Каталог переопределяется только проверкой скрипта.
REMOTE_DIR="${PINGWIN_DIR:-/opt/pingwin}"
DOMAIN="${PINGWIN_DOMAIN:-}"
CLIENT_PORT="${PINGWIN_PORT:-443}"
CERT_EMAIL="${PINGWIN_EMAIL:-}"
USER_NAME="${PINGWIN_USER:-client}"
PROFILE_NAME="${PINGWIN_PROFILE:-Pingwin $DOMAIN}"
SOURCE="${PINGWIN_SOURCE:-}"
MODE="${PINGWIN_MODE:-full}"

step() { printf '::step %s\n' "$1"; }
ok()   { printf '::ok %s\n' "$1"; }
info() { printf '::info %s\n' "$1"; }
die()  { printf '::fail %s\n' "$1"; exit 1; }

TEMP=""
trap '[[ -n "$TEMP" ]] && rm -rf "$TEMP"; true' EXIT

# --- что спросили ------------------------------------------------------------

[[ "$(id -u)" == 0 ]] || die "нужны права root"
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "имя «$DOMAIN» не похоже на доменное"
[[ "$CLIENT_PORT" =~ ^[0-9]+$ ]] && (( CLIENT_PORT >= 1 && CLIENT_PORT <= 65535 )) \
    || die "порт «$CLIENT_PORT» вне 1–65535"
# Имя уходит в TOML как есть: кавычка сломала бы настройки сервера.
[[ "$USER_NAME" =~ ^[A-Za-z0-9._-]+$ ]] \
    || die "имя пользователя: латиница, цифры, точка, дефис, подчёркивание"
[[ "$PROFILE_NAME" != *"'"* ]] || die "в имени профиля не должно быть апострофа"
[[ "$MODE" == full || "$MODE" == user ]] || die "режим «$MODE» неизвестен"

# Пароль машинный: вводить его руками не придётся — он уедет в ссылку.
new_password() { head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '='; }

has_user() { grep -qxF "name = \"$USER_NAME\"" "$REMOTE_DIR/pingwin.toml"; }

# Дописывание, а не перезапись: файл примонтирован в живой контейнер, а
# bind-mount держит inode. Владелец и права при дописывании остаются прежними.
append_user() {
    printf '\n[[users]]\nname = "%s"\npassword = "%s"\n' "$USER_NAME" "$(new_password)" \
        >> "$REMOTE_DIR/pingwin.toml" || die "не дописал пользователя в $REMOTE_DIR/pingwin.toml"
}

# Ссылка собирается здесь: ключ и пароль лежат только тут.
print_link() {
    step link
    local link
    link="$(docker run --rm -v "$REMOTE_DIR/pingwin.toml:/etc/pingwin/pingwin.toml:ro" \
        pingwin-server:latest link --config /etc/pingwin/pingwin.toml --user "$USER_NAME" \
        --host "$DOMAIN:$CLIENT_PORT" --name "$PROFILE_NAME")" || die "ссылка не собралась"
    [[ -n "$link" ]] || die "ссылка не собралась"
    printf '::link %s\n' "$link"
}

# --- что уже стоит -----------------------------------------------------------

step inspect
DEPLOYED=0
if [[ -s "$REMOTE_DIR/pingwin.toml" ]] && docker image inspect pingwin-server:latest >/dev/null 2>&1; then
    DEPLOYED=1
    ok "сервер уже развёрнут; ключ и пароли останутся прежними"
else
    ok "чисто — ставлю с нуля"
fi

if [[ "$MODE" == user ]]; then
    [[ "$DEPLOYED" == 1 ]] || die "сервер ещё не развёрнут — нужен полный путь"
    step keys
    if has_user; then
        ok "$USER_NAME уже заведён — пароль прежний, ссылка будет та же"
    else
        append_user
        # Настройки читаются при старте: без перезапуска сервер о пароле не узнает.
        (cd "$REMOTE_DIR" && docker compose up -d pingwin && docker compose restart pingwin) \
            >/dev/null 2>&1 || die "сервер не перезапустился; docker compose logs pingwin"
        ok "$USER_NAME заведён, сервер перечитал настройки"
    fi
    print_link
    exit 0
fi

# --- Docker ------------------------------------------------------------------

step docker
if command -v docker >/dev/null 2>&1; then
    ok "уже стоит: $(docker --version)"
else
    info 'ставлю — это пара минут'
    export DEBIAN_FRONTEND=noninteractive
    (command -v apt-get >/dev/null && apt-get update -qq && apt-get install -y -qq curl ca-certificates) \
        >/dev/null 2>&1 || true
    { curl -fsSL https://get.docker.com -o /tmp/get-docker.sh \
        && sh /tmp/get-docker.sh >/tmp/docker-install.log 2>&1; } \
        || die "Docker не поставился; подробности на сервере в /tmp/docker-install.log"
    ok "поставлен: $(docker --version)"
fi
docker compose version >/dev/null 2>&1 || die "нет docker compose — обновите Docker на сервере"

# --- память ------------------------------------------------------------------

step memory
MEMORY="$(free -m 2>/dev/null | awk '/^Mem:/ {print $2}' || echo 0)"
if [[ "${MEMORY:-0}" -gt 0 && "${MEMORY:-0}" -lt 3000 ]]; then
    if swapon --show 2>/dev/null | grep -q .; then
        ok "своп уже есть; памяти ${MEMORY} МБ"
    else
        info "памяти ${MEMORY} МБ — добавляю 2 ГБ свопа, иначе сборка не доживёт до конца"
        if { fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null \
                && swapon /swapfile; } 2>/dev/null; then
            grep -q "^/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
            ok "своп добавлен"
        else
            info "своп не добавился — пробую собрать так"
        fi
    fi
else
    ok "памяти ${MEMORY:-?} МБ, свопа не нужно"
fi

# --- исходники ---------------------------------------------------------------

step source
mkdir -p "$REMOTE_DIR"
if [[ "$SOURCE" == uploaded ]]; then
    [[ -f "$REMOTE_DIR/Dockerfile" ]] || die "исходники не привезены в $REMOTE_DIR"
    ok "исходники привезены"
else
    [[ "$SOURCE" == https://* ]] || die "не задано, откуда брать исходники"
    command -v curl >/dev/null 2>&1 || die "нет curl — поставьте его на сервере"
    TEMP="$(mktemp -d)"
    info "качаю $SOURCE"
    curl -fsSL "$SOURCE" | tar -xz -C "$TEMP" --strip-components=1 \
        || die "исходники не скачались: есть ли выпуск этой версии на GitHub?"
    bash "$TEMP/servers/pingwin/docker/stage.sh" "$TEMP/context" >/dev/null \
        || die "исходники не разложились"
    # Старые исходники сносятся, настройки — нет. `cover` не сносится: он
    # примонтирован в живой контейнер, и новая папка осталась бы ему не видна.
    rm -rf "$REMOTE_DIR/crates" "$REMOTE_DIR/protocols" "$REMOTE_DIR/servers"
    cp -R "$TEMP/context/." "$REMOTE_DIR/"
    ok "исходники на месте"
fi

# `PINGWIN_DOMAIN` compose не читает: он нужен продлению сертификата.
printf 'PINGWIN_PORT=%s\nPINGWIN_DOMAIN=%s\n' "$CLIENT_PORT" "$DOMAIN" > "$REMOTE_DIR/.env"
cd "$REMOTE_DIR"

# --- сборка ------------------------------------------------------------------

step build
info 'первый раз это минуты: сервер собирается из исходников на месте'
docker compose build --quiet >/dev/null 2>&1 || die "образ не собрался; cd $REMOTE_DIR && docker compose build"
ok "образ готов"

# --- сертификат --------------------------------------------------------------

step cert
ufw_active() { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; }
if [[ -d "letsencrypt/live/$DOMAIN" ]]; then
    ok "уже выписан на $DOMAIN"
else
    if [[ -n "$CERT_EMAIL" ]]; then
        CERT_CONTACT=(--email "$CERT_EMAIL")
    else
        CERT_CONTACT=(--register-unsafely-without-email)
    fi
    if ufw_active && ufw allow 80/tcp >/dev/null 2>&1; then
        ok "порт 80/tcp открыт в ufw для проверки имени"
    fi
    info "прошу Let's Encrypt — он сходит на http://$DOMAIN/"
    docker compose run --rm --service-ports certbot certonly --standalone -d "$DOMAIN" \
        --agree-tos -n "${CERT_CONTACT[@]}" >/dev/null 2>&1 \
        || die "сертификат не выписан: $DOMAIN указывает на этот сервер? порт 80/tcp открыт?"
    ok "выписан на $DOMAIN"
fi
bash "$REMOTE_DIR/renew.sh" >/dev/null 2>&1 || die "сертификат не разложился для сервера"

# Сертификат живёт 90 дней. Продление — раз в неделю: certbot сам решает,
# пора ли, а сервер перезапускается, только если файл сменился.
# `|| true`: без crontab `grep` ничего не находит, а `set -e` оборвал бы строку.
if { crontab -l 2>/dev/null | grep -v pingwin-renew || true; \
    echo "17 4 * * 1 bash $REMOTE_DIR/renew.sh >/dev/null 2>&1 # pingwin-renew"; } | crontab - 2>/dev/null; then
    ok "продление раз в неделю — в cron"
else
    info "cron не настроился: продлевайте руками — bash $REMOTE_DIR/renew.sh"
fi

# --- ключи и настройки -------------------------------------------------------

step keys
if [[ -s pingwin.toml ]]; then
    ok "настройки уже есть — ключ и пароли не трогаю"
    if has_user; then
        ok "$USER_NAME уже заведён"
    else
        append_user
        ok "$USER_NAME заведён"
    fi
else
    SERVER_KEY="$(docker run --rm pingwin-server:latest keygen | sed -n 's/^key = "\(.*\)"$/\1/p')"
    [[ -n "$SERVER_KEY" ]] || die "ключ не сгенерировался"
    cat > pingwin.toml <<PINGWIN_CONFIG
# Настройки сервера Pingwin. Созданы при развёртывании.
# Ключ и пароли есть только здесь — не копируйте этот файл никуда.

# UDP и TCP. Внутри контейнера порт непривилегированный: наружу его публикует
# compose.yml на том, который спросили при развёртывании.
listen = "0.0.0.0:8443"

key = "$SERVER_KEY"

# Сертификат на $DOMAIN; его раскладывает и продлевает renew.sh.
cert = "/etc/pingwin/certs/fullchain.pem"
cert_key = "/etc/pingwin/certs/privkey.pem"

# Сайт, который видит тот, кто не прошёл опознание.
cover = "/srv/cover"

[[users]]
name = "$USER_NAME"
password = "$(new_password)"
PINGWIN_CONFIG
    # Владелец — тот, под кем сервер работает в контейнере (Dockerfile, uid 10001).
    chown 10001:10001 pingwin.toml && chmod 600 pingwin.toml
    ok "ключ заведён, пользователь — $USER_NAME"
fi

# --- запуск ------------------------------------------------------------------

step start
# `--force-recreate`: иначе контейнер с прошлого раза читал бы прежние файлы.
docker compose up -d --force-recreate --remove-orphans >/dev/null 2>&1 \
    || die "не поднялось; docker compose logs pingwin"
sleep 5
docker compose ps --format '{{.Service}} {{.Status}}' | grep -q 'pingwin.*Up' \
    || die "сервер не запустился; docker compose logs pingwin"
ok "работает"

# --- брандмауэр --------------------------------------------------------------

step firewall
if ufw_active; then
    ufw allow "$CLIENT_PORT/udp" >/dev/null 2>&1 && ufw allow "$CLIENT_PORT/tcp" >/dev/null 2>&1 \
        && ok "порт $CLIENT_PORT (udp и tcp) открыт в ufw" \
        || info "ufw не открыл порт $CLIENT_PORT — откройте руками"
else
    ok "ufw не включён; порт $CLIENT_PORT у хостера должен быть открыт для udp и tcp"
fi

# --- проверка ----------------------------------------------------------------

step check
if curl -sS --http2 --max-time 15 -o /dev/null --resolve "$DOMAIN:$CLIENT_PORT:127.0.0.1" \
    "https://$DOMAIN:$CLIENT_PORT/" 2>/dev/null; then
    ok "сервер отвечает сайтом прикрытия"
else
    info "сервер не ответил на этой машине — посмотрите docker compose logs pingwin"
fi

print_link
