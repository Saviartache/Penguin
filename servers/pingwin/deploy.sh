#!/usr/bin/env bash
#
# Разворачивает сервер Pingwin на чужой машине от начала и до конца.
#
#   bash servers/pingwin/deploy.sh
#
# Спрашивает, куда ставить, и делает всё остальное сам: ставит Docker, увозит
# исходники, собирает образ, получает сертификат Let's Encrypt, заводит ключи,
# поднимает сервер и печатает ссылку-приглашение для клиента.
#
# Запускать можно сколько угодно раз: скрипт сначала смотрит, что уже стоит на
# сервере, и на повторном запуске предлагает просто завести ещё одного
# пользователя и выдать ему ссылку, ничего не пересобирая. Ключ и пароли не
# трогаются в любом случае — иначе разосланные ссылки перестали бы работать.
#
# Что нужно на этой машине: ssh, tar и OpenSSH 8.4 или новее — тот, что умеет
# SSH_ASKPASS_REQUIRE. Что нужно на той: доступ по SSH, выход в интернет и
# доменное имя, которое указывает на неё: без него не выписать сертификат.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REMOTE_DIR="/opt/pingwin"

CONTEXT=""
ASKPASS_DIR=""

cleanup() {
    [[ -n "$CONTEXT" ]] && rm -rf "$CONTEXT"
    [[ -n "$ASKPASS_DIR" ]] && rm -rf "$ASKPASS_DIR"
    unset PINGWIN_SSH_PASSWORD || true
    return 0
}
trap cleanup EXIT

# --- как это выглядит --------------------------------------------------------

bold() { printf '\n\033[1m▶ %s\033[0m\n' "$1"; }
ok()   { printf '\033[32m  ✓ %s\033[0m\n' "$1"; }
info() { printf '    %s\n' "$1"; }
die()  { printf '\033[31m  ✗ %s\033[0m\n' "$1" >&2; exit 1; }

# Спрашивает и подставляет умолчание, если человек нажал ввод.
ask() {
    local prompt="$1" default="${2:-}" answer
    if [[ -n "$default" ]]; then
        read -r -p "  $prompt [$default]: " answer
        printf '%s' "${answer:-$default}"
    else
        read -r -p "  $prompt: " answer
        printf '%s' "$answer"
    fi
}

# То же, но не показывает набранное: пароль не должен остаться на экране.
ask_secret() {
    local prompt="$1" answer
    read -r -s -p "  $prompt: " answer
    echo >&2
    printf '%s' "$answer"
}

yes_no() {
    local answer
    answer="$(ask "$1 (y/n)" "${2:-y}")"
    [[ "$answer" =~ ^[YyДд] ]]
}

# --- вопросы -----------------------------------------------------------------

cat <<'HELLO'

  Pingwin — развёртывание сервера

  Спрошу, куда ставить, и сделаю остальное сам. Понадобится доступ
  по SSH, выход в интернет и доменное имя, указывающее на сервер.

HELLO

bold "Куда ставим"
SSH_HOST="$(ask 'Адрес сервера (IP или имя)')"
[[ -n "$SSH_HOST" ]] || die "без адреса ставить некуда"
SSH_USER="$(ask 'Пользователь SSH' 'root')"
SSH_PORT="$(ask 'Порт SSH' '22')"

SSH_PASSWORD=""
SSH_KEY=""
if yes_no 'Заходить по паролю?' 'y'; then
    SSH_PASSWORD="$(ask_secret "Пароль SSH для $SSH_USER@$SSH_HOST")"
    [[ -n "$SSH_PASSWORD" ]] || die "пустой пароль"
else
    SSH_KEY="$(ask 'Файл ключа (пусто — как настроено у ssh)' '')"
fi

# --- связь -------------------------------------------------------------------

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 -p "$SSH_PORT")

if [[ -n "$SSH_PASSWORD" ]]; then
    # Пароль отдаётся ssh через SSH_ASKPASS: так он не попадает ни в список
    # процессов, ни в историю оболочки. Файл лежит в частной папке и стирается
    # при выходе, каким бы этот выход ни был.
    ASKPASS_DIR="$(mktemp -d)"
    printf '#!/bin/sh\nprintf %%s "$PINGWIN_SSH_PASSWORD"\n' > "$ASKPASS_DIR/askpass"
    chmod 700 "$ASKPASS_DIR/askpass"
    export PINGWIN_SSH_PASSWORD="$SSH_PASSWORD"
    export SSH_ASKPASS="$ASKPASS_DIR/askpass" SSH_ASKPASS_REQUIRE=force
    SSH_OPTS+=(-o NumberOfPasswordPrompts=1
               -o PreferredAuthentications=password,keyboard-interactive)
elif [[ -n "$SSH_KEY" ]]; then
    SSH_OPTS+=(-i "$SSH_KEY" -o IdentitiesOnly=yes)
fi

remote() { ssh "${SSH_OPTS[@]}" "$SSH_USER@$SSH_HOST" "$@"; }

# Ссылка собирается на сервере: ключ и пароль лежат только там, и тащить их
# сюда ради одной строки незачем.
show_link() {
    local link
    link="$(remote "docker run --rm -v $REMOTE_DIR/pingwin.toml:/etc/pingwin/pingwin.toml:ro \
        pingwin-server:latest link --config /etc/pingwin/pingwin.toml --user '$USER_NAME' \
        --host '$DOMAIN:$CLIENT_PORT' --name '$PROFILE_NAME'")"
    [[ -n "$link" ]] || die "ссылка не собралась"

    printf '\n\033[1m▶ Готово\033[0m\n\n'
    printf '  Вставьте эту ссылку в клиент: «Добавить сервер» → «Ссылка».\n\n'
    printf '\033[32m%s\033[0m\n\n' "$link"
    printf '  Что дальше:\n'
    printf '    журнал       ssh -p %s %s@%s "cd %s && docker compose logs -f pingwin"\n' \
        "$SSH_PORT" "$SSH_USER" "$SSH_HOST" "$REMOTE_DIR"
    printf '    ещё человек  запустите скрипт снова — он предложит добавить пользователя\n'
    printf '    обновить     запустите скрипт снова и откажитесь от добавления\n\n'
}

bold "Проверяю связь"
remote 'echo ok' >/dev/null 2>&1 \
    || die "не захожу по SSH на $SSH_USER@$SSH_HOST:$SSH_PORT"
SYSTEM="$(remote 'sed -n "s/^PRETTY_NAME=//p" /etc/os-release 2>/dev/null | tr -d \" ' || true)"
ok "связь есть: ${SYSTEM:-неизвестная система}"

# --- что уже стоит -----------------------------------------------------------

# Сервер считается развёрнутым, когда есть и настройки, и образ: по ним одним
# можно завести пользователя и выдать ссылку, ничего не пересобирая.
bold "Смотрю, что уже стоит"
MODE="full"
USERS=""
if remote "test -s $REMOTE_DIR/pingwin.toml && docker image inspect pingwin-server:latest >/dev/null 2>&1"; then
    USERS="$(remote "sed -n 's/^name = \"\\(.*\\)\"$/\\1/p' $REMOTE_DIR/pingwin.toml")"
    ok "сервер уже развёрнут; пользователи: $(printf '%s' "$USERS" | tr '\n' ' ')"
    if yes_no 'Только добавить пользователя и выдать ссылку?' 'y'; then
        MODE="user"
    else
        info 'хорошо, пройду весь путь заново — ключ и пароли останутся прежними'
    fi
else
    ok "чисто — ставлю с нуля"
fi

# --- каким будет профиль -----------------------------------------------------

if [[ "$MODE" == "user" ]]; then
    # Порт и имя у работающего сервера уже выбраны: спрашивать их заново
    # значило бы предлагать выдать ссылку, которая никуда не придёт.
    bold "Кому ссылку"
    CLIENT_PORT="$(remote "sed -n 's/^PINGWIN_PORT=//p' $REMOTE_DIR/.env 2>/dev/null" || true)"
    DOMAIN="$(remote "sed -n 's/^PINGWIN_DOMAIN=//p' $REMOTE_DIR/.env 2>/dev/null" || true)"
    CLIENT_PORT="${CLIENT_PORT:-443}"
    [[ -n "$DOMAIN" ]] || die "в $REMOTE_DIR/.env нет PINGWIN_DOMAIN — пройдите развёртывание заново"
    info "порт $CLIENT_PORT/udp, имя $DOMAIN — как при развёртывании"
else
    bold "Каким будет сервер"
    info 'Имя: на него выписывается сертификат, и его увидит DPI. Оно должно'
    info 'уже указывать на этот сервер (запись A или AAAA), а порт 80/tcp —'
    info 'быть открыт: через него Let'"'"'s Encrypt проверяет, что имя ваше.'
    DOMAIN="$(ask 'Доменное имя сервера')"
    [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "имя «$DOMAIN» не похоже на доменное"
    info 'Порт: HTTP/3 браузеры ищут на 443/udp — там он и выглядит обычно.'
    CLIENT_PORT="$(ask 'Порт UDP, на который будут приходить клиенты' '443')"
    CERT_EMAIL="$(ask 'Почта для Let'"'"'s Encrypt (пусто — без неё)' '')"
fi

USER_NAME="$(ask 'Имя пользователя в профиле' 'client')"
# Имя уходит в TOML как есть: кавычка или обратная косая черта сломали бы
# настройки работающего сервера.
[[ "$USER_NAME" =~ ^[A-Za-z0-9._-]+$ ]] \
    || die "имя пользователя: латиница, цифры, точка, дефис, подчёркивание"
PROFILE_NAME="$(ask 'Как назвать профиль в клиенте' "Pingwin $DOMAIN")"

# Пароль машинный: человеческий подбирается, а вводить его руками всё равно
# не придётся — он уедет в ссылку.
USER_PASSWORD="$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"

# --- ещё один пользователь ---------------------------------------------------

if [[ "$MODE" == "user" ]]; then
    bold "Добавляю пользователя"
    if printf '%s\n' "$USERS" | grep -qxF "$USER_NAME"; then
        ok "$USER_NAME уже заведён — пароль прежний, ссылка будет та же"
    else
        # Дописывание, а не перезапись: файл примонтирован в живой контейнер,
        # а bind-mount держит inode. Владелец и права при дописывании тоже
        # остаются прежними.
        remote "cat >> $REMOTE_DIR/pingwin.toml <<'PINGWIN_USER'

[[users]]
name = \"$USER_NAME\"
password = \"$USER_PASSWORD\"
PINGWIN_USER" || die "не дописал пользователя в $REMOTE_DIR/pingwin.toml"
        ok "$USER_NAME заведён"

        # Настройки читаются один раз при старте: без перезапуска сервер о
        # новом пароле не узнает. `up -d` — на случай, если сейчас всё лежит.
        remote "cd $REMOTE_DIR && docker compose up -d pingwin && docker compose restart pingwin" \
            >/dev/null 2>&1 \
            || die "сервер не перезапустился; посмотрите docker compose logs pingwin на сервере"
        ok "сервер перечитал настройки"
    fi
    show_link
    exit 0
fi

# --- Docker ------------------------------------------------------------------

bold "Docker"
if remote 'command -v docker >/dev/null 2>&1'; then
    ok "уже стоит: $(remote 'docker --version')"
else
    info 'ставлю — это пара минут'
    remote 'set -e
        export DEBIAN_FRONTEND=noninteractive
        (command -v apt-get >/dev/null && apt-get update -qq && apt-get install -y -qq curl ca-certificates) >/dev/null 2>&1 || true
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
        sh /tmp/get-docker.sh >/tmp/docker-install.log 2>&1' \
        || die "Docker не поставился; подробности на сервере в /tmp/docker-install.log"
    ok "поставлен: $(remote 'docker --version')"
fi
remote 'docker compose version >/dev/null 2>&1' \
    || die "нет docker compose — обновите Docker на сервере"

# --- память ------------------------------------------------------------------

bold "Память под сборку"
MEMORY="$(remote "free -m 2>/dev/null | awk '/^Mem:/ {print \$2}'" 2>/dev/null || echo 0)"
if [[ "${MEMORY:-0}" -gt 0 && "${MEMORY:-0}" -lt 3000 ]]; then
    if remote 'swapon --show 2>/dev/null | grep -q .'; then
        ok "своп уже есть; памяти ${MEMORY} МБ"
    else
        info "памяти ${MEMORY} МБ — добавляю 2 ГБ свопа, иначе сборка не доживёт до конца"
        if remote 'set -e
            fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
            grep -q "^/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab' 2>/dev/null
        then
            ok "своп добавлен"
        else
            info "своп не добавился — пробую собрать так"
        fi
    fi
else
    ok "памяти ${MEMORY:-?} МБ, свопа не нужно"
fi

# --- исходники ---------------------------------------------------------------

bold "Везу исходники"
CONTEXT="$(mktemp -d)"
bash "$ROOT/servers/pingwin/docker/stage.sh" "$CONTEXT" >/dev/null
info "$(du -sh "$CONTEXT" | cut -f1) исходников"

# Через tar, а не rsync: его может не быть ни здесь, ни там, а ставить его
# ради одной выгрузки — лишний шаг в скрипте, который должен просто работать.
# Старые исходники сносятся, настройки — нет.
#
# `cover` не сносится, хотя это тоже привезённое: он примонтирован в живой
# контейнер, а bind-mount держит **inode**, а не путь. Удалить и создать
# заново — значит оставить сервер с папкой, которой больше нет, и прикрытие
# ответит `404` на всё. Файлы внутри tar заменит и так.
remote "rm -rf $REMOTE_DIR/crates $REMOTE_DIR/protocols $REMOTE_DIR/servers
        mkdir -p $REMOTE_DIR"
tar -C "$CONTEXT" -czf - . | remote "tar -C $REMOTE_DIR -xzf -"
ok "исходники на месте"

# Порт наружу спрашивается у человека, а файл в репозитории один на всех, —
# поэтому он приезжает переменной окружения, а не правкой compose.yml.
#
# `PINGWIN_DOMAIN` compose не читает: он лежит рядом, чтобы повторный запуск и
# продление сертификата знали имя и не переспрашивали его.
remote "printf 'PINGWIN_PORT=%s\nPINGWIN_DOMAIN=%s\n' '$CLIENT_PORT' '$DOMAIN' > $REMOTE_DIR/.env"

# --- сборка ------------------------------------------------------------------

bold "Собираю образ"
info 'первый раз это минуты: сервер собирается из исходников на месте'
remote "cd $REMOTE_DIR && docker compose build --quiet" || die "образ не собрался"
ok "образ готов"

# --- сертификат --------------------------------------------------------------

bold "Сертификат"
if remote "test -d $REMOTE_DIR/letsencrypt/live/$DOMAIN"; then
    ok "уже выписан на $DOMAIN"
else
    if [[ -n "${CERT_EMAIL:-}" ]]; then
        CERT_CONTACT="--email '$CERT_EMAIL'"
    else
        CERT_CONTACT="--register-unsafely-without-email"
    fi
    if remote 'command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"'; then
        remote "ufw allow 80/tcp" >/dev/null 2>&1 && ok "порт 80/tcp открыт в ufw для проверки имени"
    fi
    info "прошу Let's Encrypt — он сходит на http://$DOMAIN/"
    remote "cd $REMOTE_DIR && docker compose run --rm --service-ports certbot certonly \
        --standalone -d '$DOMAIN' --agree-tos -n $CERT_CONTACT" >/dev/null 2>&1 \
        || die "сертификат не выписан: $DOMAIN указывает на этот сервер? порт 80/tcp открыт?"
    ok "выписан на $DOMAIN"
fi
remote "bash $REMOTE_DIR/renew.sh" || die "сертификат не разложился для сервера"

# Сертификат живёт 90 дней. Продление — раз в неделю: certbot сам решает,
# пора ли, а сервер перезапускается, только если файл сменился.
remote "( crontab -l 2>/dev/null | grep -v pingwin-renew; \
    echo '17 4 * * 1 bash $REMOTE_DIR/renew.sh >/dev/null 2>&1 # pingwin-renew' ) | crontab -" \
    && ok "продление раз в неделю — в cron" \
    || info "cron не настроился: продлевайте руками — bash $REMOTE_DIR/renew.sh"

# --- ключи и настройки -------------------------------------------------------

bold "Ключи и пользователи"
if remote "test -s $REMOTE_DIR/pingwin.toml"; then
    ok "настройки уже есть — ключ и пароли не трогаю"
    info 'иначе разосланные ссылки перестали бы работать'
    # Настройки сервера поверх TCP: прикрытие было адресом, сертификата не было.
    if remote "grep -q '^fallback' $REMOTE_DIR/pingwin.toml"; then
        remote "sed -i 's|^fallback = .*|cert = \"/etc/pingwin/certs/fullchain.pem\"\\ncert_key = \"/etc/pingwin/certs/privkey.pem\"\\ncover = \"/srv/cover\"|' $REMOTE_DIR/pingwin.toml" \
            || die "не переписал прежние настройки"
        ok "прежние настройки переведены на HTTP/3"
    fi
    USER_NAME="$(remote "sed -n 's/^name = \"\\(.*\\)\"$/\\1/p' $REMOTE_DIR/pingwin.toml | head -1")"
else
    SERVER_KEY="$(remote 'docker run --rm pingwin-server:latest keygen' \
        | sed -n 's/^key = "\(.*\)"$/\1/p')"
    [[ -n "$SERVER_KEY" ]] || die "ключ не сгенерировался"

    remote "cat > $REMOTE_DIR/pingwin.toml <<'PINGWIN_CONFIG'
# Настройки сервера Pingwin. Созданы при развёртывании.
# Ключ и пароли есть только здесь — не копируйте этот файл никуда.

# UDP. Внутри контейнера порт непривилегированный: наружу его публикует
# compose.yml на том, который спросили при развёртывании.
listen = \"0.0.0.0:8443\"

key = \"$SERVER_KEY\"

# Сертификат на $DOMAIN; его раскладывает и продлевает renew.sh.
cert = \"/etc/pingwin/certs/fullchain.pem\"
cert_key = \"/etc/pingwin/certs/privkey.pem\"

# Сайт, который видит тот, кто не прошёл опознание.
cover = \"/srv/cover\"

[[users]]
name = \"$USER_NAME\"
password = \"$USER_PASSWORD\"
PINGWIN_CONFIG"

    # Владелец — тот, под кем работает сервер внутри контейнера (Dockerfile,
    # --uid 10001): иначе файл либо читается всеми на хосте, либо не читается
    # сервером.
    remote "chown 10001:10001 $REMOTE_DIR/pingwin.toml && chmod 600 $REMOTE_DIR/pingwin.toml"
    ok "ключ заведён, пользователь — $USER_NAME"
fi

# --- запуск ------------------------------------------------------------------

bold "Поднимаю"
# `--force-recreate`, а не просто `up -d`: сам по себе он пересоздаёт только
# то, у чего изменился образ, а привезённые файлы примонтированы — и
# контейнер, оставшийся с прошлого раза, продолжил бы читать прошлые.
remote "cd $REMOTE_DIR && docker compose up -d --force-recreate --remove-orphans" >/dev/null 2>&1 \
    || die "не поднялось; посмотрите docker compose logs pingwin на сервере"
sleep 5
STATUS="$(remote "cd $REMOTE_DIR && docker compose ps --format '{{.Service}} {{.Status}}'")"
echo "$STATUS" | sed 's/^/    /'
echo "$STATUS" | grep -q 'pingwin.*Up' \
    || die "сервер не запустился; посмотрите docker compose logs pingwin на сервере"
ok "работает"

# --- брандмауэр --------------------------------------------------------------

if remote 'command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"'; then
    remote "ufw allow $CLIENT_PORT/udp" >/dev/null 2>&1 && ok "порт $CLIENT_PORT/udp открыт в ufw"
fi

# --- проверка снаружи --------------------------------------------------------

bold "Проверяю снаружи"
if command -v curl >/dev/null 2>&1 && curl --version | grep -q HTTP3; then
    if curl -sS --http3-only --max-time 15 -o /dev/null "https://$DOMAIN:$CLIENT_PORT/" 2>/dev/null; then
        ok "по HTTP/3 отвечает обычный сайт — так и задумано: чужой видит прикрытие"
    else
        info "по HTTP/3 снаружи не ответил; проверьте UDP $CLIENT_PORT у хостера"
    fi
else
    info 'curl без HTTP/3 — проверку снаружи пропускаю'
fi

# --- ссылка ------------------------------------------------------------------

show_link
