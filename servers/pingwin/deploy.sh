#!/usr/bin/env bash
#
# Разворачивает сервер Pingwin на чужой машине от начала и до конца.
#
#   bash servers/pingwin/deploy.sh
#
# Спрашивает, куда ставить, и делает всё остальное сам: ставит Docker, увозит
# исходники, собирает образ, поднимает сервер и прикрытие, заводит ключи и
# печатает ссылку-приглашение для клиента.
#
# Запускать можно сколько угодно раз: ключ и пароли, если они уже есть, не
# трогаются — иначе разосланные ссылки перестали бы работать.
#
# Что нужно на этой машине: ssh, tar и OpenSSH 8.4 или новее — тот, что умеет
# SSH_ASKPASS_REQUIRE. Что нужно на той: доступ по SSH и выход в интернет.

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

  Спрошу, куда ставить, и сделаю остальное сам. Всё, что понадобится
  на той машине, — доступ по SSH и выход в интернет.

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

bold "Каким будет сервер"
CLIENT_PORT="$(ask 'Порт, на который будут приходить клиенты' '443')"
COVER_SNI="$(ask 'Имя прикрытия (его увидит DPI)' 'www.microsoft.com')"
USER_NAME="$(ask 'Имя пользователя в профиле' 'client')"
PROFILE_NAME="$(ask 'Как назвать профиль в клиенте' "Pingwin $SSH_HOST")"

# Пароль машинный: человеческий подбирается, а вводить его руками всё равно
# не придётся — он уедет в ссылку.
USER_PASSWORD="$(head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')"

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

bold "Проверяю связь"
remote 'echo ok' >/dev/null 2>&1 \
    || die "не захожу по SSH на $SSH_USER@$SSH_HOST:$SSH_PORT"
SYSTEM="$(remote 'sed -n "s/^PRETTY_NAME=//p" /etc/os-release 2>/dev/null | tr -d \" ' || true)"
ok "связь есть: ${SYSTEM:-неизвестная система}"

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
# заново — значит оставить nginx с папкой, которой больше нет: он ответит
# `403`, и прикрытие перестанет быть прикрытием. Файлы внутри tar заменит и
# так.
remote "rm -rf $REMOTE_DIR/crates $REMOTE_DIR/protocols $REMOTE_DIR/servers
        mkdir -p $REMOTE_DIR"
tar -C "$CONTEXT" -czf - . | remote "tar -C $REMOTE_DIR -xzf -"
ok "исходники на месте"

# Порт наружу спрашивается у человека, а файл в репозитории один на всех, —
# поэтому он приезжает переменной окружения, а не правкой compose.yml.
remote "printf 'PINGWIN_PORT=%s\n' '$CLIENT_PORT' > $REMOTE_DIR/.env"

# --- сборка ------------------------------------------------------------------

bold "Собираю образ"
info 'первый раз это минуты: сервер собирается из исходников на месте'
remote "cd $REMOTE_DIR && docker compose build --quiet" || die "образ не собрался"
ok "образ готов"

# --- ключи и настройки -------------------------------------------------------

bold "Ключи и пользователи"
if remote "test -s $REMOTE_DIR/pingwin.toml"; then
    ok "настройки уже есть — не трогаю"
    info 'ключ и пароли остаются прежними: иначе разосланные ссылки перестали бы работать'
    USER_NAME="$(remote "sed -n 's/^name = \"\\(.*\\)\"$/\\1/p' $REMOTE_DIR/pingwin.toml | head -1")"
else
    SERVER_KEY="$(remote 'docker run --rm pingwin-server:latest keygen' \
        | sed -n 's/^key = "\(.*\)"$/\1/p')"
    [[ -n "$SERVER_KEY" ]] || die "ключ не сгенерировался"

    remote "cat > $REMOTE_DIR/pingwin.toml <<'PINGWIN_CONFIG'
# Настройки сервера Pingwin. Созданы при развёртывании.
# Ключ и пароли есть только здесь — не копируйте этот файл никуда.

# Внутри контейнера порт непривилегированный: наружу его публикует
# compose.yml на том, который спросили при развёртывании.
listen = \"0.0.0.0:8443\"

key = \"$SERVER_KEY\"

# Имя службы прикрытия из compose.yml: сюда уходит всё, что не прошло
# опознание.
fallback = \"cover:80\"

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
# контейнер, оставшийся с прошлого раза, продолжил бы читать прошлые. Пауза
# в пару секунд на развёртывании дешевле, чем прикрытие, показывающее `403`.
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
    remote "ufw allow $CLIENT_PORT/tcp" >/dev/null 2>&1 && ok "порт $CLIENT_PORT открыт в ufw"
fi

# --- проверка снаружи --------------------------------------------------------

bold "Проверяю снаружи"
if command -v curl >/dev/null 2>&1; then
    if curl -sS --max-time 15 -o /dev/null "http://$SSH_HOST:$CLIENT_PORT/" 2>/dev/null; then
        ok "порт отвечает обычным сайтом — так и задумано: чужой видит прикрытие"
    else
        info "порт снаружи не ответил; проверьте брандмауэр у хостера"
    fi
else
    info 'curl не нашёлся — проверку снаружи пропускаю'
fi

# --- ссылка ------------------------------------------------------------------

LINK="$(remote "docker run --rm -v $REMOTE_DIR/pingwin.toml:/etc/pingwin/pingwin.toml:ro \
    pingwin-server:latest link --config /etc/pingwin/pingwin.toml --user '$USER_NAME' \
    --host '$SSH_HOST:$CLIENT_PORT' --sni '$COVER_SNI' --name '$PROFILE_NAME'")"
[[ -n "$LINK" ]] || die "ссылка не собралась"

printf '\n\033[1m▶ Готово\033[0m\n\n'
printf '  Вставьте эту ссылку в клиент: «Добавить сервер» → «Ссылка».\n\n'
printf '\033[32m%s\033[0m\n\n' "$LINK"
printf '  Что дальше:\n'
printf '    журнал       ssh -p %s %s@%s "cd %s && docker compose logs -f pingwin"\n' \
    "$SSH_PORT" "$SSH_USER" "$SSH_HOST" "$REMOTE_DIR"
printf '    обновить     bash servers/pingwin/deploy.sh — ключи и пароли сохранятся\n'
printf '    ещё человек  допишите [[users]] в %s/pingwin.toml и перезапустите\n\n' "$REMOTE_DIR"
