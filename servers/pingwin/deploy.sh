#!/usr/bin/env bash
#
# Разворачивает сервер Pingwin на чужой машине от начала и до конца.
#
#   bash servers/pingwin/deploy.sh
#
# Спрашивает, куда ставить, увозит исходники из этого дерева и запускает на
# сервере `docker/install.sh`: он ставит Docker, собирает образ, получает
# сертификат Let's Encrypt, заводит ключи, поднимает сервер и печатает
# ссылку-приглашение. Тот же `install.sh` зовёт окно клиента («Развернуть
# сервер»), только исходники сервер качает сам — тег версии клиента с GitHub.
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
INSTALL="$ROOT/servers/pingwin/docker/install.sh"
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

CERT_EMAIL=""
if [[ "$MODE" == "user" ]]; then
    # Порт и имя у работающего сервера уже выбраны: спрашивать их заново
    # значило бы предлагать выдать ссылку, которая никуда не придёт.
    bold "Кому ссылку"
    CLIENT_PORT="$(remote "sed -n 's/^PINGWIN_PORT=//p' $REMOTE_DIR/.env 2>/dev/null" || true)"
    DOMAIN="$(remote "sed -n 's/^PINGWIN_DOMAIN=//p' $REMOTE_DIR/.env 2>/dev/null" || true)"
    CLIENT_PORT="${CLIENT_PORT:-443}"
    [[ -n "$DOMAIN" ]] || die "в $REMOTE_DIR/.env нет PINGWIN_DOMAIN — пройдите развёртывание заново"
    info "порт $CLIENT_PORT (udp и tcp), имя $DOMAIN — как при развёртывании"
else
    bold "Каким будет сервер"
    info 'Имя: на него выписывается сертификат, и его увидит DPI. Оно должно'
    info 'уже указывать на этот сервер (запись A или AAAA), а порт 80/tcp —'
    info 'быть открыт: через него Let'"'"'s Encrypt проверяет, что имя ваше.'
    DOMAIN="$(ask 'Доменное имя сервера')"
    [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "имя «$DOMAIN» не похоже на доменное"
    info 'Порт: сайты живут на 443 (HTTP/3 по udp, HTTP/2 по tcp) — там он и выглядит обычно.'
    CLIENT_PORT="$(ask 'Порт (udp и tcp), на который будут приходить клиенты' '443')"
    CERT_EMAIL="$(ask 'Почта для Let'"'"'s Encrypt (пусто — без неё)' '')"
fi

USER_NAME="$(ask 'Имя пользователя в профиле' 'client')"
# Имя уходит в TOML как есть: кавычка или обратная косая черта сломали бы
# настройки работающего сервера.
[[ "$USER_NAME" =~ ^[A-Za-z0-9._-]+$ ]] \
    || die "имя пользователя: латиница, цифры, точка, дефис, подчёркивание"
PROFILE_NAME="$(ask 'Как назвать профиль в клиенте' "Pingwin $DOMAIN")"

# --- исходники ---------------------------------------------------------------

if [[ "$MODE" == "full" ]]; then
    bold "Везу исходники"
    CONTEXT="$(mktemp -d)"
    bash "$ROOT/servers/pingwin/docker/stage.sh" "$CONTEXT" >/dev/null
    info "$(du -sh "$CONTEXT" | cut -f1) исходников"

    # Через tar, а не rsync: его может не быть ни здесь, ни там. Старые
    # исходники сносятся, настройки — нет. `cover` не сносится: он примонтирован
    # в живой контейнер, а bind-mount держит inode; файлы внутри tar заменит.
    remote "rm -rf $REMOTE_DIR/crates $REMOTE_DIR/protocols $REMOTE_DIR/servers
            mkdir -p $REMOTE_DIR"
    tar -C "$CONTEXT" -czf - . | remote "tar -C $REMOTE_DIR -xzf -"
    ok "исходники на месте"
fi

# --- установка на сервере ----------------------------------------------------

# Значения уже проверены; `%q` — на случай пробела в имени профиля.
ENVIRONMENT="$(printf 'PINGWIN_DOMAIN=%q PINGWIN_PORT=%q PINGWIN_EMAIL=%q PINGWIN_USER=%q PINGWIN_PROFILE=%q PINGWIN_SOURCE=uploaded PINGWIN_MODE=%q' \
    "$DOMAIN" "$CLIENT_PORT" "$CERT_EMAIL" "$USER_NAME" "$PROFILE_NAME" "$MODE")"
if [[ "$SSH_USER" == root ]]; then
    RUN="env $ENVIRONMENT bash -s"
else
    RUN="sudo -n env $ENVIRONMENT bash -s"
fi

# Без `declare -A`: у macOS bash 3.2.
title() {
    case "$1" in
        inspect) echo "Смотрю, что уже стоит" ;;  docker) echo "Docker" ;;
        memory) echo "Память под сборку" ;;       source) echo "Исходники" ;;
        build) echo "Собираю образ" ;;            cert) echo "Сертификат" ;;
        keys) echo "Ключи и пользователи" ;;      start) echo "Поднимаю" ;;
        firewall) echo "Брандмауэр" ;;            check) echo "Проверяю на сервере" ;;
        link) echo "Ссылка" ;;                    *) echo "$1" ;;
    esac
}

LINK=""
FAILURE=""
while IFS= read -r line; do
    case "$line" in
        "::step "*) bold "$(title "${line#::step }")" ;;
        "::ok "*)   ok "${line#::ok }" ;;
        "::info "*) info "${line#::info }" ;;
        "::link "*) LINK="${line#::link }" ;;
        "::fail "*) FAILURE="${line#::fail }" ;;
    esac
done < <(remote "$RUN" < "$INSTALL" 2>/dev/null || true)

[[ -z "$FAILURE" ]] || die "$FAILURE"
[[ -n "$LINK" ]] || die "установка оборвалась; на сервере: cd $REMOTE_DIR && docker compose logs pingwin"

# --- проверка снаружи --------------------------------------------------------

if [[ "$MODE" == "full" ]]; then
    bold "Проверяю снаружи"
    if command -v curl >/dev/null 2>&1 && curl --version | grep -q HTTP3; then
        if curl -sS --http3-only --max-time 15 -o /dev/null "https://$DOMAIN:$CLIENT_PORT/" 2>/dev/null; then
            ok "по HTTP/3 отвечает обычный сайт — так и задумано: чужой видит прикрытие"
        else
            info "по HTTP/3 снаружи не ответил; проверьте UDP $CLIENT_PORT у хостера"
        fi
    else
        info 'curl без HTTP/3 — проверку по UDP пропускаю'
    fi
    if command -v curl >/dev/null 2>&1; then
        if curl -sS --http2 --max-time 15 -o /dev/null "https://$DOMAIN:$CLIENT_PORT/" 2>/dev/null; then
            ok "по HTTP/2 (tcp) отвечает тот же сайт — там, где режут UDP, клиент пойдёт сюда"
        else
            info "по HTTP/2 снаружи не ответил; проверьте TCP $CLIENT_PORT у хостера"
        fi
    fi
fi

# --- ссылка ------------------------------------------------------------------

printf '\n\033[1m▶ Готово\033[0m\n\n'
printf '  Вставьте эту ссылку в клиент: «Добавить сервер» → «Ссылка».\n\n'
printf '\033[32m%s\033[0m\n\n' "$LINK"
printf '  Что дальше:\n'
printf '    журнал       ssh -p %s %s@%s "cd %s && docker compose logs -f pingwin"\n' \
    "$SSH_PORT" "$SSH_USER" "$SSH_HOST" "$REMOTE_DIR"
printf '    ещё человек  запустите скрипт снова — он предложит добавить пользователя\n'
printf '    обновить     запустите скрипт снова и откажитесь от добавления\n\n'
