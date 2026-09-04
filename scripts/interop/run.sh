#!/usr/bin/env bash
#
# Проверка протоколов о чужие реализации.
#
#   ./run.sh            # все профили
#   ./run.sh socks5     # один
#
# Нужны `docker`, `openssl`, `curl`. Из `check.sh` не зовётся: образы тянутся
# долго, а падение сети выглядело бы падением коммита.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

ROOT="$(cd ../.. && pwd)"
# Свой каталог настроек: проверка не имеет права трогать настоящие профили
# того, кто её запустил. Подменяется не путь внутри клиента, а то, откуда он
# его берёт, — переменные среды системы.
SCRATCH="$(mktemp -d)"
BIN="$ROOT/target/debug/penguin"
ONLY="${1:-}"

FAILED=()
bold() { printf '\n\033[1m▶ %s\033[0m\n' "$1"; }
ok()   { printf '\033[32m  ✓ %s\033[0m\n' "$1"; }
bad()  { printf '\033[31m  ✗ %s\033[0m\n' "$1"; }

cleanup() {
    docker compose down --remove-orphans >/dev/null 2>&1
    rm -rf "$SCRATCH"
}
trap cleanup EXIT

need() {
    command -v "$1" >/dev/null 2>&1 || { bad "нет $1"; exit 1; }
}
need docker
need openssl
need curl

# --- сертификат для Hysteria 2 -------------------------------------------
if [[ ! -f tls/cert.pem ]]; then
    bold "самоподписанный сертификат"
    mkdir -p tls
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout tls/key.pem -out tls/cert.pem \
        -subj "/CN=interop.penguin.test" >/dev/null 2>&1
    ok "готов"
fi

# --- серверы --------------------------------------------------------------
bold "эталонные серверы"
docker compose up -d --wait || { bad "не поднялись"; exit 1; }
ok "подняты"

# --- клиент ---------------------------------------------------------------
bold "сборка клиента"
(cd "$ROOT" && cargo build -p penguin-app) || { bad "не собрался"; exit 1; }
ok "собран"

# Настройки клиента кладём в свой каталог: и Windows, и Linux, и macOS
# смотрят в переменные среды, и подменить их достаточно.
#
# На Windows путь обязан быть родным: клиент склеивает его средствами системы,
# и `/tmp/...` из-под Git Bash она не понимает — файл просто не находится, а
# выглядит это как «нет профиля».
WINDOWS=0
case "$OSTYPE" in
    msys* | cygwin* | win32) WINDOWS=1 ;;
esac

if [[ $WINDOWS -eq 1 ]]; then
    NATIVE="$(cygpath -w "$SCRATCH")"
    export APPDATA="$NATIVE"
    # Общий каталог сильнее пользовательского, и настоящий бы перебил наш.
    export ProgramData="$NATIVE\none"
else
    export XDG_CONFIG_HOME="$SCRATCH/config"
    export XDG_DATA_HOME="$SCRATCH/data"
    export HOME="$SCRATCH"
fi

# Один профиль на запуск: файл переписывается целиком перед каждой проверкой.
#
# Раскладка — та же, что в `assets/config.example.toml`: `active_profile` и
# `version` стоят до первой таблицы, иначе TOML отнесёт их к ней.
write_profile() {
    local protocol="$1" params="$2"
    local dir
    if [[ $WINDOWS -eq 1 ]]; then
        dir="$SCRATCH/Saviartache/Penguin/config"
    else
        dir="$XDG_CONFIG_HOME/penguin"
    fi
    mkdir -p "$dir"
    cat > "$dir/config.toml" <<TOML
version = 2
active_profile = "interop"

[[profiles]]
id   = "interop"
name = "Проверка"

[profiles.outbound]
protocol = "$protocol"
$params
TOML
}

# Поднимает локальный SOCKS5 поверх профиля и ходит через него до `target`.
#
# `--no-rules` обязателен: проверяется протокол, и маршрутизация в этой
# проверке — лишняя переменная.
check() {
    local name="$1" protocol="$2" params="$3"
    [[ -n "$ONLY" && "$ONLY" != "$name" ]] && return 0

    bold "$name"
    write_profile "$protocol" "$params"

    # Сначала без сети: ошибка в настройках профиля и молчащий сервер
    # выглядят одинаково, если не разделить их здесь.
    if ! "$BIN" profiles check >"$SCRATCH/$name.check" 2>&1; then
        bad "$name: настройки не проходят проверку"
        cat "$SCRATCH/$name.check"
        FAILED+=("$name")
        return 0
    fi

    "$BIN" socks --profile interop --listen 127.0.0.1:11111 --no-rules \
        >"$SCRATCH/$name.log" 2>&1 &
    local pid=$!

    # Ждём, пока порт откроется: фиксированная пауза либо коротка на холодной
    # машине, либо тратит время впустую на тёплой.
    local ready=0
    for _ in $(seq 1 50); do
        if curl -s --socks5-hostname 127.0.0.1:11111 -o /dev/null \
            --max-time 1 http://target/ 2>/dev/null; then
            ready=1
            break
        fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.2
    done

    local body=""
    if [[ $ready -eq 1 ]]; then
        body="$(curl -s --socks5-hostname 127.0.0.1:11111 --max-time 5 http://target/)"
    fi
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null

    if [[ "$body" == *penguin-interop-ok* ]]; then
        ok "TCP через домен"
    else
        bad "$name: ответ не пришёл"
        sed -n '1,20p' "$SCRATCH/$name.log"
        FAILED+=("$name")
    fi
}

# Адреса — со стороны хоста: клиент запущен не в контейнере, а рядом.
check socks5 socks5 'server = "127.0.0.1:11080"
username = "penguin"
password = "secret"'

check socks5-open socks5 'server = "127.0.0.1:11081"'

# Тот же прокси и тот же пароль — но по дороге не видно ни того, ни адреса
# назначения. Сертификат самоподписанный, отсюда `insecure`.
check socks5-tls socks5-tls 'server   = "127.0.0.1:11443"
username = "penguin"
password = "secret"

[profiles.outbound.tls]
sni      = "interop.penguin.test"
insecure = true'

check http http 'server = "127.0.0.1:18888"'

# Сертификат самоподписанный — отсюда `insecure`. Пароль проверить нечем:
# сервер Trojan не отвечает на заголовок ничем, и неверный пароль выглядит
# ровно так же, как верный (см. документ крейта).
check trojan trojan 'server   = "127.0.0.1:14431"
password = "secret"

[profiles.outbound.tls]
sni      = "interop.penguin.test"
insecure = true'

check hysteria2 hysteria2 'server   = "127.0.0.1:14443"
password = "secret"

[profiles.outbound.bandwidth]
up   = "50 mbps"
down = "50 mbps"

# Сертификат самоподписанный — единственное место, где `insecure` уместен.
[profiles.outbound.tls]
sni      = "interop.penguin.test"
insecure = true'

echo
if [[ ${#FAILED[@]} -gt 0 ]]; then
    printf '\033[31mПРОВАЛЕНО:\033[0m\n'
    printf '  · %s\n' "${FAILED[@]}"
    exit 1
fi
printf '\033[32mВсе протоколы прошли.\033[0m\n'
