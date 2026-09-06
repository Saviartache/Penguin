#!/usr/bin/env bash
#
# Проверка протоколов о чужие реализации.
#
#   ./run.sh            # все профили
#   ./run.sh socks5     # один
#
# Нужны `docker`, `openssl`, `curl`. Из `check.sh` не зовётся: образы тянутся
# долго, а падение сети выглядело бы падением коммита.
#
# Всё, что происходит, дублируется в `report.txt` рядом со скриптом. Он и есть
# то, что нужно показать после прогона: по нему видно не только какой протокол
# не прошёл, но и что ответил его сервер.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

ROOT="$(cd ../.. && pwd)"
# Свой каталог настроек: проверка не имеет права трогать настоящие профили
# того, кто её запустил. Подменяется не путь внутри клиента, а то, откуда он
# его берёт, — переменные среды системы.
SCRATCH="$(mktemp -d)"
BIN="$ROOT/target/debug/penguin"
ONLY="${1:-}"
REPORT="$PWD/report.txt"

# Весь вывод — и на экран, и в отчёт. Скрипт перезапускает сам себя один раз:
# так под `tee` попадает всё, включая то, что печатают `docker` и `cargo`.
if [[ -z "${INTEROP_REPORT:-}" ]]; then
    export INTEROP_REPORT="$REPORT"
    "$0" "$@" 2>&1 | tee "$REPORT"
    status="${PIPESTATUS[0]}"
    # На Windows путь вида `/e/...` в проводник не вставить, поэтому рядом
    # печатается и родной.
    if command -v cygpath >/dev/null 2>&1; then
        printf '\nОтчёт: %s\n' "$(cygpath -w "$REPORT")"
    else
        printf '\nОтчёт: %s\n' "$REPORT"
    fi
    exit "$status"
fi

FAILED=()
# Цвет только на живом терминале: под `tee` он превратился бы в мусор посреди
# отчёта, который потом читают глазами.
if [[ -t 1 ]]; then
    bold() { printf '\n\033[1m▶ %s\033[0m\n' "$1"; }
    ok()   { printf '\033[32m  ✓ %s\033[0m\n' "$1"; }
    bad()  { printf '\033[31m  ✗ %s\033[0m\n' "$1"; }
else
    bold() { printf '\n▶ %s\n' "$1"; }
    ok()   { printf '  [ок]     %s\n' "$1"; }
    bad()  { printf '  [ПРОВАЛ] %s\n' "$1"; }
fi

# Уборка не имеет права висеть. `docker compose down` на неотвечающем демоне
# ждёт молча и без конца, и выглядит это как зависшая проверка — хотя она уже
# всё сказала. Отсюда и проверка живости демона, и срок поверх неё.
cleanup() {
    if command -v docker >/dev/null 2>&1 &&
        timeout 10 docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
        timeout 120 docker compose down --remove-orphans >/dev/null 2>&1
    fi
    rm -rf "$SCRATCH"
}
trap cleanup EXIT

# --- docker ---------------------------------------------------------------
#
# Ищем сам, а не требуем в `PATH`. Docker Desktop на Windows кладёт себя в
# каталог пользователя и правит `PATH` в реестре — а оболочка, запущенная до
# установки, о новом `PATH` не знает. Человек при этом видит работающий
# `docker` в своём окне и справедливо считает, что всё установлено.
find_docker() {
    command -v docker >/dev/null 2>&1 && return 0

    local candidates=(
        "${LOCALAPPDATA:-}/Programs/DockerDesktop/resources/bin"
        "${PROGRAMFILES:-}/Docker/Docker/resources/bin"
        "/c/Program Files/Docker/Docker/resources/bin"
        "/c/ProgramData/DockerDesktop/version-bin"
        "$HOME/AppData/Local/Programs/DockerDesktop/resources/bin"
    )
    local dir
    for dir in "${candidates[@]}"; do
        [[ -x "$dir/docker.exe" || -x "$dir/docker" ]] || continue
        PATH="$PATH:$dir"
        export PATH
        command -v docker >/dev/null 2>&1 && return 0
    done
    return 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || { bad "нет $1"; exit 1; }
}

bold "окружение"
if ! find_docker; then
    bad "docker не найден ни в PATH, ни там, куда его ставит Docker Desktop"
    exit 1
fi
need openssl
need curl

# Установленный `docker` и запущенный демон — разные вещи, и путать их не
# стоит: без демона любая команда падает так, будто docker не установлен.
if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    bad "демон docker не отвечает — запустите Docker Desktop и повторите"
    docker version 2>&1 | tail -3
    exit 1
fi
printf '  docker %s, compose %s\n' \
    "$(docker version --format '{{.Server.Version}}' 2>/dev/null)" \
    "$(docker compose version --short 2>/dev/null)"
printf '  система: %s\n' "$(uname -sr 2>/dev/null || echo неизвестна)"
ok "готово"

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
#
# Без `--wait`: он падает целиком, если хоть один образ не поднялся, и тогда
# не проверяется ни один протокол. Здесь же важно обратное — пройти по всем и
# увидеть, что именно сломано. Про упавшие серверы скажет `ps` ниже.
bold "эталонные серверы"
if ! docker compose up -d; then
    bad "часть серверов не поднялась — смотрите вывод выше"
fi

printf '\nсостояние контейнеров:\n'
docker compose ps

# Журнал каждого, кто не работает: без него «сервер молчит» ничего не говорит,
# а причина у половины отказов видна в первых же строках журнала сервера.
#
# Списками служб, а не шаблоном вывода: `--format` у `compose ps` менялся от
# версии к версии, а `--services` есть везде и печатает по имени на строку.
running="$(docker compose ps --services --filter status=running 2>/dev/null)"
for service in $(docker compose ps --services 2>/dev/null); do
    if ! printf '%s\n' "$running" | grep -qx -- "$service"; then
        printf '\n--- журнал `%s` (не запущен) ---\n' "$service"
        docker compose logs --no-color --tail 25 "$service" 2>&1
    fi
done

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

# UUID и пароль те же, что в `singbox/tuic.json`. Отпечаток по сети не идёт:
# он выводится из ключевого материала самого рукопожатия TLS.
check tuic tuic 'server   = "127.0.0.1:14433"
uuid     = "b831381d-6324-4d53-ad4f-8cda48b30811"
password = "secret"

[profiles.outbound.tls]
sni      = "interop.penguin.test"
insecure = true'

# UUID тот же, что в `singbox/vless.json`. Проверить его сервер не даст:
# не узнав, он молча закрывает соединение — как и Trojan.
check vless vless 'server = "127.0.0.1:14432"
uuid   = "b831381d-6324-4d53-ad4f-8cda48b30811"

[profiles.outbound.tls]
sni      = "interop.penguin.test"
insecure = true'

# Пароля сервер не подтверждает: не узнав отпечаток, он закрывает соединение —
# как Trojan и VLESS. Проверяется здесь то, что после опознания сессия
# поднимается и по ней идут данные.
check anytls anytls 'server   = "127.0.0.1:14434"
password = "secret"

[profiles.outbound.tls]
sni      = "interop.penguin.test"
insecure = true'

# UUID и пароль те же, что в `juicity/server.json`. В отличие от Trojan и
# VLESS, неверный пароль здесь виден: сервер закрывает соединение QUIC с
# отдельным кодом, и клиент обязан вернуть `AuthRejected`.
check juicity juicity 'server   = "127.0.0.1:14435"
uuid     = "b831381d-6324-4d53-ad4f-8cda48b30811"
password = "secret"

[profiles.outbound.tls]
sni      = "interop.penguin.test"
insecure = true'

# Часы: сервер отвергает метку времени, отставшую больше чем на минуту. Если
# проверка падает «сервер молчит», сверьте часы машины, а не протокол.
check brook brook 'server   = "127.0.0.1:19999"
password = "secret"'

# Имя и пароль те же, что в `naive/Caddyfile`. Сертификат самоподписанный —
# отсюда `insecure`. Проверяются оба переноса: схема дополнения у них
# общая, а вот то, что под ней, — разное целиком.
check naive-h2 http2 'server   = "127.0.0.1:14436"
username = "penguin"
password = "secret"

[profiles.outbound.tls]
sni      = "interop.penguin.test"
insecure = true'

check naive-h3 http3 'server   = "127.0.0.1:14436"
username = "penguin"
password = "secret"

[profiles.outbound.tls]
sni      = "interop.penguin.test"
insecure = true'

# Отпечаток хоста заранее неизвестен: ключ рождается при сборке образа,
# точно так же, как у настоящего сервера при первом запуске. Читаем его тем
# же способом, каким его читает человек, — строкой `ssh-keyscan`: её клиент
# принимает как есть, вместе с именем хоста в начале.
if [[ -z "$ONLY" || "$ONLY" == ssh ]]; then
    if command -v ssh-keyscan >/dev/null 2>&1; then
        SSH_HOST_KEY="$(ssh-keyscan -t ed25519 -p 18446 127.0.0.1 2>/dev/null | grep -m1 ssh-ed25519)"
    else
        SSH_HOST_KEY=""
    fi

    if [[ -z "$SSH_HOST_KEY" ]]; then
        bad "ssh: ключ хоста не прочитан (нужен ssh-keyscan)"
        FAILED+=(ssh)
    else
        check ssh ssh "server           = \"127.0.0.1:18446\"
username         = \"penguin\"
password         = \"secret\"
host_fingerprint = \"$SSH_HOST_KEY\""
    fi
fi

# Без имени и пароля: сервер запущен без настроенных пользователей, и признак
# опознания в запросе тогда не посылается вовсе.
check gost-relay gost-relay 'server = "127.0.0.1:18445"'

# Версия — часть договора с сервером, и умолчания у неё нет: неверная не даёт
# отказа, а даёт молчание. Здесь та же, что в `mihomo/config.yaml`.
check snell snell 'server  = "127.0.0.1:18443"
psk     = "secret"
version = 3'

# Четвёртая версия — это другое обрамление, а не другая настройка: проверять
# её надо отдельно.
check snell-v4 snell 'server  = "127.0.0.1:18444"
psk     = "secret"
version = 4'

# Метод — часть договора с сервером: он же стоит в `singbox/shadowsocks.json`,
# и разойтись им нельзя, иначе соединение откроется и ничего не передаст.
check shadowsocks shadowsocks 'server   = "127.0.0.1:18388"
method   = "aes-256-gcm"
password = "secret"'

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

# --- итог -----------------------------------------------------------------
#
# Отдельно называется и то, для чего сервера нет вовсе: без этой строки
# «все протоколы прошли» читается как «весь клиент проверен», а это неправда.
bold "чего эта проверка не касалась"
cat <<'NOTE'
  Своего эталонного сервера в наборе пока нет у шести протоколов, и ни один
  из них ниже не проверялся:

    shadowsocksr   готового образа с сервером SSR не нашлось
    mieru          сервер есть у самого проекта, служба не написана
    masque         сервер CONNECT-UDP по RFC 9298 надо искать
    wireguard      служба не написана
    openconnect    нужен `ocserv` со своими учётными данными
    trusttunnel    сервер открыт, служба не написана

  Ещё не проверяется UDP ни у кого: готовой утилиты, которая ходит по UDP
  через SOCKS5, нет, а своя проверяла бы протокол нашим же кодом.
NOTE

bold "итог"
if [[ ${#FAILED[@]} -gt 0 ]]; then
    bad "не прошли: ${#FAILED[@]}"
    printf '  · %s\n' "${FAILED[@]}"
    exit 1
fi
ok "все, у кого есть эталонный сервер, прошли"
