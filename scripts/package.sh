#!/usr/bin/env bash
#
# Собирает поставку — каталог, который можно отдать человеку.
#
#   ./scripts/package.sh            # для системы, на которой запущен
#   ./scripts/package.sh windows    # только Windows
#   ./scripts/package.sh linux      # только Linux
#   ./scripts/package.sh macos      # только macOS
#   ./scripts/package.sh all        # все три
#
# Установщика тут нет намеренно (он в фазе 9 плана). Каталог самодостаточен:
# распаковал и запустил — ровно то, чем проверяют сборку до установщика.
#
# # Чем собирается чужая система
#
# Своей хватает `cargo build`. Чужой — нет: в графе есть `ring`, и часть себя
# он собирает из исходников на C и ассемблере, поэтому одного
# `rustup target add` мало — нужен компилятор C для чужой цели.
#
# | цель    | со своей системы | с чужой                            |
# |---------|------------------|------------------------------------|
# | Windows | `cargo build`    | `cargo xwin` + `llvm-rc`           |
# | Linux   | `cargo build`    | `cargo zigbuild`                   |
# | macOS   | `cargo build`    | нечем: SDK Apple есть только там   |
#
# Отсюда правило, которое стоит знать заранее: `all` с Windows соберёт два
# пакета из трёх и скажет, почему третьего нет. Третий собирается на macOS.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

bold() { printf '\n\033[1m▶ %s\033[0m\n' "$1"; }
ok() { printf '\033[32m  ✓ %s\033[0m\n' "$1"; }
bad() { printf '\033[31m  ✗ %s\033[0m\n' "$1" >&2; }

usage() {
    cat << 'ТЕКСТ'
Собирает поставку — каталог, который можно отдать человеку.

  ./scripts/package.sh            для системы, на которой запущен
  ./scripts/package.sh windows    только Windows
  ./scripts/package.sh linux      только Linux
  ./scripts/package.sh macos      только macOS
  ./scripts/package.sh all        все три

Чужая система собирается не всегда: Windows — через cargo-xwin и llvm-rc,
Linux — через cargo-zigbuild, macOS — только на macOS.
ТЕКСТ
}

# Система, на которой запущен скрипт.
#
# На Windows он живёт в Git Bash, и `uname` там отвечает `MINGW64_NT-…`.
host_system() {
    case "$(uname -s)" in
        Darwin) echo macos ;;
        Linux) echo linux ;;
        MINGW* | MSYS* | CYGWIN*) echo windows ;;
        *) echo unknown ;;
    esac
}

HOST="$(host_system)"

# Тройка цели. У macOS их две, и какая — решает железо: чужую macOS отсюда всё
# равно не собрать, значит своя архитектура и есть ответ.
triple() {
    case "$1" in
        windows) echo x86_64-pc-windows-msvc ;;
        linux) echo x86_64-unknown-linux-gnu ;;
        macos)
            case "$(uname -m)" in
                arm64 | aarch64) echo aarch64-apple-darwin ;;
                *) echo x86_64-apple-darwin ;;
            esac
            ;;
    esac
}

# Чем собирать эту систему отсюда: печатает команду, а когда собрать нечем —
# говорит почему и возвращает 1.
builder() {
    local system="$1"

    if [[ "$system" == "$HOST" ]]; then
        echo "cargo build"
        return 0
    fi

    case "$system" in
        windows)
            if ! command -v cargo-xwin > /dev/null; then
                bad "Windows с $HOST: нужен cargo-xwin — cargo install cargo-xwin"
                return 1
            fi
            # Без него `winresource` не соберёт ресурс с иконкой и уронит
            # сборку: молча остаться без иконки она не умеет и не должна.
            if ! command -v llvm-rc > /dev/null; then
                bad "Windows с $HOST: нужен llvm-rc из LLVM — brew install llvm"
                return 1
            fi
            echo "cargo xwin build"
            ;;
        linux)
            if ! command -v cargo-zigbuild > /dev/null; then
                bad "Linux с $HOST: нужны zig и cargo-zigbuild — cargo install cargo-zigbuild"
                return 1
            fi
            echo "cargo zigbuild"
            ;;
        macos)
            bad "macOS собирается только на macOS: нужен SDK Apple, а он есть лишь там"
            return 1
            ;;
    esac
}

# Собирает и раскладывает поставку для одной системы.
#
# Каждый шаг проверяется вручную, хотя вверху стоит `set -e`: функцию зовут из
# условия `if`, а там оболочка выход по ошибке выключает. Без проверок провал
# сборки прошёл бы молча, и в поставку лёг бы файл от прошлого раза — то есть
# зелёная надпись «готово» поверх старого двоичного файла.
package() {
    local system="$1"
    local tool triple dist suffix
    local -a build

    if ! tool="$(builder "$system")"; then
        return 1
    fi
    read -ra build <<< "$tool"

    triple="$(triple "$system")"
    dist="dist/penguin-$system"

    # Драйвер нужен только Windows: там TUN-адаптер создаёт `wintun.dll`,
    # которой в поставке системы нет. У Linux он в ядре (`/dev/net/tun`), у
    # macOS — utun, и класть в поставку нечего.
    if [[ "$system" == windows ]]; then
        if ! ./scripts/fetch-wintun.sh; then
            bad "$system: драйвер не скачался"
            return 1
        fi
    fi

    if ! "${build[@]}" --workspace --release --target "$triple"; then
        bad "$system: сборка не прошла"
        return 1
    fi

    # Чистится содержимое, а не сам каталог: в Windows его держит открытым кто
    # угодно — проводник, антивирус, оболочка, — и удаление падает на ровном
    # месте.
    mkdir -p "$dist" || return 1
    rm -f "${dist:?}"/* || return 1

    # Суффикс — по цели, а не по машине сборки: поставка для Windows остаётся
    # `penguin.exe`, откуда бы её ни собирали.
    suffix=""
    if [[ "$system" == windows ]]; then
        suffix=".exe"
    fi

    # Файл один. Кем ему быть — окном, службой или командой терминала — он
    # решает сам по своим аргументам, и человеку об этом знать не надо.
    #
    # Иконка уже внутри него: её кладёт в ресурсы `crates/app/build.rs` при
    # сборке выше. Отдельным файлом рядом её класть некуда — проводник
    # смотрит в `.exe`.
    cp "target/$triple/release/penguin${suffix}" "$dist/" || return 1

    # Драйвер кладётся рядом с исполняемым файлом: `wintun::load()` ищет его по
    # обычному пути поиска библиотек, то есть в каталоге программы.
    if [[ "$system" == windows ]]; then
        cp assets/wintun/wintun.dll "$dist/" || return 1
    fi

    # Ни настроек, ни описания: настройки клиент заводит сам при первом
    # запуске, и человеку в них лезть незачем. Лишний файл рядом с программой —
    # это приглашение его открыть и что-нибудь там поправить.
}

# Отдельным именем, а не через `$1`: без аргумента его просто нет, и ветки
# ниже читали бы несуществующее.
REQUEST="${1:-$HOST}"

case "$REQUEST" in
    all) SYSTEMS=(windows linux macos) ;;
    windows | linux | macos) SYSTEMS=("$REQUEST") ;;
    -h | --help) usage && exit 0 ;;
    unknown)
        bad "не понимаю, что за система: $(uname -s). Назовите её сами."
        usage
        exit 2
        ;;
    *)
        bad "не знаю такой системы: $REQUEST"
        usage
        exit 2
        ;;
esac

BUILT=()
MISSING=()
for SYSTEM in "${SYSTEMS[@]}"; do
    bold "$SYSTEM"
    if package "$SYSTEM"; then
        ok "dist/penguin-$SYSTEM"
        BUILT+=("$SYSTEM")
    else
        MISSING+=("$SYSTEM")
    fi
done

bold "что получилось"
# Пустой массив разворачивать нельзя: в bash 3.2, который стоит в macOS, при
# `set -u` это ошибка, а не пустой список.
if [[ ${#BUILT[@]} -gt 0 ]]; then
    for SYSTEM in "${BUILT[@]}"; do
        printf '  %s: %s\n' "$SYSTEM" "$(du -sh "dist/penguin-$SYSTEM" | cut -f1)"
        ls -la "dist/penguin-$SYSTEM" | tail -n +2
    done
else
    echo "  ничего"
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo
    bad "не собрано: ${MISSING[*]}"
    exit 1
fi

echo
printf '\033[32mготово.\033[0m\n'
