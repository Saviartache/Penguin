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
# # Что в нём лежит
#
# | цель    | содержимое                                          |
# |---------|-----------------------------------------------------|
# | Windows | `penguin.exe` и `wintun.dll` рядом с ним            |
# | Linux   | `penguin`, `penguin.png`, `penguin.desktop`         |
# | macOS   | `Penguin.app` и ссылка `penguin` внутрь неё         |
#
# Связка на macOS — не украшение: голый исполняемый файл система программой не
# считает и по двойному щелчку открывает его в Терминале, то есть рядом с
# окном появляется консоль. Подробности — у `bundle_app`.
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
        linux)
            # Своя архитектура, когда Linux и есть эта машина: на ARM-машине
            # собирать x86_64 нечем, и «поставка для Linux» означала бы там
            # отказ. С чужой системы выбора нет — x86_64.
            if [[ "$HOST" == linux ]]; then
                arch_suffix
            else
                echo x86_64-unknown-linux-gnu
            fi
            ;;
        macos)
            case "$(uname -m)" in
                arm64 | aarch64) echo aarch64-apple-darwin ;;
                *) echo x86_64-apple-darwin ;;
            esac
            ;;
    esac
}

# Тройка Linux под архитектуру этой машины.
arch_suffix() {
    case "$(uname -m)" in
        aarch64 | arm64) echo aarch64-unknown-linux-gnu ;;
        *) echo x86_64-unknown-linux-gnu ;;
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

# `penguin.icns` из `assets/icon.png`.
#
# У macOS иконка связки — файл в `Resources`, а не ресурс внутри двоичного
# файла, как на Windows. Отсюда и место: не `build.rs`, а раскладка поставки.
icns() {
    local out="$1" iconset size

    iconset="$(mktemp -d)/penguin.iconset"
    mkdir -p "$iconset" || return 1

    # Набор размеров задан Apple. Чего в нём нет, то система дорисовывает сама
    # и хуже, чем `sips`.
    for size in 16 32 128 256 512; do
        sips -z "$size" "$size" assets/icon.png \
            --out "$iconset/icon_${size}x${size}.png" > /dev/null 2>&1 || return 1
        sips -z "$((size * 2))" "$((size * 2))" assets/icon.png \
            --out "$iconset/icon_${size}x${size}@2x.png" > /dev/null 2>&1 || return 1
    done

    iconutil --convert icns "$iconset" --output "$out" || return 1
    rm -rf "$(dirname "$iconset")"
}

# Кладёт рядом с файлом иконку и `penguin.desktop`.
#
# Консоль на Linux сама собой не открывается: файловые менеджеры ELF через
# терминал не запускают. Но у запуска из меню есть отдельный выключатель —
# `Terminal=true` в `.desktop` заставил бы оболочку открыть терминал и работать
# в нём. Здесь он выключен прямо, а не по умолчанию.
#
# Иконку не пересобираем: PNG и есть тот формат, который system нужен, — в
# отличие от macOS, где связка требует `.icns`. Раскладывать её по размерам
# `hicolor` будет установщик; здесь она лежит целой картинкой.
desktop_entry() {
    local dist="$1"

    cp assets/icon.png "$dist/penguin.png" || return 1

    # `Icon` и `Exec` — короткими именами, а не путями: путь до каталога, куда
    # поставку распакуют, здесь неизвестен, а установщик кладёт файл в PATH и
    # иконку в тему.
    #
    # `StartupWMClass` и `application_id` окна (`crates/gui/src/lib.rs`) — одна
    # и та же строка `penguin`, что и имя этого файла: по ней оболочка и
    # связывает открытое окно с этой записью.
    cat > "$dist/penguin.desktop" << 'ЗАПИСЬ' || return 1
[Desktop Entry]
Type=Application
Name=Penguin
Comment=VPN client with split tunnelling
Comment[ru]=VPN-клиент с раздельным тоннелированием
Exec=penguin
Icon=penguin
Terminal=false
Categories=Network;
StartupWMClass=penguin
ЗАПИСЬ
}

# Собирает `Penguin.app` — то, что macOS считает программой.
#
# Голый исполняемый файл ею не считается: двойной щелчок по нему в Finder
# открывает Терминал и запускает файл там, и рядом с окном программы остаётся
# чёрное окно консоли, которое человек не просил. Программу делает не файл, а
# связка — каталог с суффиксом `.app`, `Info.plist` внутри и исполняемый файл
# там, куда plist показывает.
#
# Это ровно то же, что `windows_subsystem = "windows"` на Windows, только
# средствами системы, а не компоновщика.
bundle_app() {
    local dist="$1" triple="$2"
    local app="$dist/Penguin.app" version

    mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" || return 1
    cp "target/$triple/release/penguin" "$app/Contents/MacOS/" || return 1

    # Номер спрашивается у самой программы: так номер в свойствах связки и
    # номер, который печатает `--version`, не разъедутся.
    version="$("$app/Contents/MacOS/penguin" --version | awk '{print $2}')"
    if [[ -z "$version" ]]; then
        bad "macos: программа не назвала свою версию"
        return 1
    fi

    icns "$app/Contents/Resources/penguin.icns" || return 1

    # `CFBundleIdentifier` — та же строка, что и каталог настроек в macOS
    # (`~/Library/Application Support/Saviartache.Penguin`): одно имя программы
    # в системе, а не два похожих.
    cat > "$app/Contents/Info.plist" << PLIST || return 1
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>              <string>Penguin</string>
    <key>CFBundleDisplayName</key>       <string>Penguin</string>
    <key>CFBundleIdentifier</key>        <string>Saviartache.Penguin</string>
    <key>CFBundleExecutable</key>        <string>penguin</string>
    <key>CFBundleIconFile</key>          <string>penguin</string>
    <key>CFBundlePackageType</key>       <string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$version</string>
    <key>CFBundleVersion</key>           <string>$version</string>
    <key>NSHighResolutionCapable</key>   <true/>
</dict>
</plist>
PLIST

    # Ссылка для терминала: `./penguin doctor` короче и привычнее, чем путь
    # внутрь связки. Файл тот же самый — роль он выбирает по аргументам.
    ln -sf "Penguin.app/Contents/MacOS/penguin" "$dist/penguin" || return 1
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
    # `-r`: в поставке для macOS лежит не файл, а каталог связки.
    rm -rf "${dist:?}"/* || return 1

    # Суффикс — по цели, а не по машине сборки: поставка для Windows остаётся
    # `penguin.exe`, откуда бы её ни собирали.
    suffix=""
    if [[ "$system" == windows ]]; then
        suffix=".exe"
    fi

    # Файл один. Кем ему быть — окном, службой или командой терминала — он
    # решает сам по своим аргументам, и человеку об этом знать не надо.
    #
    # Иконка на Windows уже внутри него: её кладёт в ресурсы
    # `crates/app/build.rs` при сборке выше. Отдельным файлом рядом её класть
    # некуда — проводник смотрит в `.exe`. У macOS иначе, и там её кладёт
    # `bundle_app`.
    if [[ "$system" == macos ]]; then
        bundle_app "$dist" "$triple" || return 1
    else
        cp "target/$triple/release/penguin${suffix}" "$dist/" || return 1
    fi

    if [[ "$system" == linux ]]; then
        desktop_entry "$dist" || return 1
    fi

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
