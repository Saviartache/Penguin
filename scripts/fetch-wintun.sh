#!/usr/bin/env bash
#
# Скачивает `wintun.dll` — драйвер, без которого не поднимается тоннель.
#
# В git библиотека не лежит намеренно: это чужой подписанный бинарник, и его
# место — рядом с исполняемым файлом, а не в истории нашего репозитория.
# Отсюда и скрипт: сборка должна собираться на чистой машине без ручных шагов.
#
#   ./scripts/fetch-wintun.sh
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION="0.14.1"
URL="https://www.wintun.net/builds/wintun-${VERSION}.zip"

# Хеш архива с сайта проекта. Проверяется до распаковки: подменённый архив
# должен упереться здесь, а не в подпись, которую кто-то поленится посмотреть.
SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"

DEST="assets/wintun/wintun.dll"

# Поставку для Windows собирают и с macOS, значит и качать драйвер приходится
# оттуда. `sha256sum` есть в Linux и в Git Bash, в macOS вместо неё `shasum`.
sha256() {
    if command -v sha256sum > /dev/null; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

if [[ -f "$DEST" ]]; then
    echo "уже на месте: $DEST"
    exit 0
fi

TEMP="$(mktemp -d)"
trap 'rm -rf "$TEMP"' EXIT

echo "качаю $URL"
curl -fsSL --retry 3 -o "$TEMP/wintun.zip" "$URL"

echo "проверяю хеш"
ACTUAL="$(sha256 "$TEMP/wintun.zip")"
if [[ "$ACTUAL" != "$SHA256" ]]; then
    echo "хеш не совпал!" >&2
    echo "  ожидался: $SHA256" >&2
    echo "  получен:  $ACTUAL" >&2
    exit 1
fi

unzip -q "$TEMP/wintun.zip" -d "$TEMP/unpacked"

mkdir -p "$(dirname "$DEST")"
cp "$TEMP/unpacked/wintun/bin/amd64/wintun.dll" "$DEST"

echo "готово: $DEST"
echo
echo "Библиотека подписана WireGuard LLC. Проверить подпись:"
echo "  powershell -c \"Get-AuthenticodeSignature '$DEST' | Format-List Status, SignerCertificate\""
