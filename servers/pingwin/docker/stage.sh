#!/usr/bin/env bash
#
# Собирает контекст сборки образа: вырезку из репозитория, в которой есть
# ровно то, от чего зависит сервер.
#
#   bash servers/pingwin/docker/stage.sh /tmp/pingwin-ctx
#
# Дальше эту папку можно собрать на месте (`docker compose up -d --build`)
# либо увезти на сервер целиком — она самодостаточна.

set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "куда складывать: $0 <папка>" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
HERE="$ROOT/servers/pingwin/docker"

rm -rf "$TARGET"
mkdir -p "$TARGET"

# Корневой манифест — свой, не репозиторный: почему, написано в нём самом.
cp "$HERE/workspace.toml" "$TARGET/Cargo.toml"

for CRATE in crates/core crates/proto protocols/transport protocols/utls \
             protocols/pingwin servers/pingwin; do
    mkdir -p "$TARGET/$CRATE"
    cp "$ROOT/$CRATE/Cargo.toml" "$TARGET/$CRATE/Cargo.toml"
    # Только исходники и проверки: `target/` в контекст не попадает, иначе
    # сборка увезла бы на сервер десятки гигабайт чужих артефактов.
    cp -R "$ROOT/$CRATE/src" "$TARGET/$CRATE/src"
    [[ -d "$ROOT/$CRATE/tests" ]] && cp -R "$ROOT/$CRATE/tests" "$TARGET/$CRATE/tests"
done

cp "$HERE/Dockerfile" "$TARGET/Dockerfile"
cp "$HERE/compose.yml" "$TARGET/compose.yml"
cp -R "$HERE/cover" "$TARGET/cover"
# Под своим именем: в репозитории файл лежит без точки, иначе он прятался бы
# от `ls` и от глаз, а прячется в нём как раз самое важное — `target/`.
cp "$HERE/dockerignore" "$TARGET/.dockerignore"

echo "контекст собран: $TARGET"
du -sh "$TARGET"
