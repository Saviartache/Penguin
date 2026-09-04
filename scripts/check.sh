#!/usr/bin/env bash
#
# Проверки перед коммитом. Правила — AGENTS.md §6.
#
#   ./scripts/check.sh          # всё
#   ./scripts/check.sh --fast   # без сборки без фич и без doc
#
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

FAST=0
[[ "${1:-}" == "--fast" ]] && FAST=1

FAILED=()
bold() { printf '\n\033[1m▶ %s\033[0m\n' "$1"; }
ok()   { printf '\033[32m  ✓ %s\033[0m\n' "$1"; }
bad()  { printf '\033[31m  ✗ %s\033[0m\n' "$1"; }

run() {
    local name="$1"; shift
    bold "$name"
    if "$@"; then ok "$name"; else bad "$name"; FAILED+=("$name"); fi
}

run "fmt"    cargo fmt --all -- --check
run "clippy" cargo clippy --workspace --all-targets -- -D warnings
run "build"  cargo build --workspace
run "test"   cargo test --workspace

if [[ $FAST -eq 0 ]]; then
    # Фичи не должны быть обязательными: движок обязан собираться без
    # единого протокола, иначе «опционально» на деле не проверено.
    run "build --no-default-features" cargo build -p penguin-engine --no-default-features

    # И демон — ровно затем его список фич и заведён. Собирается он отдельно:
    # у движка фичи включает ещё и `cli`, и объединение фич Cargo вернуло бы
    # протоколы обратно, а проверка бы этого не заметила.
    run "daemon --no-default-features" cargo build -p penguin-daemon --no-default-features

    # Платформенный слой написан трижды, и код для чужой системы не проверяется
    # ничем, кроме такой сборки: иначе ошибка находится у того, кто первым
    # запустит сборку на той системе. Крейты перечислены поимённо, а не взят
    # весь workspace: `ring` собирает свою часть на C и требует компилятора для
    # чужой цели, которого на машине разработчика нет.
    for TARGET in x86_64-pc-windows-msvc x86_64-unknown-linux-gnu aarch64-apple-darwin; do
        run "check $TARGET" cargo check --target "$TARGET" --all-targets \
            -p penguin-platform -p penguin-tun -p penguin-process
    done

    run "doc" env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
fi

echo
if [[ ${#FAILED[@]} -gt 0 ]]; then
    printf '\033[31mПРОВАЛЕНО:\033[0m\n'
    printf '  · %s\n' "${FAILED[@]}"
    exit 1
fi
printf '\033[32mВсе проверки пройдены.\033[0m\n'
