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
    run "doc" env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
fi

echo
if [[ ${#FAILED[@]} -gt 0 ]]; then
    printf '\033[31mПРОВАЛЕНО:\033[0m\n'
    printf '  · %s\n' "${FAILED[@]}"
    exit 1
fi
printf '\033[32mВсе проверки пройдены.\033[0m\n'
