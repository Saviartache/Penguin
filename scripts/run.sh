#!/usr/bin/env bash
# Запуск Penguin на этой машине. Аргументы уходят приложению: `./scripts/run.sh doctor`.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

exec cargo run -p penguin-app -- "$@"
