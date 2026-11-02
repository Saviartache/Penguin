#!/usr/bin/env bash
# Сборка workspace на этой машине; поставка — ./scripts/package.sh.
# Аргументы уходят в cargo: `./scripts/build.sh --release`.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

exec cargo build --workspace "$@"
